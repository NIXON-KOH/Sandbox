import docker
import os
import time
import json
import yara
from datetime import datetime, timezone
from tools.useful import Log
from hashlib import file_digest, new
import yaml
from dotenv import load_dotenv  
import vt
from google import genai
import warnings
warnings.filterwarnings("ignore", category=ResourceWarning, module="aiohttp")

# Load environment variables from .env 
load_dotenv()

# Load settings
with open('settings.yaml', 'r') as file:
    settings = yaml.safe_load(file)

log = Log()
client = docker.from_env()

VT_API_KEY = os.getenv("VT_API_KEY")      
vtClient = vt.Client(VT_API_KEY)

def verify_images():
    default_image = settings["sandbox"]["default_image"]
    fakenet_image = settings["sandbox"]["fakenet_image"]
    dockerfiles_dir = settings["paths"]["dockerfiles_dir"]

    try:
        client.images.get(default_image)
        log.success(f"Sandbox image found locally: {default_image}")
    except docker.errors.ImageNotFound:
        log.warning(f"Image not found. Building {default_image}...")
        client.images.build(path=dockerfiles_dir, tag=default_image, rm=True)
        log.success("Sandbox image built successfully!")

    try:
        client.images.get(fakenet_image)
        log.success(f"FakeNet gateway image found locally: {fakenet_image}")
    except docker.errors.ImageNotFound:
        log.warning(f"FakeNet image not found. Building {fakenet_image}...")
        client.images.build(
            path=dockerfiles_dir,
            dockerfile="Dockerfile.fakenet",
            tag=fakenet_image,
            rm=True
        )
        log.success("FakeNet gateway image built successfully!")

def ensure_network_exists():
    network_name = settings["sandbox"]["network_name"]
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        log.info(f"Creating isolated internal network: {network_name}")
        client.networks.create(network_name, driver="bridge", internal=True)

def calculate_sha256(file_path):
    with open(file_path, "rb") as f:
        digest = file_digest(f, "sha256")
    return digest.hexdigest()

def hash_results(directory, algorithm="sha256"):
    """Compute a hash of all files in a directory (for integrity checks)."""
    h = new(algorithm)
    if not os.path.exists(directory):
        return h.hexdigest()
    for root, _, files in os.walk(directory):
        for name in sorted(files):
            path = os.path.join(root, name)
            h.update(os.path.relpath(path, directory).encode())
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    h.update(chunk)
    return h.hexdigest()

def run_static_analysis(sample_path, output_dir=None):
    """
    Perform static analysis on the sample using VirusTotal and YARA (optional).
    If output_dir is provided, results are saved there; otherwise a new folder is created.
    Returns a dict with static findings.
    """
    log.info("Starting static analysis...")
    results = {
        "analysis_type": "static",
        "sample_name": os.path.basename(sample_path),
        "sha256": calculate_sha256(sample_path),
        "vt_report": None,
        "yara_matches": [],
        "entropy": None,
        "aiEvalStatic": None
    }

    if settings.get("static", {}).get("virusTotal", False):
        if VT_API_KEY:
            try:
                analysis = vtClient.get_object(f"/files/{results['sha256']}")
                stats = analysis.last_analysis_stats
                if hasattr(stats, 'items'):
                    stats = dict(stats)
                results["vt_report"] = {
                    "detections": stats,
                    "permalink": f"https://www.virustotal.com/gui/file/{results['sha256']}",
                }
                log.success("SHA256 found on VirusTotal.")
            except vt.APIError:
                # Fallback to upload if not found
                with open(sample_path, "rb") as f:
                    data = vtClient.scan_file(f, wait_for_completion=True)
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if hasattr(stats, 'items'):
                        stats = dict(stats)
                    results["vt_report"] = {
                        "detections": stats,
                        "permalink": f"https://www.virustotal.com/gui/file/{results['sha256']}",
                    }
                    log.success("VirusTotal lookup succeeded.")
        else:
            log.warning("VT_API_KEY not set; skipping VirusTotal.")
    else:
        log.info("VirusTotal disabled.")

    # ----- YARA -----
    yara_rules_path = settings.get("paths", {}).get("yara_rules", None)
    if settings.get("static", {}).get("yaraMatching", False):
        if yara_rules_path and os.path.exists(yara_rules_path):
            rules = yara.compile(yara_rules_path)
            matches = rules.match(sample_path)
            results["yara_matches"] = [str(match) for match in matches]
        else:
            log.info("No YARA rules path provided; skipping.")
    else:
        log.info("Yara Matching disabled.")

    # ----- Entropy -----
    if settings.get("static", {}).get("entropy", False):
        try:
            with open(sample_path, "rb") as f:
                data = f.read()
                if data:
                    import math
                    entropy = 0
                    for x in range(256):
                        p_x = data.count(x) / len(data)
                        if p_x > 0:
                            entropy -= p_x * math.log2(p_x)
                    results["entropy"] = round(entropy, 2)
        except Exception:
            pass
    else:
        log.info("Entropy disabled.")

    if settings.get("static", {}).get("aiEval", False):
        GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        if GEMINI_API_KEY:
            try:
                sclient = genai.Client(api_key=GEMINI_API_KEY)
                sample_file = sclient.files.upload(file=sample_path)

                response = sclient.models.generate_content(
                    model=settings.get("static", {}).get("aiModelName", "gemini-3.5-flash"),   # adjust to your model
                    contents=[
                        {
                            "role": "user",
                            "parts": [
                                {"file_data": {"file_uri": sample_file.uri}},
                                {"text": (
                                    "Analyze this file. Explain what it does and break down its logic. "
                                    "Highlight suspicious indicators or malicious behaviour."
                                    "Reply in markdown, keep it simple bullet point."
                                )}
                            ]
                        }
                    ]
                )
                results["aiEvalStatic"] = response.text.replace("\n\n","\n")
                log.success("Static AI evaluation completed.")
            except Exception as e:
                log.error(f"Static AI evaluation failed: {e}")
        else:
            log.warning("GEMINI_API_KEY not set; skipping static AI evaluation.")
    else:
        log.info("Static AI evaluation disabled.")

    # Determine output directory
    if output_dir is None:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_hash = results["sha256"][:6]
        folder_name = f"{timestamp}_{file_hash}_static"
        result_dir = settings["paths"]["result_dir"]   
        output_dir = os.path.abspath(os.path.join(result_dir, folder_name))
        os.makedirs(output_dir, exist_ok=True)
    else:
        os.makedirs(output_dir, exist_ok=True)

    results["output_dir"] = output_dir
    return results

def run_sandbox(sample_path):
    verify_images()
    ensure_network_exists()

    log.info("Initializing isolated analysis lab with FakeNet gateway...")

    filetype = sample_path.split(".")[-1].lower()
    runners = settings.get("runners", {})
    executor = runners.get(filetype, "bash")

    abs_sample_path = os.path.abspath(sample_path)
    file_hash = calculate_sha256(abs_sample_path)
    started_time = datetime.now(timezone.utc)
    start_perf = time.perf_counter()

    # Prepare output directory
    report_folder_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:6]}"
    result_dir = settings["paths"]["result_dir"]
    output_dir = os.path.abspath(os.path.join(result_dir, report_folder_name))
    os.makedirs(output_dir, exist_ok=True)

    fakenet_container = None
    container = None
    container_id = "N/A"
    status = "completed"
    exit_code = 0
    container_diffs = []

    try:
        log.info("Starting FakeNet network listener container...")
        fakenet_env = {"FAKENET_SINKHOLE": "true"}  
        fakenet_container = client.containers.run(
            image=settings["sandbox"]["fakenet_image"],
            name=f"fakenet_{file_hash[:6]}",
            network=settings["sandbox"]["network_name"],
            detach=True,
            cap_add=["NET_ADMIN"],
            environment=fakenet_env,       
        )
        log.success("FakeNet gateway container active.")

        volumes = {
            abs_sample_path: {'bind': f'/sandbox/sample.{filetype}', 'mode': 'ro'},
            output_dir: {'bind': '/results', 'mode': 'rw'},
        }
        env_vars = None

        fake_lib = settings["paths"].get("fake_tracer_lib")
        if fake_lib and os.path.isfile(fake_lib):
            abs_fake_lib = os.path.abspath(fake_lib)
            volumes[abs_fake_lib] = {'bind': '/lib/libfake_tracer.so', 'mode': 'ro'}
            env_vars = {
                "LD_PRELOAD": "/lib/libfake_tracer.so",
                "container": "lxc",          
                "HOSTNAME": "ubuntu-host",    
            }
        else:
            log.warning("Fake tracer library missing. Proceeding without LD_PRELOAD.")

        # Container resources from settings
        resources = settings.get("container_resources", {})
        mem_limit = resources.get("mem_limit", "512m")
        pids_limit = resources.get("pids_limit", 256)
        cpu_period = resources.get("cpu_period", 100000)
        cpu_quota = resources.get("cpu_quota", 50000)

        log.info("Launching malware sandbox container...")
        container = client.containers.run(
            image=settings["sandbox"]["default_image"],
            command=[executor, f"/sandbox/sample.{filetype}"],
            volumes=volumes,
            network_mode=f"container:{fakenet_container.id}",
            environment=env_vars,
            cap_add=["SYS_PTRACE"],
            detach=True,
            mem_limit=mem_limit,
            pids_limit=pids_limit,
            cpu_period=cpu_period,
            cpu_quota=cpu_quota,
            cap_drop=["ALL"],
        )

        container_id = container.id
        log.info("Detonating sample inside container...")

        detonation_timeout = settings["sandbox"]["detonation_timeout"]
        time.sleep(detonation_timeout)

        log.info("Checking execution status...")
        container.reload()
        if container.status == 'running':
            container.stop(timeout=1)
            status = "timeout"

        res = container.wait(timeout=1)
        exit_code = res.get("StatusCode", 0)

        # Capture filesystem changes
        try:
            container_diffs = container.diff() or []
            diff_log_path = os.path.join(output_dir, "filesystem_diff.json")
            with open(diff_log_path, "w", encoding="utf-8") as diff_file:
                json.dump(container_diffs, diff_file, indent=4)
        except Exception as diff_err:
            log.error(f"Failed to capture container diff: {diff_err}")

    except Exception as e:
        status = "failed"
        exit_code = 1
        log.error(f"Error during analysis execution: {e}")

    finally:
        # Collect FakeNet logs
        try:
            log.info("Collecting network activity logs from FakeNet...")
            fakenet_logs = fakenet_container.logs(stdout=True, stderr=True).decode('utf-8')
            network_log_path = os.path.join(output_dir, "network_activity.log")
            with open(network_log_path, "w", encoding="utf-8") as net_file:
                net_file.write(fakenet_logs)
            log.success(f"Network log saved to: {network_log_path}")
        except Exception:
            log.error("Failed to collect Network Activity Log from FakeNet")

        log.info("Cleaning up: Destroying containers safely...")
        for c in [container, fakenet_container]:
            if c:
                try:
                    c.stop(timeout=2)
                    c.remove(force=True)
                except Exception:
                    pass
        log.success("Environment wiped clean.")

    finished_time = datetime.now(timezone.utc)

    duration = round(time.perf_counter() - start_perf, 3)
    aiEval = None

    if settings.get("sandbox", {}).get("aiEval", False):
        GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        if GEMINI_API_KEY:
            try:
                trace_path = os.path.join(output_dir, "trace.log")
                if os.path.isfile(trace_path) and os.path.getsize(trace_path) > 0:
                    txt_path = trace_path.replace(".log", ".txt")
                    os.rename(trace_path, txt_path)

                    geclient = genai.Client(api_key=GEMINI_API_KEY)
                    sample_file = geclient.files.upload(file=txt_path)

                    response = geclient.models.generate_content(
                        model=settings.get("sandbox", {}).get("aiModelName", "gemini-3.5-flash"), 
                        contents=[
                            {
                                "role": "user",
                                "parts": [
                                    {"file_data": {"file_uri": sample_file.uri}},
                                    {"text": (
                                        "This is a strace result of a file. "
                                        "Highlight suspicious indicators or malicious behaviour. "
                                        "Reply in bullet point, markdown. Keep it short and simple."
                                    )}
                                ]
                            }
                        ]
                    )
                    aiEval = response.text.replace("\n\n", "\n")
                    log.success("Dynamic AI evaluation completed.")
                else:
                    log.warning(f"Trace log not found or empty at {trace_path}. Skipping dynamic AI evaluation.")
            except Exception as e:
                log.error(f"Dynamic AI evaluation failed: {e}")
        else:
            log.warning("GEMINI_API_KEY not set; skipping dynamic AI evaluation.")
    else:
        log.info("Dynamic AI evaluation disabled.")

    # Return all raw results 
    return {
        "analysis_type": "sandbox",
        "sample_path": abs_sample_path,
        "file_hash": file_hash,
        "output_dir": output_dir,
        "container_id": container_id,
        "status": status,
        "exit_code": exit_code,
        "duration": duration,
        "started_time": started_time,
        "finished_time": finished_time,
        "detonation_timeout": detonation_timeout,
        "image": settings["sandbox"]["default_image"],
        "sample_name": os.path.basename(sample_path),
        "aiEvalDynamic": aiEval,
    }

def build_report(analysis_results):
    """Generate a single metadata.json from the provided results dict."""
    # Extract values from results dict
    sample_name = analysis_results["sample_name"]
    file_hash = analysis_results.get("file_hash", "unknown")
    output_dir = analysis_results["output_dir"]
    container_id = analysis_results.get("container_id", "N/A")
    status = analysis_results.get("status", "unknown")
    exit_code = analysis_results.get("exit_code", -1)
    duration = analysis_results.get("duration", 0)
    started_time = analysis_results.get("started_time", datetime.now(timezone.utc))
    finished_time = analysis_results.get("finished_time", datetime.now(timezone.utc))
    detonation_timeout = analysis_results.get("detonation_timeout", "N/A")
    image = analysis_results.get("image", "unknown")

    report_data = {
        "sample": sample_name,
        "SHA256": file_hash,
        "analysis_type": analysis_results["analysis_type"],
        "image": image,
        "detonation_duration_seconds": detonation_timeout,
        "started": started_time.isoformat(),
        "status": status,
        "container_id": container_id,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "finished": finished_time.isoformat(),
        "Directory_SHA256": hash_results(output_dir),
    }

    if "vt_report" in analysis_results:
        report_data["virustotal"] = analysis_results["vt_report"]
    if "entropy" in analysis_results:
        report_data["entropy"] = analysis_results["entropy"]
    if "yara_matches" in analysis_results:
        report_data["yara_matches"] = analysis_results["yara_matches"]
    if "aiEvalStatic" in analysis_results:
        report_data["aiEvalStatic"] = analysis_results.get("aiEvalStatic", None)
    if "aiEvalDynamic" in analysis_results:
        report_data["aiEvalDynamic"] = analysis_results.get("aiEvalDynamic", None)

    # Write the report
    report_path = os.path.join(output_dir, "metadata.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    log.success(f"Metadata report saved to: {report_path}")
    return report_data

def orchestrate(sample_path):
    """
    Run static and/or sandbox analyses as per settings.
    If both are enabled, results are merged into a single output folder
    and a unified metadata.json is produced.
    """
    results = []
    sandbox_results = None
    static_results = None

    # Run sandbox analysis if enabled
    if settings.get("sandbox", {}).get("enabled", False):
        log.info("Sandbox analysis enabled: starting...")
        sandbox_results = run_sandbox(sample_path)
        results.append(sandbox_results)
    else:
        log.info("Sandbox analysis disabled in settings.")

    # Run static analysis if enabled
    if settings.get("static", {}).get("enabled", False):
        log.info("Static analysis enabled: starting...")
        output_dir = sandbox_results["output_dir"] if sandbox_results else None
        static_results = run_static_analysis(sample_path, output_dir=output_dir)
        results.append(static_results)
    else:
        log.info("Static analysis disabled in settings.")

    # Generate final report(s)
    if sandbox_results and static_results:
        combined = sandbox_results.copy()
        for key in ["vt_report", "entropy", "yara_matches", "aiEvalStatic"]:
            if key in static_results:
                combined[key] = static_results[key]
        combined["analysis_type"] = "combined" 
        combined["output_dir"] = sandbox_results["output_dir"]
        build_report(combined)
    elif sandbox_results:
        build_report(sandbox_results)
    elif static_results:
        build_report(static_results)
    else:
        log.warning("No analysis enabled. Nothing to report.")

    return results

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    default_sample = settings.get("paths", {}).get("default_sample", "Zoo/snail.sh")
    orchestrate(os.path.join(".", default_sample))