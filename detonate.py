import tempfile

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
import requests
from google import genai
import warnings
import argparse
import math
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import functools
import traceback
import random

# Suppress noisy ResourceWarning from aiohttp
warnings.filterwarnings("ignore", category=ResourceWarning, module="aiohttp")

log = Log()

# ----------------------------------------------------------------------
# Load environment and settings
# ----------------------------------------------------------------------
load_dotenv()

with open('settings.yaml', 'r') as file:
    settings = yaml.safe_load(file)

client = docker.from_env()
VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_CLIENT = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# ----------------------------------------------------------------------
# JobStore
# ----------------------------------------------------------------------
class JobStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._jobs = {}
                cls._instance._jobs_lock = threading.Lock()
        return cls._instance

    def create_job(self, sample_path, job_type="combined"):
        job_id = f"{int(time.time())}_{os.path.basename(sample_path)}_{job_type}"
        job = {
            "id": job_id,
            "sample": sample_path,
            "type": job_type,
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "finished_at": None,
            "result": None,
            "error": None,
        }
        with self._jobs_lock:
            self._jobs[job_id] = job
        return job_id

    def update_job(self, job_id, **kwargs):
        with self._jobs_lock:
            if job_id in self._jobs:
                self._jobs[job_id].update(kwargs)

    def get_job(self, job_id):
        with self._jobs_lock:
            return self._jobs.get(job_id)

    def get_all_jobs(self):
        with self._jobs_lock:
            return dict(self._jobs)

job_store = JobStore()

# ----------------------------------------------------------------------
# Retry decorator for external API calls
# ----------------------------------------------------------------------
def retry_with_backoff(retries=3, backoff_in_seconds=2, exceptions=(Exception,)):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while attempt < retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt == retries:
                        log.error(f"Failed after {retries} attempts: {e}")
                        raise
                    wait = backoff_in_seconds * (2 ** (attempt - 1))
                    log.warning(f"Attempt {attempt} failed ({e}). Retrying in {wait}s...")
                    time.sleep(wait)
        return wrapper
    return decorator

# ----------------------------------------------------------------------
# Configuration validation
# ----------------------------------------------------------------------
def validate_settings():
    required_keys = {
        "sandbox": ["default_image", "fakenet_image", "network_name", "detonation_timeout"],
        "paths": ["result_dir", "dockerfiles_dir"]
    }
    for section, keys in required_keys.items():
        if section not in settings:
            log.error(f"Missing section '{section}' in settings.yaml")
            sys.exit(1)
        for key in keys:
            if key not in settings[section]:
                log.error(f"Missing key '{key}' in settings.yaml[{section}]")
                sys.exit(1)

validate_settings()

# ----------------------------------------------------------------------
# Docker image verification
# ----------------------------------------------------------------------
class BuildLock:
    LOCK_PATH = os.path.join(tempfile.gettempdir(), "malware_analysis_build.lock")
    TIMEOUT = 60 

    @classmethod
    def acquire(cls):
        start_time = time.time()
        while True:
            try:
                os.mkdir(cls.LOCK_PATH)
                return
            except FileExistsError:
                if time.time() - start_time > cls.TIMEOUT:
                    raise TimeoutError("Could not acquire build lock")
                time.sleep(1)
            except FileNotFoundError:
                # Parent directory missing – create it and try again
                os.makedirs(os.path.dirname(cls.LOCK_PATH), exist_ok=True)

    @classmethod
    def release(cls):
        try:
            os.rmdir(cls.LOCK_PATH)
        except OSError:
            pass

def verify_images():
    default_image = settings["sandbox"]["default_image"]
    fakenet_image = settings["sandbox"]["fakenet_image"]
    dockerfiles_dir = settings["paths"]["dockerfiles_dir"]

    BuildLock.acquire()
    try:
        try:
            client.images.get(default_image)
            log.success(f"Sandbox image found locally: {default_image}")
        except docker.errors.ImageNotFound:
            log.warning(f"Image not found. Building {default_image}...")
            try:
                client.images.build(path=dockerfiles_dir, tag=default_image, rm=True)
                log.success("Sandbox image built successfully!")
            except docker.errors.BuildError as e:
                log.error(f"Failed to build sandbox image: {e}")
                raise

        try:
            client.images.get(fakenet_image)
            log.success(f"FakeNet gateway image found locally: {fakenet_image}")
        except docker.errors.ImageNotFound:
            log.warning(f"FakeNet image not found. Building {fakenet_image}...")
            try:
                client.images.build(
                    path=dockerfiles_dir,
                    dockerfile="Dockerfile.fakenet",
                    tag=fakenet_image,
                    rm=True
                )
                log.success("FakeNet gateway image built successfully!")
            except docker.errors.BuildError as e:
                log.error(f"Failed to build FakeNet image: {e}")
                raise
    finally:
        BuildLock.release()

def ensure_network_exists():
    network_name = settings["sandbox"]["network_name"]
    try:
        client.networks.get(network_name)
    except docker.errors.NotFound:
        log.info(f"Creating isolated internal network: {network_name}")
        client.networks.create(network_name, driver="bridge", internal=True)

# ----------------------------------------------------------------------
# Hashing utilities
# ----------------------------------------------------------------------
def calculate_sha256(file_path):
    with open(file_path, "rb") as f:
        digest = file_digest(f, "sha256")
    return digest.hexdigest()

def hash_results(directory, algorithm="sha256"):
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

# ----------------------------------------------------------------------
# File type detection 
# ----------------------------------------------------------------------
try:
    import magic
    def detect_file_type(file_path):
        mime = magic.from_file(file_path, mime=True)
        # Map MIME to runner
        if mime.startswith('text/x-python') or mime.startswith('application/x-python'):
            return 'python3'
        elif mime.startswith('application/x-sh') or mime.startswith('text/x-shellscript'):
            return 'bash'
        elif mime.startswith('application/x-executable') or mime.startswith('application/x-elf'):
            return 'executable'
        else:
            # fallback to extension
            ext = file_path.split('.')[-1].lower()
            return ext
except ImportError:
    def detect_file_type(file_path):
        return file_path.split('.')[-1].lower()

# ----------------------------------------------------------------------
# VirusTotal API 
# ----------------------------------------------------------------------
@retry_with_backoff(retries=3, backoff_in_seconds=2, exceptions=(requests.RequestException,))
def _vt_lookup(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, timeout=30)
    if response.status_code == 404:
        raise requests.HTTPError("File not found", response=response)
    response.raise_for_status()
    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if hasattr(stats, 'items'):
        stats = dict(stats)
    return {
        "detections": stats,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }

@retry_with_backoff(retries=3, backoff_in_seconds=2, exceptions=(requests.RequestException,))
def _vt_upload(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(url, headers=headers, files=files, timeout=60)
    response.raise_for_status()
    data = response.json()
    sha256 = data.get("data", {}).get("id", "")
    if not sha256:
        sha256 = calculate_sha256(file_path)

    analysis_id = data["data"]["id"]
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    analysis_data = None
    # Exponential backoff polling – up to 15 attempts (max ~ 30s)
    for attempt in range(15):
        sleep_time = min(2 ** attempt, 30)
        time.sleep(sleep_time)
        analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
        analysis_response.raise_for_status()
        analysis_data = analysis_response.json()
        status = analysis_data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break

    stats = {}
    if analysis_data:
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        if hasattr(stats, 'items'):
            stats = dict(stats)

    return {
        "detections": stats,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }

def _vt_task(sample_path, sha256, enabled, max_upload_size):
    if not enabled or not VT_API_KEY:
        log.warning("VirusTotal disabled or API key missing.")
        return None
    try:
        return _vt_lookup(sha256)
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            file_size = os.path.getsize(sample_path)
            if file_size <= max_upload_size:
                log.info("File not found on VT. Uploading...")
                return _vt_upload(sample_path)
            else:
                log.warning(f"File size {file_size} exceeds VT upload limit. Skipping.")
                return None
        else:
            log.error(f"VirusTotal request failed: {e}")
            return None

# ----------------------------------------------------------------------
# YARA 
# ----------------------------------------------------------------------
_yara_rules_cache = None
_yara_rules_path_cache = None

def _get_yara_rules(rules_path):
    global _yara_rules_cache, _yara_rules_path_cache
    if rules_path != _yara_rules_path_cache:
        _yara_rules_cache = None
    if _yara_rules_cache is None:
        if not rules_path or not os.path.exists(rules_path):
            log.info("No YARA rules path provided or file missing.")
            _yara_rules_cache = None
            _yara_rules_path_cache = None
        else:
            try:
                _yara_rules_cache = yara.compile(rules_path)
                _yara_rules_path_cache = rules_path
                log.success("YARA rules compiled and cached.")
            except yara.Error as e:
                log.error(f"YARA compilation failed: {e}")
                _yara_rules_cache = None
    return _yara_rules_cache

def _yara_task(sample_path, enabled, rules_path):
    if not enabled:
        return []
    rules = _get_yara_rules(rules_path)
    if rules is None:
        return []
    try:
        matches = rules.match(sample_path)
        return [str(match) for match in matches]
    except yara.Error as e:
        log.error(f"YARA matching failed: {e}")
        return []

def _entropy_task(sample_path, enabled):
    """Compute Shannon entropy of the file using streaming to avoid memory issues."""
    if not enabled:
        return None
    try:
        freq = [0] * 256
        total = 0
        with open(sample_path, "rb") as f:
            while chunk := f.read(8192):
                for byte in chunk:
                    freq[byte] += 1
                    total += 1
        if total == 0:
            return None
        entropy = 0.0
        for count in freq:
            if count:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return None

def _ai_evaluate_text(text, prompt, model_name):
    """Shared helper for AI evaluation of text content."""
    if not GEMINI_CLIENT:
        log.warning("Gemini client not available.")
        return None
    try:
        # If text is small enough, include directly; else upload as file.
        if len(text) < 1024 * 1024:  # 1 MB
            content = [
                {"role": "user", "parts": [{"text": prompt}, {"text": text}]}
            ]
        else:
            # Upload as file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                tf.write(text)
                tf_path = tf.name
            try:
                sample_file = GEMINI_CLIENT.files.upload(file=tf_path)
                content = [
                    {"role": "user", "parts": [
                        {"file_data": {"file_uri": sample_file.uri}},
                        {"text": prompt}
                    ]}
                ]
            finally:
                os.unlink(tf_path)
        response = GEMINI_CLIENT.models.generate_content(
            model=model_name,
            contents=content
        )
        return response.text.replace("\n\n", "\n")
    except Exception as e:
        log.error(f"AI evaluation failed: {e}")
        traceback.print_exc()
        return None

def _ai_static_task(sample_path, enabled, model_name):
    if not enabled:
        return None
    if not GEMINI_CLIENT:
        log.warning("GEMINI_API_KEY not set; skipping static AI.")
        return None
    try:
        # Upload the sample file
        sample_file = GEMINI_CLIENT.files.upload(file=sample_path)
        response = GEMINI_CLIENT.models.generate_content(
            model=model_name,
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
        return response.text.replace("\n\n", "\n")
    except Exception as e:
        log.error(f"Static AI evaluation failed: {e}")
        traceback.print_exc()
        return None

# ----------------------------------------------------------------------
# Static analysis orchestration
# ----------------------------------------------------------------------
def run_static_analysis(sample_path, output_dir=None, file_hash=None):
    log.info("Starting static analysis...")
    if file_hash is None:
        file_hash = calculate_sha256(sample_path)

    if output_dir is None:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        folder_name = f"{timestamp}_{file_hash[:6]}_static"
        result_dir = settings["paths"]["result_dir"]
        output_dir = os.path.abspath(os.path.join(result_dir, folder_name))
        os.makedirs(output_dir, exist_ok=True)
    else:
        os.makedirs(output_dir, exist_ok=True)

    results = {
        "analysis_type": "static",
        "sample_name": os.path.basename(sample_path),
        "sha256": file_hash,
        "vt_report": None,
        "yara_matches": [],
        "entropy": None,
        "aiEvalStatic": None,
        "output_dir": output_dir
    }

    vt_enabled = settings.get("static", {}).get("virusTotal", False)
    yara_enabled = settings.get("static", {}).get("yaraMatching", False)
    entropy_enabled = settings.get("static", {}).get("entropy", False)
    ai_enabled = settings.get("static", {}).get("aiEval", False)
    ai_model = settings.get("static", {}).get("aiModelName", "gemini-3.5-flash")
    vt_max_upload = settings.get("static", {}).get("vt_upload_max_size", 33554432)
    yara_rules_path = settings.get("paths", {}).get("yara_rules")

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_vt = executor.submit(_vt_task, sample_path, file_hash, vt_enabled, vt_max_upload)
        future_yara = executor.submit(_yara_task, sample_path, yara_enabled, yara_rules_path)
        future_entropy = executor.submit(_entropy_task, sample_path, entropy_enabled)
        future_ai = executor.submit(_ai_static_task, sample_path, ai_enabled, ai_model)

        results["vt_report"] = future_vt.result()
        results["yara_matches"] = future_yara.result()
        results["entropy"] = future_entropy.result()
        results["aiEvalStatic"] = future_ai.result()

    return results

# ----------------------------------------------------------------------
# Sandbox execution
# ----------------------------------------------------------------------
def run_sandbox(sample_path, output_dir=None, file_hash=None):
    verify_images()
    ensure_network_exists()

    log.info("Initializing isolated analysis lab with FakeNet gateway...")

    filetype = detect_file_type(sample_path)
    runners = settings.get("runners", {})
    executor_cmd = runners.get(filetype)
    if executor_cmd is None:
        log.warning(f"No runner defined for type '{filetype}', falling back to 'bash'.")
        executor_cmd = "bash"

    abs_sample_path = os.path.abspath(sample_path)
    if file_hash is None:
        file_hash = calculate_sha256(abs_sample_path)

    if output_dir is None:
        report_folder_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:6]}"
        result_dir = settings["paths"]["result_dir"]
        output_dir = os.path.abspath(os.path.join(result_dir, report_folder_name))
        os.makedirs(output_dir, exist_ok=True)
    else:
        os.makedirs(output_dir, exist_ok=True)

    started_time = datetime.now(timezone.utc)
    start_perf = time.perf_counter()

    pre_delay_min = settings.get("sandbox", {}).get("pre_delay_min", 0)
    pre_delay_max = settings.get("sandbox", {}).get("pre_delay_max", 0)
    if pre_delay_max > 0:
        delay = random.uniform(pre_delay_min, pre_delay_max)
        log.info(f"Adding {delay:.2f}s random delay before execution...")
        time.sleep(delay)

    fakenet_container = None
    container = None
    container_id = "N/A"
    status = "completed"
    exit_code = 0
    container_diffs = []

    try:
        log.info("Starting FakeNet network listener container...")
        fakenet_container = client.containers.run(
            image=settings["sandbox"]["fakenet_image"],
            name=f"fakenet_{file_hash[:6]}",
            network=settings["sandbox"]["network_name"],
            detach=True,
            cap_add=["NET_ADMIN"],
            environment={"FAKENET_SINKHOLE": "true"},
        )
        log.success("FakeNet gateway container active.")

        volumes = {
            abs_sample_path: {'bind': f'/sandbox/sample.{filetype}', 'mode': 'ro'},
            output_dir: {'bind': '/results', 'mode': 'rw'},
        }
        env_vars = {}

        fake_lib = settings["paths"].get("fake_tracer_lib")
        if fake_lib and os.path.isfile(fake_lib):
            abs_fake_lib = os.path.abspath(fake_lib)
            volumes[abs_fake_lib] = {'bind': '/lib/libfake_tracer.so', 'mode': 'ro'}
            env_vars["LD_PRELOAD"] = "/lib/libfake_tracer.so"
        else:
            log.warning("Fake tracer library missing. Proceeding without LD_PRELOAD.")

        env_vars.update({
            "container": "lxc",
            "HOSTNAME": "ubuntu-host",
        })

        resources = settings.get("container_resources", {})
        mem_limit = resources.get("mem_limit", "512m")
        pids_limit = resources.get("pids_limit", 256)
        cpu_period = resources.get("cpu_period", 100000)
        cpu_quota = resources.get("cpu_quota", 50000)
        cpuset_cpus = resources.get("cpuset_cpus", "0-1")

        # Sysctls that are safe (no kernel.randomize_va_space)
        sysctls = {
            "net.ipv4.tcp_timestamps": "1",
            "kernel.dmesg_restrict": "0",
        }

        log.info("Launching malware sandbox container...")
        container = client.containers.run(
            image=settings["sandbox"]["default_image"],
            command=[executor_cmd, f"/sandbox/sample.{filetype}"],
            volumes=volumes,
            network=settings["sandbox"]["network_name"],   # bridge network
            environment=env_vars,
            cap_add=["SYS_PTRACE"],
            detach=True,
            mem_limit=mem_limit,
            pids_limit=pids_limit,
            cpu_period=cpu_period,
            cpu_quota=cpu_quota,
            cpuset_cpus=cpuset_cpus,
            cap_drop=["ALL"],
        )

        container_id = container.id
        log.info("Detonating sample inside container...")

        detonation_timeout = settings["sandbox"]["detonation_timeout"]
        start_wait = time.time()
        while time.time() - start_wait < detonation_timeout:
            container.reload()
            if container.status != 'running':
                break
            time.sleep(0.5)
        else:
            container.reload()
            if container.status == 'running':
                container.stop(timeout=1)
                status = "timeout"

        res = container.wait(timeout=1)
        exit_code = res.get("StatusCode", 0)

        # Capture container diff with a timeout
        try:
            with ThreadPoolExecutor(max_workers=1) as diff_exec:
                future_diff = diff_exec.submit(container.diff)
                container_diffs = future_diff.result(timeout=30) or []
                diff_log_path = os.path.join(output_dir, "filesystem_diff.json")
                with open(diff_log_path, "w", encoding="utf-8") as diff_file:
                    json.dump(container_diffs, diff_file, indent=4)
        except TimeoutError:
            log.error("Container diff timed out after 30s – skipping.")
        except Exception as diff_err:
            log.error(f"Failed to capture container diff: {diff_err}")

    except Exception as e:
        status = "failed"
        exit_code = 1
        log.error(f"Error during analysis execution: {e}")
        traceback.print_exc()

    finally:
        if fakenet_container:
            try:
                log.info("Collecting network activity logs from FakeNet...")
                fakenet_logs = fakenet_container.logs(stdout=True, stderr=True).decode('utf-8')
                network_log_path = os.path.join(output_dir, "network_activity.log")
                with open(network_log_path, "w", encoding="utf-8") as net_file:
                    net_file.write(fakenet_logs)
                log.success(f"Network log saved to: {network_log_path}")
            except Exception as e:
                log.error(f"Failed to collect network logs: {e}")

        log.info("Cleaning up containers...")
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
    if settings.get("sandbox", {}).get("aiEval", False) and GEMINI_CLIENT:
        try:
            trace_path = os.path.join(output_dir, "trace.log")
            if os.path.isfile(trace_path) and os.path.getsize(trace_path) > 0:
                with open(trace_path, "r", encoding="utf-8") as tf:
                    trace_text = tf.read()
                model_name = settings.get("sandbox", {}).get("aiModelName", "gemini-3.5-flash")
                aiEval = _ai_evaluate_text(
                    trace_text,
                    "This is a strace result. Highlight suspicious indicators or malicious behaviour. "
                    "Reply in bullet point, markdown. Keep it short and simple.",
                    model_name
                )
                log.success("Dynamic AI evaluation completed.")
            else:
                log.warning(f"Trace log not found or empty at {trace_path}. Skipping dynamic AI evaluation.")
        except Exception as e:
            log.error(f"Dynamic AI evaluation failed: {e}")
            traceback.print_exc()
    else:
        if not GEMINI_CLIENT:
            log.warning("GEMINI_API_KEY not set; skipping dynamic AI evaluation.")
        else:
            log.info("Dynamic AI evaluation disabled.")

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

# ----------------------------------------------------------------------
# Report building
# ----------------------------------------------------------------------
def build_report(analysis_results):
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

    report_path = os.path.join(output_dir, "metadata.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    log.success(f"Metadata report saved to: {report_path}")
    return report_data

# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------
def orchestrate(sample_path):
    sandbox_enabled = settings.get("sandbox", {}).get("enabled", False)
    static_enabled = settings.get("static", {}).get("enabled", False)

    if not sandbox_enabled and not static_enabled:
        log.warning("No analysis enabled. Nothing to report.")
        return None

    overall_start = time.perf_counter()

    sample_path = os.path.abspath(sample_path)
    file_hash = calculate_sha256(sample_path)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    folder_name = f"{timestamp}_{file_hash[:6]}"
    result_dir = settings["paths"]["result_dir"]
    shared_output_dir = os.path.abspath(os.path.join(result_dir, folder_name))
    os.makedirs(shared_output_dir, exist_ok=True)

    sandbox_results = None
    static_results = None

    if sandbox_enabled and static_enabled:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_sandbox = executor.submit(run_sandbox, sample_path, shared_output_dir, file_hash)
            future_static = executor.submit(run_static_analysis, sample_path, shared_output_dir, file_hash)
            sandbox_results = future_sandbox.result()
            static_results = future_static.result()
    elif sandbox_enabled:
        sandbox_results = run_sandbox(sample_path, shared_output_dir, file_hash)
    elif static_enabled:
        static_results = run_static_analysis(sample_path, shared_output_dir, file_hash)

    overall_end = time.perf_counter()
    total_duration = round(overall_end - overall_start, 3)

    if sandbox_results and static_results:
        combined = sandbox_results.copy()
        for key in ["vt_report", "entropy", "yara_matches", "aiEvalStatic"]:
            if key in static_results:
                combined[key] = static_results[key]
        combined["analysis_type"] = "combined"
        combined["output_dir"] = shared_output_dir
        combined["duration"] = total_duration
        build_report(combined)
        return combined
    elif sandbox_results:
        sandbox_results["duration"] = total_duration
        sandbox_results["output_dir"] = shared_output_dir
        build_report(sandbox_results)
        return sandbox_results
    elif static_results:
        static_results["duration"] = total_duration
        static_results["output_dir"] = shared_output_dir
        build_report(static_results)
        return static_results

# ----------------------------------------------------------------------
# Job management API
# ----------------------------------------------------------------------
def start_analysis(sample_path, wait=True):
    sample_path = os.path.abspath(sample_path)
    if not os.path.isfile(sample_path):
        log.error(f"Sample file not found: {sample_path}")
        return None

    job_id = job_store.create_job(sample_path, job_type="combined")
    job_store.update_job(job_id, status="running", started_at=datetime.now(timezone.utc).isoformat())

    if wait:
        try:
            result = orchestrate(sample_path)
            if result:
                job_store.update_job(
                    job_id,
                    status="completed",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    result=result
                )
            else:
                job_store.update_job(
                    job_id,
                    status="failed",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    error="Analysis produced no results"
                )
            return result
        except Exception as e:
            job_store.update_job(
                job_id,
                status="failed",
                finished_at=datetime.now(timezone.utc).isoformat(),
                error=str(e)
            )
            log.error(f"Analysis failed: {e}")
            traceback.print_exc()
            return None
    else:
        def run_background():
            try:
                result = orchestrate(sample_path)
                if result:
                    job_store.update_job(
                        job_id,
                        status="completed",
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        result=result
                    )
                else:
                    job_store.update_job(
                        job_id,
                        status="failed",
                        finished_at=datetime.now(timezone.utc).isoformat(),
                        error="Analysis produced no results"
                    )
            except Exception as e:
                job_store.update_job(
                    job_id,
                    status="failed",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    error=str(e)
                )
                log.error(f"Background analysis failed: {e}")
                traceback.print_exc()

        thread = threading.Thread(target=run_background, daemon=True)
        thread.start()
        return job_id

def get_job_status(job_id):
    job = job_store.get_job(job_id)
    if not job:
        return None
    return {
        "id": job["id"],
        "status": job["status"],
        "sample": job["sample"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "error": job["error"]
    }

def get_job_result(job_id):
    job = job_store.get_job(job_id)
    if not job:
        return None
    if job["status"] != "completed":
        return None
    return job["result"]

# ----------------------------------------------------------------------
# Command‑line interface
# ----------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated malware analysis with Docker sandbox.")
    parser.add_argument("sample", nargs="?", default=None,
                        help="Path to the sample file to analyze.")
    parser.add_argument("--no-sandbox", action="store_true", help="Disable sandbox analysis.")
    parser.add_argument("--no-static", action="store_true", help="Disable static analysis.")
    parser.add_argument("--force-sandbox", action="store_true", help="Force sandbox analysis.")
    parser.add_argument("--force-static", action="store_true", help="Force static analysis.")
    parser.add_argument("--wait", type=bool, default=False, help="Wait for completion (True) or run in background (False).")
    parser.add_argument("--job-id", help="Poll status or result of a specific job.")
    parser.add_argument("--status", action="store_true", help="Show status of the given --job-id.")
    parser.add_argument("--result", action="store_true", help="Get result of the given --job-id.")
    args = parser.parse_args()

    if args.job_id:
        if args.status:
            status = get_job_status(args.job_id)
            if status:
                print(json.dumps(status, indent=2, default=str))
            else:
                print("Job not found.")
        elif args.result:
            result = get_job_result(args.job_id)
            if result:
                print(json.dumps(result, indent=2, default=str))
            else:
                print("Job not completed or not found.")
        else:
            print("Please specify --status or --result with --job-id.")
        sys.exit(0)

    if args.sample:
        sample_path = args.sample
    else:
        sample_path = settings.get("paths", {}).get("default_sample", "Zoo/snail.sh")
    sample_path = os.path.abspath(sample_path)

    if args.no_sandbox:
        settings["sandbox"]["enabled"] = False
    if args.no_static:
        settings["static"]["enabled"] = False
    if args.force_sandbox:
        settings["sandbox"]["enabled"] = True
    if args.force_static:
        settings["static"]["enabled"] = True

    os.system("cls" if os.name == "nt" else "clear")

    if args.wait:
        result = start_analysis(sample_path, wait=True)
        if result:
            print(json.dumps(result, indent=2, default=str))
        else:
            print("Analysis failed.")
    else:
        job_id = start_analysis(sample_path, wait=False)
        print(f"Analysis started in background. Job ID: {job_id}")
        print("Use --job-id <ID> --status to check status, or --job-id <ID> --result to get results.")