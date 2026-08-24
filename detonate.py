import docker
import os
import time
import json
from datetime import datetime, timezone
from tools.useful import Log 
from hashlib import file_digest, new

log = Log()
result_dir = "Results"
detonate = 15
NETWORK_NAME = "sandbox-net"

client = docker.from_env()

def verify_images():
    try:
        client.images.get("ubuntu-sandbox:latest")
        log.success("Sandbox image found locally.")
    except docker.errors.ImageNotFound:
        log.warning("Image not found. Building ubuntu-sandbox:latest...")
        client.images.build(path="dockerfiles", tag="ubuntu-sandbox:latest", rm=True)
        log.success("Sandbox image built successfully!")

    try:
        client.images.get("fakenet-gateway:latest")
        log.success("FakeNet gateway image found locally.")
    except docker.errors.ImageNotFound:
        log.warning("FakeNet image not found. Building fakenet-gateway:latest...")
        client.images.build(path="dockerfiles", dockerfile="Dockerfile.fakenet", tag="fakenet-gateway:latest", rm=True)
        log.success("FakeNet gateway image built successfully!")

def ensure_network_exists():
    try:
        client.networks.get(NETWORK_NAME)
    except docker.errors.NotFound:
        log.info(f"Creating isolated internal network: {NETWORK_NAME}")
        client.networks.create(
            NETWORK_NAME,
            driver="bridge",
            internal=True
        )

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



def run_analysis(sample_path):
    verify_images()
    ensure_network_exists()

    log.info("Initializing isolated analysis lab with FakeNet gateway...")

    filetype = sample_path.split(".")[-1].lower()
    runners = {"sh": "bash", "py": "python3"}
    executor = runners.get(filetype, "bash")
    
    abs_sample_path = os.path.abspath(sample_path)
    file_hash = calculate_sha256(abs_sample_path)
    started_time = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    
    report_folder_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:6]}"
    host_output_dir = os.path.abspath(os.path.join(result_dir, report_folder_name))
    os.makedirs(host_output_dir, exist_ok=True)

    fakenet_container = None
    container = None
    container_id = "N/A"
    status = "completed"
    exit_code = 0
    container_diffs = []

    try:
        log.info("Starting FakeNet network listener container...")
        # FakeNet owns the network namespace. The malware container is attached
        # to it below via network_mode="container:<id>" instead of being routed
        # through it, so FakeNet's own NFQUEUE/iptables interception (running in
        # SingleHost mode) automatically sees all of the sandboxed process's
        # traffic on the shared loopback/interfaces. No custom gateway IP,
        # static IP pinning, or per-container DNS override needed.
        fakenet_container = client.containers.run(
            image="fakenet-gateway:latest",
            name=f"fakenet_{file_hash[:6]}",
            network=NETWORK_NAME,
            detach=True,
            cap_add=["NET_ADMIN"]
        )
        log.success("FakeNet gateway container active.")

        volumes = {
            abs_sample_path: {'bind': f'/sandbox/sample.{filetype}', 'mode': 'ro'},
            host_output_dir: {'bind': '/results', 'mode': 'rw'},
        }

        env_vars = None

        fake_lib = os.path.abspath(os.path.join("tools", "fake_tracer", "libfake_tracer.so"))
        if not os.path.isfile(fake_lib):
            log.warning("Fake tracer Library is missing. Please build it first\ncd tools/fake_tracer\ndocker build -t tracer-builder -f Dockerfile.builder .\ndocker run --rm -v ${PWD}:/output tracer-builder cp /build/libfake_tracer.so /output/")
        else:
            volumes = {
                abs_sample_path: {'bind': f'/sandbox/sample.{filetype}', 'mode': 'ro'},
                host_output_dir: {'bind': '/results', 'mode': 'rw'},
                fake_lib: {'bind': '/lib/libfake_tracer.so', 'mode': 'ro'}
            }

            env_vars = {
                "LD_PRELOAD": "/lib/libfake_tracer.so"
            }

        log.info("Launching malware sandbox container...")
        container = client.containers.run(
            image="ubuntu-sandbox:latest",
            command=[executor, f"/sandbox/sample.{filetype}"],
            volumes=volumes,
            network_mode=f"container:{fakenet_container.id}",
            environment=env_vars,
            cap_add=["SYS_PTRACE"],
            detach=True,
            mem_limit="512m",
            pids_limit=256,
            cpu_period=100000,
            cpu_quota=50000 
        )

        container_id = container.id
        log.info("Detonating sample inside container...")
        
        time.sleep(detonate)
        
        log.info("Checking execution status...")
        container.reload()
        if container.status == 'running':
            container.stop(timeout=1)
            status = "timeout"
        
        res = container.wait(timeout=1)
        exit_code = res.get("StatusCode", 0)

        # Extract container filesystem modifications before cleanup
        try:
            container_diffs = container.diff() or []
            diff_log_path = os.path.join(host_output_dir, "filesystem_diff.json")
            with open(diff_log_path, "w", encoding="utf-8") as diff_file:
                json.dump(container_diffs, diff_file, indent=4)
        except Exception as diff_err:
            log.error(f"Failed to capture container diff: {diff_err}")

    except Exception as e:
        status = "failed"
        exit_code = 1
        log.error(f"Error during analysis execution: {e}")

    finally:
        fakenet_logs = ""
        try:
            log.info("Collecting network activity logs from FakeNet...")
            fakenet_logs = fakenet_container.logs(stdout=True, stderr=True).decode('utf-8')
            network_log_path = os.path.join(host_output_dir, "network_activity.log")
            with open(network_log_path, "w", encoding="utf-8") as net_file:
                net_file.write(fakenet_logs)
            log.success(f"Network log saved to: {network_log_path}")
        except Exception:
            log.error("Failed to collect Network Activity Log from Fakenet")

        log.info("Cleaning up: Destroying containers safely...")
        # The malware container must be stopped/removed before FakeNet, since it
        # depends on FakeNet's network namespace still existing while it's alive.
        for c in [container, fakenet_container]:
            if c:
                try:
                    c.stop(timeout=2)
                    c.remove(force=True)  # Hard-kill fallback safety
                except Exception:
                    pass
        log.success("Environment wiped clean.")

    finished_time = datetime.now(timezone.utc)
    duration = round(time.perf_counter() - start_perf, 3)

    report_data = {
        "sample": os.path.basename(sample_path),
        "Metadata (SHA256)": file_hash,
        "image": "ubuntu-sandbox:latest",
        "detonation duration": detonate,
        "started": started_time.isoformat(),
        "status": status,
        "container_id": container_id,
        "duration": duration,
        "exit_code": exit_code,
        "finished": finished_time.isoformat()
    }

    report_filename = os.path.join(host_output_dir, "metadata.json")
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    # Append directory checksum to final report
    report_data["Directory (SHA256)"] = hash_results(host_output_dir)
    
    log.success(f"Report successfully saved to: {host_output_dir}")
    return report_data, report_folder_name

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    report = run_analysis(os.path.join(".", "Zoo", "snail.sh"))
    print(json.dumps(report, indent=2))