import docker
import os
import time
import json
from datetime import datetime, timezone
from useful import Log 
from hashlib import file_digest, new

log = Log()
result_dir = "Results"
detonate = 5

client = docker.from_env()

try:
    client.images.get("ubuntu-sandbox:latest")
    log.success("Sandbox image found locally.")
except docker.errors.ImageNotFound:
    log.warning("Image not found. Building ubuntu-sandbox:latest from Dockerfile...")
    client.images.build(
        path=".", 
        tag="ubuntu-sandbox:latest", 
        rm=True
    )
    log.success("Image built successfully!")


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
    log.info("Initializing isolated analysis sandbox...")

    filetype = sample_path.split(".")[-1].lower()
    runners = {
        "sh": "bash",
        "py": "python3"
    }

    executor = runners.get(filetype, "bash")
    
    # Generate metadata metrics
    abs_sample_path = os.path.abspath(sample_path)
    file_hash = calculate_sha256(abs_sample_path)
    started_time = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    
    # Prepare staging directory path (won't populate files until post-execution verification)
    report_folder_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file_hash[:6]}"
    host_output_dir = os.path.abspath(os.path.join(result_dir, report_folder_name))

    container = client.containers.run(
        image="ubuntu-sandbox:latest",
        command=[
            executor, f"/sandbox/malware.{filetype}"
        ],
        volumes={
            abs_sample_path: {
                'bind': f'/sandbox/malware.{filetype}',
                'mode': 'ro'
            },
            host_output_dir: {
                'bind': '/results',
                'mode': 'rw'
            }
        },
        cap_add=["SYS_PTRACE"],
        network_mode="none",
        detach=True,
        mem_limit="512m",
        cpu_period=100000,
        cpu_quota=50000 
    )

    container_id = container.id
    status = "completed"
    exit_code = 0

    try:
        log.info("Detonating sample inside container...")
        
        # Let the sample execute up to the timeout limit
        time.sleep(detonate)
        
        log.info("Checking execution status...")
        container.reload()
        if container.status == 'running':
            # Force stop if it exceeds timeout window
            container.stop(timeout=1)
            status = "timeout"
        
        res = container.wait(timeout=1)
        exit_code = res.get("StatusCode", 0)

    except Exception as e:
        status = "failed"
        exit_code = 1
        log.error(f"Error during analysis execution: {e}")

    finally:
        log.info("Cleaning up: Destroying container...")
        try:
            container.stop(timeout=2)
            container.remove(force=True)
        except Exception:
            pass
        log.info("Environment wiped clean.")

    finished_time = datetime.now(timezone.utc)
    duration = round(time.perf_counter() - start_perf, 3)

    # Only create the results folder and write artifacts AFTER safe detonation/teardown
    os.makedirs(host_output_dir, exist_ok=True)

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
        "finished": finished_time.isoformat(),
        "strace_log": "trace.log"
    }

    report_filename = os.path.join(host_output_dir, "metadata.json")
    
    # Calculate integrity hash of the final isolated output bundle
    dirhash = hash_results(host_output_dir)
    report_data["Directory (SHA256)"] = dirhash
    
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    log.success(f"Report and strace logs successfully saved to: {host_output_dir}")
    return report_data

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    report = run_analysis(".\\Zoo\\snail.sh")
    print(json.dumps(report, indent=2))