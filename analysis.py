import re
import os
import json


def extraction(file):
    if not os.path.exists(file):
        return {"error": f"Trace log not found at {file}"}

    files_accessed = set()
    processes_spawned = set()
    network_connections = set()

    execve_pattern = re.compile(r'execve\("([^"]+)"')
    openat_pattern = re.compile(r'openat\([^,]+,\s*"([^"]+)"')
    connect_pattern = re.compile(r'connect\([^,]+,\s*\{[^}]*sin_addr=inet_addr\("([^"]+)"\)')

    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # 1. Capture process executions
            exec_match = execve_pattern.search(line)
            if exec_match:
                bin_path = exec_match.group(1)
                # Ignore common system binaries to keep signal clean
                if not bin_path.startswith(('/lib', '/usr/lib', '/bin/bash')):
                    processes_spawned.add(bin_path)

            # 2. Capture file accesses/creations
            open_match = openat_pattern.search(line)
            if open_match:
                filepath = open_match.group(1)
                # Filter out system boilerplate paths, focus on user/payload modifications
                if not filepath.startswith(('/lib', '/usr', '/etc', '/proc', '/sys', '/dev')):
                    files_accessed.add(filepath)

            # 3. Capture outbound IPv4 connections
            conn_match = connect_pattern.search(line)
            if conn_match:
                network_connections.add(conn_match.group(1))

    return {
        "dropped_or_accessed_files": sorted(list(files_accessed)),
        "spawned_processes": sorted(list(processes_spawned)),
        "network_indicators": sorted(list(network_connections))
    }



if __name__ == "__main__":
    tracelog = "Results\\20260822100612_fb49b6\\trace.log"
    response = extraction(tracelog)
    print(response)