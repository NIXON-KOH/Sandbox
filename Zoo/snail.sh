#!/bin/bash

if grep -q "fake_tracer" /proc/self/maps 2>/dev/null; then

    exec env -i PATH="/usr/local/bin:/usr/bin:/bin" /bin/bash -c '
        
        # --- WE ARE NOW CLEAN (No LD_PRELOAD) ---
        # The tracer will ONLY see the 'execve' syscall that launches this shell.
        # It will NOT see any syscalls inside this block because the preload library is gone.
        
        # 3. Do something malicious but extremely quiet.
        #    Use nslookup to a suspicious domain (FakeNet still catches DNS!).
        nslookup update-system.xyz > /dev/null 2>&1
        
        # 4. Write a file to a persistent location (to test if diff catches it).
        echo "Evasion successful!" > /root/.evasion_test.log
        
        # 5. Attempt a curl (just in case the tracer is somehow still attached).
        curl -s --connect-timeout 3 http://cdn-cache.tech > /dev/null 2>&1
        
        exit 0
    '
    
else
    echo "No tracer found. Doing nothing." > /dev/null
fi

exit 0