#!/bin/bash
echo "========================================"
echo "  DLPL PKE/KEM - All Security Levels"
echo "========================================"

for level in 1 3 5; do
    echo ""
    echo "=== LEVEL $level ==="
    make clean > /dev/null 2>&1
    make CFLAGS="-DDLPL_SECURITY_LEVEL=$level -Wall -Wextra -std=c11 -O2" > /dev/null 2>&1
    
    echo "--- PKE Tests ---"
    ./test_dlpl 2>&1 | grep -E "(Parameter|n=|Passed|Failed)"
    
    echo "--- KEM Tests ---"
    ./test_kem 2>&1 | grep -E "(Parameter|n=|Passed|Failed)"
done
