#!/bin/bash
#
# run_tests.sh - Run all ptr_checker FD tests
#

set -e

echo "================================"
echo "Running ptr_checker FD tests"
echo "================================"
echo ""

# Build the tests
echo "[1/2] Building tests..."
make clean > /dev/null 2>&1
make all

echo ""
echo "[2/2] Running FD send/receive test..."
echo ""

# Run the test
./fd_sender_test

exit_code=$?

echo ""
if [ $exit_code -eq 0 ]; then
    echo "================================"
    echo "All tests PASSED"
    echo "================================"
else
    echo "================================"
    echo "Some tests FAILED"
    echo "================================"
fi

exit $exit_code
