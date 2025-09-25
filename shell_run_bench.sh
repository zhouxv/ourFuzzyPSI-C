#! /bin/bash
set -e
source ./shell_utils.sh

# Cleanup function to handle script termination
# This function will be called on script exit or interruption
cleanup() {
    pkill -P $$  # Kill all the child processes of the current process group
    # Optional: Delete temporary files
    [ -f "$TMP_FILE" ] && rm "$TMP_FILE"
    exit 1
}

# Register Signal Capture
trap 'cleanup' INT TERM EXIT


log "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

./build/main -p 3 -n 8 -d 2 -delta 16 64 256 -m 0  -log 0 -trait 5
./build/main -p 3 -n 8 -d 2 -delta 16 64 256 -m 1  -log 0 -trait 5
./build/main -p 3 -n 8 -d 2 -delta 16 64 256 -m 2  -log 0 -trait 5

./build/main -p 4 -n 8 -d 5 -delta 16 64 256 -m 0  -log 0 -trait 5
./build/main -p 4 -n 8 -d 5 -delta 16 64 256 -m 1  -log 0 -trait 5
./build/main -p 4 -n 8 -d 5 -delta 16 64 256 -m 2  -log 0 -trait 5

./build/main -p 4 -n 8 -d 8 -delta 16 64 256 -m 0  -log 0 -trait 5
./build/main -p 4 -n 8 -d 8 -delta 16 64 256 -m 1  -log 0 -trait 5
./build/main -p 4 -n 8 -d 8 -delta 16 64 256 -m 2  -log 0 -trait 5