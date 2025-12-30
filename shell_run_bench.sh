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

ns=(8 12)
dims=(2 6 10 15)
deltas=(10 60 250)

log "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"


for n in "${ns[@]}"; do
    for delta in "${deltas[@]}"; do
        ./build/main -p 3 -log 0 -i 11 -d $dim -delta $delta -n $n -trait 3
    done
    echo
done

for n in "${ns[@]}"; do
    for delta in "${deltas[@]}"; do
        ./build/main -p 4 -log 0 -i 11 -d $dim -delta $delta -n $n -trait 3
    done
    echo
done