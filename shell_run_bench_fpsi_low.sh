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

ns=(8 12 16)
deltas=(10 60 250)
metrics=(0 1 2)

log "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

for n in "${ns[@]}"; do
  for m in "${metrics[@]}"; do
    for delta in "${deltas[@]}"; do
    ./build/main -p 3 -d 2 -n $n -delta $delta -m $m -trait 3 -log 0 -fake
    done
  done
done