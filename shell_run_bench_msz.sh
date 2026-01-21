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

ns=(11 14)
deltas=(30 60 1000)

log "Running benchmarks for FuzzyPSI protocol..."
printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"


for n in "${ns[@]}"; do
  for delta in "${deltas[@]}"; do
  ./build/main -p 3 -d 2 -n $n -delta $delta -m 0 -trait 3 -log 0 -fake
  done
done


echo "#################################################################"


for n in "${ns[@]}"; do
  for delta in "${deltas[@]}"; do
  ./build/main -p 4 -d 5 -n $n -delta $delta -m 0 -trait 3 -log 0 -fake
  done
done