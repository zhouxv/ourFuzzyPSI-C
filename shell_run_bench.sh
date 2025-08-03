#! /bin/bash
set -e
source ./shell_utils.sh

# cleanup function to handle script termination
# This function will be called on script exit or interruption
cleanup() {
    # 杀死所有子进程
    pkill -P $$  # 杀死当前进程组的所有子进程
    # 可选：删除临时文件
    [ -f "$TMP_FILE" ] && rm "$TMP_FILE"
    exit 1
}

# 注册信号捕获
trap 'cleanup' INT TERM EXIT

# 
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