#! /bin/bash
set -e

#!/bin/bash

# colors for output
# These colors are used to format the output of the script
GREEN='\033[32m'
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

cols=$(tput cols 2>/dev/null || echo 80)
max_len=$((cols - 6))

# This function prints a message to the console with a specific format
docker_build_style() {
    local header="$1"
    local command="$2"
    local logfile=$(mktemp)

    printf "${BOLD} ${header}${RESET}\n" >&2

    # 执行并捕获输出
    eval "$command" 2>&1 | tee "$logfile" | {
        while read -r line; do
            if [ ${#line} -gt $max_len ]; then
                line="${line:0:max_len}…"
            fi
            printf "\r\033[K   │ %s" "$line" >&2  # 实时显示
        done
    }

    status=${PIPESTATUS[0]}  # 获取 eval 的退出状态

    if [ $status -eq 0 ]; then
        printf "\r\033[K   └─ ${GREEN}✓ Success${RESET}\n" >&2
    else
        printf "\r\033[K   └─ ${RED}✗ Failed${RESET}\n" >&2
        echo "   └─ Full log:" >&2
        cat "$logfile" | sed 's/^/      /' >&2  # 错误时展开日志
        rm "$logfile"
        exit 1
    fi

    rm "$logfile"
}

log(){
    printf "${GREEN}$1${RESET}\n"
}