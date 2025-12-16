#! /bin/bash
set -e
source ./shell_utils.sh

# Run the Docker container with the necessary capabilities
# --cap-add=NET_ADMIN is used to allow network administration capabilities
# --rm is used to remove the container after it exits
# -it is used to run the container in interactive mode with a TTY
# bash is used to start a shell in the container

log "Running Docker container with network administration capabilities..."
docker run -it --cap-add=NET_ADMIN --rm fpsi_artifact bash