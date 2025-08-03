#! /bin/bash
set -e
source ./shell_utils.sh

# This script is used to build the Docker image for the ourFuzzyPSI-C project.

# Build the Docker image with the tag 'fpsi_artifact'
# The Dockerfile should be in the same directory as this script or adjust the path accordingly.
# The '.' at the end specifies the build context, which is the current directory.

log "Building Docker image for ourFuzzyPSI-C..."
docker build -t fpsi_artifact .