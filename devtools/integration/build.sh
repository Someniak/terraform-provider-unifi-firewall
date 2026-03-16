#!/usr/bin/env bash
#
# Builds the unifi-os-server:local Docker image from the official
# UniFi OS Server installer binary.
#
# Prerequisites: docker (only)
#
# Usage:
#   UOS_DOWNLOAD_URL="<url>" bash build.sh
#   UOS_DOWNLOAD_URL="<url>" bash build.sh --force   # rebuild even if exists
#
# Get the download URL from: https://ui.com/download/software/unifi-os-server
# Right-click the download button → Copy link address.

set -euo pipefail
cd "$(dirname "$0")"

: "${UOS_DOWNLOAD_URL:?Set UOS_DOWNLOAD_URL to the installer link from ui.com/download/software/unifi-os-server}"

IMAGE_NAME="unifi-os-server:local"

# Skip if image already exists (unless --force)
if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    if [[ "${1:-}" != "--force" ]]; then
        echo "Image $IMAGE_NAME already exists. Pass --force to rebuild."
        exit 0
    fi
fi

cleanup() {
    rm -f uosserver.tar
    docker rm -f uos-extract-tmp 2>/dev/null || true
    docker rmi -f uos-extract:tmp 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Step 1/4: Building extraction container (downloads + extracts installer)..."
docker build -t uos-extract:tmp \
    --build-arg UOS_DOWNLOAD_URL="$UOS_DOWNLOAD_URL" \
    -f Dockerfile.extract .

echo "==> Step 2/4: Copying extracted image archive from container..."
CONTAINER_ID=$(docker create --name uos-extract-tmp uos-extract:tmp)
docker cp "$CONTAINER_ID:/tmp/uosserver.tar" ./uosserver.tar
docker rm "$CONTAINER_ID"

echo "==> Step 3/4: Loading base image into Docker..."
LOAD_OUTPUT=$(docker load -i uosserver.tar 2>&1)
echo "$LOAD_OUTPUT"
BASE_IMAGE=$(echo "$LOAD_OUTPUT" | grep -oP 'Loaded image: \K.*' || true)

if [ -z "$BASE_IMAGE" ]; then
    # Fallback: find the image by looking at recently loaded images
    BASE_IMAGE=$(docker images --format '{{.Repository}}:{{.Tag}}' | head -1)
    echo "Detected base image: $BASE_IMAGE"
fi

echo "==> Step 4/4: Building final image on top of $BASE_IMAGE..."
docker build -t "$IMAGE_NAME" \
    --build-arg BASE_IMAGE="$BASE_IMAGE" \
    -f Dockerfile .

echo ""
echo "==> Done! Image ready: $IMAGE_NAME"
echo "    Run with: docker compose up -d"
