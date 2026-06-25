#!/usr/bin/env bash
#
# Build the PORTABLE Linux build: a single .AppImage that runs on any distro
# (glibc >= 2.35: Ubuntu 22.04+, Debian 12+, Fedora 36+, Mint, etc.) with no
# install and no dependencies to add — users just chmod +x and run it.
#
# Runs anywhere Docker is available (the build itself happens in an Ubuntu 22.04
# container, so the result is portable regardless of YOUR distro/version).
#
#   ./scripts/build-linux-appimage.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required. Install it: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

IMAGE=vartalaap-linux-build

echo ">> Building in an Ubuntu 22.04 container (first run ~10 min; cached after)…"
docker build -f packaging/Dockerfile.ubuntu2204 -t "$IMAGE" .

echo ">> Extracting installers…"
mkdir -p packaging/out
cid="$(docker create "$IMAGE")"
docker cp "$cid:/src/app/src-tauri/target/release/bundle/appimage/." packaging/out/ 2>/dev/null || true
docker cp "$cid:/src/app/src-tauri/target/release/bundle/deb/." packaging/out/ 2>/dev/null || true
docker rm "$cid" >/dev/null

echo ""
echo ">> Done. Artifacts in packaging/out/:"
find packaging/out -maxdepth 1 \( -name '*.AppImage' -o -name '*.deb' \) -printf '   %f\n' || true
echo ""
echo "   Run it on any Linux machine with:"
echo "     chmod +x packaging/out/*.AppImage && ./packaging/out/*.AppImage"
