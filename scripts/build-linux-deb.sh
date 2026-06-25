#!/usr/bin/env bash
#
# Build a portable Debian/Ubuntu .deb (for users who prefer `apt`).
# Built in an Ubuntu 22.04 container (glibc 2.35), so the result installs and
# runs on Ubuntu 22.04+ and Debian 12+.
#
#   ./scripts/build-linux-deb.sh
#
# Install on a target machine with:
#   sudo apt install ./Vartalaap_0.1.0_amd64.deb
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

echo ">> Extracting .deb…"
mkdir -p packaging/out
cid="$(docker create "$IMAGE")"
docker cp "$cid:/src/app/src-tauri/target/release/bundle/deb/." packaging/out/
docker rm "$cid" >/dev/null

echo ""
echo ">> Done. Artifacts in packaging/out/:"
find packaging/out -maxdepth 1 -name '*.deb' -printf '   %f\n' || true
echo ""
echo "   Install with:  sudo apt install ./packaging/out/*.deb"
