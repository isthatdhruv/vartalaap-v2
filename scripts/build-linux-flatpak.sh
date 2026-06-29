#!/usr/bin/env bash
#
# Build a Flatpak bundle (.flatpak) — the build that ALSO runs on OLD Linux
# (Ubuntu 18.04 / 20.04, Debian 11, …). The GNOME runtime ships webkit2gtk-4.1
# and a modern userspace *inside the sandbox*, so the host's age stops mattering.
#
# Requires: flatpak + flatpak-builder, and a .deb built on Ubuntu 22.04
# (scripts/build-linux-deb.sh produces one). Run on any Linux with those tools.
#
#   ./scripts/build-linux-flatpak.sh
#
# Then install on ANY Linux that has flatpak (incl. 18.04/20.04):
#   flatpak install --user ./packaging/out/Vartalaap.flatpak
#   flatpak run com.vartalaap.app
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

command -v flatpak >/dev/null 2>&1 ||
  { echo "ERROR: install flatpak (e.g. sudo apt install flatpak)" >&2; exit 1; }
command -v flatpak-builder >/dev/null 2>&1 ||
  { echo "ERROR: install flatpak-builder (e.g. sudo apt install flatpak-builder)" >&2; exit 1; }

FP=packaging/flatpak
RUNTIME_VER=47

# 1) Need a portable .deb (built on 22.04). Build one if absent.
DEB="$(ls -t packaging/out/*.deb 2>/dev/null | head -1 || true)"
if [ -z "$DEB" ]; then
  echo ">> No .deb found in packaging/out — building one (Docker, 22.04)…"
  ./scripts/build-linux-deb.sh
  DEB="$(ls -t packaging/out/*.deb | head -1)"
fi
echo ">> Wrapping .deb: $DEB"
cp "$DEB" "$FP/vartalaap.deb"

# 2) Runtime + SDK from Flathub.
flatpak remote-add --if-not-exists --user flathub \
  https://flathub.org/repo/flathub.flatpakrepo
flatpak install --user -y flathub \
  "org.gnome.Platform//$RUNTIME_VER" "org.gnome.Sdk//$RUNTIME_VER"

# 3) Build + bundle into a single .flatpak.
rm -rf "$FP/build" "$FP/repo"
flatpak-builder --user --force-clean --repo="$FP/repo" "$FP/build" \
  "$FP/com.vartalaap.app.yml"
mkdir -p packaging/out
flatpak build-bundle "$FP/repo" packaging/out/Vartalaap.flatpak com.vartalaap.app

echo ""
echo ">> Done: packaging/out/Vartalaap.flatpak"
echo "   Install on ANY Linux:  flatpak install --user ./packaging/out/Vartalaap.flatpak"
