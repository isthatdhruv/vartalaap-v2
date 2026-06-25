#!/usr/bin/env bash
#
# Build the Windows .exe installer (NSIS). A Windows app must be built ON
# Windows — cross-compiling a working installer from Linux is not reliable.
#
# Run this in Git Bash on Windows:
#   ./scripts/build-windows.sh
#
# Prerequisites on the Windows machine:
#   - Node.js LTS            https://nodejs.org
#   - Rust (MSVC toolchain)  https://rustup.rs
#   - "Desktop development with C++" (Build Tools for Visual Studio)
#     https://visualstudio.microsoft.com/visual-cpp-build-tools/
#   WebView2 is bootstrapped by the installer at install time — nothing to add.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) ;;  # Git Bash / MSYS2 on Windows
  *) echo "ERROR: Windows installers must be built on Windows. Run this in Git Bash on a Windows machine." >&2; exit 1 ;;
esac

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js not found. Install the LTS from https://nodejs.org" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: Rust not found. Install it (MSVC toolchain) from https://rustup.rs" >&2
  exit 1
fi

cd app
echo ">> Installing frontend deps…"
npm install
echo ">> Building the Windows installer…"
npm run tauri build -- --bundles nsis

echo ""
echo ">> Done. Installer (.exe) at:"
find src-tauri/target/release/bundle/nsis -name '*.exe' -print 2>/dev/null || \
  echo "   (check src-tauri/target/release/bundle/nsis/)"
