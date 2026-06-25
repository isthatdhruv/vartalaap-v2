#!/usr/bin/env bash
#
# Build the macOS app + .dmg. A macOS app can only be built ON macOS — there is
# no reliable way to cross-compile it from Linux/Windows.
#
# Produces a UNIVERSAL build (one .dmg that runs on both Intel and Apple
# Silicon Macs).
#
# Run this on a Mac:
#   ./scripts/build-macos.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: macOS apps must be built on macOS. Run this on a Mac." >&2
  exit 1
fi

# --- Node ---
if ! command -v node >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo ">> Installing Node via Homebrew…"; brew install node
  else
    echo "ERROR: Node.js not found. Install it (https://nodejs.org) or Homebrew (https://brew.sh) first." >&2
    exit 1
  fi
fi

# --- Rust ---
if ! command -v cargo >/dev/null 2>&1; then
  echo ">> Installing Rust…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true

# Both architectures, so the .dmg is universal.
echo ">> Adding Rust targets for a universal binary…"
rustup target add x86_64-apple-darwin aarch64-apple-darwin

cd app
echo ">> Installing frontend deps…"
npm install
echo ">> Building (universal) — this takes a while…"
npm run tauri build -- --target universal-apple-darwin --bundles dmg

echo ""
echo ">> Done. .dmg at:"
find src-tauri/target/universal-apple-darwin/release/bundle/dmg -name '*.dmg' -print 2>/dev/null || \
  echo "   (check src-tauri/target/*/release/bundle/dmg/)"
