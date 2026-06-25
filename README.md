<div align="center">

# Vartalaap

**Serverless, end-to-end-encrypted, peer-to-peer chat for the local network.**

_No servers. No accounts. No cloud. Just peers on the same network, talking privately._

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20macOS-informational)
![Built with](https://img.shields.io/badge/built%20with-Rust%20%2B%20Tauri%20%2B%20React-orange)
[![Release](https://github.com/isthatdhruv/vartalaap-v2/actions/workflows/release.yml/badge.svg)](https://github.com/isthatdhruv/vartalaap-v2/actions/workflows/release.yml)

</div>

> **Vartalaap** (वार्तालाप) is Hindi for _conversation_.

A cross-platform desktop chat app for campus / office / LAN networks. Peers discover
each other automatically over the local network and talk **directly**, with every
message end-to-end encrypted. There is no central server to run, trust, or take down —
if two people are on the same network, they can chat privately, full stop.

---

## Why

Most chat apps route your messages through a company's servers. Vartalaap doesn't have
any. It's built for the place where you don't need the internet to reach the person next
to you: a campus, an office, a LAN party, a workshop, a flight's local Wi-Fi.

- **No server** — discovery and transport are pure peer-to-peer over the local network.
- **Private by construction** — messages and files are end-to-end encrypted with a
  Signal-style Double Ratchet; even the transport can't read them.
- **Zero setup** — open the app, see who's around, click, chat. No sign-up, no phone number.

## Features

- 💬 **1:1 and group chat** with live presence, typing indicators, and read receipts
- 🔒 **End-to-end encryption** (Olm/Double Ratchet) — forward secrecy + post-compromise security
- 📡 **Automatic LAN discovery** (mDNS) — connect to a peer by identity alone, no IP addresses
- 📎 **Send any file** — arbitrary files, encrypted end-to-end, integrity-verified
- 👤 **Cryptographic identity + profiles** — your public key *is* your identity ("Vartalaap ID")
- 🛡️ **Trust on first use (TOFU)** — peers are pinned; key changes are flagged
- 🗄️ **Encrypted at rest** — local history is sealed with a passphrase-derived key
- 🖥️ **Cross-platform** — Linux, Windows, macOS, from one codebase

## How it works

Vartalaap is a small **Rust engine** (fully usable and tested headless) wrapped in a
**Tauri 2** desktop shell with a **React + TypeScript** UI.

```
┌────────────────────────────────────────────────────────┐
│  Tauri app (Windows · Linux · macOS)                     │
│  ┌───────────────────────┐   IPC    ┌────────────────┐   │
│  │  React + TS UI         │ <──────> │  Rust engine   │   │
│  └───────────────────────┘  events  └───────┬────────┘   │
│   engine crates:                             │           │
│   identity · crypto · store · net · sync · blobs · core  │
└──────────────────────────────────────────────┼──────────┘
                                        LAN (QUIC over mDNS)
```

| Crate | Responsibility |
|---|---|
| `vartalaap-identity` | Ed25519 identity, "Vartalaap ID" fingerprint, signed profiles |
| `vartalaap-crypto` | Olm Double Ratchet (via [vodozemac]) + Argon2id/XChaCha20 at-rest crypto |
| `vartalaap-store` | Encrypted local store ([redb]) — every value sealed before disk |
| `vartalaap-net` | P2P transport + LAN discovery ([Iroh] — QUIC, mDNS, **no relays/servers**) |
| `vartalaap-sync` | Conflict-free conversation log (purpose-built CRDT) |
| `vartalaap-blobs` | End-to-end-encrypted, chunked, hash-verified file transfer |
| `vartalaap-core` | The engine that ties it all together (`Node`) |

### Security model

- **Identity** = an Ed25519 keypair generated on first run. The same key is your
  network address and your verifiable identity — no accounts, no servers.
- **Transport** is QUIC/TLS (Iroh); **message content** is additionally wrapped in a
  per-pair Double Ratchet, so content stays private even from any future relay.
- **Files** are encrypted with a fresh per-file key that travels *inside* the ratchet;
  the bytes stream sealed and are SHA-256-verified on arrival.
- **Trust** is TOFU: a peer's key is pinned on first contact; a later key change is
  surfaced as a warning.
- **At rest**, the local database is sealed with a key derived (Argon2id) from a
  passphrase.

> **What "no server" means here:** Vartalaap is **LAN-only** by design. Two peers on the
> same local network connect directly with zero infrastructure. Two peers on *different*
> networks across the open internet will not find each other — that trade-off is what
> removes all servers. The transport is isolated behind a trait, so an internet transport
> could be added later without touching the app.

## Install

Grab an installer from the [**Releases**](https://github.com/isthatdhruv/vartalaap-v2/releases)
page (produced by CI for every platform), or build from source below.

| OS | File | Install |
|---|---|---|
| Linux (any distro) | `.AppImage` | `chmod +x *.AppImage && ./*.AppImage` |
| Ubuntu / Debian | `.deb` | `sudo apt install ./Vartalaap_*.deb` |
| Windows 10/11 | `.exe` | run the installer (WebView2 is bootstrapped automatically) |
| macOS | `.dmg` | open and drag to Applications |

> Linux requires `webkit2gtk-4.1` (Ubuntu 22.04+ / Debian 12+ / Fedora 36+). The
> `.AppImage` is the most portable single-file option.

## Build from source

**Prerequisites:** [Rust](https://rustup.rs), [Node.js 20+](https://nodejs.org), and the
Tauri system dependencies for your OS ([guide](https://tauri.app/start/prerequisites/)).

```bash
git clone https://github.com/isthatdhruv/vartalaap-v2
cd vartalaap-v2

# Run the desktop app in dev mode:
cd app && npm install && npm run tauri dev
```

### Packaged installers

One bash script per target (see [`scripts/`](scripts/)):

```bash
./scripts/build-linux-appimage.sh   # portable .AppImage   (any Linux, via Docker)
./scripts/build-linux-deb.sh        # .deb                  (any Linux, via Docker)
./scripts/build-macos.sh            # universal .dmg        (run on macOS)
./scripts/build-windows.sh          # .exe installer        (run on Windows, Git Bash)
```

Or let CI build **all of them** at once: push a `v*` tag (or use **Actions → Release →
Run workflow**) and download the artifacts. See
[`.github/workflows/release.yml`](.github/workflows/release.yml).

## Development

It's a standard Cargo workspace; the engine is fully testable without the GUI.

```bash
cargo test --workspace          # the full suite (engine: crypto, CRDT, P2P, files, groups)
cargo clippy --workspace --all-targets -- -D warnings
cargo run --example two_node_chat   # headless demo: two peers exchange E2E messages on the LAN
```

```
vartalaap-v2/
├─ crates/            # the Rust engine (7 focused crates)
├─ app/               # Tauri 2 shell + React/TS UI
├─ scripts/           # per-platform build scripts
├─ packaging/         # Dockerfile for portable Linux builds
├─ .github/workflows/ # cross-platform release pipeline
└─ docs/              # design spec + implementation plan
```

## Roadmap

- [x] Encrypted identity, profiles, persistent encrypted store
- [x] LAN discovery + direct P2P transport (no servers)
- [x] 1:1 end-to-end-encrypted messaging, presence, typing, read receipts
- [x] Group chat (small groups)
- [x] End-to-end-encrypted file transfer
- [x] Desktop GUI (Linux / Windows / macOS)
- [ ] Voice / video calls
- [ ] Offline store-and-forward (peer mailbox) & multi-device
- [ ] Optional internet transport (DHT + hole-punching) for cross-network use

## Known limitations

- **LAN-only** (by design) — see the security note above.
- mDNS needs multicast on the network; some managed/enterprise Wi-Fi blocks it
  (a manual "add by ID" fallback is planned).
- The desktop app currently unlocks the local store with a **placeholder passphrase** —
  a real unlock screen / OS-keychain integration is on the list before any 1.0.
- Group messages currently fan out pairwise (great privacy, more bandwidth) rather than
  using sender-keys — fine for small campus groups.

## Contributing

Issues and PRs are welcome. The engine is TDD-driven — please keep
`cargo test --workspace` and `cargo clippy -- -D warnings` green, and run
`cargo fmt --all` before submitting. The design rationale lives in
[`docs/`](docs/).

## License

[MIT](LICENSE) © Dhruv Sharma

## Credits

Built on the excellent work of [Iroh] (P2P / QUIC), [vodozemac] (Olm/Double Ratchet),
[Tauri], and the Rust ecosystem.

[Iroh]: https://www.iroh.computer/
[vodozemac]: https://github.com/matrix-org/vodozemac
[Tauri]: https://tauri.app/
[redb]: https://www.redb.org/
