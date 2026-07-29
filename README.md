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

- 💬 **1:1 and group chat** — persistent contacts, groups, and history, with live presence,
  typing indicators, unread counts, and read receipts
- 📮 **Offline-safe delivery** — messages sent to an offline peer queue locally and heal
  automatically via CRDT delta sync on reconnect, with queued / sent / delivered status ticks
- 🔒 **End-to-end encryption** (Olm/Double Ratchet) — forward secrecy + post-compromise security
- 📡 **Automatic LAN discovery** (mDNS) — connect to a peer by identity alone, no IP addresses,
  with a copy-paste connect code as a fallback for networks that block multicast
- 📎 **Send any file** — arbitrary files, encrypted end-to-end, integrity-verified
- 👤 **Cryptographic identity + profiles** — your public key *is* your identity ("Vartalaap ID");
  profiles exchange automatically on connect, with local aliases that override a peer's chosen name
- 🛡️ **Trust on first use (TOFU)** — peers' keys are pinned on first contact; a later key change
  is flagged with a warning
- 🗄️ **Encrypted at rest** — contacts, groups, and conversation history persist locally, sealed
  with a key derived from a passphrase you set on first run and enter to unlock
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
  passphrase you choose on first run. Nothing but that passphrase opens it —
  there is no recovery path and no copy on any server. You can optionally have
  it remembered in your OS credential store (macOS Keychain, Windows Credential
  Manager, freedesktop Secret Service), which trades a prompt each launch for
  "anyone who can log in as you can open the vault".

> **What "no server" means here:** Vartalaap is **LAN-only** by design. Two peers on the
> same local network connect directly with zero infrastructure. Two peers on *different*
> networks across the open internet will not find each other — that trade-off is what
> removes all servers. The transport is isolated behind a trait, so an internet transport
> could be added later without touching the app.

## Install

Grab an installer from the [**Releases**](https://github.com/isthatdhruv/vartalaap-v2/releases)
page (produced by CI for every platform), or build from source below.

| Your system | File | Install |
|---|---|---|
| **Linux, 2022+** (Ubuntu 22.04+, Debian 12+, Fedora 36+) | `.AppImage` (portable, bundles webkit) | `chmod +x *.AppImage && ./*.AppImage` |
| Ubuntu / Debian (prefer apt) | `.deb` | `sudo apt install ./Vartalaap_*.deb` |
| **Older Linux** (Ubuntu 18.04 / 20.04, Debian 11) | **`.flatpak`** | `flatpak install --user ./Vartalaap.flatpak && flatpak run com.vartalaap.app` |
| Windows 10/11 | `.exe` | run the installer (WebView2 is bootstrapped automatically) |
| macOS | `.dmg` | open and drag to Applications |

> **The installers are not code-signed or notarized** (that needs paid
> Apple/Microsoft developer certificates), so the OS will object the first time.
>
> **macOS** — the `.dmg` is *universal*: one file that runs natively on both
> Intel and Apple Silicon, macOS 10.13 or newer. But Gatekeeper will block it:
> 1. Drag Vartalaap to Applications and try to open it once. It will be refused.
> 2. Open *System Settings → Privacy & Security*, scroll down, and click
>    **Open Anyway** next to the message about Vartalaap.
>
> On **macOS 15 (Sequoia) and newer this is the only route** — Apple removed the
> old Control-click → *Open* shortcut, so that no longer works. If the app was
> copied off a USB stick or otherwise still refuses, clear the download
> quarantine flag directly:
> ```bash
> xattr -dr com.apple.quarantine /Applications/Vartalaap.app
> ```
>
> **Windows** — SmartScreen shows "Windows protected your PC." Click **More
> info** → **Run anyway**.
>
> Build from source if you would rather not take that on trust.

> **Linux support floor.** Tauri 2 requires `webkit2gtk-4.1`, which only ships on
> ~2022+ distros — so the `.deb`/`.AppImage` need **Ubuntu 22.04+ / Debian 12+ /
> Fedora 36+**. On **older Linux** (Ubuntu 18.04/20.04, Debian 11) use the
> **`.flatpak`**: it runs on anything with Flatpak installed, regardless of the
> host's age. The first install pulls the GNOME runtime from Flathub (needs
> internet once); if it reports a missing `org.gnome.Platform`, run:
> `flatpak remote-add --if-not-exists --user flathub https://flathub.org/repo/flathub.flatpakrepo`

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
./scripts/build-linux-appimage.sh   # portable .AppImage  (Linux 2022+, via Docker)
./scripts/build-linux-deb.sh        # .deb                (Linux 2022+, via Docker)
./scripts/build-linux-flatpak.sh    # .flatpak            (runs on OLD Linux too)
./scripts/build-macos.sh            # universal .dmg       (run on macOS)
./scripts/build-windows.sh          # .exe installer       (run on Windows, Git Bash)
```

> ⚠️ **Build Linux packages with these scripts, not a bare `tauri build`.** The
> Linux scripts compile inside an **Ubuntu 22.04 container** (glibc 2.35). A
> native build on a newer distro (e.g. 24.04/26.04) bakes in a higher glibc
> floor and **won't start on 22.04** — which is the usual "it installed but
> won't open" cause.

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
- [x] Offline message delivery (CRDT delta sync heals on reconnect)
- [x] Passphrase-locked vault (identity, roster and history sealed at rest)
- [x] OS-keychain unlock ("remember me")
- [x] Connect by code when multicast discovery is blocked
- [ ] Voice / video calls
- [ ] Multi-device identity
- [ ] Optional internet transport (DHT + hole-punching) for cross-network use

## If two devices can't find each other

Peers normally appear under **Nearby** within a few seconds. That relies on
mDNS, which is multicast — and multicast is the first thing many networks throw
away. If the list stays empty:

**Use a connect code — this always works, and needs no discovery at all.**
Click **+** next to *Nearby*, copy the code shown (`id@ip:port`), send it to the
other person however you like, and have them paste it into the same panel. The
two then dial each other directly over ordinary unicast QUIC. Nothing in the
network has to cooperate beyond letting the two machines talk at all.

Worth fixing anyway, so discovery works on its own:

- **Windows Firewall.** The installer is unsigned, so Windows often never
  prompts. In an Administrator PowerShell:
  ```powershell
  Get-NetConnectionProfile          # "Public" blocks discovery outright
  Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
  New-NetFirewallRule -DisplayName "Vartalaap" -Direction Inbound `
    -Program "C:\Program Files\Vartalaap\Vartalaap.exe" -Action Allow -Profile Any
  ```
- **IGMP snooping on your router.** Many consumer routers wrongly apply it to
  `224.0.0.251` (mDNS), which is link-local and should always be flooded. It
  breaks discovery most often between a wired and a wireless machine. Unless you
  actually run IPTV multicast, turn **IGMP Snooping off**.
- **Guest networks, AP isolation, and VPNs.** Check both machines are on the
  same subnet (`ip addr` / `ipconfig`) — e.g. both `192.168.0.x`. Client
  isolation on a guest SSID blocks peers from seeing each other by design.

## Known limitations

- **LAN-only** (by design) — see the security note above.
- mDNS needs multicast; plenty of networks block it. There is a connect-code
  fallback that works regardless — see [above](#if-two-devices-cant-find-each-other).
- The installers are **unsigned**, so the OS will warn on first launch — see
  [Install](#install). Signing needs paid developer certificates.
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
