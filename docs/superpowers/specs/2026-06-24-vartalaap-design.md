# Vartalaap — Design Spec

**Status:** Approved (design phase)
**Date:** 2026-06-24
**One-liner:** A cross-platform (Windows + Linux), web-UI-based, peer-to-peer, serverless, end-to-end-encrypted chat application for campus/LAN networks, with profiles, full chat feature set, and arbitrary file transfer.

---

## 0. The "no server" contract (scope boundary — read first)

Vartalaap is **campus/LAN-only** peer-to-peer. The deliberate contract:

- Two peers **on the same local network** (campus Wi-Fi/LAN/subnet, or a shared VPN/overlay) discover each other and connect **directly**, with **zero infrastructure** — no server we run, no accounts, no cloud.
- All messages and files flow **directly device-to-device**, end-to-end encrypted.
- **Out of scope (deliberate):** two peers on different networks across the open internet will not find each other. This is the trade-off of LAN-only. The transport layer is isolated behind a trait so an internet transport (DHT + hole-punch) can be added later as an additive module, not a rewrite.
- **Offline delivery:** with no server, a 1:1 message to a powered-off recipient cannot arrive until they return online. Group history *self-heals* via CRDT delta sync (any peer holding the messages re-syncs them to a returning peer). An optional **peer mailbox** (online peers hold *encrypted* ciphertext blobs for an absent member, unable to read them) is deferred to a later phase.

## 1. High-level architecture

A Tauri application: a Rust **core engine** (the entire app logic, headless-runnable) plus a **web UI** view layer communicating over Tauri IPC (commands in, event stream out). One codebase compiles unchanged for Windows and Linux.

```
Tauri App (.msi / .deb / .AppImage)
├─ Web UI (React + TypeScript + Vite)  ──IPC(commands/events)──┐
└─ Rust core engine                                            │
   ├─ net      P2P transport + LAN (mDNS) discovery   ──► LAN  │
   ├─ identity keypairs, profiles, trust (TOFU)                │
   ├─ crypto   E2E Double Ratchet, group keys, at-rest         │
   ├─ sync     CRDT chat/group state                           │
   ├─ blobs    content-addressed file transfer        ──► LAN  │
   └─ store    encrypted SQLite + blob store           ──► disk│
```

## 2. Networking core

**Decision: Iroh** (`iroh`, `iroh-blobs`, `iroh-docs`) over rust-libp2p.

- Dial peers by public key; automatic LAN-direct connections; QUIC transport.
- `iroh-blobs`: content-addressed, resumable, arbitrary-size file transfer — directly serves the "send any file" requirement.
- `iroh-docs`: multi-writer eventually-consistent documents — candidate sync substrate.
- Isolated behind an internal `net` trait/abstraction so the engine never depends on Iroh types directly (swap to libp2p or add internet transport without touching app logic).
- Transport encryption (QUIC/TLS, Ed25519 peer identity) protects the wire; our own E2E layer (§4) protects content independently.

**Fallback:** rust-libp2p (mDNS + Noise + gossipsub + custom blob chunking) if Iroh proves unsuitable. The `net` trait keeps this a contained swap.

## 3. Identity, profiles & trust

- **Identity = keypair** generated on first launch. No accounts/phone/email. Public-key fingerprint ("Vartalaap ID") is the identity. Ed25519 identity keys; X25519 for key agreement.
- **Profile**: display name, avatar, status/bio, presence — a small *signed* record gossiped on the LAN; editable, re-broadcast on change.
- **Trust: TOFU (trust-on-first-use) + safety numbers.** First connection pins the peer's key. Out-of-band verification via safety-number comparison or QR scan (campus = people physically nearby). Post-pin key change ⇒ loud MITM warning.
- **Private key at rest**: OS keychain (Windows Credential Manager / libsecret) when available; else encrypted keyfile unlocked by passphrase.
- **Phase 1 = one device per identity.** Multi-device linking deferred.

## 4. Encryption

- **Transport:** QUIC/TLS (Iroh) — authenticated, encrypted wire.
- **End-to-end (content):** Signal-style **Double Ratchet** + X3DH-style async key agreement (forward secrecy + post-compromise security). Use the audited **`vodozemac`** crate rather than a hand-rolled ratchet.
- **Groups:** **sender-keys** scheme (each member ratchets their own sender key, distributed pairwise); membership changes rotate keys. Sized for small groups (≤ ~50).
- **At rest:** SQLite encrypted (SQLCipher or app-level XChaCha20-Poly1305) with a key derived from the identity secret / OS keychain.
- **Principle:** never trust the network. Any future relay/mailbox handles ciphertext only.

## 5. Data & sync model (CRDT)

- Chat history and group state are **CRDTs** (offline-tolerant, conflict-free merge, no central ordering). Substrate: **Automerge** (Rust-native) or `iroh-docs` — final choice justified in the implementation plan.
- Each conversation is a document: append-mostly message log plus mutable state (reactions, edits, deletes, read state) that merges cleanly across partitions.
- **Presence, typing, read receipts** are *ephemeral* (gossiped, not persisted as CRDT) to keep documents small.
- **Self-healing history:** reconnecting peers exchange CRDT deltas; group backlog fills from whoever holds it.

## 6. File transfer (any kind, any size)

- **Content-addressed blobs** (BLAKE3 hash = address), chunked and streamed directly peer→peer over the encrypted transport.
- **Any file or whole folders**, **resumable** (re-dial, continue from last verified chunk), integrity-verified by hash.
- Messages carry a blob reference + metadata (name, size, mime, hash); bytes transfer on accept/on demand, so large files never bloat the chat document.
- Optional auto-accept from verified contacts, size warnings, transfer manager UI (progress, pause, cancel, retry). Local thumbnails/previews for images/video/pdf.

## 7. Local persistence

- **Encrypted SQLite** for messages, contacts, profiles, settings, transfer state.
- **Content-addressed blob store** on disk for received files + media cache.
- Fully usable offline (read history, queue outbound).

## 8. Feature set & phasing

Each phase yields a usable app.

- **Phase 0 — Skeleton:** Tauri boots on Win/Linux; Rust core ↔ UI IPC; identity keypair generation; local encrypted store. No networking yet.
- **Phase 1 — Peers & 1:1 chat:** LAN discovery, connect to peer, profiles, TOFU + safety numbers, E2E 1:1 text, presence/typing/read receipts, message status.
- **Phase 2 — Files:** arbitrary file/folder transfer, resumable, transfer manager, previews/thumbnails.
- **Phase 3 — Groups:** small CRDT groups, membership, sender-key group encryption, self-healing history, group profiles/avatars.
- **Phase 4 — Chat polish ("every feature"):** reactions, replies/threads, edits, deletes, forwarding, search, mentions, pinned messages, local link previews, markdown/code blocks, voice notes, emoji/stickers, native notifications, unread/badges, drafts, block/mute, export. (Curated list — YAGNI on the long tail.)
- **Phase 5 (later) — Calls:** voice → video → screen share, reusing WebRTC/QUIC plumbing.
- **Phase 6 (optional) — Resilience:** peer mailbox (offline ciphertext store-and-forward), QR contact exchange, multi-device, optional internet transport.

## 9. Repo & stack

```
vartalaap/
├─ src-tauri/            Rust: Tauri shell + commands/events
│  └─ crates/
│     ├─ core            engine: wires modules, headless-runnable
│     ├─ net             transport + LAN discovery (iroh)
│     ├─ identity        keypairs, profiles, trust/TOFU
│     ├─ crypto          ratchet (vodozemac), group keys, at-rest
│     ├─ sync            CRDT docs (automerge / iroh-docs)
│     ├─ blobs           file transfer
│     └─ store           encrypted sqlite + blob store
├─ ui/                   React + TypeScript + Vite
│  └─ views, components, state store, IPC client
└─ docs/                 spec, architecture, threat model
```

Frontend: **React + TypeScript + Vite**, Tailwind + shadcn/ui (tentative), lightweight state store subscribing to core events.

## 10. Testing strategy

- **Rust unit tests** per crate (crypto vectors, CRDT merge properties, blob chunk/resume).
- **Headless integration tests:** N in-process cores over a loopback/virtual network asserting convergence of messages/files/group state — no UI. The backbone of correctness.
- **Property tests** for CRDT convergence and ratchet correctness.
- **E2E:** two real Tauri instances on a CI LAN namespace exchanging a message + file.
- **Crypto:** audited crates, known-answer tests, explicit threat-model doc.

## 11. Top risks

1. **Iroh maturity** vs libp2p — biggest bet; mitigated by the `net` trait isolation enabling swap.
2. **Group E2E encryption** (sender-keys) is the hardest crypto — heavy test vectors.
3. **mDNS reliability** on managed campus networks (multicast may be blocked) — fallback: manual add-by-IP / QR peer entry.
4. **"Every feature" is unbounded** — Phase 4 is a curated list, not infinite scope.

## 12. Out of scope (explicit)

Cross-internet discovery; accounts/cloud/backup-to-server; multi-device (deferred); large public channels/communities; moderation tooling at community scale.
