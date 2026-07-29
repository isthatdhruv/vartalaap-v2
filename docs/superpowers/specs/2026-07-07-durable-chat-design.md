# Durable Chat: Persistent Contacts, Groups, History, and Offline Delivery

**Date:** 2026-07-07
**Status:** Approved (design review with user, sections 1–3)

## Problem

Nothing outlives a connection. All live state — conversations, groups, group
histories, TOFU pins, ratchet sessions, discovered peers — sits in the
in-memory `State` struct (`crates/vartalaap-core/src/node.rs`). The encrypted
redb vault persists only the identity key and the local profile. Consequences:

1. **No history.** Conversations vanish on app close. The `history` command
   reads an in-memory CRDT.
2. **Contacts disappear.** The sidebar is the live mDNS `discovered` set; a
   peer going offline drops off the list within one 4-second poll.
3. **Groups disappear.** `GroupInfo` is in-memory; restart wipes it. Members
   offline at `create_group` time are silently skipped and never learn the
   group exists.
4. **Messages are silently lost** (user-reported: "messages are not sent
   sometimes until a file is sent"). Three confirmed mechanisms:
   - Sends require a live `Conn`, but QUIC connections idle out (~30 s, no
     keepalive traffic) and nothing reconnects on send. The frontend swallows
     the error (`console.error`) after clearing the input box.
   - If both peers send their first message concurrently, each initiates its
     own ratchet session; each side then fails to decrypt everything the other
     sends and drops it silently, forever (sessions are never evicted, and
     there is no PreKey fallback in `decrypt_payload`).
   - A peer restarting its app leaves the other side encrypting into a stale
     session; all those messages are dropped on decrypt.

## Scope (user decisions)

- **Full durable chat**: roster + groups + history persist across offline and
  restarts, **and** messages sent while a peer is unreachable are delivered
  automatically on reconnect.
- **Contact naming**: automatic signed-profile exchange on connect, plus a
  local alias that overrides the peer-chosen name.
- **Architecture**: sealed whole-value snapshots in the existing encrypted
  vault (chosen over per-message tables and frontend-side storage).

## Approaches considered

- **A. Sealed snapshots in the existing vault (chosen).** Whole-value
  encrypted blobs via the existing `Store`. No new dependencies, no schema
  machinery; effort goes to sync + UX. Appending a message rewrites that
  conversation's blob — O(conversation size), fine at campus scale (10k
  messages ≈ 1–2 MB), and the narrow `Store` facade allows swapping internals
  later.
- **B. Per-message append tables.** O(1) appends and paging for huge
  histories, at the cost of substantially more storage-layer code and a
  migration story. Right shape eventually; premature now.
- **C. Frontend persistence (tauri-plugin-store).** Rejected: history would
  leave the encrypted vault, and the Rust core would stop being the source of
  truth.

## Data model & persistence

All values sealed into the existing `vault.redb` with the existing key
derivation.

| Store key | Value | Written when |
|---|---|---|
| `contact/<peer-hex>` | `Contact { peer, profile: Option<Profile>, alias: Option<String>, pinned_msg_key: Option<[u8;32]>, last_seen: u64, added_at: u64 }` | first completed handshake; profile/alias/presence updates |
| `convo/<peer-hex>` | conversation snapshot | every conversation mutation |
| `group/<group-hex>` | `GroupInfo` | create / invite / announce |
| `gconvo/<group-hex>` | conversation snapshot | every group-convo mutation |
| `identity_sk`, `profile` | unchanged | — |

- **Contact lifecycle.** A contact is created on first completed handshake
  ("clients talked to"). Merely-discovered peers are never persisted; they
  appear in a separate "Nearby" list.
- **Snapshot API.** `Conversation` gains `snapshot()` / `from_snapshot()` in
  `vartalaap-sync`. Snapshot shape: `{ messages: Vec<Message>, reactions:
  Vec<Reaction>, read: Vec<(AuthorId, u64)> }` — Vec-based because serde_json
  cannot serialize the CRDT's byte-array-keyed maps. Restore rebuilds the maps
  and sets the lamport clock to the max seen. CRDT internals stay hidden.
- **Store change.** One new method: prefix scan (`list(prefix)`), to load the
  key families at startup. Everything else uses `put_json` / `get_json`.
- **Write policy: synchronous write-through.** On mutation, snapshot under the
  state lock, seal-and-write outside the lock. Milliseconds at realistic
  sizes; eliminates lost-write-on-exit bugs. Per-conversation debounce is a
  drop-in later if bursts ever hurt.
- **Startup.** `Node::start_persistent` loads all key families into `State`
  before networking starts; sidebar and history render instantly offline.
- **TOFU pinning becomes real.** Today's `pinned` map stores each peer id as
  its own pin (a no-op). Instead, the contact record pins the peer's messaging
  identity key from their first `Hello` bundle; a mismatch on a later connect
  raises an "identity changed" warning.
- **Persisted messaging account.** The vodozemac `MessagingAccount` is sealed
  into the vault (`msg_account`, via its pickle) and re-saved whenever it
  mutates (one-time-key generation/consumption). Without this the messaging
  identity key would change on every app start and the TOFU pin would fire a
  false "identity changed" warning on every restart.
- **Deliberately unpersisted:** ratchet sessions. Sessions become
  per-connection (below), so nothing durable exists to store.

## Protocol

New content rides inside the existing ratchet encryption as new `Payload`
variants (never plaintext on the wire):

```
Payload::Profile(SignedProfile)
Payload::GroupAnnounce(GroupInfo)
Payload::SyncHave  { scope, ids }        // scope = Direct | Group(GroupId)
Payload::SyncDelta { scope, messages, reactions, read }
```

- **Connect-time initiator rule.** To avoid racing session initiation on
  every connect, the peer with the lexicographically lower id sends its
  post-connect payloads immediately; the higher-id peer queues its own until
  a ratchet session is established (its first inbound decrypt), then flushes.
  The PreKey tie-break below remains as a backstop for user-concurrent sends.
- **Connect-time sequence.** After `Hello`, each side sends: `Profile`
  (signature verified AND signer id must equal the peer's key; stored if
  `updated_at` newer) → `GroupAnnounce` for each group containing the peer
  (idempotent upsert; heals members who were offline at creation) →
  `SyncHave` for the 1:1 conversation and each shared group. `SyncHave` is
  answered with `SyncDelta` computed via the existing `delta_since()`; deltas
  are applied via `merge()`/`apply()`. Delta application emits a single
  `HistorySynced { scope, added }` event, not per-message notifications.
- **The CRDT is the outbox.** `send_text` no longer errors when offline: the
  message is recorded locally as *queued* and delivered by the next connect's
  sync round. Group messages heal transitively: any member who has a message
  delivers it to any member who lacks it, even if the author stays offline.
- **Auto-connect.** On `PeerDiscovered` of a known contact, dial
  automatically. Sends to a disconnected peer attempt one dial before
  queueing.
- **Session lifecycle fixes.**
  1. Evict the ratchet session when its connection dies (sessions are
     per-connection).
  2. PreKey fallback: if decrypt with the existing session fails and the
     ciphertext is PreKey-type, accept it as a fresh inbound session, with a
     deterministic tie-break — the session initiated by the lexicographically
     lower peer id wins — so simultaneous initiations converge on one session
     instead of ping-ponging. Any message lost in the race is re-delivered by
     delta sync.
  3. Delivery tracking falls out free, no extra protocol: a message counts as
     *delivered* when the peer's `SyncHave` contains its id, or when the
     peer's read watermark (already carried by `Wire::Read`) reaches its
     lamport.
- **Compatibility.** A 0.3.0 client receiving new payload variants fails JSON
  decode and drops the frame; plain chat still works cross-version, without
  sync/profiles, until both sides upgrade. Acceptable (no deployed base).

## UI & commands

- **Sidebar: roster-first.** *Contacts* (persistent; green dot = live
  connection as reported by the backend; grey = offline with last-seen; unread
  badge) and *Nearby* (discovered peers never talked to; clicking connects and
  promotes to contact). Groups persist and show member names.
- **Name resolution:** alias → peer profile name → fingerprint prefix. Alias
  editable from the contact.
- **Commands.** `list_contacts` replaces `list_peers` → `{ id, name, online,
  last_seen, unread }`; new `list_nearby`, `set_alias(peer, alias)`,
  `remove_contact(peer)` (confirm, then delete contact + conversation blobs),
  `mark_read(target)` (wires the existing read-watermark machinery; `unread` =
  messages above own watermark, computed backend-side). `history` /
  `group_history` / `send` / `send_group` keep signatures; `send` returns the
  message with status instead of erroring offline.
- **Message status glyphs** on own messages: *queued* (clock), *sent* (single
  tick — written to a live connection), *delivered* (double tick — per the
  delivery rule above: peer's `SyncHave` contains the id, or peer's read
  watermark reaches its lamport). New event kinds: `history_synced`,
  `message_status`, `contact_updated`.

## Error handling

- **Send/connect failures**: dismissible error banner in the conversation view
  (replacing console-only logging).
- **Vault load failure**: quarantine the unreadable blob (rename `.corrupt`),
  start with what loads, banner the affected conversation. Never crash, never
  silently destroy.
- **Pin mismatch**: persistent yellow banner with old/new fingerprints;
  sending stays enabled; explicit "accept new identity" re-pins. Hard-blocking
  is future work.
- **Snapshot write failure** (disk full): message still sends/applies in
  memory; banner warns persistence is failing.

## Testing

- **vartalaap-sync:** snapshot round-trip preserves order, reactions,
  watermarks, lamport continuity.
- **vartalaap-store:** prefix scan; corrupt-value quarantine.
- **Node integration** (extending `node.rs` test patterns):
  1. Restart persistence: chat → restart one node → history, contacts, groups
     intact.
  2. Offline queue: send while peer down → peer returns → auto-delivery with
     status transitions.
  3. Group heal: offline member receives missed group messages from a third
     member.
  4. Race convergence: both nodes send first messages concurrently → both
     converge, nothing permanently lost.
  5. Profile propagation and alias precedence.
  6. Pin-change detection.
- **App layer:** TypeScript type-check + production build (as CI does today).

## Out of scope

Message edit/delete (CRDT phase 2), multi-device identity, retention limits,
hard-blocking on pin change, passphrase-entry screen (vault key remains the
dev passphrase in `app/src-tauri/src/lib.rs`; separate future feature), and
internet-wide (non-LAN) sync.

## Implementation notes

Reviewed-and-approved deviations/additions from this spec that landed during
implementation (Tasks 1–12):

- `Payload::Profile` is `Option<SignedProfile>` and is ALWAYS sent as the
  post-connect beacon (guarantees the higher-id side's flush trigger even
  with no profile set).
- Delivery-ack round: `apply_delta` sends one fresh Direct-scope `SyncHave`
  back after merging a non-empty delta (without it the sender of a queued
  message never learns of delivery; bounded, terminates on empty deltas).
- `IrohTransport::closed()` added to vartalaap-net so `Node::shutdown()`
  drains the discovery loop and releases the vault. **Amended 2026-07-29:**
  closing the endpoint only *starts* the drain — reader loops and dial
  tasks still held an `Arc<Ctx>`, and with it the redb file lock, so
  reopening the same data directory right after shutdown could fail with
  "Database already open" (5/30 runs). `shutdown` now also waits, bounded
  at ~2s, for that `Arc` to become uniquely held.
- Group-announce ack: a newly-learned group (announce OR invite) replies
  with a SyncHave for that group so late-joining members backfill.
- `send_group` Tauri command kept its unit return (group per-member
  delivery status is out of scope).
- ~~Known residual: back-to-back sends immediately after a fresh connect
  can lose the live MessageReceived event; live GroupMessage/GroupInvite
  arms remain membership-ungated.~~ **Closed 2026-07-29 (v1.0.0).** The
  lost-event residual had two independent causes, both fixed: a peer's
  second pre-key message was re-accepted against a one-time key the
  first accept had already spent (`State::inbound_sessions` now retains a
  peer-initiated session we do not adopt), and `setup_connection` never
  cleared per-peer sessions, so a stale one survived a reconnect and kept
  emitting pre-key messages naming a spent key. Frames overtaking a
  peer's Hello are also now buffered and replayed once the bundle lands,
  rather than handled while undecryptable. GroupInvite is gated by
  `group_info_admits`, shared with GroupAnnounce.
- Delivered status is session-transient (peer_have); after a restart, own
  delivered messages render as single-tick until the next sync round
  restores the double tick.
- Test suites run serially in constrained environments due to a
  pre-existing iroh discovery flake under parallel load.
