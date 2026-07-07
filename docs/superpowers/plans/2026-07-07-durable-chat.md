# Durable Chat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Contacts, groups, and message history persist across offline periods and app restarts, messages sent to unreachable peers auto-deliver on reconnect, and the silent message-loss bugs (dead-connection sends, concurrent-session race, stale sessions) are fixed.

**Architecture:** Sealed whole-value snapshots in the existing encrypted redb vault (`Store`), loaded into `Node`'s in-memory `State` at startup with synchronous write-through on mutation. New ratchet-encrypted `Payload` variants carry profile exchange, group announcements, and CRDT delta sync (`SyncHave`/`SyncDelta`) on every connect — the CRDT itself is the offline outbox. Sessions become per-connection with a PreKey fallback + deterministic tie-break.

**Tech Stack:** Rust workspace (redb, vodozemac, iroh, serde_json), Tauri 2, React/TypeScript (vite).

**Spec:** `docs/superpowers/specs/2026-07-07-durable-chat-design.md` (approved; read it first).

## Global Constraints

- Workspace: edition 2021, `rust-version = "1.96"`; the Tauri app (`app/`) builds separately (own Cargo.lock).
- No new crate dependencies anywhere (vodozemac, redb, serde_json already present). One exception: `vartalaap-crypto` may need `serde_json = { workspace = true }` added to its `[dependencies]` if absent.
- Every task must end with `cargo test --workspace` green and `cargo clippy --workspace --all-targets -- -D warnings` clean (run from repo root `/home/babayaga/Projects/vartalaap-v2`).
- All persisted values go through the existing `Store` seal/open path — never plaintext to disk.
- New wire content rides **inside** `Wire::Message` ciphertext as `Payload` variants; never new plaintext `Wire` variants (exception: none).
- Locking discipline (documented in `node.rs` header): never hold `state`/`messaging` mutexes across `.await`; never both at once. Preserve it in every change.
- Vault key names (exact): `contact/<hex64>`, `convo/<hex64>`, `group/<hex32>`, `gconvo/<hex32>`, `msg_account`, quarantine prefix `corrupt/`. `<hex64>` = lowercase hex of the 32-byte peer key; `<hex32>` = lowercase hex of the 16-byte group id.
- Commit messages: conventional (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`) + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Integration tests that need two connected nodes use explicit `connect()` (not mDNS timing) and `timeout(Duration::from_secs(20), ...)` like the existing tests in `crates/vartalaap-core/src/node.rs`.

---

### Task 1: Conversation snapshot API (vartalaap-sync)

**Files:**
- Modify: `crates/vartalaap-sync/src/lib.rs`

**Interfaces:**
- Consumes: existing `Conversation`, `Message`, `Reaction`, `AuthorId`.
- Produces (later tasks rely on these exact names):
  - `pub struct Snapshot { pub messages: Vec<Message>, pub reactions: Vec<Reaction>, pub read: Vec<(AuthorId, u64)> }` (derives `Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq`)
  - `impl Conversation { pub fn snapshot(&self) -> Snapshot; pub fn from_snapshot(s: Snapshot) -> Self }`

- [ ] **Step 1: Write the failing test** (append inside `mod tests` in `crates/vartalaap-sync/src/lib.rs`)

```rust
    /// Snapshot → restore preserves messages, order, reactions, watermarks,
    /// and lamport continuity (a message created after restore sorts last).
    #[test]
    fn snapshot_roundtrip_preserves_state_and_clock() {
        let mut c = Conversation::new();
        let m1 = c.create_text(ALICE, 100, "one");
        let m2 = c.create_text(BOB, 101, "two");
        c.react(m1.id, BOB, "👍");
        c.mark_read(BOB, 7);

        let snap = c.snapshot();
        let json = serde_json::to_vec(&snap).expect("snapshot serializes");
        let back: Snapshot = serde_json::from_slice(&json).expect("snapshot deserializes");
        let mut r = Conversation::from_snapshot(back);

        let ids: Vec<_> = r.messages_ordered().iter().map(|m| m.id).collect();
        assert_eq!(ids, vec![m1.id, m2.id]);
        assert_eq!(r.reactions_for(&m1.id).len(), 1);
        assert_eq!(r.read_watermark(&BOB), 7);

        // Clock continuity: a new message must sort after restored ones.
        let m3 = r.create_text(ALICE, 102, "three");
        let ids: Vec<_> = r.messages_ordered().iter().map(|m| m.id).collect();
        assert_eq!(ids.last(), Some(&m3.id));
        assert!(m3.lamport > m2.lamport);
    }

    /// The watermark can exceed message lamports; the restored clock must
    /// cover it so fresh messages are never born already-read.
    #[test]
    fn snapshot_restores_clock_past_read_watermark() {
        let mut c = Conversation::new();
        c.create_text(ALICE, 1, "hi");
        c.mark_read(BOB, 50);
        let mut r = Conversation::from_snapshot(c.snapshot());
        let m = r.create_text(ALICE, 2, "new");
        assert!(m.lamport > 50, "new lamport {} must exceed watermark 50", m.lamport);
    }
```

Also add `serde_json` to `[dev-dependencies]` of `crates/vartalaap-sync/Cargo.toml` if not present:

```toml
[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p vartalaap-sync snapshot`
Expected: FAIL to compile with "cannot find type `Snapshot`".

- [ ] **Step 3: Write the implementation** (in `crates/vartalaap-sync/src/lib.rs`, after the `Conversation` struct definition)

```rust
/// A serializable snapshot of a [`Conversation`], used for encrypted
/// persistence. Vec-based because serde_json cannot serialize the CRDT's
/// byte-array-keyed maps directly.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub messages: Vec<Message>,
    pub reactions: Vec<Reaction>,
    pub read: Vec<(AuthorId, u64)>,
}

impl Conversation {
    /// Capture the full conversation state.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            messages: self.messages.values().cloned().collect(),
            reactions: self.reactions.iter().cloned().collect(),
            read: self.read.iter().map(|(a, l)| (*a, *l)).collect(),
        }
    }

    /// Rebuild a conversation from a snapshot. The local clock resumes past
    /// every message lamport and read watermark, so newly-authored messages
    /// sort after (and are never born already-read).
    pub fn from_snapshot(s: Snapshot) -> Self {
        let mut c = Conversation::new();
        for m in s.messages {
            c.apply(m);
        }
        for r in s.reactions {
            c.reactions.insert(r);
        }
        for (a, l) in s.read {
            c.mark_read(a, l);
            c.lamport = c.lamport.max(l);
        }
        c
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p vartalaap-sync`
Expected: all tests PASS (existing 7 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-sync
git commit -m "feat(sync): serializable Conversation snapshot with clock continuity

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Store prefix scan, delete, and quarantine (vartalaap-store)

**Files:**
- Modify: `crates/vartalaap-store/src/lib.rs`

**Interfaces:**
- Consumes: existing `Store`, `StoreError`, `seal`/`open`, `CryptoError`.
- Produces:
  - `pub fn list_secrets(&self, prefix: &str) -> Result<Vec<(String, Result<Vec<u8>, CryptoError>)>, StoreError>` — per-entry decrypt result so one corrupt blob doesn't fail the whole load.
  - `pub fn delete_secret(&self, name: &str) -> Result<(), StoreError>`
  - `pub fn quarantine(&self, name: &str) -> Result<(), StoreError>` — moves the raw sealed bytes to `corrupt/<name>` and deletes the original.

- [ ] **Step 1: Write the failing tests** (append inside `mod tests`)

```rust
    #[test]
    fn list_secrets_returns_prefix_matches_only() {
        let path = tmpdb();
        let s = Store::open(&path, VaultKey::from([7u8; 32])).unwrap();
        s.put_secret("contact/aa", b"a").unwrap();
        s.put_secret("contact/bb", b"b").unwrap();
        s.put_secret("convo/aa", b"c").unwrap();
        let got = s.list_secrets("contact/").unwrap();
        let mut keys: Vec<_> = got.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        assert_eq!(keys, vec!["contact/aa", "contact/bb"]);
        assert!(got.iter().all(|(_, v)| v.is_ok()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn delete_secret_removes_entry() {
        let path = tmpdb();
        let s = Store::open(&path, VaultKey::from([7u8; 32])).unwrap();
        s.put_secret("gone", b"x").unwrap();
        s.delete_secret("gone").unwrap();
        assert!(s.get_secret("gone").unwrap().is_none());
        std::fs::remove_file(&path).ok();
    }

    /// A value sealed under a different key fails to decrypt; list_secrets
    /// surfaces it per-entry and quarantine moves it aside.
    #[test]
    fn corrupt_value_is_reported_and_quarantined() {
        let path = tmpdb();
        {
            let other = Store::open(&path, VaultKey::from([1u8; 32])).unwrap();
            other.put_secret("convo/xx", b"sealed-under-other-key").unwrap();
        }
        let s = Store::open(&path, VaultKey::from([2u8; 32])).unwrap();
        let got = s.list_secrets("convo/").unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].1.is_err(), "wrong-key value must fail decryption");

        s.quarantine("convo/xx").unwrap();
        assert!(s.get_secret("convo/xx").unwrap().is_none());
        assert!(s.list_secrets("convo/").unwrap().is_empty());
        // The raw bytes were preserved under the quarantine prefix.
        let q = s.list_secrets("corrupt/convo/xx").unwrap();
        assert_eq!(q.len(), 1);
        std::fs::remove_file(&path).ok();
    }
```

Note: `Store::open` uses `Database::create`, which opens an existing file too, so reopening under a different key in the corrupt test works.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p vartalaap-store`
Expected: FAIL to compile with "no method named `list_secrets`".

- [ ] **Step 3: Write the implementation** (in `impl Store`)

```rust
    /// All entries whose key starts with `prefix`, with a per-entry decrypt
    /// result: one corrupt value must not hide the healthy ones.
    pub fn list_secrets(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, Result<Vec<u8>, CryptoError>)>, StoreError> {
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let t = rtx
            .open_table(SECRETS)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let mut out = Vec::new();
        for entry in t
            .range(prefix..)
            .map_err(|e| StoreError::Db(e.to_string()))?
        {
            let (k, v) = entry.map_err(|e| StoreError::Db(e.to_string()))?;
            let key = k.value().to_string();
            if !key.starts_with(prefix) {
                break; // keys are ordered; past the prefix range
            }
            out.push((key, open(&self.key, v.value())));
        }
        Ok(out)
    }

    /// Remove an entry (no-op if absent).
    pub fn delete_secret(&self, name: &str) -> Result<(), StoreError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(SECRETS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.remove(name).map_err(|e| StoreError::Db(e.to_string()))?;
        }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// Move an entry's raw sealed bytes to `corrupt/<name>` (preserving the
    /// evidence) and delete the original. Used when a value fails to decrypt
    /// or deserialize, so startup never crashes and never silently destroys.
    pub fn quarantine(&self, name: &str) -> Result<(), StoreError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(SECRETS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            let raw = match t.get(name).map_err(|e| StoreError::Db(e.to_string()))? {
                Some(v) => v.value().to_vec(),
                None => return Ok(()), // nothing to quarantine
            };
            t.insert(format!("corrupt/{name}").as_str(), raw.as_slice())
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.remove(name).map_err(|e| StoreError::Db(e.to_string()))?;
        }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }
```

Borrow note: `t.get(name)` returns a guard borrowing `t`; copy out with `.to_vec()` and `drop` the guard before `t.insert` (the `match` above already scopes it — if the borrow checker complains, bind `let raw = { ... };` in its own block). If type inference stumbles on `t.range(prefix..)`, use the explicit form `t.range::<&str>(prefix..)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p vartalaap-store`
Expected: all tests PASS (existing 3 + 3 new).

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-store
git commit -m "feat(store): prefix scan, delete, and corrupt-value quarantine

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Messaging-account pickle + Contact type + vault persistence helpers (crypto + core)

**Files:**
- Modify: `crates/vartalaap-crypto/src/ratchet.rs`
- Modify: `crates/vartalaap-crypto/Cargo.toml` (add `serde_json = { workspace = true }` to `[dependencies]` if absent)
- Create: `crates/vartalaap-core/src/persist.rs`
- Modify: `crates/vartalaap-core/src/lib.rs` (add `pub mod persist;` and `signed_profile()`)

**Interfaces:**
- Consumes: `Store` methods from Task 2, `Snapshot` from Task 1, existing `GroupInfo`/`PeerKey` from `crate::node`, `Profile`/`SignedProfile` from vartalaap-identity.
- Produces:
  - crypto: `impl MessagingAccount { pub fn to_pickle_json(&self) -> Vec<u8>; pub fn from_pickle_json(bytes: &[u8]) -> Result<Self, RatchetError> }`
  - core `persist::Contact`:
    ```rust
    pub struct Contact {
        pub peer: [u8; 32],
        pub profile: Option<Profile>,
        pub alias: Option<String>,
        pub pinned_msg_key: Option<[u8; 32]>,
        pub pending_msg_key: Option<[u8; 32]>,
        pub last_seen: u64,
        pub added_at: u64,
    }
    ```
    (derives `Clone, Debug, Serialize, Deserialize, PartialEq, Eq`) plus `impl Contact { pub fn display_name(&self) -> Option<String> }` returning `alias.clone().or(profile.display_name if non-empty)`.
  - core `impl Engine` (all in persist.rs; every `load_*` returns `(Vec<...>, Vec<String>)` where the second element is human-readable quarantine warnings):
    - `pub fn save_contact(&self, c: &Contact) -> Result<(), CoreError>`
    - `pub fn load_contacts(&self) -> Result<(Vec<Contact>, Vec<String>), CoreError>`
    - `pub fn delete_contact(&self, peer: &[u8; 32]) -> Result<(), CoreError>` (removes `contact/<hex>` and `convo/<hex>`)
    - `pub fn save_convo(&self, peer: &[u8; 32], s: &Snapshot) -> Result<(), CoreError>`
    - `pub fn load_convos(&self) -> Result<(Vec<([u8; 32], Snapshot)>, Vec<String>), CoreError>`
    - `pub fn save_group(&self, g: &GroupInfo) -> Result<(), CoreError>`
    - `pub fn load_groups(&self) -> Result<(Vec<GroupInfo>, Vec<String>), CoreError>`
    - `pub fn save_group_convo(&self, gid: &[u8; 16], s: &Snapshot) -> Result<(), CoreError>`
    - `pub fn load_group_convos(&self) -> Result<(Vec<([u8; 16], Snapshot)>, Vec<String>), CoreError>`
    - `pub fn load_or_create_msg_account(&self) -> Result<MessagingAccount, CoreError>`
    - `pub fn save_msg_account(&self, acct: &MessagingAccount) -> Result<(), CoreError>`
  - core `lib.rs`: `pub fn signed_profile(&self) -> Result<Option<SignedProfile>, CoreError>` (raw load, no unwrap of profile)

- [ ] **Step 1: Write the failing crypto test** (append inside `mod tests` in `ratchet.rs`)

```rust
    /// The pickled account restores to the same messaging identity, and a
    /// bundle from the restored account still accepts sessions.
    #[test]
    fn account_pickle_roundtrip_preserves_identity() {
        let mut bob = MessagingAccount::new();
        let ik = bob.identity_key();
        let bundle = bob.prekey_bundle();

        let pickled = bob.to_pickle_json();
        let mut restored = MessagingAccount::from_pickle_json(&pickled).unwrap();
        assert_eq!(restored.identity_key(), ik);

        // A session initiated against the pre-pickle bundle must be accepted
        // by the restored account (one-time key survived the roundtrip).
        let alice = MessagingAccount::new();
        let (_s, first) = RatchetSession::initiate(&alice, &bundle, b"hi").unwrap();
        let (_bs, plain) =
            RatchetSession::accept(&mut restored, alice.identity_key(), &first).unwrap();
        assert_eq!(plain, b"hi");
    }
```

Note the ordering: `prekey_bundle()` BEFORE pickling, so the one-time key is part of the pickled state.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p vartalaap-crypto account_pickle`
Expected: FAIL to compile with "no method named `to_pickle_json`".

- [ ] **Step 3: Implement the pickle methods** (in `impl MessagingAccount`, ratchet.rs)

```rust
    /// Serialize the account (including unpublished one-time keys) for sealed
    /// storage. The output is sensitive: callers must encrypt it at rest.
    pub fn to_pickle_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.inner.pickle()).expect("account pickle serializes")
    }

    /// Restore an account previously serialized with [`to_pickle_json`].
    pub fn from_pickle_json(bytes: &[u8]) -> Result<Self, RatchetError> {
        let pickle: vodozemac::olm::AccountPickle = serde_json::from_slice(bytes)
            .map_err(|e| RatchetError::SessionCreation(format!("bad account pickle: {e}")))?;
        Ok(Self {
            inner: Account::from_pickle(pickle),
        })
    }
```

If `serde_json` is missing from `crates/vartalaap-crypto/Cargo.toml` `[dependencies]`, add `serde_json = { workspace = true }`.

- [ ] **Step 4: Run crypto tests**

Run: `cargo test -p vartalaap-crypto`
Expected: PASS.

- [ ] **Step 5: Write the failing core persistence test** (new file section — create `crates/vartalaap-core/src/persist.rs` containing ONLY the test module first, plus `pub mod persist;` in lib.rs)

```rust
//! Vault persistence for roster, conversations, and groups: maps domain
//! state to sealed values in the [`Store`] under stable key prefixes.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use vartalaap_sync::Conversation;

    fn tmpdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-persist-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn contacts_convos_groups_roundtrip_across_reopen() {
        let dir = tmpdir();
        let peer = [9u8; 32];
        let gid = [4u8; 16];
        {
            let e = Engine::open(&dir, "pw").unwrap();
            let c = Contact {
                peer,
                profile: None,
                alias: Some("roomie".into()),
                pinned_msg_key: Some([1u8; 32]),
                pending_msg_key: None,
                last_seen: 42,
                added_at: 1,
            };
            e.save_contact(&c).unwrap();

            let mut convo = Conversation::new();
            convo.create_text(peer, 100, "hello");
            e.save_convo(&peer, &convo.snapshot()).unwrap();

            let g = crate::node::GroupInfo {
                id: gid,
                name: "study".into(),
                members: vec![peer],
                creator: peer,
            };
            e.save_group(&g).unwrap();
            e.save_group_convo(&gid, &convo.snapshot()).unwrap();
        }
        let e = Engine::open(&dir, "pw").unwrap();
        let (contacts, warn) = e.load_contacts().unwrap();
        assert!(warn.is_empty());
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].alias.as_deref(), Some("roomie"));
        assert_eq!(contacts[0].display_name().as_deref(), Some("roomie"));

        let (convos, _) = e.load_convos().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].0, peer);
        assert_eq!(convos[0].1.messages.len(), 1);

        let (groups, _) = e.load_groups().unwrap();
        assert_eq!(groups[0].name, "study");
        let (gconvos, _) = e.load_group_convos().unwrap();
        assert_eq!(gconvos[0].0, gid);

        e.delete_contact(&peer).unwrap();
        assert!(e.load_contacts().unwrap().0.is_empty());
        assert!(e.load_convos().unwrap().0.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn msg_account_persists_across_reopen() {
        let dir = tmpdir();
        let ik = {
            let e = Engine::open(&dir, "pw").unwrap();
            let acct = e.load_or_create_msg_account().unwrap();
            e.save_msg_account(&acct).unwrap();
            acct.identity_key()
        };
        let e = Engine::open(&dir, "pw").unwrap();
        let acct = e.load_or_create_msg_account().unwrap();
        assert_eq!(acct.identity_key(), ik, "messaging identity must be stable");
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `cargo test -p vartalaap-core persist`
Expected: FAIL to compile with "cannot find struct `Contact`".

- [ ] **Step 7: Implement persist.rs** (above the test module)

```rust
use serde::{Deserialize, Serialize};
use vartalaap_crypto::ratchet::MessagingAccount;
use vartalaap_identity::Profile;
use vartalaap_sync::Snapshot;

use crate::node::{GroupInfo, PeerKey};
use crate::{CoreError, Engine};

const MSG_ACCOUNT_KEY: &str = "msg_account";

/// A known peer: someone we've completed at least one handshake with.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub peer: PeerKey,
    /// Latest verified peer-published profile.
    pub profile: Option<Profile>,
    /// Local user-chosen name; overrides the profile name.
    pub alias: Option<String>,
    /// TOFU pin: the messaging identity key from the first Hello bundle.
    pub pinned_msg_key: Option<[u8; 32]>,
    /// A different key seen later, awaiting explicit user acceptance.
    pub pending_msg_key: Option<[u8; 32]>,
    /// Unix millis of last connect/disconnect/message.
    pub last_seen: u64,
    pub added_at: u64,
}

impl Contact {
    /// Resolved human name: alias wins, then a non-empty profile name.
    pub fn display_name(&self) -> Option<String> {
        if let Some(a) = &self.alias {
            if !a.is_empty() {
                return Some(a.clone());
            }
        }
        match &self.profile {
            Some(p) if !p.display_name.is_empty() => Some(p.display_name.clone()),
            _ => None,
        }
    }
}

fn hex64(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn hex32(b: &[u8; 16]) -> String {
    hex::encode(b)
}

impl Engine {
    fn load_prefix<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
    ) -> Result<(Vec<(String, T)>, Vec<String>), CoreError> {
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        for (key, val) in self.store.list_secrets(prefix)? {
            let parsed = val
                .map_err(|e| e.to_string())
                .and_then(|bytes| serde_json::from_slice::<T>(&bytes).map_err(|e| e.to_string()));
            match parsed {
                Ok(v) => out.push((key, v)),
                Err(e) => {
                    // Move the unreadable blob aside; never crash, never destroy.
                    self.store.quarantine(&key)?;
                    warnings.push(format!("unreadable vault entry {key} quarantined: {e}"));
                }
            }
        }
        Ok((out, warnings))
    }

    pub fn save_contact(&self, c: &Contact) -> Result<(), CoreError> {
        Ok(self.store.put_json(&format!("contact/{}", hex64(&c.peer)), c)?)
    }

    pub fn load_contacts(&self) -> Result<(Vec<Contact>, Vec<String>), CoreError> {
        let (items, warnings) = self.load_prefix::<Contact>("contact/")?;
        Ok((items.into_iter().map(|(_, c)| c).collect(), warnings))
    }

    pub fn delete_contact(&self, peer: &PeerKey) -> Result<(), CoreError> {
        self.store.delete_secret(&format!("contact/{}", hex64(peer)))?;
        self.store.delete_secret(&format!("convo/{}", hex64(peer)))?;
        Ok(())
    }

    pub fn save_convo(&self, peer: &PeerKey, s: &Snapshot) -> Result<(), CoreError> {
        Ok(self.store.put_json(&format!("convo/{}", hex64(peer)), s)?)
    }

    pub fn load_convos(&self) -> Result<(Vec<(PeerKey, Snapshot)>, Vec<String>), CoreError> {
        let (items, warnings) = self.load_prefix::<Snapshot>("convo/")?;
        let mut out = Vec::new();
        for (key, snap) in items {
            if let Some(peer) = parse_hex32_key(&key, "convo/") {
                out.push((peer, snap));
            }
        }
        Ok((out, warnings))
    }

    pub fn save_group(&self, g: &GroupInfo) -> Result<(), CoreError> {
        Ok(self.store.put_json(&format!("group/{}", hex32(&g.id)), g)?)
    }

    pub fn load_groups(&self) -> Result<(Vec<GroupInfo>, Vec<String>), CoreError> {
        let (items, warnings) = self.load_prefix::<GroupInfo>("group/")?;
        Ok((items.into_iter().map(|(_, g)| g).collect(), warnings))
    }

    pub fn save_group_convo(&self, gid: &[u8; 16], s: &Snapshot) -> Result<(), CoreError> {
        Ok(self.store.put_json(&format!("gconvo/{}", hex32(gid)), s)?)
    }

    pub fn load_group_convos(
        &self,
    ) -> Result<(Vec<([u8; 16], Snapshot)>, Vec<String>), CoreError> {
        let (items, warnings) = self.load_prefix::<Snapshot>("gconvo/")?;
        let mut out = Vec::new();
        for (key, snap) in items {
            if let Some(gid) = parse_hex16_key(&key, "gconvo/") {
                out.push((gid, snap));
            }
        }
        Ok((out, warnings))
    }

    /// Load the persisted messaging account, or create-and-persist a fresh
    /// one. Keeping it stable across restarts keeps the TOFU pin meaningful.
    pub fn load_or_create_msg_account(&self) -> Result<MessagingAccount, CoreError> {
        match self.store.get_secret(MSG_ACCOUNT_KEY)? {
            Some(bytes) => match MessagingAccount::from_pickle_json(&bytes) {
                Ok(a) => Ok(a),
                Err(_) => {
                    // Unreadable pickle: quarantine and start fresh rather
                    // than refusing to start.
                    self.store.quarantine(MSG_ACCOUNT_KEY)?;
                    let a = MessagingAccount::new();
                    self.save_msg_account(&a)?;
                    Ok(a)
                }
            },
            None => {
                let a = MessagingAccount::new();
                self.save_msg_account(&a)?;
                Ok(a)
            }
        }
    }

    pub fn save_msg_account(&self, acct: &MessagingAccount) -> Result<(), CoreError> {
        Ok(self.store.put_secret(MSG_ACCOUNT_KEY, &acct.to_pickle_json())?)
    }
}

fn parse_hex32_key(key: &str, prefix: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(key.strip_prefix(prefix)?).ok()?;
    bytes.try_into().ok()
}

fn parse_hex16_key(key: &str, prefix: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(key.strip_prefix(prefix)?).ok()?;
    bytes.try_into().ok()
}
```

In `crates/vartalaap-core/src/lib.rs`: add `pub mod persist;` next to `pub mod node;`, change the `Engine` field to `pub(crate) store: Store` (persist.rs is a sibling module and needs field access — `identity` can stay private), and add the raw signed-profile accessor to `impl Engine`:

```rust
    /// The stored signed profile, unverified-as-loaded (verification happens
    /// in [`Engine::profile`]); used to publish over the wire.
    pub fn signed_profile(&self) -> Result<Option<SignedProfile>, CoreError> {
        Ok(self.store.get_json::<SignedProfile>(PROFILE_KEY)?)
    }
```

Check `crates/vartalaap-core/Cargo.toml` has `hex = { workspace = true }`; add if absent.

- [ ] **Step 8: Run tests**

Run: `cargo test -p vartalaap-core && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, clippy clean.

- [ ] **Step 9: Commit**

```bash
git add crates/vartalaap-crypto crates/vartalaap-core
git commit -m "feat(core): Contact type, sealed vault persistence helpers, stable messaging account

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Extract protocol module (mechanical refactor)

**Files:**
- Create: `crates/vartalaap-core/src/protocol.rs`
- Modify: `crates/vartalaap-core/src/node.rs`, `crates/vartalaap-core/src/lib.rs`

**Interfaces:**
- Produces: `crate::protocol` containing, moved verbatim from node.rs: `pub type PeerKey`, `pub type GroupId`, `pub struct GroupInfo`, `pub(crate) enum Wire`, `pub(crate) enum Payload`, `pub(crate) struct PendingFile`. node.rs keeps `pub use crate::protocol::{GroupId, GroupInfo, PeerKey};` so the public API path `vartalaap_core::node::GroupInfo` is unchanged (persist.rs and the app depend on it).

- [ ] **Step 1: Move the types.** Create `protocol.rs` with the exact definitions currently at `node.rs:34-126` (`PeerKey`, `EngineEvent` stays in node.rs; move `Wire`, `GroupId`, `GroupInfo`, `Payload`, `PendingFile`). Add `use serde::{Deserialize, Serialize};` and `use vartalaap_crypto::ratchet::PreKeyBundle; use vartalaap_sync::Message;` as needed. Mark `Wire`, `Payload`, `PendingFile` as `pub(crate)`. In `lib.rs` add `pub mod protocol;`. In node.rs delete the moved definitions and add:

```rust
pub use crate::protocol::{GroupId, GroupInfo, PeerKey};
use crate::protocol::{Payload, PendingFile, Wire};
```

- [ ] **Step 2: Verify the suite is green (this is the test for a mechanical move)**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all 40+ tests PASS, clippy clean, no public-API change (`persist.rs`'s `use crate::node::{GroupInfo, PeerKey}` still resolves via the re-export).

- [ ] **Step 3: Commit**

```bash
git add crates/vartalaap-core
git commit -m "refactor(core): extract wire/payload protocol types into protocol module

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Node context refactor + persistence wiring + restart survival

**Files:**
- Modify: `crates/vartalaap-core/src/node.rs`
- Test: integration tests inside `node.rs` `mod tests`

**Interfaces:**
- Consumes: Task 3 Engine helpers, Task 1 snapshots.
- Produces (later tasks build on these exact shapes):
  ```rust
  pub(crate) struct Ctx {
      my_id: PeerKey,
      transport: Arc<IrohTransport>,
      messaging: Arc<Mutex<MessagingAccount>>,
      state: Arc<Mutex<State>>,
      events: mpsc::UnboundedSender<EngineEvent>,
      session_init: Arc<Mutex<()>>,
      download_dir: PathBuf,
      engine: Option<Arc<Engine>>,
  }
  pub struct Node { id: PeerKey, ctx: Arc<Ctx> }
  async fn setup_connection(conn: Conn, ctx: Arc<Ctx>) -> Result<PeerKey>
  async fn reader_loop(conn: Conn, peer: PeerKey, generation: u64, ctx: Arc<Ctx>)
  fn handle_frame(wire: Wire, peer: PeerKey, ctx: &Arc<Ctx>)
  fn persist_convo(ctx: &Ctx, peer: &PeerKey)        // + persist_group_convo, persist_group, persist_contact
  pub async fn shutdown(&self)                        // on Node
  pub fn contacts(&self) -> Vec<Contact>              // on Node
  ```
  New `State` field: `contacts: HashMap<PeerKey, Contact>`. New event: `EngineEvent::StorageWarning { detail: String }`.
- Persistence rule: snapshot/clone under the state lock, write to the vault OUTSIDE the lock; a write error emits `StorageWarning` and continues (in-memory state stays correct).

- [ ] **Step 1: Mechanical Ctx refactor.** Introduce `Ctx`, store `ctx: Arc<Ctx>` in `Node`, and rewrite `start_inner`, `setup_connection`, `reader_loop`, `handle_frame`, `handle_blob`, `decrypt_payload`, and every `Node` method to go through `ctx` (e.g. `self.ctx.state.lock()...`). The accept loop and the discovery loop in `start_inner` each capture a `ctx.clone()` instead of individual field clones (Task 9 needs the full ctx inside the discovery loop). `session_init` moves from `Node` into `Ctx` as `Arc<Mutex<()>>`. Signatures as in Interfaces. `MessagingAccount` comes from `engine.load_or_create_msg_account()?` when persistent, `MessagingAccount::new()` otherwise. No behavior change.

- [ ] **Step 2: Verify suite green after refactor**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Commit the refactor**

```bash
git add crates/vartalaap-core
git commit -m "refactor(core): thread shared Ctx through node connection machinery

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Write the failing restart test** (in node.rs `mod tests`)

```rust
    /// Persistence: messages, groups, and contacts survive an app restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn state_survives_restart() -> Result<()> {
        let dir = {
            let mut p = std::env::temp_dir();
            let n: u64 = rand::random();
            p.push(format!("vartalaap-restart-{n}"));
            p
        };
        let (bob, mut bob_rx) = Node::start([61u8; 32]).await?;
        let bob_id = bob.id();

        let gid;
        {
            let (alice, mut alice_rx) = Node::start_persistent(&dir, "pw").await?;
            timeout(Duration::from_secs(20), alice.connect(bob_id))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            alice.send_text(bob_id, "remember me").await?;
            wait_message(&mut bob_rx).await;
            bob.send_text(alice.id(), "and me").await?;
            wait_message(&mut alice_rx).await;
            gid = alice.create_group("study".into(), vec![bob_id]).await?;
            alice.send_group_text(gid, "group msg").await?;
            alice.shutdown().await;
        }

        // Restart from the same directory: everything must reload, offline.
        let (alice2, _rx) = Node::start_persistent(&dir, "pw").await?;
        let bodies = alice2.conversation_bodies(&bob_id);
        assert!(bodies.contains(&"remember me".to_string()));
        assert!(bodies.contains(&"and me".to_string()));
        let groups = alice2.groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "study");
        assert_eq!(alice2.group_conversation(&gid).len(), 1);
        let contacts = alice2.contacts();
        assert_eq!(contacts.len(), 1, "bob must be a persisted contact");
        assert_eq!(contacts[0].peer, bob_id);
        alice2.shutdown().await;
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
```

- [ ] **Step 5: Run to verify it fails**

Run: `cargo test -p vartalaap-core state_survives_restart`
Expected: FAIL to compile ("no method named `shutdown`" / "no method named `contacts`").

- [ ] **Step 6: Implement persistence wiring.**

(a) `State` gains `contacts: HashMap<PeerKey, Contact>` (`use crate::persist::Contact;`).

(b) New event variant:

```rust
    /// A vault read/write problem the user should know about (load quarantine
    /// or write failure). The app keeps running on in-memory state.
    StorageWarning { detail: String },
```

(c) In `start_inner`, when `engine` is `Some`, load everything before spawning loops:

```rust
        let mut initial = State::default();
        if let Some(engine) = &engine {
            let mut warn_all = Vec::new();
            let (contacts, w) = engine.load_contacts()?;
            warn_all.extend(w);
            for c in contacts {
                initial.contacts.insert(c.peer, c);
            }
            let (convos, w) = engine.load_convos()?;
            warn_all.extend(w);
            for (peer, snap) in convos {
                initial.conversations.insert(peer, Conversation::from_snapshot(snap));
            }
            let (groups, w) = engine.load_groups()?;
            warn_all.extend(w);
            for g in groups {
                initial.groups.insert(g.id, g);
            }
            let (gconvos, w) = engine.load_group_convos()?;
            warn_all.extend(w);
            for (gid, snap) in gconvos {
                initial.group_convos.insert(gid, Conversation::from_snapshot(snap));
            }
            for detail in warn_all {
                let _ = tx.send(EngineEvent::StorageWarning { detail });
            }
        }
        let state = Arc::new(Mutex::new(initial));
```

(d) Write-through helpers (free functions near `handle_frame`):

```rust
/// Snapshot under the lock, write outside it. Failures warn, never crash.
fn persist_convo(ctx: &Ctx, peer: &PeerKey) {
    let Some(engine) = &ctx.engine else { return };
    let snap = {
        let st = ctx.state.lock().unwrap();
        st.conversations.get(peer).map(|c| c.snapshot())
    };
    if let Some(snap) = snap {
        if let Err(e) = engine.save_convo(peer, &snap) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist conversation: {e}"),
            });
        }
    }
}

fn persist_group_convo(ctx: &Ctx, gid: &GroupId) {
    let Some(engine) = &ctx.engine else { return };
    let snap = {
        let st = ctx.state.lock().unwrap();
        st.group_convos.get(gid).map(|c| c.snapshot())
    };
    if let Some(snap) = snap {
        if let Err(e) = engine.save_group_convo(gid, &snap) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist group conversation: {e}"),
            });
        }
    }
}

fn persist_group(ctx: &Ctx, gid: &GroupId) {
    let Some(engine) = &ctx.engine else { return };
    let info = {
        let st = ctx.state.lock().unwrap();
        st.groups.get(gid).cloned()
    };
    if let Some(info) = info {
        if let Err(e) = engine.save_group(&info) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist group: {e}"),
            });
        }
    }
}

fn persist_contact(ctx: &Ctx, peer: &PeerKey) {
    let Some(engine) = &ctx.engine else { return };
    let contact = {
        let st = ctx.state.lock().unwrap();
        st.contacts.get(peer).cloned()
    };
    if let Some(contact) = contact {
        if let Err(e) = engine.save_contact(&contact) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist contact: {e}"),
            });
        }
    }
}
```

(e) Call sites (each right after the state mutation, outside the lock):
- `send_text` → `persist_convo(&self.ctx, &peer)` after creating the message
- `send_file` → same
- `apply_direct_message` → `persist_convo(ctx, &peer)` (change its signature to take `ctx: &Arc<Ctx>`)
- `mark_read` → `persist_convo`
- `create_group` → `persist_group` + `persist_group_convo`
- `send_group_text` → `persist_group_convo`
- `handle_frame` `GroupInvite` arm → `persist_group` + `persist_group_convo`
- `handle_frame` `GroupMessage` arm → `persist_group_convo`
- `handle_frame` `Wire::Read` arm → `persist_convo`

(f) Contact creation on handshake — in `setup_connection`, replace the vestigial `st.pinned.entry(peer).or_insert(peer);` with contact upsert (and DELETE the `pinned` field from `State`):

```rust
        let now = now_millis();
        let is_new_contact = {
            let mut st = ctx.state.lock().unwrap();
            // ... existing bundle/conn/generation bookkeeping ...
            let is_new = !st.contacts.contains_key(&peer);
            let entry = st.contacts.entry(peer).or_insert_with(|| Contact {
                peer,
                profile: None,
                alias: None,
                pinned_msg_key: None, // pinned in Task 7
                pending_msg_key: None,
                last_seen: now,
                added_at: now,
            });
            entry.last_seen = now;
            is_new
        };
        persist_contact(&ctx, &peer);
        let _ = is_new_contact; // used by Task 7's ContactUpdated event
```

Also update `last_seen` + `persist_contact` in `reader_loop`'s disconnect path (inside the `was_current` branch) and in `apply_direct_message`.

(g) Node additions:

```rust
    /// Known contacts (persisted when the node is persistent).
    pub fn contacts(&self) -> Vec<Contact> {
        self.ctx.state.lock().unwrap().contacts.values().cloned().collect()
    }

    /// Close the endpoint so the accept loop ends and background tasks drain.
    pub async fn shutdown(&self) {
        self.ctx.transport.close().await;
    }
```

- [ ] **Step 7: Run the full suite**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS including `state_survives_restart`.

- [ ] **Step 8: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): load roster/history from vault at startup, write-through on mutation

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Session lifecycle — per-connection eviction, PreKey fallback, tie-break

**Files:**
- Modify: `crates/vartalaap-crypto/src/ratchet.rs` (add `is_prekey`)
- Modify: `crates/vartalaap-core/src/node.rs`

**Interfaces:**
- Consumes: Ctx from Task 5.
- Produces:
  - crypto: `pub fn is_prekey(wire: &[u8]) -> bool` (true when the leading type byte is the Olm PreKey type, i.e. `0`)
  - node: `fn encrypt_for(ctx: &Ctx, peer: PeerKey, plaintext: &[u8]) -> Result<Vec<u8>>` (free function; `Node::send_*` and later `post_connect` both use it), `async fn send_payload_ctx(ctx: &Arc<Ctx>, peer: PeerKey, payload: &Payload) -> Result<()>`
  - Behavior: reader_loop evicts `sessions[peer]` alongside the conn (guarded by generation, i.e. only in the `was_current` branch); `decrypt_payload` falls back to accepting a PreKey message as a new inbound session when the existing session can't decrypt it AND `peer < my_id`, replacing the stored session.
  - After any `prekey_bundle()` or successful `RatchetSession::accept`, persist the messaging account: `if let Some(e) = &ctx.engine { let _ = e.save_msg_account(&ctx.messaging.lock().unwrap()); }` (lock, pickle, drop guard, then write — pickle happens inside `save_msg_account`'s argument evaluation, so bind the pickle bytes first to avoid holding the lock during I/O: `let bytes = ctx.messaging.lock().unwrap().to_pickle_json();` then a raw `store` write via a small `Engine::save_msg_account_bytes(&self, bytes: &[u8])` — add it in this task).

- [ ] **Step 1: Write the failing crypto test** (ratchet.rs `mod tests`)

```rust
    #[test]
    fn is_prekey_distinguishes_message_types() {
        let mut bob = MessagingAccount::new();
        let bundle = bob.prekey_bundle();
        let alice = MessagingAccount::new();
        let (mut alice_session, first) =
            RatchetSession::initiate(&alice, &bundle, b"open").unwrap();
        assert!(is_prekey(&first), "first message is a PreKey message");

        let (mut bob_session, _) =
            RatchetSession::accept(&mut bob, alice.identity_key(), &first).unwrap();
        let reply = bob_session.encrypt(b"ok").unwrap();
        assert!(!is_prekey(&reply), "post-handshake replies are Normal");
        alice_session.decrypt(&reply).unwrap();
        let next = alice_session.encrypt(b"more").unwrap();
        assert!(!is_prekey(&next));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p vartalaap-crypto is_prekey`
Expected: FAIL to compile ("cannot find function `is_prekey`").

- [ ] **Step 3: Implement `is_prekey`** (ratchet.rs, near `encode`/`decode`)

```rust
/// Whether a wire ciphertext produced by [`encode`] is an Olm PreKey
/// (handshake) message. PreKey's numeric message type is 0.
pub fn is_prekey(wire: &[u8]) -> bool {
    wire.first() == Some(&0)
}
```

Export it from the crypto crate root if `ratchet` isn't already `pub mod` re-exported (check `crates/vartalaap-crypto/src/lib.rs`; node.rs imports from `vartalaap_crypto::ratchet::`, so a plain `pub fn` in ratchet.rs suffices).

Run: `cargo test -p vartalaap-crypto` — PASS.

- [ ] **Step 4: Write the failing node race test** (node.rs `mod tests`)

```rust
    /// Both sides send their FIRST message concurrently: each initiates its
    /// own session. Without the PreKey fallback + tie-break this deadlocks
    /// (all subsequent messages silently dropped both ways). With it, both
    /// sides converge on one session and later messages flow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_sends_do_not_deadlock() -> Result<()> {
        let (alice, mut alice_rx) = Node::start([71u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([72u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());

        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        // Fire the first messages truly concurrently.
        let (ra, rb) = tokio::join!(alice.send_text(bid, "a1"), bob.send_text(aid, "b1"));
        ra?;
        rb?;

        // Regardless of which first message won, LATER messages must flow
        // both directions (the deadlock symptom is: nothing ever arrives).
        alice.send_text(bid, "a2").await?;
        let got = wait_message(&mut bob_rx).await;
        assert!(got.body == "a1" || got.body == "a2");

        bob.send_text(aid, "b2").await?;
        let got = wait_message(&mut alice_rx).await;
        assert!(got.body == "b1" || got.body == "b2");
        Ok(())
    }
```

- [ ] **Step 5: Run to verify it fails**

Run: `cargo test -p vartalaap-core concurrent_first_sends -- --nocapture`
Expected: FAIL (timeout waiting for a message) — this reproduces the reported bug. If it flakily passes (the race didn't trigger), re-run; the implementation below must make it pass deterministically either way.

- [ ] **Step 6: Implement the three fixes.**

(a) **Evict session with the conn** — in `reader_loop`'s exit block, inside the `was_current` branch:

```rust
        if st.conn_gen.get(&peer).copied() == Some(generation) {
            st.conns.remove(&peer);
            st.conn_gen.remove(&peer);
            st.sessions.remove(&peer); // sessions are per-connection
            true
        } else {
            false
        }
```

(b) **Free-function `encrypt_for`** — move the body of `Node::encrypt_for` to:

```rust
/// Encrypt for `peer` on the existing session, or initiate one from the
/// peer's published bundle. `session_init` serializes concurrent first-sends.
fn encrypt_for(ctx: &Ctx, peer: PeerKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    // (identical logic to the current method, using ctx.state / ctx.messaging /
    //  ctx.session_init; after initiating, persist the account — a one-time
    //  key may have been consumed on the peer side, ours mutates on bundle
    //  generation elsewhere.)
}
```

`Node::send_text`/`send_file`/`send_payload` delegate to it. Add:

```rust
/// Encrypt a payload for `peer` and send it on the registered connection.
async fn send_payload_ctx(ctx: &Arc<Ctx>, peer: PeerKey, payload: &Payload) -> Result<()> {
    let ciphertext = encrypt_for(ctx, peer, &serde_json::to_vec(payload)?)?;
    let conn = {
        let st = ctx.state.lock().unwrap();
        st.conns.get(&peer).cloned()
    }
    .ok_or_else(|| anyhow!("no connection to peer"))?;
    conn.send_frame(&serde_json::to_vec(&Wire::Message { ciphertext })?)
        .await?;
    Ok(())
}
```

(c) **PreKey fallback + tie-break** in `decrypt_payload` (which now takes `ctx: &Arc<Ctx>`): replace the `has_session` branch with:

```rust
    let has_session = ctx.state.lock().unwrap().sessions.contains_key(&peer);
    let plaintext = if has_session {
        let attempt = {
            let mut st = ctx.state.lock().unwrap();
            let session = st.sessions.get_mut(&peer).unwrap();
            session.decrypt(ciphertext)
        };
        match attempt {
            Ok(p) => p,
            // The peer initiated a competing session (both sides sent first
            // messages concurrently, or the peer restarted). Deterministic
            // winner: the initiation from the lexicographically LOWER id.
            // We accept theirs only if they are the lower side; otherwise we
            // drop the frame and keep ours — they will adopt ours by the
            // same rule. Content lost here heals via delta sync (Task 8).
            Err(_) if vartalaap_crypto::ratchet::is_prekey(ciphertext) && peer < ctx.my_id => {
                let their_identity_key = {
                    let st = ctx.state.lock().unwrap();
                    st.bundles.get(&peer).map(|b| b.identity_key)
                }
                .ok_or_else(|| anyhow!("no bundle for peer; cannot accept session"))?;
                let (session, plaintext) = {
                    let mut acct = ctx.messaging.lock().unwrap();
                    RatchetSession::accept(&mut acct, their_identity_key, ciphertext)?
                };
                ctx.state.lock().unwrap().sessions.insert(peer, session);
                persist_msg_account(ctx);
                plaintext
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        // ... existing no-session accept path, plus persist_msg_account(ctx) ...
    };
```

(d) **Account persistence helper** (node.rs) + raw-bytes saver (persist.rs):

```rust
// node.rs
fn persist_msg_account(ctx: &Ctx) {
    let Some(engine) = &ctx.engine else { return };
    let bytes = ctx.messaging.lock().unwrap().to_pickle_json();
    if let Err(e) = engine.save_msg_account_bytes(&bytes) {
        let _ = ctx.events.send(EngineEvent::StorageWarning {
            detail: format!("failed to persist messaging account: {e}"),
        });
    }
}
```

```rust
// persist.rs, in impl Engine
    pub fn save_msg_account_bytes(&self, bytes: &[u8]) -> Result<(), CoreError> {
        Ok(self.store.put_secret(MSG_ACCOUNT_KEY, bytes)?)
    }
```

Call `persist_msg_account(&ctx)` in `setup_connection` right after `prekey_bundle()` (bundle generation consumes account randomness/one-time keys).

- [ ] **Step 7: Run the full suite (race test now passes; repeat it to shake out flake)**

Run: `cargo test --workspace && cargo test -p vartalaap-core concurrent_first_sends -- --test-threads=1` (run the race test 3 times)
Expected: PASS every run; clippy clean.

- [ ] **Step 8: Commit**

```bash
git add crates/vartalaap-core crates/vartalaap-crypto
git commit -m "fix(core): per-connection sessions with PreKey fallback and deterministic tie-break

Fixes silent message loss when both peers send first messages concurrently
or when one side restarts mid-session.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Post-connect profile exchange, real TOFU pins, contact events

**Files:**
- Modify: `crates/vartalaap-core/src/protocol.rs` (new `Payload::Profile`)
- Modify: `crates/vartalaap-core/src/node.rs`

**Interfaces:**
- Consumes: `send_payload_ctx`/`encrypt_for` (Task 6), `Contact` (Task 3), `Engine::signed_profile()` (Task 3).
- Produces:
  - `Payload::Profile(SignedProfile)` (import `vartalaap_identity::SignedProfile` in protocol.rs)
  - `State` field: `pending_post_connect: BTreeSet<PeerKey>`
  - `async fn post_connect(ctx: Arc<Ctx>, peer: PeerKey)` — sends the connect-time payload sequence; Task 8 extends it with announces + sync.
  - Events: `EngineEvent::ContactUpdated(PeerKey)`, `EngineEvent::PinWarning { peer: PeerKey, old_fingerprint: String, new_fingerprint: String }`
  - Node methods: `pub fn set_alias(&self, peer: PeerKey, alias: Option<String>)`, `pub fn remove_contact(&self, peer: PeerKey) -> Result<()>`, `pub fn accept_new_key(&self, peer: PeerKey)`
  - Initiator rule: in `setup_connection`, after registering the conn: if `ctx.my_id < peer` → `tokio::spawn(post_connect(ctx.clone(), peer))`; else insert `peer` into `pending_post_connect`. In `decrypt_payload`, after ANY successful session insert (both accept paths), remove `peer` from `pending_post_connect` and, if it was present, `tokio::spawn(post_connect(ctx.clone(), peer))`. `decrypt_payload` cannot spawn directly if it stays sync — return a flag or do the check in `handle_frame` after a successful decrypt: `maybe_flush_post_connect(ctx, peer)`:

    ```rust
    /// The higher-id side defers its post-connect sends until a session
    /// exists (the lower side initiates), then flushes exactly once.
    fn maybe_flush_post_connect(ctx: &Arc<Ctx>, peer: PeerKey) {
        let should = {
            let mut st = ctx.state.lock().unwrap();
            st.sessions.contains_key(&peer) && st.pending_post_connect.remove(&peer)
        };
        if should {
            let ctx = ctx.clone();
            tokio::spawn(async move { post_connect(ctx, peer).await });
        }
    }
    ```
    Call it in `handle_frame` at the top of the `Wire::Message` arm after `decrypt_payload` succeeds.

- [ ] **Step 1: Write the failing tests** (node.rs `mod tests`)

```rust
    /// Profiles propagate on connect; alias overrides the profile name; the
    /// messaging key is pinned on first contact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn profile_exchange_and_alias_precedence() -> Result<()> {
        let dir_a = tmp_data_dir("profile-a");
        let dir_b = tmp_data_dir("profile-b");
        let (alice, _arx) = Node::start_persistent(&dir_a, "pw").await?;
        alice.set_display_name("Asha".into())?;
        let (bob, mut brx) = Node::start_persistent(&dir_b, "pw").await?;
        let aid = alice.id();

        timeout(Duration::from_secs(20), bob.connect(aid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        // Wait until bob learns alice's profile.
        wait_for(&mut brx, |e| {
            matches!(e, EngineEvent::ContactUpdated(p) if *p == aid)
        })
        .await;

        let contact = bob
            .contacts()
            .into_iter()
            .find(|c| c.peer == aid)
            .expect("alice is a contact");
        assert_eq!(contact.display_name().as_deref(), Some("Asha"));
        assert!(contact.pinned_msg_key.is_some(), "first bundle key is pinned");

        bob.set_alias(aid, Some("roomie".into()));
        let contact = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_eq!(contact.display_name().as_deref(), Some("roomie"));

        alice.shutdown().await;
        bob.shutdown().await;
        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
        Ok(())
    }

    /// A peer reappearing with the same node id but a different messaging
    /// key (fresh in-memory account, same seed) triggers PinWarning, and
    /// accept_new_key() re-pins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn changed_messaging_key_raises_pin_warning() -> Result<()> {
        let (bob, mut brx) = Node::start([82u8; 32]).await?;
        let seed = [81u8; 32];
        let first_key = {
            let (alice, _arx) = Node::start(seed).await?;
            timeout(Duration::from_secs(20), bob.connect(alice.id()))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            wait_for(&mut brx, |e| {
                matches!(e, EngineEvent::PeerConnected(p) if *p == alice.id())
            })
            .await;
            let c = bob.contacts().into_iter().find(|c| c.peer == alice.id()).unwrap();
            alice.shutdown().await;
            c.pinned_msg_key.expect("pinned on first connect")
        };

        // Same identity seed → same PeerId, but a fresh MessagingAccount.
        let (alice2, _arx) = Node::start(seed).await?;
        let aid = alice2.id();
        timeout(Duration::from_secs(20), bob.connect(aid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        wait_for(&mut brx, |e| {
            matches!(e, EngineEvent::PinWarning { peer, .. } if *peer == aid)
        })
        .await;
        let c = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_eq!(c.pinned_msg_key, Some(first_key), "old pin kept until accepted");
        assert!(c.pending_msg_key.is_some());

        bob.accept_new_key(aid);
        let c = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_ne!(c.pinned_msg_key, Some(first_key), "accept re-pins");
        assert!(c.pending_msg_key.is_none());
        Ok(())
    }
```

Add the shared helper near the other test helpers:

```rust
    fn tmp_data_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-{tag}-{n}"));
        p
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p vartalaap-core profile_exchange changed_messaging_key`
Expected: FAIL to compile ("no variant `ContactUpdated`", "no method `set_alias`").

- [ ] **Step 3: Implement.**

(a) protocol.rs: add to `Payload`:

```rust
    /// The sender's signed profile, published on connect and on change.
    Profile(vartalaap_identity::SignedProfile),
```

(b) Events:

```rust
    /// A contact's stored data (profile/alias/pin/last-seen) changed.
    ContactUpdated(PeerKey),
    /// The peer's messaging key differs from the TOFU pin. Sending remains
    /// enabled; the new key takes effect only after accept_new_key().
    PinWarning { peer: PeerKey, old_fingerprint: String, new_fingerprint: String },
```

(c) Pinning in `setup_connection` (where the bundle is first registered) and in the `Wire::Hello` arm of `handle_frame` — extract a helper and call from both:

```rust
/// TOFU: pin the first-seen messaging key; flag any later change.
fn check_pin(ctx: &Arc<Ctx>, peer: PeerKey, bundle_identity_key: [u8; 32]) {
    let event = {
        let mut st = ctx.state.lock().unwrap();
        let Some(c) = st.contacts.get_mut(&peer) else { return };
        match c.pinned_msg_key {
            None => {
                c.pinned_msg_key = Some(bundle_identity_key);
                None
            }
            Some(pinned) if pinned == bundle_identity_key => {
                c.pending_msg_key = None;
                None
            }
            Some(pinned) => {
                c.pending_msg_key = Some(bundle_identity_key);
                Some(EngineEvent::PinWarning {
                    peer,
                    old_fingerprint: hex::encode(&pinned[..8]),
                    new_fingerprint: hex::encode(&bundle_identity_key[..8]),
                })
            }
        }
    };
    persist_contact(ctx, &peer);
    if let Some(e) = event {
        let _ = ctx.events.send(e);
    }
}
```

In `setup_connection`, call `check_pin(&ctx, peer, bundle.identity_key)` after the contact upsert (Task 5f). Note ordering: the contact must exist before `check_pin` runs. Add `hex = { workspace = true }` to core's dependencies if Task 3 didn't already.

(d) `post_connect` (first version — Task 8 extends):

```rust
/// Connect-time exchange. The lower-id side runs this immediately; the
/// higher-id side runs it once a session is established (initiator rule).
async fn post_connect(ctx: Arc<Ctx>, peer: PeerKey) {
    // 1) Publish our signed profile, if we have one.
    let signed = ctx.engine.as_ref().and_then(|e| e.signed_profile().ok().flatten());
    if let Some(signed) = signed {
        let _ = send_payload_ctx(&ctx, peer, &Payload::Profile(signed)).await;
    }
    // Task 8 appends: GroupAnnounce for shared groups + SyncHave frames.
}
```

In `setup_connection`, after `events.send(EngineEvent::PeerConnected(peer))`:

```rust
    if ctx.my_id < peer {
        let ctx2 = ctx.clone();
        tokio::spawn(async move { post_connect(ctx2, peer).await });
    } else {
        ctx.state.lock().unwrap().pending_post_connect.insert(peer);
    }
```

And `maybe_flush_post_connect` (from Interfaces above) called in `handle_frame`'s `Wire::Message` arm after a successful decrypt.

(e) `Payload::Profile` handler in `handle_frame`:

```rust
                Payload::Profile(signed) => {
                    let Ok((vid, profile)) = signed.verify() else { return };
                    // The profile must be signed by the connected peer itself.
                    if vid.to_bytes() != peer {
                        return;
                    }
                    let updated = {
                        let mut st = ctx.state.lock().unwrap();
                        let Some(c) = st.contacts.get_mut(&peer) else { return };
                        let newer = c
                            .profile
                            .as_ref()
                            .map(|p| profile.updated_at > p.updated_at)
                            .unwrap_or(true);
                        if newer {
                            c.profile = Some(profile.clone());
                        }
                        newer
                    };
                    if updated {
                        persist_contact(ctx, &peer);
                        let _ = ctx.events.send(EngineEvent::ContactUpdated(peer));
                    }
                }
```

(f) Node methods:

```rust
    /// Set or clear the local alias for a contact.
    pub fn set_alias(&self, peer: PeerKey, alias: Option<String>) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            if let Some(c) = st.contacts.get_mut(&peer) {
                c.alias = alias;
            } else {
                return;
            }
        }
        persist_contact(&self.ctx, &peer);
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
    }

    /// Forget a contact and its conversation (vault + memory).
    pub fn remove_contact(&self, peer: PeerKey) -> Result<()> {
        {
            let mut st = self.ctx.state.lock().unwrap();
            st.contacts.remove(&peer);
            st.conversations.remove(&peer);
        }
        if let Some(e) = &self.ctx.engine {
            e.delete_contact(&peer)?;
        }
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
        Ok(())
    }

    /// Accept a changed messaging key: promote pending → pinned.
    pub fn accept_new_key(&self, peer: PeerKey) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            if let Some(c) = st.contacts.get_mut(&peer) {
                if let Some(k) = c.pending_msg_key.take() {
                    c.pinned_msg_key = Some(k);
                }
            } else {
                return;
            }
        }
        persist_contact(&self.ctx, &peer);
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
    }
```

Also: `set_profile` pushes the fresh profile to every live connection (and `set_display_name` inherits this since it calls `set_profile`). In `Node::set_profile`, after the engine write succeeds:

```rust
        if let Some(engine) = &self.ctx.engine {
            if let Ok(Some(signed)) = engine.signed_profile() {
                let peers: Vec<PeerKey> = {
                    let st = self.ctx.state.lock().unwrap();
                    st.conns.keys().copied().collect()
                };
                let ctx = self.ctx.clone();
                tokio::spawn(async move {
                    for peer in peers {
                        let _ = send_payload_ctx(&ctx, peer, &Payload::Profile(signed.clone())).await;
                    }
                });
            }
        }
```

(g) Emit `ContactUpdated(peer)` from `setup_connection` when `is_new_contact` (Task 5f flag) and on every `last_seen` refresh in the disconnect path.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. The pin test relies on in-memory nodes keeping ephemeral accounts — that stays true (only persistent nodes load `msg_account`).

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): connect-time profile exchange, real TOFU pins, alias + contact events

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Group announce + CRDT delta sync (offline delivery)

**Files:**
- Modify: `crates/vartalaap-core/src/protocol.rs`
- Modify: `crates/vartalaap-core/src/node.rs`

**Interfaces:**
- Consumes: `post_connect` (Task 7), `Snapshot` pieces (`Message`, `Reaction`), `send_payload_ctx`.
- Produces:
  - protocol.rs:
    ```rust
    /// Which conversation a sync frame refers to.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub enum SyncScope {
        /// The 1:1 conversation between the two connected peers.
        Direct,
        Group(GroupId),
    }
    ```
    New `Payload` variants:
    ```rust
    /// A group this connection's peers share; heals members who were
    /// offline at creation time. Idempotent.
    GroupAnnounce(GroupInfo),
    /// The message ids the sender already holds for `scope`.
    SyncHave { scope: SyncScope, ids: Vec<vartalaap_sync::MessageId> },
    /// Everything the receiver was missing for `scope`.
    SyncDelta {
        scope: SyncScope,
        messages: Vec<Message>,
        reactions: Vec<vartalaap_sync::Reaction>,
        read: Vec<([u8; 32], u64)>,
    },
    ```
  - Event: `EngineEvent::HistorySynced { peer: PeerKey, scope: SyncScope, added: usize }` (`peer` = the connection the sync ran over; Task 11 needs it to route Direct-scope events)
  - `vartalaap-sync`: make `Reaction`'s fields already pub (they are) and add `pub fn reactions(&self) -> Vec<Reaction>` + `pub fn read_map(&self) -> Vec<(AuthorId, u64)>` accessors to `Conversation` (needed to build deltas; snapshot() also works but clones all messages — use `snapshot()` for simplicity: delta building below uses `have()`/`delta_since()` for messages and `snapshot()` for reactions/read).
- Rules: `GroupAnnounce`/`GroupMessage`/group-scoped sync frames are honored only if the sender AND we are members. `SyncHave` is answered with `SyncDelta` (always — the read watermarks ride along even when no messages are missing). Applying a delta emits ONE `HistorySynced`, not per-message `MessageReceived`.

- [ ] **Step 1: Write the failing tests** (node.rs `mod tests`)

```rust
    /// A text sent while the peer's node was down is delivered by delta sync
    /// when the peer comes back — the CRDT is the outbox.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offline_message_heals_on_reconnect() -> Result<()> {
        let seed_b = [92u8; 32];
        let (alice, mut arx) = Node::start([91u8; 32]).await?;
        let bid = {
            let (bob, mut brx) = Node::start(seed_b).await?;
            let bid = bob.id();
            timeout(Duration::from_secs(20), alice.connect(bid))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            alice.send_text(bid, "seen live").await?;
            wait_message(&mut brx).await;
            bob.shutdown().await;
            // Wait until alice notices the disconnect.
            wait_for(&mut arx, |e| {
                matches!(e, EngineEvent::PeerDisconnected(p) if *p == bid)
            })
            .await;
            bid
        };

        // Peer is gone: author a message into the local replica. This task
        // introduces queue_local_text for exactly this; Task 9 folds it into
        // send_text (and rewrites this line — see Task 9 step 3b).
        alice.queue_local_text(bid, "while you were out")?;

        // Bob restarts with the same identity and reconnects.
        let (bob2, mut brx2) = Node::start(seed_b).await?;
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("reconnect timed out"))??;
        // Delta sync delivers the missed message.
        timeout(Duration::from_secs(20), async {
            loop {
                match brx2.recv().await {
                    Some(EngineEvent::HistorySynced { .. }) | Some(EngineEvent::MessageReceived { .. }) => {
                        if bob2
                            .conversation_bodies(&alice.id())
                            .contains(&"while you were out".to_string())
                        {
                            break;
                        }
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("sync never delivered the offline message"))?;
        // And bob's copy of the LIVE message also survived his restart? No —
        // bob2 is in-memory; what matters is the offline message arrived and
        // both replicas converge for it.
        assert!(bob2
            .conversation_bodies(&alice.id())
            .contains(&"while you were out".to_string()));
        Ok(())
    }

    /// A group created while a member was offline reaches them via ANY
    /// member (announce + delta ride every connection).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn group_heals_transitively_for_offline_member() -> Result<()> {
        let seed_c = [95u8; 32];
        let (alice, _arx) = Node::start([93u8; 32]).await?;
        let (bob, mut brx) = Node::start([94u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());
        let cid = {
            let (carol, _crx) = Node::start(seed_c).await?;
            let cid = carol.id();
            carol.shutdown().await; // carol is offline from the start
            cid
        };

        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("a-b timeout"))??;
        // Group created while carol is offline; only bob gets the invite.
        let gid = alice.create_group("study".into(), vec![bid, cid]).await?;
        wait_for(&mut brx, |e| matches!(e, EngineEvent::GroupInvited(g) if *g == gid)).await;
        alice.send_group_text(gid, "carol missed this").await?;
        wait_for(&mut brx, |e| {
            matches!(e, EngineEvent::GroupMessageReceived { group, .. } if *group == gid)
        })
        .await;

        // Carol returns and connects to BOB (not the creator).
        let (carol2, mut crx2) = Node::start(seed_c).await?;
        timeout(Duration::from_secs(20), carol2.connect(bid))
            .await
            .map_err(|_| anyhow!("c-b timeout"))??;
        timeout(Duration::from_secs(20), async {
            loop {
                match crx2.recv().await {
                    Some(EngineEvent::GroupInvited(g)) if g == gid => {}
                    Some(EngineEvent::HistorySynced { .. })
                    | Some(EngineEvent::GroupMessageReceived { .. }) => {
                        if carol2.group_conversation(&gid).len() == 1 {
                            break;
                        }
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("group never healed for carol"))?;
        assert_eq!(carol2.groups().len(), 1);
        assert_eq!(carol2.group_conversation(&gid)[0].body, "carol missed this");
        let _ = aid;
        Ok(())
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p vartalaap-core offline_message_heals group_heals`
Expected: FAIL to compile ("no method `queue_local_text`", "no variant `HistorySynced`").

- [ ] **Step 3: Implement.**

(a) protocol.rs: `SyncScope` + the three `Payload` variants exactly as in Interfaces.

(b) node.rs — interim local-authoring API (Task 9 folds it into `send_text`):

```rust
    /// Record a text in the local replica without requiring a connection.
    /// Delivery happens via delta sync on the next connect (Task 9 makes
    /// send_text call this automatically when the peer is unreachable).
    pub fn queue_local_text(&self, peer: PeerKey, body: &str) -> Result<Message> {
        let now = now_millis();
        let message = {
            let mut st = self.ctx.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .create_text(self.id, now, body)
        };
        persist_convo(&self.ctx, &peer);
        Ok(message)
    }
```

(c) Extend `post_connect` (after the profile step):

```rust
    // 2) Announce shared groups + offer sync for every shared scope.
    let (announces, haves) = {
        let st = ctx.state.lock().unwrap();
        let announces: Vec<GroupInfo> = st
            .groups
            .values()
            .filter(|g| g.members.contains(&peer))
            .cloned()
            .collect();
        let mut haves: Vec<(SyncScope, Vec<vartalaap_sync::MessageId>)> = Vec::new();
        let direct_have = st
            .conversations
            .get(&peer)
            .map(|c| c.have().into_iter().collect())
            .unwrap_or_default();
        haves.push((SyncScope::Direct, direct_have));
        for g in &announces {
            let ids = st
                .group_convos
                .get(&g.id)
                .map(|c| c.have().into_iter().collect())
                .unwrap_or_default();
            haves.push((SyncScope::Group(g.id), ids));
        }
        (announces, haves)
    };
    for g in announces {
        let _ = send_payload_ctx(&ctx, peer, &Payload::GroupAnnounce(g)).await;
    }
    for (scope, ids) in haves {
        let _ = send_payload_ctx(&ctx, peer, &Payload::SyncHave { scope, ids }).await;
    }
```

(d) `handle_frame` new arms (inside the decrypted `Payload` match; each spawns for async sends since handle_frame stays sync):

```rust
                Payload::GroupAnnounce(info) => {
                    // Only meaningful if the sender and we are both members.
                    if !info.members.contains(&peer) || !info.members.contains(&ctx.my_id) {
                        return;
                    }
                    let id = info.id;
                    let inserted = {
                        let mut st = ctx.state.lock().unwrap();
                        let fresh = !st.groups.contains_key(&id);
                        st.groups.entry(id).or_insert(info);
                        st.group_convos.entry(id).or_default();
                        fresh
                    };
                    if inserted {
                        persist_group(ctx, &id);
                        persist_group_convo(ctx, &id);
                        let _ = ctx.events.send(EngineEvent::GroupInvited(id));
                        // We just learned this group exists, so our
                        // post_connect sent no SyncHave for it. Offer one now
                        // so the announcer backfills us — without this, a
                        // late-joining member never receives missed history.
                        offer_group_sync(ctx, peer, id);
                    }
                }
                Payload::SyncHave { scope, ids } => {
                    if let Some(delta) = build_delta(ctx, peer, scope, &ids) {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            let _ = send_payload_ctx(&ctx2, peer, &delta).await;
                        });
                    }
                }
                Payload::SyncDelta { scope, messages, reactions, read } => {
                    apply_delta(ctx, peer, scope, messages, reactions, read);
                }
```

Apply the same `offer_group_sync(ctx, peer, id)` call in the existing `Payload::GroupInvite` arm when the group is newly inserted (a live invite can also arrive after messages we missed).

```rust
/// Send a SyncHave for one group scope (used when we learn a group exists
/// mid-connection, after post_connect already ran).
fn offer_group_sync(ctx: &Arc<Ctx>, peer: PeerKey, gid: GroupId) {
    let ids: Vec<vartalaap_sync::MessageId> = {
        let st = ctx.state.lock().unwrap();
        st.group_convos
            .get(&gid)
            .map(|c| c.have().into_iter().collect())
            .unwrap_or_default()
    };
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let _ = send_payload_ctx(&ctx2, peer, &Payload::SyncHave { scope: SyncScope::Group(gid), ids }).await;
    });
}
```

(e) The two sync helpers:

```rust
/// Answer a peer's have-list with everything they're missing in `scope`.
/// Returns None only when the scope is invalid (unknown/forbidden group).
fn build_delta(
    ctx: &Arc<Ctx>,
    peer: PeerKey,
    scope: SyncScope,
    their_ids: &[vartalaap_sync::MessageId],
) -> Option<Payload> {
    let have: std::collections::BTreeSet<_> = their_ids.iter().copied().collect();
    let st = ctx.state.lock().unwrap();
    let convo = match scope {
        SyncScope::Direct => st.conversations.get(&peer),
        SyncScope::Group(gid) => {
            let g = st.groups.get(&gid)?;
            // Membership gate: never leak a group convo to a non-member.
            if !g.members.contains(&peer) || !g.members.contains(&ctx.my_id) {
                return None;
            }
            st.group_convos.get(&gid)
        }
    }?;
    let snap = convo.snapshot();
    Some(Payload::SyncDelta {
        scope,
        messages: convo.delta_since(&have),
        reactions: snap.reactions,
        read: snap.read,
    })
}

/// Merge a received delta into the right conversation; one event per delta.
fn apply_delta(
    ctx: &Arc<Ctx>,
    peer: PeerKey,
    scope: SyncScope,
    messages: Vec<Message>,
    reactions: Vec<vartalaap_sync::Reaction>,
    read: Vec<([u8; 32], u64)>,
) {
    let added = {
        let mut st = ctx.state.lock().unwrap();
        let convo = match scope {
            SyncScope::Direct => st.conversations.entry(peer).or_default(),
            SyncScope::Group(gid) => {
                let Some(g) = st.groups.get(&gid) else { return };
                if !g.members.contains(&peer) || !g.members.contains(&ctx.my_id) {
                    return;
                }
                st.group_convos.entry(gid).or_default()
            }
        };
        let before = convo.len();
        for m in messages {
            convo.apply(m);
        }
        for r in reactions {
            convo.react(r.message, r.author, r.emoji);
        }
        for (author, lamport) in read {
            convo.mark_read(author, lamport);
        }
        convo.len() - before
    };
    match scope {
        SyncScope::Direct => persist_convo(ctx, &peer),
        SyncScope::Group(gid) => persist_group_convo(ctx, &gid),
    }
    let _ = ctx.events.send(EngineEvent::HistorySynced { peer, scope, added });
}
```

(f) Event variant:

```rust
    /// A delta sync with `peer` merged `added` missing messages for `scope`.
    HistorySynced { peer: PeerKey, scope: SyncScope, added: usize },
```

Import `SyncScope` in node.rs (`use crate::protocol::SyncScope;`) and re-export: `pub use crate::protocol::SyncScope;`.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, including both new heal tests and everything from Tasks 1–7.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): connect-time CRDT delta sync and group announce — offline messages heal

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Queued sends, auto-connect, delivery status

**Files:**
- Modify: `crates/vartalaap-core/src/protocol.rs` (DeliveryStatus)
- Modify: `crates/vartalaap-core/src/node.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - protocol.rs:
    ```rust
    /// Lifecycle of an own message, as far as we can honestly know it.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub enum DeliveryStatus {
        /// Recorded locally; the peer was unreachable at send time.
        Queued,
        /// Written to a live connection without error.
        Sent,
        /// The peer confirmed holding it (their SyncHave contains the id, or
        /// their read watermark reached its lamport).
        Delivered,
    }
    ```
  - `State` fields: `peer_have: HashMap<PeerKey, BTreeSet<MessageId>>` (session-learned; repopulated by every SyncHave), `queued: HashMap<PeerKey, BTreeSet<MessageId>>` (session-transient).
  - Event: `EngineEvent::MessageStatus { peer: PeerKey, id: MessageId, status: DeliveryStatus }`
  - Node: `send_text` signature changes to `pub async fn send_text(&self, peer: PeerKey, body: &str) -> Result<(Message, DeliveryStatus)>`; `pub fn conversation_with_status(&self, peer: &PeerKey) -> Vec<(Message, Option<DeliveryStatus>)>` (status `Some` only for own messages); `pub fn nearby(&self) -> Vec<PeerKey>` (discovered minus contacts); `send_group_text` queues for the group (no per-member dial) and returns `Result<Message>`.
  - Behavior: `send_text` tries the existing conn; if none, ONE dial attempt with a 3-second timeout; if that fails → record + `Queued`. Discovery loop auto-dials discovered **contacts** that have no live conn. On receiving `Payload::SyncHave` from a peer, update `peer_have`, drop those ids from `queued`, and emit `MessageStatus { status: Delivered }` for each own message newly covered. On receiving `Wire::Read`, emit `Delivered` for own messages whose lamport is newly ≤ watermark. `MessageKind::File` sends still require a live connection (file bytes can't queue): keep the current error when no conn and the dial fails.
  - Delivered rule (single source of truth, used by both the event emission and `conversation_with_status`):
    ```rust
    fn delivered(st: &State, peer: &PeerKey, m: &Message) -> bool {
        st.peer_have.get(peer).is_some_and(|h| h.contains(&m.id))
            || st
                .conversations
                .get(peer)
                .is_some_and(|c| c.read_watermark(peer) >= m.lamport)
    }
    ```

- [ ] **Step 1: Write the failing test** (node.rs `mod tests`)

```rust
    /// send_text to an unreachable peer queues instead of erroring, and the
    /// message transitions to Delivered once the peer syncs it down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queued_send_transitions_to_delivered() -> Result<()> {
        let seed_b = [102u8; 32];
        let (alice, mut arx) = Node::start([101u8; 32]).await?;
        let bid = {
            let (bob, _brx) = Node::start(seed_b).await?;
            let bid = bob.id();
            timeout(Duration::from_secs(20), alice.connect(bid))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            bob.shutdown().await;
            wait_for(&mut arx, |e| {
                matches!(e, EngineEvent::PeerDisconnected(p) if *p == bid)
            })
            .await;
            bid
        };

        // Unreachable → queued, not an error.
        let (msg, status) = alice.send_text(bid, "catch up later").await?;
        assert_eq!(status, DeliveryStatus::Queued);
        let statuses = alice.conversation_with_status(&bid);
        assert_eq!(statuses.last().unwrap().1, Some(DeliveryStatus::Queued));

        // Bob returns; alice reconnects; sync delivers; status flips.
        let (bob2, _brx2) = Node::start(seed_b).await?;
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("reconnect timed out"))??;
        wait_for(&mut arx, |e| {
            matches!(e, EngineEvent::MessageStatus { id, status: DeliveryStatus::Delivered, .. } if *id == msg.id)
        })
        .await;
        assert!(bob2
            .conversation_bodies(&alice.id())
            .contains(&"catch up later".to_string()));
        Ok(())
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p vartalaap-core queued_send_transitions`
Expected: FAIL to compile (send_text returns `()`; no `DeliveryStatus`).

- [ ] **Step 3: Implement.**

(a) `DeliveryStatus` in protocol.rs (as in Interfaces), re-export from node.rs, plus the `MessageStatus` event variant.

(b) Rewrite `send_text`:

```rust
    /// Send a text: deliver on a live connection when possible (one dial
    /// attempt if needed), otherwise record locally as Queued — the message
    /// heals over via delta sync on the next connect.
    pub async fn send_text(&self, peer: PeerKey, body: &str) -> Result<(Message, DeliveryStatus)> {
        let conn = self.live_or_dialed_conn(peer).await;

        let message = {
            let mut st = self.ctx.state.lock().unwrap();
            let m = st
                .conversations
                .entry(peer)
                .or_default()
                .create_text(self.id, now_millis(), body);
            if conn.is_none() {
                st.queued.entry(peer).or_default().insert(m.id);
            }
            m
        };
        persist_convo(&self.ctx, &peer);

        let status = match conn {
            None => DeliveryStatus::Queued,
            Some(conn) => {
                let plaintext = serde_json::to_vec(&Payload::Chat(message.clone()))?;
                match encrypt_for(&self.ctx, peer, &plaintext) {
                    Ok(ciphertext) => {
                        let frame = serde_json::to_vec(&Wire::Message { ciphertext })?;
                        if conn.send_frame(&frame).await.is_ok() {
                            DeliveryStatus::Sent
                        } else {
                            self.ctx.state.lock().unwrap().queued.entry(peer).or_default().insert(message.id);
                            DeliveryStatus::Queued
                        }
                    }
                    Err(_) => {
                        self.ctx.state.lock().unwrap().queued.entry(peer).or_default().insert(message.id);
                        DeliveryStatus::Queued
                    }
                }
            }
        };
        let _ = self.ctx.events.send(EngineEvent::MessageStatus {
            peer,
            id: message.id,
            status,
        });
        Ok((message, status))
    }

    /// The registered live connection, or the result of one bounded dial.
    async fn live_or_dialed_conn(&self, peer: PeerKey) -> Option<Conn> {
        if let Some(c) = self.ctx.state.lock().unwrap().conns.get(&peer).cloned() {
            return Some(c);
        }
        let dial = tokio::time::timeout(Duration::from_secs(3), self.connect(peer)).await;
        match dial {
            Ok(Ok(())) => self.ctx.state.lock().unwrap().conns.get(&peer).cloned(),
            _ => None,
        }
    }
```

Add `use std::time::Duration;` and `use crate::protocol::DeliveryStatus;`. Delete `queue_local_text` (Task 8's interim API) and update the Task 8 test to use the new `send_text` (it now queues): replace `alice.queue_local_text(bid, "while you were out")?;` with `let (_m, s) = alice.send_text(bid, "while you were out").await?; assert_eq!(s, DeliveryStatus::Queued);`.

(c) `send_group_text`: keep current shape (fan out to reachable members via `send_payload_ctx`, skip unreachable silently — sync heals them; that's now by-design, add the comment), no dialing loop.

(d) `conversation_with_status`:

```rust
    /// Ordered messages plus, for own messages, the honest delivery status.
    pub fn conversation_with_status(
        &self,
        peer: &PeerKey,
    ) -> Vec<(Message, Option<DeliveryStatus>)> {
        let st = self.ctx.state.lock().unwrap();
        let Some(conv) = st.conversations.get(peer) else {
            return Vec::new();
        };
        conv.messages_ordered()
            .into_iter()
            .map(|m| {
                let status = if m.author == self.id {
                    Some(if delivered(&st, peer, m) {
                        DeliveryStatus::Delivered
                    } else if st.queued.get(peer).is_some_and(|q| q.contains(&m.id)) {
                        DeliveryStatus::Queued
                    } else {
                        DeliveryStatus::Sent
                    })
                } else {
                    None
                };
                (m.clone(), status)
            })
            .collect()
    }

    /// mDNS-visible peers that are NOT yet contacts (the "Nearby" list).
    pub fn nearby(&self) -> Vec<PeerKey> {
        let st = self.ctx.state.lock().unwrap();
        st.discovered
            .iter()
            .filter(|p| !st.contacts.contains_key(*p))
            .copied()
            .collect()
    }
```

(e) In the `Payload::SyncHave` handler (Task 8d), BEFORE building the delta, absorb the peer's have-set (Direct scope only — group delivery per-member is out of scope):

```rust
                Payload::SyncHave { scope, ids } => {
                    if matches!(scope, SyncScope::Direct) {
                        absorb_peer_have(ctx, peer, &ids);
                    }
                    // ... existing build_delta + spawn reply ...
                }
```

```rust
/// Learn what the peer holds; flip newly-covered own messages to Delivered.
fn absorb_peer_have(ctx: &Arc<Ctx>, peer: PeerKey, ids: &[vartalaap_sync::MessageId]) {
    let newly_delivered: Vec<vartalaap_sync::MessageId> = {
        let mut st = ctx.state.lock().unwrap();
        let have = st.peer_have.entry(peer).or_default();
        let fresh: Vec<_> = ids.iter().filter(|i| !have.contains(*i)).copied().collect();
        have.extend(ids.iter().copied());
        if let Some(q) = st.queued.get_mut(&peer) {
            for i in ids {
                q.remove(i);
            }
        }
        let mine: std::collections::BTreeSet<_> = st
            .conversations
            .get(&peer)
            .map(|c| {
                c.messages_ordered()
                    .into_iter()
                    .filter(|m| m.author == ctx.my_id)
                    .map(|m| m.id)
                    .collect()
            })
            .unwrap_or_default();
        fresh.into_iter().filter(|i| mine.contains(i)).collect()
    };
    for id in newly_delivered {
        let _ = ctx.events.send(EngineEvent::MessageStatus {
            peer,
            id,
            status: DeliveryStatus::Delivered,
        });
    }
}
```

(f) In the `Wire::Read` arm, after the existing `mark_read` bookkeeping:

```rust
            let newly_delivered: Vec<vartalaap_sync::MessageId> = {
                let mut st = ctx.state.lock().unwrap();
                let mine: Vec<_> = st
                    .conversations
                    .get(&peer)
                    .map(|c| {
                        c.messages_ordered()
                            .into_iter()
                            .filter(|m| m.author == ctx.my_id && m.lamport <= up_to)
                            .map(|m| m.id)
                            .collect()
                    })
                    .unwrap_or_default();
                let have = st.peer_have.entry(peer).or_default();
                let fresh: Vec<_> = mine.into_iter().filter(|i| !have.contains(i)).collect();
                have.extend(fresh.iter().copied());
                if let Some(q) = st.queued.get_mut(&peer) {
                    for i in &fresh {
                        q.remove(i);
                    }
                }
                fresh
            };
            for id in newly_delivered {
                let _ = ctx.events.send(EngineEvent::MessageStatus {
                    peer,
                    id,
                    status: DeliveryStatus::Delivered,
                });
            }
```

(g) Auto-dial contacts in the discovery loop — inside the `PeerEvent::Discovered` arm, after the `is_new` insert (ctx is available there after Task 5's refactor):

```rust
                            if is_new {
                                let _ = events.send(EngineEvent::PeerDiscovered(key));
                                // Known contact with no live conn → dial so
                                // queued messages and history sync promptly.
                                let should_dial = {
                                    let st = ctx.state.lock().unwrap();
                                    st.contacts.contains_key(&key) && !st.conns.contains_key(&key)
                                };
                                if should_dial {
                                    let ctx2 = ctx.clone();
                                    tokio::spawn(async move {
                                        if let Ok(pid) = peer_id_from_bytes(key) {
                                            if let Ok(conn) = ctx2.transport.connect_by_id(pid).await {
                                                let _ = setup_connection(conn, ctx2.clone()).await;
                                            }
                                        }
                                    });
                                }
                            }
```

(h) Update `send_file`: use `live_or_dialed_conn`; if still `None`, keep the existing hard error (`file transfers need a live peer`).

(i) The Tauri bridge's `send` command call site changes in Task 11 (send_text's return type changed — fix `examples/two_node_chat.rs` too: `let _ = alice.send_text(...).await?;` pattern-match the tuple).

- [ ] **Step 4: Run the full suite**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (including the reworked Task 8 offline test and the new status test). The example must also compile: `cargo build --workspace --examples`.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): queued offline sends, contact auto-connect, honest delivery status

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: Read/unread wiring

**Files:**
- Modify: `crates/vartalaap-core/src/node.rs`

**Interfaces:**
- Consumes: conversations + watermarks (existing `mark_read`), persistence helpers.
- Produces (Node methods; Tauri exposes them in Task 11):
  - `pub async fn mark_read_direct(&self, peer: PeerKey)` — set own watermark to the convo's max lamport, persist, best-effort `Wire::Read` to a live conn (no error when offline).
  - `pub fn mark_read_group(&self, gid: GroupId)` — local watermark + persist (propagates via SyncDelta.read).
  - `pub fn unread_direct(&self, peer: &PeerKey) -> usize`, `pub fn unread_group(&self, gid: &GroupId) -> usize` — messages authored by others with `lamport >` own watermark.

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unread_counts_and_mark_read() -> Result<()> {
        let (alice, _arx) = Node::start([111u8; 32]).await?;
        let (bob, mut brx) = Node::start([112u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        alice.send_text(bid, "one").await?;
        alice.send_text(bid, "two").await?;
        wait_message(&mut brx).await;
        wait_message(&mut brx).await;

        assert_eq!(bob.unread_direct(&aid), 2);
        assert_eq!(alice.unread_direct(&bid), 0, "own messages are not unread");
        bob.mark_read_direct(aid).await;
        assert_eq!(bob.unread_direct(&aid), 0);
        Ok(())
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p vartalaap-core unread_counts`
Expected: FAIL to compile ("no method named `unread_direct`").

- [ ] **Step 3: Implement**

```rust
    /// Unread = messages from others above our own read watermark.
    pub fn unread_direct(&self, peer: &PeerKey) -> usize {
        let st = self.ctx.state.lock().unwrap();
        let Some(c) = st.conversations.get(peer) else { return 0 };
        let mine = c.read_watermark(&self.id);
        c.messages_ordered()
            .iter()
            .filter(|m| m.author != self.id && m.lamport > mine)
            .count()
    }

    pub fn unread_group(&self, gid: &GroupId) -> usize {
        let st = self.ctx.state.lock().unwrap();
        let Some(c) = st.group_convos.get(gid) else { return 0 };
        let mine = c.read_watermark(&self.id);
        c.messages_ordered()
            .iter()
            .filter(|m| m.author != self.id && m.lamport > mine)
            .count()
    }

    /// Mark the whole 1:1 conversation read; tell the peer if reachable.
    pub async fn mark_read_direct(&self, peer: PeerKey) {
        let up_to = {
            let mut st = self.ctx.state.lock().unwrap();
            let Some(c) = st.conversations.get_mut(&peer) else { return };
            let max = c.messages_ordered().last().map(|m| m.lamport).unwrap_or(0);
            let me = self.id;
            c.mark_read(me, max);
            max
        };
        persist_convo(&self.ctx, &peer);
        let _ = self.send_to(peer, &Wire::Read { up_to }).await; // best-effort
    }

    /// Mark a group conversation read locally (spreads via delta sync).
    pub fn mark_read_group(&self, gid: GroupId) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            let Some(c) = st.group_convos.get_mut(&gid) else { return };
            let max = c.messages_ordered().last().map(|m| m.lamport).unwrap_or(0);
            let me = self.id;
            c.mark_read(me, max);
        }
        persist_group_convo(&self.ctx, &gid);
    }
```

(The pre-existing `pub async fn mark_read(&self, peer, up_to)` stays for wire-level use.)

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): unread counts and mark-read for direct and group conversations

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 11: Tauri bridge — commands, DTOs, events

**Files:**
- Modify: `app/src-tauri/src/lib.rs`
- Modify: `crates/vartalaap-core/src/node.rs` (one small addition: `connected_peers()`)

**Interfaces:**
- Consumes: every Node method above.
- Produces (TypeScript-facing; Task 12 consumes these EXACT shapes):
  - DTOs:
    ```rust
    #[derive(Serialize)]
    struct ContactDto { id: String, name: String, online: bool, last_seen: u64, unread: usize, pin_pending: bool }
    #[derive(Serialize)]
    struct NearbyDto { id: String }
    ```
    `MessageDto` gains `status: Option<String>` (`"queued" | "sent" | "delivered"`, own messages only).
  - Commands (registered in `invoke_handler`): `list_contacts() -> Vec<ContactDto>`, `list_nearby() -> Vec<NearbyDto>`, `set_alias(peer: String, alias: Option<String>)`, `remove_contact(peer: String)`, `accept_new_key(peer: String)`, `mark_read(kind: String, id: String)` (`kind` ∈ `"peer" | "group"`), and `send` now returns `Result<MessageDto, String>`.
  - `emit_event` arms for:
    - `StorageWarning → {kind:"storage_warning", detail}`
    - `ContactUpdated → {kind:"contact_updated", id: hexkey(peer)}`
    - `PinWarning → {kind:"pin_warning", id: hexkey(peer), old, new}`
    - `HistorySynced → {kind:"history_synced", scope:"peer"|"group", id, added}` where for `SyncScope::Direct` → `scope:"peer", id: hexkey(peer)` and for `SyncScope::Group(gid)` → `scope:"group", id: hex(gid)`
    - `MessageStatus → {kind:"message_status", peer: hexkey(peer), id: hex(message id), status:"queued"|"sent"|"delivered"}`
  - Name resolution for `ContactDto.name`: `contact.display_name()` else first 8 chars of `VartalaapId::from_bytes(peer).fingerprint()` else hex prefix.

- [ ] **Step 1: Implement the DTOs, commands, and event arms.** Follow the existing command style (`state: State<'_, NodeState>`, hex ↔ key helpers `hexkey`/`parse_key` already in the file). `list_contacts`:

```rust
#[tauri::command]
fn list_contacts(state: State<'_, NodeState>) -> Vec<ContactDto> {
    let node = &state.node;
    let online: std::collections::HashSet<String> = node
        .connected_peers()
        .into_iter()
        .map(|p| hexkey(&p))
        .collect();
    node.contacts()
        .into_iter()
        .map(|c| {
            let name = c.display_name().unwrap_or_else(|| {
                vartalaap_identity::VartalaapId::from_bytes(c.peer)
                    .map(|v| v.fingerprint().chars().take(8).collect())
                    .unwrap_or_else(|_| hexkey(&c.peer).chars().take(8).collect())
            });
            ContactDto {
                id: hexkey(&c.peer),
                name,
                online: online.contains(&hexkey(&c.peer)),
                last_seen: c.last_seen,
                unread: node.unread_direct(&c.peer),
                pin_pending: c.pending_msg_key.is_some(),
            }
        })
        .collect()
}
```

This needs one more tiny Node method (add to node.rs in this task):

```rust
    /// Peers with a live registered connection.
    pub fn connected_peers(&self) -> Vec<PeerKey> {
        self.ctx.state.lock().unwrap().conns.keys().copied().collect()
    }
```

`send` (replacing the current body):

```rust
#[tauri::command]
async fn send(peer: String, body: String, state: State<'_, NodeState>) -> Result<MessageDto, String> {
    let key = parse_key(&peer)?;
    let (message, status) = state.node.send_text(key, &body).await.map_err(|e| e.to_string())?;
    Ok(message_dto(&message, true, Some(status), &state.node))
}
```

(Adapt to the existing `MessageDto` construction helper; if none exists, write `fn message_dto(...)` once and use it in `history`/`group_history`/`send`.) `history` uses `conversation_with_status` and maps `DeliveryStatus` to the lowercase strings; `group_history` passes `status: None`.

`mark_read`:

```rust
#[tauri::command]
async fn mark_read(kind: String, id: String, state: State<'_, NodeState>) -> Result<(), String> {
    match kind.as_str() {
        "peer" => {
            let key = parse_key(&id)?;
            state.node.mark_read_direct(key).await;
            Ok(())
        }
        "group" => {
            // Parse the 16-byte group id the same way group_history already
            // parses its `group` argument — reuse that exact helper/inline code.
            let gid = parse_group_id(&id)?;
            state.node.mark_read_group(gid);
            Ok(())
        }
        _ => Err("kind must be 'peer' or 'group'".into()),
    }
}
```

`set_alias`, `remove_contact`, `accept_new_key`, `list_nearby` are one-liners over the Node methods. Register ALL new commands in `generate_handler![...]`. Keep `list_peers` registered (the old UI path) — Task 12 deletes it together with its caller.

- [ ] **Step 2: Verify it compiles + clippy** (the app crate is a separate workspace)

Run: `cd app/src-tauri && cargo clippy --all-targets -- -D warnings && cd ../..`
Expected: clean. (No UI tests exist; the compile + Task 12's build are the gate.)

- [ ] **Step 3: Commit**

```bash
git add app/src-tauri crates/vartalaap-core
git commit -m "feat(app): roster/read/status Tauri commands and engine event bridging

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 12: Frontend — roster sidebar, status glyphs, banners, read wiring

**Files:**
- Modify: `app/src/App.tsx`
- Modify: `app/src/App.css` (or the existing stylesheet — check the import at the top of App.tsx)
- Modify: `app/src-tauri/src/lib.rs` (delete the now-unused `list_peers` command + `PeerDto`)

**Interfaces:**
- Consumes: Task 11 commands/DTOs/events, exactly as specified there.
- Produces: the user-visible feature. No new frontend dependencies.

Implementation checklist (single task, several commits are fine at the marked points):

- [ ] **Step 1: Types + state.** Replace `type Peer` with:

```ts
type Contact = { id: string; name: string; online: boolean; last_seen: number; unread: number; pin_pending: boolean };
type Nearby = { id: string };
type Message = {
  id: string;
  author: string;
  body: string;
  sent_at: number;
  mine: boolean;
  file: FileInfo | null;
  status: "queued" | "sent" | "delivered" | null;
};
type Banner = { kind: "error" | "warn"; text: string; peer?: string };
```

State: `const [contacts, setContacts] = useState<Contact[]>([])`, `const [nearby, setNearby] = useState<Nearby[]>([])`, `const [banners, setBanners] = useState<Banner[]>([])`. Delete `connectedRef` entirely — `online` now comes from the backend.

- [ ] **Step 2: Data flow.** `refreshRoster` invokes `list_contacts` + `list_nearby` and replaces both lists; call it on mount, on a 4000 ms interval (replacing the `refreshPeers` poll), and on these events: `contact_updated`, `peer_connected`, `peer_disconnected`, `peer_discovered`. Event switch additions:

```ts
        case "history_synced":
          refreshRoster();
          if (
            selectedRef.current &&
            ((p.scope === "peer" && selectedRef.current.kind === "peer" && selectedRef.current.id === p.id) ||
              (p.scope === "group" && selectedRef.current.kind === "group" && selectedRef.current.id === p.id))
          )
            loadHistory(selectedRef.current);
          break;
        case "message_status":
          setMessages((prev) => prev.map((m) => (m.id === p.id ? { ...m, status: p.status } : m)));
          break;
        case "storage_warning":
          pushBanner({ kind: "warn", text: p.detail });
          break;
        case "pin_warning":
          pushBanner({ kind: "warn", text: `Identity changed for this contact (was ${p.old}, now ${p.new}). Accept only if you trust it.`, peer: p.id });
          refreshRoster();
          break;
```

(`selectedRef` mirrors `selected` via a ref so the listener closure stays fresh — same pattern the file already uses for `connectedRef`/`meRef`.) `pushBanner` appends with de-dup; banners render at the top of the conversation pane with a dismiss ×; a `pin_warning` banner for the selected peer additionally renders an "Accept new identity" button calling `invoke("accept_new_key", { peer })`.

- [ ] **Step 3: Sidebar rendering.** Two sections + groups:

```tsx
      <div className="section-label">Contacts</div>
      {/* const isSelected = (k: string, i: string) => selected?.kind === k && selected?.id === i; */}
      {contacts.map((c) => (
        <div key={c.id} className={`peer ${isSelected("peer", c.id) ? "sel" : ""}`} onClick={() => selectPeer(c.id)}>
          <span className={`dot ${c.online ? "on" : ""}`} />
          <span className="peer-name">{c.name}</span>
          {c.pin_pending && <span className="pin-flag" title="identity changed">⚠</span>}
          {c.unread > 0 && <span className="unread">{c.unread}</span>}
        </div>
      ))}
      <div className="section-label">Nearby</div>
      {nearby.map((n) => (
        <div key={n.id} className="peer" onClick={() => connectNearby(n.id)}>
          <span className="dot on" />
          <span className="peer-name">{n.id.slice(0, 8)}…</span>
          <span className="hint">tap to connect</span>
        </div>
      ))}
```

`connectNearby(id)` = `invoke("connect", { id })` then `refreshRoster()` (handshake promotes it to a contact). `selectPeer` drops its `ensureConnected` call (the backend auto-dials contacts; sends dial on demand) — delete `ensureConnected` and `joinMesh` (group mesh now heals via announce+sync; keep `createGroup`'s pre-connect loop removed too: `create_group` invites reachable members and sync heals the rest).

- [ ] **Step 4: Conversation view.** Selected-contact header shows resolved name + an ✎ alias editor (inline `<input>` toggled by state; save via `invoke("set_alias", { peer, alias })`, empty string → `alias: null`), a "Remove contact" button behind a `window.confirm`, and "last seen" when offline. Message bubbles append a status glyph for `m.mine`:

```tsx
  const glyph = (s: Message["status"]) =>
    s === "queued" ? "🕓" : s === "sent" ? "✓" : s === "delivered" ? "✓✓" : "";
```

`sendMessage`'s catch now calls `pushBanner({ kind: "error", text: `Send failed: ${e}` })` (and `send_file`/`connect` likewise) instead of console-only. `sendMessage` also applies the returned `MessageDto` optimistically (append to `messages`).

- [ ] **Step 5: Read wiring.** When a conversation is selected AND messages change, mark read:

```ts
  useEffect(() => {
    if (!selected) return;
    invoke("mark_read", { kind: selected.kind, id: selected.id }).catch(() => {});
  }, [selected, messages.length]);
```

`loadHistory` stays (now returns status-bearing DTOs).

- [ ] **Step 6: Cleanup + styles.** Delete `list_peers` usage; remove the `list_peers` command + `PeerDto` from `app/src-tauri/src/lib.rs` and its `generate_handler!` entry. Add CSS for `.section-label`, `.unread` (small pill), `.pin-flag`, `.banner` rows, `.hint`, keeping the existing visual language.

- [ ] **Step 7: Verify**

Run: `cd app && npm run build && cd ..` (runs `tsc` + vite build — must pass with zero TS errors)
Run: `cd app/src-tauri && cargo clippy --all-targets -- -D warnings && cd ../..`
Expected: both clean.

- [ ] **Step 8: Commit**

```bash
git add app
git commit -m "feat(ui): roster-first sidebar, delivery glyphs, error/pin banners, read receipts

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 13: Final verification sweep

**Files:**
- Modify (if needed): whatever the sweep flags; `README.md` feature list.

- [ ] **Step 1: Full workspace gate**

Run, from repo root:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --examples
cd app/src-tauri && cargo clippy --all-targets -- -D warnings && cd ../..
cd app && npm run build && cd ..
```
Expected: every command clean/green. Fix anything that isn't, amend the relevant commit or add a `fix:` commit.

- [ ] **Step 2: Spec cross-check.** Open `docs/superpowers/specs/2026-07-07-durable-chat-design.md` and verify each spec section maps to landed code (data model → Tasks 3/5, protocol → 6/7/8/9, UI & commands → 11/12, error handling → 5/7/12, testing → the six integration tests). Note any deliberate deviation at the bottom of the spec under a `## Implementation notes` heading.

- [ ] **Step 3: Manual smoke (two instances, one machine).** The data dir is currently fixed to `app_data_dir()` (`app/src-tauri/src/lib.rs:312`). Add an env override in this task so two local instances can run side by side:

```rust
            let data_dir = std::env::var("VARTALAAP_DATA_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| app.path().app_data_dir().expect("resolve app data dir"));
```

Then run instance 1 normally and instance 2 with `VARTALAAP_DATA_DIR=/tmp/vartalaap-b npm run tauri dev` (or the project's dev command), and verify:
  1. Chat A↔B, quit B, send from A (glyph shows 🕓), relaunch B → message arrives, glyph flips ✓✓.
  2. Restart A → sidebar and history intact offline.
  3. Create a group with B offline; bring B back; B sees the group and the missed message.

- [ ] **Step 4: Update README features + commit**

```bash
git add -A
git commit -m "docs: durable-chat feature notes and verification sweep

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

- [ ] **Step 5: Run `graphify update .`** (project rule: keep the knowledge graph current after code changes).
