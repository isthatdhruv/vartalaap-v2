# Vartalaap — Foundation (Phase 0) + 1:1 Chat (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the headless Rust engine for Vartalaap — a campus/LAN-only, serverless, end-to-end-encrypted P2P chat app — through a working 1:1 encrypted text-messaging core, proven by headless integration tests.

**Architecture:** A cargo workspace of focused crates behind a single `vartalaap-core` engine facade. Phase 0 (pure Rust, no C toolchain, no sudo) builds identity, at-rest crypto, and an encrypted store. Phase 1 adds Iroh-based LAN networking, a vodozemac Double-Ratchet session, and 1:1 message exchange. The web UI (Tauri) is wired on top later; the engine is fully usable and testable headless.

**Tech Stack:** Rust 1.96; ed25519-dalek 2, x25519-dalek 2, sha2, argon2, chacha20poly1305 (XChaCha20Poly1305), zeroize, redb 2, serde/serde_json, bs58, thiserror 2, anyhow (Phase 0); vodozemac, iroh, tokio, automerge (Phase 1).

## Global Constraints

- **Platforms:** Windows + Linux. Engine crates must compile and test headless on Linux with no GUI/system libs.
- **No C toolchain in Phase 0:** every Phase 0 dependency must be pure Rust (no `cc`/`build.rs` C compilation). Verified pure-Rust set listed in Tech Stack.
- **Serverless / LAN-only:** no network dependency may require an external server, account, bootstrap node, or relay. Discovery is mDNS on the local network only.
- **Never trust the network:** all message *content* is end-to-end encrypted independently of transport encryption.
- **Secrets:** private keys and derived symmetric keys must be wrapped in `zeroize::Zeroizing` (or implement `ZeroizeOnDrop`) and never logged.
- **TDD:** every task writes a failing test first, then the minimal code to pass. Commit after each task.
- **Crate naming:** all crates are `vartalaap-<module>`; the workspace lives at repo root.
- **Error handling:** library crates return `Result<T, ThisError>` with a per-crate `thiserror` error enum; no `unwrap()` in non-test code except documented invariants.

---

## File Structure

```
vartalaap-v2/
├─ Cargo.toml                         # workspace root (members + shared deps)
├─ rust-toolchain.toml                # pin stable
├─ crates/
│  ├─ vartalaap-identity/
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs                   # Identity, VartalaapId, Profile, SignedProfile
│  ├─ vartalaap-crypto/
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs                   # at-rest KDF + AEAD seal/open (Phase 0)
│  │                                  # + ratchet session wrapper (Phase 1)
│  ├─ vartalaap-store/
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs                   # redb-backed encrypted store
│  ├─ vartalaap-net/                  # Phase 1
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs                   # Transport trait + Iroh impl, mDNS discovery
│  ├─ vartalaap-sync/                 # Phase 1 (CRDT/log of a conversation)
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs
│  └─ vartalaap-core/
│     ├─ Cargo.toml
│     └─ src/lib.rs                   # Engine facade wiring all modules
├─ src-tauri/                         # GUI shell (later; needs webkit2gtk)
└─ ui/                                # React app (later)
```

Each crate has one responsibility and a small public surface. `vartalaap-core` is the only crate the Tauri/UI layer talks to.

---

## PHASE 0 — Foundation (pure Rust, no sudo)

### Task 1: Cargo workspace skeleton

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `rust-toolchain.toml`
- Create: `crates/vartalaap-core/Cargo.toml`
- Create: `crates/vartalaap-core/src/lib.rs`
- Test: in `crates/vartalaap-core/src/lib.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces: a buildable workspace; `vartalaap_core::version() -> &'static str`.

- [ ] **Step 1: Write the failing test**

In `crates/vartalaap-core/src/lib.rs`:
```rust
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }
}
```

- [ ] **Step 2: Create the manifests**

`Cargo.toml` (root):
```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
edition = "2021"
license = "MIT"
rust-version = "1.96"

[workspace.dependencies]
thiserror = "2"
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = { version = "1", features = ["zeroize_derive"] }
ed25519-dalek = { version = "2", features = ["rand_core", "serde"] }
x25519-dalek = { version = "2", features = ["serde", "static_secrets"] }
sha2 = "0.10"
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand = "0.8"
bs58 = "0.5"
hex = "0.4"
redb = "2"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
```

`crates/vartalaap-core/Cargo.toml`:
```toml
[package]
name = "vartalaap-core"
version = "0.1.0"
edition.workspace = true

[dependencies]
```

- [ ] **Step 3: Run the test (verify it passes)**

Run: `cargo test -p vartalaap-core`
Expected: 1 passed. (Confirms the workspace builds end to end.)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml rust-toolchain.toml crates/ .gitignore
git commit -m "chore: cargo workspace skeleton"
```

---

### Task 2: Identity keypair (`vartalaap-identity`)

**Files:**
- Create: `crates/vartalaap-identity/Cargo.toml`
- Create: `crates/vartalaap-identity/src/lib.rs`
- Test: inline `#[cfg(test)]` in `src/lib.rs`

**Interfaces:**
- Produces:
  - `struct Identity` — holds an Ed25519 `SigningKey` (zeroized on drop).
  - `Identity::generate() -> Identity`
  - `Identity::public_id(&self) -> VartalaapId`
  - `Identity::sign(&self, msg: &[u8]) -> Signature` (re-export `ed25519_dalek::Signature`)
  - `Identity::secret_bytes(&self) -> Zeroizing<[u8; 32]>` and `Identity::from_secret_bytes([u8;32]) -> Identity` (for persistence)
  - `struct VartalaapId(VerifyingKey)` with `fn fingerprint(&self) -> String` (base58 of SHA-256 of the public key, the human-facing "Vartalaap ID"), `fn verify(&self, msg, sig) -> Result<(), IdentityError>`, `to_bytes/from_bytes`.
  - `enum IdentityError` (thiserror).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_stable_id_and_sig_roundtrip() {
        let id = Identity::generate();
        let pid = id.public_id();
        let msg = b"hello vartalaap";
        let sig = id.sign(msg);
        assert!(pid.verify(msg, &sig).is_ok());
        assert!(pid.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn secret_roundtrip_preserves_identity() {
        let id = Identity::generate();
        let bytes = *id.secret_bytes();
        let id2 = Identity::from_secret_bytes(bytes);
        assert_eq!(id.public_id().to_bytes(), id2.public_id().to_bytes());
    }

    #[test]
    fn fingerprint_is_deterministic_and_nonempty() {
        let id = Identity::generate();
        let f1 = id.public_id().fingerprint();
        let f2 = id.public_id().fingerprint();
        assert_eq!(f1, f2);
        assert!(f1.len() >= 8);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vartalaap-identity`
Expected: FAIL (crate/types not defined).

- [ ] **Step 3: Implement**

`crates/vartalaap-identity/Cargo.toml`:
```toml
[package]
name = "vartalaap-identity"
version = "0.1.0"
edition.workspace = true

[dependencies]
ed25519-dalek = { workspace = true }
sha2 = { workspace = true }
bs58 = { workspace = true }
rand = { workspace = true }
zeroize = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
```

`crates/vartalaap-identity/src/lib.rs`:
```rust
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid public key bytes")]
    BadPublicKey,
}

pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Identity { signing: SigningKey::generate(&mut csprng) }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Identity { signing: SigningKey::from_bytes(&bytes) }
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn public_id(&self) -> VartalaapId {
        VartalaapId(self.signing.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VartalaapId(VerifyingKey);

impl VartalaapId {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(&bytes)
            .map(VartalaapId)
            .map_err(|_| IdentityError::BadPublicKey)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), IdentityError> {
        self.0.verify(msg, sig).map_err(|_| IdentityError::BadSignature)
    }

    /// Human-facing "Vartalaap ID": base58(SHA-256(pubkey)).
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.to_bytes());
        bs58::encode(digest).into_string()
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vartalaap-identity`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-identity
git commit -m "feat(identity): Ed25519 identity, VartalaapId fingerprint, sign/verify"
```

---

### Task 3: Profile + signed profile (`vartalaap-identity`)

**Files:**
- Modify: `crates/vartalaap-identity/src/lib.rs` (append `Profile`, `SignedProfile`)
- Test: inline tests

**Interfaces:**
- Produces:
  - `struct Profile { display_name: String, bio: String, status: String, avatar: Option<Vec<u8>>, updated_at: u64 }` (Serialize/Deserialize, Clone).
  - `struct SignedProfile { id: [u8;32], profile: Profile, sig: [u8;64] }`.
  - `Identity::sign_profile(&self, p: Profile) -> SignedProfile`
  - `SignedProfile::verify(&self) -> Result<(VartalaapId, &Profile), IdentityError>` — recomputes the canonical bytes, checks the signature against the embedded id.
  - canonical serialization = `serde_json::to_vec` of `Profile` (deterministic enough for v0; a canonical codec is a later hardening task).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn signed_profile_verifies_and_detects_tampering() {
    let id = Identity::generate();
    let p = Profile {
        display_name: "Asha".into(),
        bio: "CS '27".into(),
        status: "online".into(),
        avatar: None,
        updated_at: 1,
    };
    let mut sp = id.sign_profile(p);
    let (vid, prof) = sp.verify().expect("valid");
    assert_eq!(vid.to_bytes(), id.public_id().to_bytes());
    assert_eq!(prof.display_name, "Asha");

    sp.profile.display_name = "Mallory".into();
    assert!(sp.verify().is_err());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vartalaap-identity signed_profile`
Expected: FAIL (types not defined).

- [ ] **Step 3: Implement**

Add `serde_json` to `vartalaap-identity/Cargo.toml` deps (`serde_json = { workspace = true }`), then append to `src/lib.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub display_name: String,
    pub bio: String,
    pub status: String,
    pub avatar: Option<Vec<u8>>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProfile {
    pub id: [u8; 32],
    pub profile: Profile,
    pub sig: [u8; 64],
}

impl Identity {
    pub fn sign_profile(&self, profile: Profile) -> SignedProfile {
        let bytes = serde_json::to_vec(&profile).expect("profile serializes");
        let sig = self.sign(&bytes);
        SignedProfile {
            id: self.public_id().to_bytes(),
            profile,
            sig: sig.to_bytes(),
        }
    }
}

impl SignedProfile {
    pub fn verify(&self) -> Result<(VartalaapId, &Profile), IdentityError> {
        let vid = VartalaapId::from_bytes(self.id)?;
        let bytes = serde_json::to_vec(&self.profile).map_err(|_| IdentityError::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig);
        vid.verify(&bytes, &sig)?;
        Ok((vid, &self.profile))
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vartalaap-identity`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-identity
git commit -m "feat(identity): signed, verifiable profiles"
```

---

### Task 4: At-rest crypto (`vartalaap-crypto`)

**Files:**
- Create: `crates/vartalaap-crypto/Cargo.toml`
- Create: `crates/vartalaap-crypto/src/lib.rs`
- Test: inline tests

**Interfaces:**
- Produces:
  - `fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]>` (Argon2id).
  - `struct VaultKey([u8;32])` wrapping the AEAD key (zeroized).
  - `fn seal(key: &VaultKey, plaintext: &[u8]) -> Vec<u8>` — XChaCha20Poly1305; output = 24-byte nonce ‖ ciphertext+tag. Nonce from `OsRng`.
  - `fn open(key: &VaultKey, blob: &[u8]) -> Result<Vec<u8>, CryptoError>`.
  - `enum CryptoError` (thiserror): `Decrypt`, `Format`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = VaultKey::from(*derive_key("hunter2", &[7u8; 16]));
        let blob = seal(&key, b"top secret");
        assert_eq!(open(&key, &blob).unwrap(), b"top secret");
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = VaultKey::from(*derive_key("hunter2", &[7u8; 16]));
        let mut blob = seal(&key, b"top secret");
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(matches!(open(&key, &blob), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = VaultKey::from(*derive_key("a", &[1u8; 16]));
        let k2 = VaultKey::from(*derive_key("b", &[1u8; 16]));
        let blob = seal(&k1, b"x");
        assert!(open(&k2, &blob).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vartalaap-crypto`
Expected: FAIL.

- [ ] **Step 3: Implement**

`crates/vartalaap-crypto/Cargo.toml`:
```toml
[package]
name = "vartalaap-crypto"
version = "0.1.0"
edition.workspace = true

[dependencies]
chacha20poly1305 = { workspace = true }
argon2 = { workspace = true }
rand = { workspace = true }
zeroize = { workspace = true }
thiserror = { workspace = true }
```

`crates/vartalaap-crypto/src/lib.rs`:
```rust
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed ciphertext")]
    Format,
}

pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .expect("argon2 kdf");
    out
}

pub struct VaultKey(Zeroizing<[u8; 32]>);

impl From<[u8; 32]> for VaultKey {
    fn from(b: [u8; 32]) -> Self {
        VaultKey(Zeroizing::new(b))
    }
}

const NONCE_LEN: usize = 24;

pub fn seal(key: &VaultKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("aead encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &VaultKey, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Format);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.0.as_ref().into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| CryptoError::Decrypt)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vartalaap-crypto`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-crypto
git commit -m "feat(crypto): Argon2id KDF + XChaCha20Poly1305 seal/open"
```

---

### Task 5: Encrypted store (`vartalaap-store`)

**Files:**
- Create: `crates/vartalaap-store/Cargo.toml`
- Create: `crates/vartalaap-store/src/lib.rs`
- Test: inline tests (use a temp dir via `std::env::temp_dir()` + unique subdir; clean up).

**Interfaces:**
- Produces:
  - `struct Store` over a `redb::Database`, holding a `VaultKey`.
  - `Store::open(path: &Path, key: VaultKey) -> Result<Store, StoreError>`
  - `Store::put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError>` — seals then writes to the `secrets` table.
  - `Store::get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError>` — reads + opens.
  - `Store::put_json<T: Serialize>` / `get_json<T: DeserializeOwned>` convenience (sealed).
  - `enum StoreError` (thiserror): wraps `redb` + `CryptoError`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vartalaap_crypto::{derive_key, VaultKey};

    fn tmpdb() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-test-{n}.redb"));
        p
    }

    #[test]
    fn secret_persists_across_reopen() {
        let path = tmpdb();
        let key = || VaultKey::from(*derive_key("pw", &[3u8; 16]));
        {
            let s = Store::open(&path, key()).unwrap();
            s.put_secret("identity", b"sk-bytes").unwrap();
        }
        {
            let s = Store::open(&path, key()).unwrap();
            assert_eq!(s.get_secret("identity").unwrap().unwrap(), b"sk-bytes");
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_secret_is_none() {
        let path = tmpdb();
        let s = Store::open(&path, VaultKey::from([9u8; 32])).unwrap();
        assert!(s.get_secret("nope").unwrap().is_none());
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vartalaap-store`
Expected: FAIL.

- [ ] **Step 3: Implement**

`crates/vartalaap-store/Cargo.toml`:
```toml
[package]
name = "vartalaap-store"
version = "0.1.0"
edition.workspace = true

[dependencies]
vartalaap-crypto = { path = "../vartalaap-crypto" }
redb = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
rand = { workspace = true }
```

`crates/vartalaap-store/src/lib.rs`:
```rust
use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};
use vartalaap_crypto::{open, seal, CryptoError, VaultKey};

const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("serialization error")]
    Serde,
}

impl<E: std::fmt::Display> From<E> for StoreError
where
    E: redb::ReadableError,
{
    // placeholder note: concrete redb error conversions are wired explicitly below
    fn from(e: E) -> Self {
        StoreError::Db(e.to_string())
    }
}

pub struct Store {
    db: Database,
    key: VaultKey,
}

impl Store {
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::Db(e.to_string()))?;
        let wtx = db.begin_write().map_err(|e| StoreError::Db(e.to_string()))?;
        { let _ = wtx.open_table(SECRETS).map_err(|e| StoreError::Db(e.to_string()))?; }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(Store { db, key })
    }

    pub fn put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let blob = seal(&self.key, plaintext);
        let wtx = self.db.begin_write().map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = wtx.open_table(SECRETS).map_err(|e| StoreError::Db(e.to_string()))?;
            t.insert(name, blob.as_slice()).map_err(|e| StoreError::Db(e.to_string()))?;
        }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self.db.begin_read().map_err(|e| StoreError::Db(e.to_string()))?;
        let t = rtx.open_table(SECRETS).map_err(|e| StoreError::Db(e.to_string()))?;
        let Some(v) = t.get(name).map_err(|e| StoreError::Db(e.to_string()))? else {
            return Ok(None);
        };
        let plaintext = open(&self.key, v.value())?;
        Ok(Some(plaintext))
    }

    pub fn put_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value).map_err(|_| StoreError::Serde)?;
        self.put_secret(name, &bytes)
    }

    pub fn get_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, StoreError> {
        match self.get_secret(name)? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| StoreError::Serde),
        }
    }
}
```

> **Execution note:** The blanket `From<E>` impl above is illustrative; during execution, replace it with explicit `.map_err` (already used at every call site) and delete the blanket impl if it conflicts with redb's error types. The call sites already convert via `to_string()`, so the blanket impl can simply be removed.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vartalaap-store`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-store
git commit -m "feat(store): redb-backed encrypted secret store"
```

---

### Task 6: Engine facade — first-run identity + profile (`vartalaap-core`)

**Files:**
- Modify: `crates/vartalaap-core/Cargo.toml` (add deps), `crates/vartalaap-core/src/lib.rs`
- Test: inline tests

**Interfaces:**
- Produces:
  - `struct Engine { identity: Identity, store: Store }`
  - `Engine::open(data_dir: &Path, passphrase: &str) -> Result<Engine, CoreError>` — on first run, generates an `Identity`, persists its secret (sealed) under key `"identity_sk"` plus a fresh random 16-byte salt under `"kdf_salt"` (the salt itself stored in a small sidecar file or a plaintext table, since it's not secret); on later runs, loads the existing identity. Uses `derive_key(passphrase, salt)` for the `VaultKey`.
  - `Engine::vartalaap_id(&self) -> String` (fingerprint).
  - `Engine::set_profile(&self, p: Profile) -> Result<(), CoreError>` (signs + stores under `"profile"`).
  - `Engine::profile(&self) -> Result<Option<Profile>, CoreError>`.
  - `enum CoreError` (thiserror) wrapping identity/store errors.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vartalaap_identity::Profile;

    fn tmpdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-engine-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_run_creates_identity_second_run_loads_same() {
        let dir = tmpdir();
        let id_a = {
            let e = Engine::open(&dir, "pw").unwrap();
            e.vartalaap_id()
        };
        let id_b = {
            let e = Engine::open(&dir, "pw").unwrap();
            e.vartalaap_id()
        };
        assert_eq!(id_a, id_b, "identity must persist across runs");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_roundtrips() {
        let dir = tmpdir();
        let e = Engine::open(&dir, "pw").unwrap();
        assert!(e.profile().unwrap().is_none());
        e.set_profile(Profile {
            display_name: "Asha".into(),
            bio: String::new(),
            status: "online".into(),
            avatar: None,
            updated_at: 1,
        }).unwrap();
        assert_eq!(e.profile().unwrap().unwrap().display_name, "Asha");
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p vartalaap-core`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add to `crates/vartalaap-core/Cargo.toml`:
```toml
[dependencies]
vartalaap-identity = { path = "../vartalaap-identity" }
vartalaap-crypto = { path = "../vartalaap-crypto" }
vartalaap-store = { path = "../vartalaap-store" }
thiserror = { workspace = true }
rand = { workspace = true }

[dev-dependencies]
rand = { workspace = true }
```

Implement `Engine` in `src/lib.rs` (keep `version()` + its test). Salt handling: store the 16-byte KDF salt in a tiny plaintext sidecar file `kdf.salt` in `data_dir` (created with `OsRng` on first run); the redb file is `vault.redb`. The identity secret is sealed inside the vault. Pseudocode of `open`:
```rust
// 1. read-or-create kdf.salt (16 random bytes) in data_dir
// 2. key = VaultKey::from(*derive_key(passphrase, &salt))
// 3. store = Store::open(data_dir/"vault.redb", key)
// 4. match store.get_secret("identity_sk")?:
//      Some(bytes) => Identity::from_secret_bytes(bytes[..32])
//      None => { let id = Identity::generate(); store.put_secret("identity_sk", &*id.secret_bytes())?; id }
// 5. Engine { identity, store }
```
`set_profile` signs via `identity.sign_profile` and stores the `SignedProfile` JSON under `"profile"`; `profile()` loads it, calls `.verify()`, returns the `Profile`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p vartalaap-core`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add crates/vartalaap-core
git commit -m "feat(core): engine facade with persistent encrypted identity + profile"
```

---

### Task 7: Workspace-wide quality gate

- [ ] **Step 1:** Run `cargo test --workspace` → all green.
- [ ] **Step 2:** Run `cargo clippy --workspace --all-targets -- -D warnings` → fix any lints.
- [ ] **Step 3:** Run `cargo fmt --all` → commit formatting.
- [ ] **Step 4: Commit**
```bash
git add -A && git commit -m "chore: phase 0 green — fmt + clippy clean"
```

**Phase 0 deliverable:** a headless engine that, given a data dir + passphrase, creates or loads a persistent encrypted identity and signed profile. Fully tested, pure Rust, no sudo, no GUI.

---

## PHASE 1 — LAN networking + 1:1 encrypted chat

> Requires the C toolchain (`build-essential`) from the sudo apt install, because Iroh → quinn → rustls pulls a crypto backend with C. Tasks are specified to the interface + test level; exact Iroh/vodozemac API calls are pinned during execution against the resolved crate versions (`cargo add iroh vodozemac tokio` then read `cargo doc`).

### Task 8: `vartalaap-net` transport trait + Iroh endpoint
- **Produces:** `trait Transport` with `async fn node_id(&self) -> NodeId`, `async fn dial(&self, NodeId) -> Result<Conn>`, `fn incoming(&self) -> impl Stream<Item = Conn>`, and `struct Conn { send, recv }` (length-prefixed framed bytes). `struct IrohTransport` implementing it via an `iroh::Endpoint`. The engine depends only on the trait.
- **Test:** two `IrohTransport`s on localhost; A dials B by node id; A sends a frame; B receives identical bytes. (No mDNS needed for this test — dial by explicit node id.)

### Task 9: mDNS LAN discovery
- **Produces:** `Discovery` that announces our node id + signed profile summary on the LAN (mDNS via Iroh's local discovery) and yields a stream of `DiscoveredPeer { id, addr, profile_summary }`. Stale entries expire.
- **Test:** two discovery instances on the loopback/test network see each other within a timeout. (Marked `#[ignore]` if CI multicast is unavailable; runs locally.)

### Task 10: Double-Ratchet session (`vartalaap-crypto`, Phase 1 half)
- **Produces:** a thin wrapper over `vodozemac` binding a peer's messaging identity to its `VartalaapId`:
  - `struct PreKeyBundle` (published via discovery/handshake) signed by the Ed25519 identity.
  - `Session::initiate(our_account, their_bundle) -> (Session, initial_msg)` and `Session::accept(our_account, initial_msg) -> Session`.
  - `Session::encrypt(&mut self, &[u8]) -> Vec<u8>`, `Session::decrypt(&mut self, &[u8]) -> Result<Vec<u8>>`.
- **Test:** known-answer + a property test: for a random sequence of messages A↔B (including out-of-order delivery), every ciphertext decrypts to its plaintext; a tampered ciphertext is rejected.

### Task 11: `vartalaap-sync` — 1:1 conversation log
- **Produces:** `struct Conversation` — an append-mostly CRDT (Automerge) of `Message { id, author, sent_at, body, kind }` plus mutable `read`/`reactions` maps; `merge(remote_delta)`; `changes_since(have)` for delta sync. Deterministic ordering by (lamport, author).
- **Test:** property test — two `Conversation`s receiving the same messages in different orders converge to identical state (CRDT convergence).

### Task 12: Wire engine — send/receive an E2E message between two engines
- **Produces:** `Engine` gains `connect(peer)`, `send_message(peer, body)`, and an event stream (`EngineEvent::MessageReceived`, `PeerDiscovered`, `PresenceChanged`). Outgoing: ratchet-encrypt → sync-append → transport-send the delta. Incoming: transport-recv → ratchet-decrypt → sync-merge → emit event. TOFU: pin peer `VartalaapId` on first contact; emit `KeyChanged` warning on mismatch.
- **Test (the headline integration test):** spin up two in-process engines on the loopback transport, exchange a message both directions, assert both `Conversation`s converge and both emit the right events. No UI, no sudo beyond the C toolchain.

### Task 13: Presence, typing, read receipts (ephemeral)
- **Produces:** gossiped ephemeral signals (`Presence{online,last_seen}`, `Typing`, `Read{up_to}`) on a separate transport channel; not persisted to the CRDT. Engine emits corresponding events; read receipts update the `read` map.
- **Test:** two engines; A types → B receives `Typing`; A reads → B sees `Read` watermark advance.

### Task 14: Phase 1 quality gate
- `cargo test --workspace`, clippy `-D warnings`, fmt. Headless two-node demo binary (`examples/two_node_chat.rs`) that prints a message delivered end to end.

**Phase 1 deliverable:** two headless engines on a LAN discover each other, establish a ratcheted session, and exchange E2E-encrypted 1:1 messages with presence/typing/receipts — the complete messaging core, GUI-independent.

---

## LATER PHASES (separate plans, written just-in-time)

- **Phase 2 — Files:** `vartalaap-blobs` over `iroh-blobs`; chunked, resumable, content-addressed transfer of any file/folder; transfer-manager events; thumbnails. *Plan: `2026-..-vartalaap-files.md`.*
- **Phase 3 — Groups:** small CRDT groups, membership, sender-key group encryption, self-healing history.
- **Phase 4 — Tauri GUI + chat polish:** wire `vartalaap-core` into a Tauri shell + React UI; reactions, replies, edits, deletes, search, mentions, notifications, etc. (needs webkit2gtk).
- **Phase 5 — Calls:** voice → video → screen share.
- **Phase 6 — Resilience:** peer mailbox, QR contact exchange, multi-device, optional internet transport.

---

## Self-Review

- **Spec coverage (Phases 0–1):** identity/profiles ✓ (T2–T3); E2E content crypto ✓ (T10, T12); at-rest crypto ✓ (T4–T5); LAN discovery ✓ (T9); 1:1 messaging ✓ (T12); CRDT sync ✓ (T11); presence/typing/receipts ✓ (T13); transport isolation behind a trait ✓ (T8). Spec items intentionally deferred to later-phase plans: files (P2), groups (P3), GUI/polish (P4), calls (P5), resilience/mailbox (P6).
- **Placeholder scan:** one illustrative blanket-`From` impl in Task 5 is flagged inline with an execution note to delete it (call sites already use explicit `.map_err`). Phase 1 tasks are interface-level by design (Iroh/vodozemac APIs pinned at execution) — flagged explicitly, not hidden TODOs.
- **Type consistency:** `VaultKey`, `VartalaapId`, `Profile`, `SignedProfile`, `Identity`, `Store`, `Engine` signatures are consistent across tasks; `seal/open`, `derive_key`, `put_secret/get_secret/put_json/get_json` names match between definition (T4–T5) and use (T6).
