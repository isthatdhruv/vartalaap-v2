//! The Vartalaap engine facade.
//!
//! [`Engine`] is the single entry point the GUI/UI layer talks to. It owns the
//! local [`Identity`] and an encrypted [`Store`]. On first run it generates an
//! identity and persists it (sealed) under a passphrase-derived key; on later
//! runs it loads the same identity back.

use std::path::Path;

use rand::RngCore;
use vartalaap_crypto::{derive_key, VaultKey};
use vartalaap_identity::{Identity, Profile, SignedProfile};
use vartalaap_store::Store;

pub mod node;
pub mod persist;
pub mod protocol;

pub use vartalaap_sync::{FileRef, Message, MessageKind};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const SALT_FILE: &str = "kdf.salt";
const VAULT_FILE: &str = "vault.redb";
const IDENTITY_KEY: &str = "identity_sk";
const PROFILE_KEY: &str = "profile";
/// Sentinel entry proving a passphrase unlocks this vault. Sealed with the
/// vault key, so decrypting it back to [`VAULT_CHECK_VALUE`] succeeds only for
/// the right passphrase.
const VAULT_CHECK_KEY: &str = "vault_check";
const VAULT_CHECK_VALUE: &[u8] = b"vartalaap vault v1";

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] vartalaap_store::StoreError),
    #[error(transparent)]
    Identity(#[from] vartalaap_identity::IdentityError),
    #[error("stored identity is corrupt")]
    CorruptIdentity,
    #[error("stored profile is corrupt or unverifiable")]
    CorruptProfile,
    #[error("wrong passphrase")]
    WrongPassphrase,
}

pub struct Engine {
    identity: Identity,
    pub(crate) store: Store,
}

impl Engine {
    /// Whether a vault already exists at `data_dir` — i.e. whether the caller
    /// should be asking the user to *unlock* rather than to choose a new
    /// passphrase. Cheap and side-effect free: it creates nothing.
    pub fn vault_exists(data_dir: &Path) -> bool {
        data_dir.join(VAULT_FILE).exists()
    }

    /// Open the engine rooted at `data_dir`, unlocking the vault with
    /// `passphrase`. Creates the directory, a persistent KDF salt, and a fresh
    /// identity on first run; loads the existing identity afterwards.
    ///
    /// Returns [`CoreError::WrongPassphrase`] rather than a generic decrypt
    /// failure when the passphrase does not open an existing vault. That
    /// distinction matters beyond the error message: callers layered above
    /// this one quarantine vault entries they cannot read, and under a wrong
    /// key *every* entry is unreadable. Failing here, before any of that runs,
    /// is what stops a typo from moving the whole vault aside.
    pub fn open(data_dir: &Path, passphrase: &str) -> Result<Self, CoreError> {
        std::fs::create_dir_all(data_dir)?;

        let salt = load_or_create_salt(data_dir)?;
        let key = VaultKey::from(*derive_key(passphrase, &salt));
        let store = Store::open(&data_dir.join(VAULT_FILE), key)?;

        // Check the sentinel before touching anything else.
        let sentinel_present = match store.get_secret(VAULT_CHECK_KEY) {
            // Present and readable: right passphrase.
            Ok(Some(v)) if v == VAULT_CHECK_VALUE => true,
            // Present but undecryptable (or decrypting to something else):
            // wrong passphrase. `get_secret` surfaces an AEAD failure as
            // `Err`, so both shapes land here.
            Ok(Some(_)) | Err(vartalaap_store::StoreError::Crypto(_)) => {
                return Err(CoreError::WrongPassphrase)
            }
            Err(e) => return Err(e.into()),
            // Absent: either a brand-new vault, or one written before the
            // sentinel existed. Both are handled below — a pre-sentinel vault
            // is proven by the identity decrypting, and gets a sentinel
            // written so later opens take the fast path above.
            Ok(None) => false,
        };

        let identity = match store.get_secret(IDENTITY_KEY) {
            Ok(Some(bytes)) => {
                let seed: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CoreError::CorruptIdentity)?;
                Identity::from_secret_bytes(seed)
            }
            Ok(None) => {
                let id = Identity::generate();
                store.put_secret(IDENTITY_KEY, &id.secret_bytes()[..])?;
                id
            }
            // An identity that will not decrypt in a vault with no sentinel
            // means a pre-sentinel vault opened under the wrong passphrase.
            Err(vartalaap_store::StoreError::Crypto(_)) => return Err(CoreError::WrongPassphrase),
            Err(e) => return Err(e.into()),
        };

        if !sentinel_present {
            store.put_secret(VAULT_CHECK_KEY, VAULT_CHECK_VALUE)?;
        }
        Ok(Engine { identity, store })
    }

    /// The human-facing Vartalaap ID (key fingerprint).
    pub fn vartalaap_id(&self) -> String {
        self.identity.public_id().fingerprint()
    }

    /// The raw 32-byte public id.
    pub fn id_bytes(&self) -> [u8; 32] {
        self.identity.public_id().to_bytes()
    }

    /// The 32-byte identity seed, used to derive the network keypair so the
    /// node's PeerId equals its Vartalaap ID.
    pub fn identity_seed(&self) -> [u8; 32] {
        *self.identity.secret_bytes()
    }

    /// Sign and persist a new profile.
    pub fn set_profile(&self, profile: Profile) -> Result<(), CoreError> {
        let signed = self.identity.sign_profile(profile);
        self.store.put_json(PROFILE_KEY, &signed)?;
        Ok(())
    }

    /// Load and verify the stored profile, if one has been set.
    pub fn profile(&self) -> Result<Option<Profile>, CoreError> {
        let Some(signed) = self.store.get_json::<SignedProfile>(PROFILE_KEY)? else {
            return Ok(None);
        };
        let (_, profile) = signed.verify().map_err(|_| CoreError::CorruptProfile)?;
        Ok(Some(profile.clone()))
    }

    /// The stored signed profile, unverified-as-loaded (verification happens
    /// in [`Engine::profile`]); used to publish over the wire.
    pub fn signed_profile(&self) -> Result<Option<SignedProfile>, CoreError> {
        Ok(self.store.get_json::<SignedProfile>(PROFILE_KEY)?)
    }
}

/// Read the 16-byte KDF salt sidecar, creating it with fresh randomness if
/// absent. The salt is not secret, so it lives in a plaintext file.
fn load_or_create_salt(data_dir: &Path) -> Result<[u8; 16], CoreError> {
    let path = data_dir.join(SALT_FILE);
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 16 => {
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&bytes);
            Ok(salt)
        }
        Ok(_) => Err(CoreError::CorruptIdentity),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut salt = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            std::fs::write(&path, salt)?;
            Ok(salt)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vartalaap_identity::Profile;

    #[test]
    fn version_is_nonempty() {
        assert!(!version().is_empty());
    }

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

    /// A wrong passphrase must be reported *as such*, and must leave the vault
    /// intact so the right passphrase still opens it afterwards. The failure
    /// has to happen at the sentinel, before any caller starts quarantining
    /// entries it cannot decrypt — under a wrong key that would be all of them.
    #[test]
    fn wrong_passphrase_is_rejected_without_damaging_the_vault() {
        let dir = tmpdir();
        let real_id = {
            let e = Engine::open(&dir, "correct horse").unwrap();
            e.set_profile(Profile {
                display_name: "Asha".into(),
                bio: String::new(),
                status: "online".into(),
                avatar: None,
                updated_at: 1,
            })
            .unwrap();
            e.vartalaap_id()
        };

        match Engine::open(&dir, "wrong horse") {
            Err(CoreError::WrongPassphrase) => {}
            Err(e) => panic!("expected WrongPassphrase, got {e:?}"),
            Ok(_) => panic!("a wrong passphrase must not open the vault"),
        }

        // Nothing was consumed or destroyed by the failed attempt.
        let e = Engine::open(&dir, "correct horse").unwrap();
        assert_eq!(e.vartalaap_id(), real_id, "identity must be untouched");
        assert_eq!(e.profile().unwrap().unwrap().display_name, "Asha");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `vault_exists` drives the UI's create-vs-unlock decision, so it must not
    /// report a vault before one is made — nor create one by asking.
    #[test]
    fn vault_exists_reports_creation_not_mere_inspection() {
        let dir = tmpdir();
        assert!(!Engine::vault_exists(&dir));
        assert!(!Engine::vault_exists(&dir), "asking must not create");
        let _ = Engine::open(&dir, "pw").unwrap();
        assert!(Engine::vault_exists(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Vaults written before the sentinel existed must keep opening under
    /// their original passphrase, and gain a sentinel on the way through.
    #[test]
    fn pre_sentinel_vault_still_opens_and_is_upgraded() {
        let dir = tmpdir();
        let id = {
            let e = Engine::open(&dir, "legacy").unwrap();
            e.vartalaap_id()
        };
        // Simulate the old on-disk shape by deleting the sentinel.
        {
            let salt = load_or_create_salt(&dir).unwrap();
            let key = VaultKey::from(*derive_key("legacy", &salt));
            let store = Store::open(&dir.join(VAULT_FILE), key).unwrap();
            store.delete_secret(VAULT_CHECK_KEY).unwrap();
            assert!(store.get_secret(VAULT_CHECK_KEY).unwrap().is_none());
        }

        // The right passphrase opens it (proven by the identity round-trip)...
        let e = Engine::open(&dir, "legacy").unwrap();
        assert_eq!(e.vartalaap_id(), id);
        drop(e);
        // ...and the wrong one is still caught, via the identity decrypt.
        assert!(matches!(
            Engine::open(&dir, "nope"),
            Err(CoreError::WrongPassphrase)
        ));
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
        })
        .unwrap();
        assert_eq!(e.profile().unwrap().unwrap().display_name, "Asha");
        std::fs::remove_dir_all(&dir).ok();
    }
}
