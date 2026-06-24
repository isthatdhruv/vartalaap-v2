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

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const SALT_FILE: &str = "kdf.salt";
const VAULT_FILE: &str = "vault.redb";
const IDENTITY_KEY: &str = "identity_sk";
const PROFILE_KEY: &str = "profile";

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
}

pub struct Engine {
    identity: Identity,
    store: Store,
}

impl Engine {
    /// Open the engine rooted at `data_dir`, unlocking the vault with
    /// `passphrase`. Creates the directory, a persistent KDF salt, and a fresh
    /// identity on first run; loads the existing identity afterwards.
    pub fn open(data_dir: &Path, passphrase: &str) -> Result<Self, CoreError> {
        std::fs::create_dir_all(data_dir)?;

        let salt = load_or_create_salt(data_dir)?;
        let key = VaultKey::from(*derive_key(passphrase, &salt));
        let store = Store::open(&data_dir.join(VAULT_FILE), key)?;

        let identity = match store.get_secret(IDENTITY_KEY)? {
            Some(bytes) => {
                let seed: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CoreError::CorruptIdentity)?;
                Identity::from_secret_bytes(seed)
            }
            None => {
                let id = Identity::generate();
                store.put_secret(IDENTITY_KEY, &id.secret_bytes()[..])?;
                id
            }
        };

        Ok(Engine { identity, store })
    }

    /// The human-facing Vartalaap ID (key fingerprint).
    pub fn vartalaap_id(&self) -> String {
        self.identity.public_id().fingerprint()
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
