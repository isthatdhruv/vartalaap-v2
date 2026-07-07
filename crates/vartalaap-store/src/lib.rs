//! Encrypted local persistence for Vartalaap.
//!
//! A [`Store`] wraps a [`redb`] database and a [`VaultKey`]. Every value is
//! sealed with the vault key before it touches disk, so the database file is
//! encrypted at rest.

use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};
use vartalaap_crypto::{open, seal, CryptoError, VaultKey};

const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");

type SecretList = Vec<(String, Result<Vec<u8>, CryptoError>)>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("serialization error")]
    Serde,
}

pub struct Store {
    db: Database,
    key: VaultKey,
}

impl Store {
    /// Open (or create) the database at `path`, encrypting values with `key`.
    pub fn open(path: &Path, key: VaultKey) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::Db(e.to_string()))?;
        let wtx = db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let _ = wtx
                .open_table(SECRETS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(Store { db, key })
    }

    /// Seal and store raw bytes under `name`.
    pub fn put_secret(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        let blob = seal(&self.key, plaintext);
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(SECRETS)
                .map_err(|e| StoreError::Db(e.to_string()))?;
            t.insert(name, blob.as_slice())
                .map_err(|e| StoreError::Db(e.to_string()))?;
        }
        wtx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
        Ok(())
    }

    /// Read and decrypt bytes stored under `name`, if present.
    pub fn get_secret(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let t = rtx
            .open_table(SECRETS)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let Some(v) = t.get(name).map_err(|e| StoreError::Db(e.to_string()))? else {
            return Ok(None);
        };
        let plaintext = open(&self.key, v.value())?;
        Ok(Some(plaintext))
    }

    /// Serialize `value` to JSON, then seal and store it.
    pub fn put_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value).map_err(|_| StoreError::Serde)?;
        self.put_secret(name, &bytes)
    }

    /// Read, decrypt, and deserialize a JSON value stored under `name`.
    pub fn get_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, StoreError> {
        match self.get_secret(name)? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| StoreError::Serde),
        }
    }

    /// All entries whose key starts with `prefix`, with a per-entry decrypt
    /// result: one corrupt value must not hide the healthy ones.
    pub fn list_secrets(
        &self,
        prefix: &str,
    ) -> Result<SecretList, StoreError> {
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let t = rtx
            .open_table(SECRETS)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        let mut out = Vec::new();
        for entry in t
            .range::<&str>(prefix..)
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
}

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

    #[test]
    fn json_roundtrip() {
        let path = tmpdb();
        let s = Store::open(&path, VaultKey::from([5u8; 32])).unwrap();
        s.put_json("nums", &vec![1u32, 2, 3]).unwrap();
        let got: Vec<u32> = s.get_json("nums").unwrap().unwrap();
        assert_eq!(got, vec![1, 2, 3]);
        std::fs::remove_file(&path).ok();
    }

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
}
