//! Vault persistence for roster, conversations, and groups: maps domain
//! state to sealed values in the [`Store`] under stable key prefixes.

use serde::{Deserialize, Serialize};
use vartalaap_crypto::ratchet::MessagingAccount;
use vartalaap_identity::Profile;
use vartalaap_store::StoreError;
use vartalaap_sync::Snapshot;

use crate::node::{GroupInfo, PeerKey};
use crate::{CoreError, Engine};

const MSG_ACCOUNT_KEY: &str = "msg_account";

/// Raw `(vault key, decoded value)` pairs returned by [`Engine::load_prefix`],
/// before per-domain key-parsing strips the string key back down to bytes.
type PrefixList<T> = Vec<(String, T)>;
/// Peer-keyed conversation snapshots, as returned by [`Engine::load_convos`].
type ConvoList = Vec<(PeerKey, Snapshot)>;
/// Group-id-keyed conversation snapshots, as returned by
/// [`Engine::load_group_convos`].
type GroupConvoList = Vec<([u8; 16], Snapshot)>;

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
    ) -> Result<(PrefixList<T>, Vec<String>), CoreError> {
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
        Ok(self
            .store
            .put_json(&format!("contact/{}", hex64(&c.peer)), c)?)
    }

    pub fn load_contacts(&self) -> Result<(Vec<Contact>, Vec<String>), CoreError> {
        let (items, warnings) = self.load_prefix::<Contact>("contact/")?;
        Ok((items.into_iter().map(|(_, c)| c).collect(), warnings))
    }

    pub fn delete_contact(&self, peer: &PeerKey) -> Result<(), CoreError> {
        self.store
            .delete_secret(&format!("contact/{}", hex64(peer)))?;
        self.store
            .delete_secret(&format!("convo/{}", hex64(peer)))?;
        Ok(())
    }

    pub fn save_convo(&self, peer: &PeerKey, s: &Snapshot) -> Result<(), CoreError> {
        Ok(self.store.put_json(&format!("convo/{}", hex64(peer)), s)?)
    }

    pub fn load_convos(&self) -> Result<(ConvoList, Vec<String>), CoreError> {
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

    pub fn load_group_convos(&self) -> Result<(GroupConvoList, Vec<String>), CoreError> {
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
        match self.store.get_secret(MSG_ACCOUNT_KEY) {
            Ok(Some(bytes)) => match MessagingAccount::from_pickle_json(&bytes) {
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
            Ok(None) => {
                let a = MessagingAccount::new();
                self.save_msg_account(&a)?;
                Ok(a)
            }
            Err(StoreError::Crypto(_)) => {
                // Corrupted or wrong-key blob: quarantine and start fresh
                // rather than refusing to start.
                self.store.quarantine(MSG_ACCOUNT_KEY)?;
                let a = MessagingAccount::new();
                self.save_msg_account(&a)?;
                Ok(a)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_msg_account(&self, acct: &MessagingAccount) -> Result<(), CoreError> {
        Ok(self
            .store
            .put_secret(MSG_ACCOUNT_KEY, &acct.to_pickle_json())?)
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

    /// A `msg_account` blob sealed under the wrong key fails AEAD decryption
    /// (`StoreError::Crypto`), not JSON parsing. That must be quarantined and
    /// regenerated too, not just the "decrypts fine but bad pickle" case.
    #[test]
    fn corrupt_msg_account_is_quarantined_and_regenerated() {
        let dir = tmpdir();
        let ik = {
            let e = Engine::open(&dir, "pw").unwrap();
            let acct = e.load_or_create_msg_account().unwrap();
            acct.identity_key()
        }; // `e` fully dropped here: redb is single-writer.

        {
            let other = vartalaap_store::Store::open(
                &dir.join("vault.redb"),
                vartalaap_crypto::VaultKey::from([99u8; 32]),
            )
            .unwrap();
            other.put_secret(MSG_ACCOUNT_KEY, b"junk").unwrap();
        } // dropped before reopening with the real engine below.

        let e = Engine::open(&dir, "pw").unwrap();
        let acct = e.load_or_create_msg_account().unwrap();
        assert_ne!(
            acct.identity_key(),
            ik,
            "corrupted msg_account must be regenerated, not reused"
        );

        let acct2 = e.load_or_create_msg_account().unwrap();
        assert_eq!(
            acct2.identity_key(),
            acct.identity_key(),
            "the regenerated account must have been persisted"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
