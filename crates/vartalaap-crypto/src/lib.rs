//! At-rest cryptography for Vartalaap.
//!
//! [`derive_key`] stretches a passphrase into a 32-byte key with Argon2id.
//! [`seal`]/[`open`] provide authenticated encryption (XChaCha20-Poly1305) with
//! a random 24-byte nonce prepended to the ciphertext.

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

/// Derive a 32-byte key from a passphrase and a 16-byte salt (Argon2id).
pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .expect("argon2 kdf");
    out
}

/// A symmetric AEAD key, zeroized on drop.
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl From<[u8; 32]> for VaultKey {
    fn from(b: [u8; 32]) -> Self {
        VaultKey(Zeroizing::new(b))
    }
}

const NONCE_LEN: usize = 24;

/// Encrypt `plaintext`; output is `nonce (24 bytes) || ciphertext+tag`.
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

/// Decrypt a blob produced by [`seal`].
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
