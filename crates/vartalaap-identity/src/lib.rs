//! Cryptographic identity for Vartalaap.
//!
//! An [`Identity`] wraps an Ed25519 signing key. Its public half is a
//! [`VartalaapId`], whose human-facing fingerprint (base58 of SHA-256 of the
//! public key) is the stable "Vartalaap ID" used to recognise a peer.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use ed25519_dalek::Signature as IdentitySignature;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid public key bytes")]
    BadPublicKey,
}

/// A secret identity: an Ed25519 signing key. The secret bytes are zeroized on
/// drop via [`SigningKey`]'s own `ZeroizeOnDrop`.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh random identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        Identity {
            signing: SigningKey::generate(&mut csprng),
        }
    }

    /// Reconstruct an identity from its 32-byte secret seed.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Identity {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    /// The 32-byte secret seed, wrapped so it is zeroized when dropped.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// This identity's public id.
    pub fn public_id(&self) -> VartalaapId {
        VartalaapId(self.signing.verifying_key())
    }

    /// Sign an arbitrary message.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }
}

/// The public half of an [`Identity`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VartalaapId(VerifyingKey);

impl VartalaapId {
    /// Raw 32-byte public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Parse a public key from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        VerifyingKey::from_bytes(&bytes)
            .map(VartalaapId)
            .map_err(|_| IdentityError::BadPublicKey)
    }

    /// Verify a signature produced by the matching [`Identity`].
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), IdentityError> {
        self.0
            .verify(msg, sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Human-facing "Vartalaap ID": base58(SHA-256(public key)).
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.to_bytes());
        bs58::encode(digest).into_string()
    }
}

/// A user-editable profile. `avatar` holds raw image bytes (kept small).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub display_name: String,
    pub bio: String,
    pub status: String,
    pub avatar: Option<Vec<u8>>,
    pub updated_at: u64,
}

/// A [`Profile`] bound to and signed by an identity, so any peer can verify it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProfile {
    pub id: [u8; 32],
    pub profile: Profile,
    /// Raw 64-byte Ed25519 signature. Stored as `Vec` because serde does not
    /// implement its traits for arrays longer than 32 elements.
    pub sig: Vec<u8>,
}

impl Identity {
    /// Sign a profile, producing a self-verifying record.
    pub fn sign_profile(&self, profile: Profile) -> SignedProfile {
        let bytes = serde_json::to_vec(&profile).expect("profile serializes");
        let sig = self.sign(&bytes);
        SignedProfile {
            id: self.public_id().to_bytes(),
            profile,
            sig: sig.to_bytes().to_vec(),
        }
    }
}

impl SignedProfile {
    /// Verify the signature over the profile, returning the signer's id.
    pub fn verify(&self) -> Result<(VartalaapId, &Profile), IdentityError> {
        let vid = VartalaapId::from_bytes(self.id)?;
        let bytes = serde_json::to_vec(&self.profile).map_err(|_| IdentityError::BadSignature)?;
        let sig_bytes: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vid.verify(&bytes, &sig)?;
        Ok((vid, &self.profile))
    }
}

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
}
