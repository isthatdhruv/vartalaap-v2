//! End-to-end message encryption via the Olm Double Ratchet (vodozemac).
//!
//! Each peer keeps a long-lived [`MessagingAccount`]. To start talking to a
//! peer you fetch their [`PreKeyBundle`] (published over the network) and call
//! [`RatchetSession::initiate`]; they call [`RatchetSession::accept`] on your
//! first message. Thereafter [`RatchetSession::encrypt`]/[`decrypt`] provide
//! forward secrecy and post-compromise security, and tolerate out-of-order
//! delivery.
//!
//! Wire format for a ciphertext is a single message-type byte followed by the
//! Olm ciphertext bytes (see [`OlmMessage::to_parts`]).

use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};
use vodozemac::Curve25519PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("session creation failed: {0}")]
    SessionCreation(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("expected a pre-key (handshake) message")]
    NotPreKey,
    #[error("malformed ciphertext")]
    Malformed,
}

/// A peer's long-lived messaging keys.
pub struct MessagingAccount {
    inner: Account,
}

impl Default for MessagingAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagingAccount {
    /// Create a fresh messaging account with new identity keys.
    pub fn new() -> Self {
        Self {
            inner: Account::new(),
        }
    }

    /// The account's long-term Curve25519 identity key (32 bytes).
    pub fn identity_key(&self) -> [u8; 32] {
        self.inner.curve25519_key().to_bytes()
    }

    /// Produce a fresh pre-key bundle (identity key + a one-time key) to publish
    /// so others can start a session with us.
    pub fn prekey_bundle(&mut self) -> PreKeyBundle {
        self.inner.generate_one_time_keys(1);
        let one_time_key = *self
            .inner
            .one_time_keys()
            .values()
            .next()
            .expect("one one-time key was just generated");
        self.inner.mark_keys_as_published();
        PreKeyBundle {
            identity_key: self.inner.curve25519_key().to_bytes(),
            one_time_key: one_time_key.to_bytes(),
        }
    }
}

/// Public bundle published by a peer so others can initiate a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreKeyBundle {
    pub identity_key: [u8; 32],
    pub one_time_key: [u8; 32],
}

/// An established 1:1 ratcheted session.
pub struct RatchetSession {
    inner: Session,
}

impl RatchetSession {
    /// Initiate a session toward a peer using their [`PreKeyBundle`]. Returns
    /// the session and the first (pre-key) ciphertext to send, which carries
    /// `first_plaintext`.
    pub fn initiate(
        account: &MessagingAccount,
        bundle: &PreKeyBundle,
        first_plaintext: &[u8],
    ) -> Result<(Self, Vec<u8>), RatchetError> {
        let identity_key = Curve25519PublicKey::from_bytes(bundle.identity_key);
        let one_time_key = Curve25519PublicKey::from_bytes(bundle.one_time_key);
        let mut session = account
            .inner
            .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
            .map_err(|e| RatchetError::SessionCreation(e.to_string()))?;
        let message = session
            .encrypt(first_plaintext)
            .map_err(|e| RatchetError::Encryption(e.to_string()))?;
        Ok((Self { inner: session }, encode(message)))
    }

    /// Accept an incoming session from a peer's first ciphertext. Returns the
    /// session and the decrypted `first_plaintext`.
    pub fn accept(
        account: &mut MessagingAccount,
        their_identity_key: [u8; 32],
        first_wire: &[u8],
    ) -> Result<(Self, Vec<u8>), RatchetError> {
        let message = decode(first_wire)?;
        let prekey = match message {
            OlmMessage::PreKey(pm) => pm,
            OlmMessage::Normal(_) => return Err(RatchetError::NotPreKey),
        };
        let their_identity_key = Curve25519PublicKey::from_bytes(their_identity_key);
        let result = account
            .inner
            .create_inbound_session(SessionConfig::version_1(), their_identity_key, &prekey)
            .map_err(|e| RatchetError::SessionCreation(e.to_string()))?;
        Ok((
            Self {
                inner: result.session,
            },
            result.plaintext,
        ))
    }

    /// Encrypt an application message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let message = self
            .inner
            .encrypt(plaintext)
            .map_err(|e| RatchetError::Encryption(e.to_string()))?;
        Ok(encode(message))
    }

    /// Decrypt a received message. Tolerates out-of-order delivery.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let message = decode(wire)?;
        self.inner
            .decrypt(&message)
            .map_err(|e| RatchetError::Decryption(e.to_string()))
    }
}

/// Encode an [`OlmMessage`] as `type_byte || ciphertext`.
fn encode(message: OlmMessage) -> Vec<u8> {
    let (message_type, mut ciphertext) = message.to_parts();
    let mut out = Vec::with_capacity(1 + ciphertext.len());
    out.push(message_type as u8);
    out.append(&mut ciphertext);
    out
}

/// Decode a wire ciphertext produced by [`encode`].
fn decode(wire: &[u8]) -> Result<OlmMessage, RatchetError> {
    let (message_type, ciphertext) = wire.split_first().ok_or(RatchetError::Malformed)?;
    OlmMessage::from_parts(*message_type as usize, ciphertext).map_err(|_| RatchetError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full handshake then chatter both directions.
    #[test]
    fn handshake_and_bidirectional_messages() {
        let mut bob = MessagingAccount::new();
        let bundle = bob.prekey_bundle();
        let alice = MessagingAccount::new();

        let (mut alice_session, first) =
            RatchetSession::initiate(&alice, &bundle, b"hi bob").unwrap();
        let (mut bob_session, first_plain) =
            RatchetSession::accept(&mut bob, alice.identity_key(), &first).unwrap();
        assert_eq!(first_plain, b"hi bob");

        // Bob replies; Alice reads it (this also ratchets Alice forward).
        let reply = bob_session.encrypt(b"hi alice").unwrap();
        assert_eq!(alice_session.decrypt(&reply).unwrap(), b"hi alice");

        // Alice sends again.
        let m = alice_session.encrypt(b"how are you").unwrap();
        assert_eq!(bob_session.decrypt(&m).unwrap(), b"how are you");
    }

    /// Out-of-order delivery must still decrypt correctly.
    #[test]
    fn tolerates_out_of_order_delivery() {
        let mut bob = MessagingAccount::new();
        let bundle = bob.prekey_bundle();
        let alice = MessagingAccount::new();

        let (mut alice_session, first) =
            RatchetSession::initiate(&alice, &bundle, b"open").unwrap();
        let (mut bob_session, _) =
            RatchetSession::accept(&mut bob, alice.identity_key(), &first).unwrap();
        // Establish two-way so Alice is fully ratcheted.
        let reply = bob_session.encrypt(b"ok").unwrap();
        alice_session.decrypt(&reply).unwrap();

        let m0 = alice_session.encrypt(b"msg0").unwrap();
        let m1 = alice_session.encrypt(b"msg1").unwrap();
        let m2 = alice_session.encrypt(b"msg2").unwrap();

        // Deliver out of order: 2, 0, 1.
        assert_eq!(bob_session.decrypt(&m2).unwrap(), b"msg2");
        assert_eq!(bob_session.decrypt(&m0).unwrap(), b"msg0");
        assert_eq!(bob_session.decrypt(&m1).unwrap(), b"msg1");
    }

    /// A tampered ciphertext is rejected.
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut bob = MessagingAccount::new();
        let bundle = bob.prekey_bundle();
        let alice = MessagingAccount::new();

        let (mut alice_session, first) =
            RatchetSession::initiate(&alice, &bundle, b"hello").unwrap();
        let (mut bob_session, _) =
            RatchetSession::accept(&mut bob, alice.identity_key(), &first).unwrap();
        let reply = bob_session.encrypt(b"hi").unwrap();
        alice_session.decrypt(&reply).unwrap();

        let mut m = alice_session.encrypt(b"secret").unwrap();
        let last = m.len() - 1;
        m[last] ^= 0xff;
        assert!(bob_session.decrypt(&m).is_err());
    }
}
