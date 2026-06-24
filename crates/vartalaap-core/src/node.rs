//! The networked Vartalaap node: ties identity, transport, the Double Ratchet,
//! and the conversation CRDT into one engine.
//!
//! A [`Node`] binds an Iroh endpoint whose `PeerId` *is* its Vartalaap ID (both
//! are the same Ed25519 key). On every connection the two peers exchange a
//! [`PreKeyBundle`] (`Hello`), pin each other (trust-on-first-use), then send
//! ratchet-encrypted application messages. Each decrypted payload is a
//! [`vartalaap_sync::Message`] applied to the per-peer [`Conversation`], so the
//! two replicas converge. Events are delivered on an unbounded channel.
//!
//! Locking discipline: the `state` and `messaging` mutexes are never held across
//! an `.await`, and never both held at once, so there is no deadlock or blocked
//! reactor.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vartalaap_crypto::ratchet::{MessagingAccount, PreKeyBundle, RatchetSession};
use vartalaap_identity::Identity;
use vartalaap_net::{peer_id_from_bytes, Conn, IrohTransport};
use vartalaap_sync::{Conversation, Message};

/// A peer's stable id: the 32-byte Vartalaap ID / Iroh PeerId.
pub type PeerKey = [u8; 32];

/// Events emitted by a [`Node`] for the UI / caller to observe.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A peer connected and completed the handshake (pinned via TOFU).
    PeerConnected(PeerKey),
    /// A decrypted application message arrived from `peer`.
    MessageReceived { peer: PeerKey, message: Message },
}

/// Frames exchanged on the wire (JSON-encoded).
#[derive(Serialize, Deserialize)]
enum Wire {
    /// Sent once per connection: the sender's pre-key bundle.
    Hello { bundle: PreKeyBundle },
    /// A ratchet-encrypted [`Message`] payload.
    Message { ciphertext: Vec<u8> },
}

#[derive(Default)]
struct State {
    conversations: HashMap<PeerKey, Conversation>,
    sessions: HashMap<PeerKey, RatchetSession>,
    /// The most recent pre-key bundle a peer published to us.
    bundles: HashMap<PeerKey, PreKeyBundle>,
    conns: HashMap<PeerKey, Conn>,
    /// Trust-on-first-use: the key we pinned for each peer.
    pinned: HashMap<PeerKey, PeerKey>,
}

/// A running Vartalaap node.
pub struct Node {
    id: PeerKey,
    messaging: Arc<Mutex<MessagingAccount>>,
    transport: Arc<IrohTransport>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
}

impl Node {
    /// Start a node from a 32-byte identity seed. Binds the LAN transport with
    /// discovery and starts accepting connections. Returns the node and a
    /// receiver of [`EngineEvent`]s.
    pub async fn start(seed: [u8; 32]) -> Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        let id = Identity::from_secret_bytes(seed).public_id().to_bytes();
        let transport = Arc::new(IrohTransport::bind_with_discovery(seed).await?);
        let messaging = Arc::new(Mutex::new(MessagingAccount::new()));
        let state = Arc::new(Mutex::new(State::default()));
        let (tx, rx) = mpsc::unbounded_channel();

        // Accept loop: each incoming connection gets handshaked and serviced.
        {
            let transport = transport.clone();
            let messaging = messaging.clone();
            let state = state.clone();
            let events = tx.clone();
            tokio::spawn(async move {
                while let Ok(Some(conn)) = transport.accept().await {
                    let messaging = messaging.clone();
                    let state = state.clone();
                    let events = events.clone();
                    tokio::spawn(async move {
                        let _ = setup_connection(conn, id, messaging, state, events).await;
                    });
                }
            });
        }

        Ok((
            Node {
                id,
                messaging,
                transport,
                state,
                events: tx,
            },
            rx,
        ))
    }

    /// This node's Vartalaap ID.
    pub fn id(&self) -> PeerKey {
        self.id
    }

    /// Connect to a peer by Vartalaap ID, performing the handshake. Resolves the
    /// address over LAN discovery.
    pub async fn connect(&self, peer: PeerKey) -> Result<()> {
        let peer_id = peer_id_from_bytes(peer)?;
        let conn = self.transport.connect_by_id(peer_id).await?;
        setup_connection(
            conn,
            self.id,
            self.messaging.clone(),
            self.state.clone(),
            self.events.clone(),
        )
        .await?;
        Ok(())
    }

    /// Send a text message to a connected peer, end-to-end encrypted.
    pub async fn send_text(&self, peer: PeerKey, body: &str) -> Result<()> {
        let now = now_millis();
        let message = {
            let mut st = self.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .create_text(self.id, now, body)
        };
        let plaintext = serde_json::to_vec(&message)?;

        let ciphertext = self.encrypt_for(peer, &plaintext)?;

        let conn = {
            let st = self.state.lock().unwrap();
            st.conns.get(&peer).cloned()
        }
        .ok_or_else(|| anyhow!("no connection to peer; call connect() first"))?;

        let frame = serde_json::to_vec(&Wire::Message { ciphertext })?;
        conn.send_frame(&frame).await?;
        Ok(())
    }

    /// Encrypt a payload for `peer`, using the existing ratchet session or
    /// initiating a new one from the peer's published bundle.
    fn encrypt_for(&self, peer: PeerKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        let has_session = self.state.lock().unwrap().sessions.contains_key(&peer);
        if has_session {
            let mut st = self.state.lock().unwrap();
            let session = st.sessions.get_mut(&peer).unwrap();
            Ok(session.encrypt(plaintext)?)
        } else {
            let bundle = {
                let st = self.state.lock().unwrap();
                st.bundles.get(&peer).copied()
            }
            .ok_or_else(|| anyhow!("no pre-key bundle for peer; handshake incomplete"))?;
            let (session, ciphertext) = {
                let acct = self.messaging.lock().unwrap();
                RatchetSession::initiate(&acct, &bundle, plaintext)?
            };
            self.state.lock().unwrap().sessions.insert(peer, session);
            Ok(ciphertext)
        }
    }

    /// A snapshot of the messages in the conversation with `peer`, ordered.
    pub fn conversation_bodies(&self, peer: &PeerKey) -> Vec<String> {
        let st = self.state.lock().unwrap();
        match st.conversations.get(peer) {
            None => Vec::new(),
            Some(conv) => conv
                .messages_ordered()
                .iter()
                .map(|m| m.body.clone())
                .collect(),
        }
    }
}

/// Perform the Hello handshake on a freshly-opened connection, then spawn a
/// reader loop to service subsequent frames. Returns once the peer is known.
async fn setup_connection(
    conn: Conn,
    _my_id: PeerKey,
    messaging: Arc<Mutex<MessagingAccount>>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
) -> Result<PeerKey> {
    // Send our Hello with a fresh pre-key bundle.
    let our_bundle = { messaging.lock().unwrap().prekey_bundle() };
    let hello = serde_json::to_vec(&Wire::Hello { bundle: our_bundle })?;
    conn.send_frame(&hello).await?;

    // Receive the peer's Hello (the first frame they send).
    let first = conn.recv_frame().await?;
    let peer = conn.remote_id_bytes();
    match serde_json::from_slice::<Wire>(&first)? {
        Wire::Hello { bundle } => {
            let mut st = state.lock().unwrap();
            st.bundles.insert(peer, bundle);
            // Trust-on-first-use: pin this id the first time we see it.
            st.pinned.entry(peer).or_insert(peer);
            st.conns.insert(peer, conn.clone());
            st.conversations.entry(peer).or_default();
        }
        Wire::Message { .. } => return Err(anyhow!("expected Hello as first frame")),
    }
    let _ = events.send(EngineEvent::PeerConnected(peer));

    // Service the rest of the connection in the background.
    tokio::spawn(async move {
        reader_loop(conn, peer, messaging, state, events).await;
    });

    Ok(peer)
}

/// Receive and process frames for the lifetime of a connection.
async fn reader_loop(
    conn: Conn,
    peer: PeerKey,
    messaging: Arc<Mutex<MessagingAccount>>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
) {
    loop {
        let frame = match conn.recv_frame().await {
            Ok(f) => f,
            Err(_) => break, // connection closed
        };
        let wire: Wire = match serde_json::from_slice(&frame) {
            Ok(w) => w,
            Err(_) => continue, // skip malformed frames
        };
        match wire {
            Wire::Hello { bundle } => {
                state.lock().unwrap().bundles.insert(peer, bundle);
            }
            Wire::Message { ciphertext } => {
                if let Ok(message) = decrypt_message(peer, &ciphertext, &messaging, &state) {
                    {
                        let mut st = state.lock().unwrap();
                        st.conversations
                            .entry(peer)
                            .or_default()
                            .apply(message.clone());
                    }
                    let _ = events.send(EngineEvent::MessageReceived { peer, message });
                }
            }
        }
    }
}

/// Decrypt a received ciphertext: continue an existing session, or accept a new
/// inbound session from a pre-key (handshake) message.
fn decrypt_message(
    peer: PeerKey,
    ciphertext: &[u8],
    messaging: &Arc<Mutex<MessagingAccount>>,
    state: &Arc<Mutex<State>>,
) -> Result<Message> {
    let has_session = state.lock().unwrap().sessions.contains_key(&peer);
    let plaintext = if has_session {
        let mut st = state.lock().unwrap();
        let session = st.sessions.get_mut(&peer).unwrap();
        session.decrypt(ciphertext)?
    } else {
        let their_identity_key = {
            let st = state.lock().unwrap();
            st.bundles.get(&peer).map(|b| b.identity_key)
        }
        .ok_or_else(|| anyhow!("no bundle for peer; cannot accept session"))?;
        let (session, plaintext) = {
            let mut acct = messaging.lock().unwrap();
            RatchetSession::accept(&mut acct, their_identity_key, ciphertext)?
        };
        state.lock().unwrap().sessions.insert(peer, session);
        plaintext
    };
    Ok(serde_json::from_slice(&plaintext)?)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    /// Drain events until a `MessageReceived` arrives (or time out).
    async fn wait_message(rx: &mut mpsc::UnboundedReceiver<EngineEvent>) -> Message {
        timeout(Duration::from_secs(20), async {
            loop {
                match rx.recv().await {
                    Some(EngineEvent::MessageReceived { message, .. }) => return message,
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for a message")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_nodes_exchange_e2e_messages() -> Result<()> {
        let (alice, mut alice_rx) = Node::start([7u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([9u8; 32]).await?;
        let alice_id = alice.id();
        let bob_id = bob.id();
        assert_ne!(alice_id, bob_id);

        // Alice finds and connects to Bob purely by id (LAN discovery).
        timeout(Duration::from_secs(20), alice.connect(bob_id))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        // Alice -> Bob, end-to-end encrypted.
        alice.send_text(bob_id, "hello bob").await?;
        let got = wait_message(&mut bob_rx).await;
        assert_eq!(got.body, "hello bob");
        assert_eq!(got.author, alice_id);

        // Bob -> Alice on the established session.
        bob.send_text(alice_id, "hi alice").await?;
        let got = wait_message(&mut alice_rx).await;
        assert_eq!(got.body, "hi alice");
        assert_eq!(got.author, bob_id);

        // Both replicas converged to the same two messages.
        assert_eq!(
            alice.conversation_bodies(&bob_id),
            bob.conversation_bodies(&alice_id),
            "conversations must converge"
        );
        assert_eq!(alice.conversation_bodies(&bob_id).len(), 2);

        Ok(())
    }
}
