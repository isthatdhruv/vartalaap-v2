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

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vartalaap_blobs::{prepare, DecryptSink, EncryptStream};
use vartalaap_crypto::ratchet::{MessagingAccount, PreKeyBundle, RatchetSession};
use vartalaap_identity::{Identity, Profile};
use vartalaap_net::{
    peer_id_bytes, peer_id_from_bytes, BlobRecv, Conn, Incoming, IrohTransport, PeerEvent,
};
use vartalaap_sync::{Conversation, FileRef, Message, MessageKind};

use crate::Engine;

/// A peer's stable id: the 32-byte Vartalaap ID / Iroh PeerId.
pub type PeerKey = [u8; 32];

/// Events emitted by a [`Node`] for the UI / caller to observe.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A peer connected and completed the handshake (pinned via TOFU).
    PeerConnected(PeerKey),
    /// A decrypted application message arrived from `peer`.
    MessageReceived { peer: PeerKey, message: Message },
    /// `peer` is currently typing.
    Typing(PeerKey),
    /// `peer`'s presence changed.
    PresenceChanged { peer: PeerKey, online: bool },
    /// `peer` has read everything up to `up_to` (a lamport watermark).
    ReadReceipt { peer: PeerKey, up_to: u64 },
    /// A peer appeared on the LAN (via mDNS), available to connect to.
    PeerDiscovered(PeerKey),
    /// A file finished downloading and was verified.
    FileReceived {
        peer: PeerKey,
        transfer_id: [u8; 16],
        name: String,
        path: String,
    },
}

/// Frames exchanged on the wire (JSON-encoded).
///
/// `Hello`/`Message` are the durable protocol; the rest are ephemeral gossip
/// (not persisted to the CRDT), carried inside the already-encrypted transport.
#[derive(Serialize, Deserialize)]
enum Wire {
    /// Sent once per connection: the sender's pre-key bundle.
    Hello { bundle: PreKeyBundle },
    /// A ratchet-encrypted [`Message`] payload.
    Message { ciphertext: Vec<u8> },
    /// The sender is typing (ephemeral).
    Typing,
    /// The sender's presence (ephemeral).
    Presence { online: bool },
    /// The sender has read up to this lamport watermark (ephemeral).
    Read { up_to: u64 },
}

/// The plaintext carried inside a ratchet-encrypted [`Wire::Message`].
#[derive(Serialize, Deserialize)]
enum Payload {
    /// A chat message (text or a file reference).
    Chat(Message),
    /// A file offer: the chat message plus the secret key for the upcoming blob
    /// stream. The key travels end-to-end and never touches the persisted CRDT.
    FileOffer { message: Message, key: [u8; 32] },
}

/// A file we've been offered and expect a blob stream for.
struct PendingFile {
    key: [u8; 32],
    sha256: [u8; 32],
    name: String,
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
    /// Peers currently visible on the LAN via mDNS.
    discovered: BTreeSet<PeerKey>,
    /// File transfers offered but not yet received, keyed by transfer id.
    pending_files: HashMap<[u8; 16], PendingFile>,
}

/// A running Vartalaap node.
pub struct Node {
    id: PeerKey,
    messaging: Arc<Mutex<MessagingAccount>>,
    transport: Arc<IrohTransport>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
    /// Where received files are written.
    download_dir: PathBuf,
    /// Present when started with persistence; owns identity/profile/store.
    engine: Option<Arc<Engine>>,
}

impl Node {
    /// Start an in-memory node from a 32-byte identity seed (no persistence).
    /// Mainly for tests; the app uses [`Node::start_persistent`].
    pub async fn start(seed: [u8; 32]) -> Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        let tag = u64::from_le_bytes(seed[..8].try_into().unwrap());
        let download_dir = std::env::temp_dir().join(format!("vartalaap-dl-{tag}"));
        std::fs::create_dir_all(&download_dir)?;
        Self::start_inner(seed, None, download_dir).await
    }

    /// Start a node backed by a persistent, encrypted identity + profile store
    /// rooted at `data_dir` and unlocked with `passphrase`. The networking
    /// keypair is derived from the stored identity, so the PeerId equals the
    /// Vartalaap ID across restarts. Received files land in `data_dir/downloads`.
    pub async fn start_persistent(
        data_dir: &Path,
        passphrase: &str,
    ) -> Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        let engine = Engine::open(data_dir, passphrase)?;
        let seed = engine.identity_seed();
        let download_dir = data_dir.join("downloads");
        std::fs::create_dir_all(&download_dir)?;
        Self::start_inner(seed, Some(Arc::new(engine)), download_dir).await
    }

    async fn start_inner(
        seed: [u8; 32],
        engine: Option<Arc<Engine>>,
        download_dir: PathBuf,
    ) -> Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
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
            let download_dir = download_dir.clone();
            tokio::spawn(async move {
                while let Ok(Some(conn)) = transport.accept().await {
                    let messaging = messaging.clone();
                    let state = state.clone();
                    let events = events.clone();
                    let download_dir = download_dir.clone();
                    tokio::spawn(async move {
                        let _ = setup_connection(conn, id, messaging, state, events, download_dir)
                            .await;
                    });
                }
            });
        }

        // Discovery loop: surface peers appearing/leaving on the LAN.
        {
            let transport = transport.clone();
            let state = state.clone();
            let events = tx.clone();
            tokio::spawn(async move {
                if let Some(mut stream) = transport.peer_events().await {
                    while let Some(ev) = stream.next().await {
                        match ev {
                            PeerEvent::Discovered(pid) => {
                                let key = peer_id_bytes(&pid);
                                if key == id {
                                    continue; // ignore ourselves
                                }
                                let is_new = state.lock().unwrap().discovered.insert(key);
                                if is_new {
                                    let _ = events.send(EngineEvent::PeerDiscovered(key));
                                }
                            }
                            PeerEvent::Expired(pid) => {
                                state
                                    .lock()
                                    .unwrap()
                                    .discovered
                                    .remove(&peer_id_bytes(&pid));
                            }
                        }
                    }
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
                download_dir,
                engine,
            },
            rx,
        ))
    }

    /// This node's Vartalaap ID.
    pub fn id(&self) -> PeerKey {
        self.id
    }

    /// Peers currently visible on the LAN.
    pub fn discovered_peers(&self) -> Vec<PeerKey> {
        self.state
            .lock()
            .unwrap()
            .discovered
            .iter()
            .copied()
            .collect()
    }

    /// A snapshot of the full ordered messages in the conversation with `peer`.
    pub fn conversation(&self, peer: &PeerKey) -> Vec<Message> {
        let st = self.state.lock().unwrap();
        match st.conversations.get(peer) {
            None => Vec::new(),
            Some(conv) => conv.messages_ordered().into_iter().cloned().collect(),
        }
    }

    /// The human-facing Vartalaap ID fingerprint, if persistence is enabled.
    pub fn fingerprint(&self) -> Option<String> {
        self.engine.as_ref().map(|e| e.vartalaap_id())
    }

    /// The stored profile, if persistence is enabled and one is set.
    pub fn profile(&self) -> Result<Option<Profile>> {
        match &self.engine {
            Some(e) => Ok(e.profile()?),
            None => Ok(None),
        }
    }

    /// Persist a new profile (requires persistence).
    pub fn set_profile(&self, profile: Profile) -> Result<()> {
        match &self.engine {
            Some(e) => {
                e.set_profile(profile)?;
                Ok(())
            }
            None => Err(anyhow!("this node has no persistent store")),
        }
    }

    /// The current display name (empty if unset).
    pub fn display_name(&self) -> String {
        self.profile()
            .ok()
            .flatten()
            .map(|p| p.display_name)
            .unwrap_or_default()
    }

    /// Update just the display name, preserving the rest of the profile.
    pub fn set_display_name(&self, name: String) -> Result<()> {
        let mut profile = self.profile()?.unwrap_or(Profile {
            display_name: String::new(),
            bio: String::new(),
            status: String::new(),
            avatar: None,
            updated_at: 0,
        });
        profile.display_name = name;
        profile.updated_at = now_millis();
        self.set_profile(profile)
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
            self.download_dir.clone(),
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
        let plaintext = serde_json::to_vec(&Payload::Chat(message))?;

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

    /// Send a file to a connected peer, end-to-end encrypted. The offer (which
    /// carries the per-file key) travels through the ratchet; the bytes stream
    /// separately, sealed with that key.
    pub async fn send_file(&self, peer: PeerKey, path: &Path) -> Result<()> {
        let meta = prepare(path)?;
        let file_ref = FileRef {
            transfer_id: meta.transfer_id,
            name: meta.name.clone(),
            size: meta.size,
            mime: meta.mime.clone(),
            sha256: meta.sha256,
        };
        let message = {
            let mut st = self.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .create_file(self.id, now_millis(), file_ref)
        };
        let payload = serde_json::to_vec(&Payload::FileOffer {
            message,
            key: meta.key,
        })?;
        let ciphertext = self.encrypt_for(peer, &payload)?;

        let conn = {
            let st = self.state.lock().unwrap();
            st.conns.get(&peer).cloned()
        }
        .ok_or_else(|| anyhow!("no connection to peer; call connect() first"))?;

        // 1) Send the encrypted offer.
        conn.send_frame(&serde_json::to_vec(&Wire::Message { ciphertext })?)
            .await?;
        // 2) Stream the sealed file bytes.
        let mut blob = conn.open_blob(meta.transfer_id).await?;
        let mut enc = EncryptStream::open(path, meta.key)?;
        while let Some(chunk) = enc.next_chunk()? {
            blob.write_chunk(&chunk).await?;
        }
        blob.finish().await?;
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

    /// Send a frame to a connected peer.
    async fn send_to(&self, peer: PeerKey, wire: &Wire) -> Result<()> {
        let conn = {
            let st = self.state.lock().unwrap();
            st.conns.get(&peer).cloned()
        }
        .ok_or_else(|| anyhow!("no connection to peer"))?;
        conn.send_frame(&serde_json::to_vec(wire)?).await?;
        Ok(())
    }

    /// Tell a peer we are typing (ephemeral).
    pub async fn notify_typing(&self, peer: PeerKey) -> Result<()> {
        self.send_to(peer, &Wire::Typing).await
    }

    /// Tell a peer our presence changed (ephemeral).
    pub async fn set_presence(&self, peer: PeerKey, online: bool) -> Result<()> {
        self.send_to(peer, &Wire::Presence { online }).await
    }

    /// Record locally that we've read up to `up_to`, and tell the peer.
    pub async fn mark_read(&self, peer: PeerKey, up_to: u64) -> Result<()> {
        {
            let mut st = self.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .mark_read(self.id, up_to);
        }
        self.send_to(peer, &Wire::Read { up_to }).await
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
    download_dir: PathBuf,
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
        _ => return Err(anyhow!("expected Hello as first frame")),
    }
    let _ = events.send(EngineEvent::PeerConnected(peer));

    // Service the rest of the connection in the background.
    tokio::spawn(async move {
        reader_loop(conn, peer, messaging, state, events, download_dir).await;
    });

    Ok(peer)
}

/// Receive and process streams (control frames + blob transfers) for the life
/// of a connection.
async fn reader_loop(
    conn: Conn,
    peer: PeerKey,
    messaging: Arc<Mutex<MessagingAccount>>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
    download_dir: PathBuf,
) {
    loop {
        match conn.accept_incoming().await {
            Ok(Incoming::Frame(frame)) => {
                if let Ok(wire) = serde_json::from_slice::<Wire>(&frame) {
                    handle_frame(wire, peer, &messaging, &state, &events);
                }
            }
            Ok(Incoming::Blob(blob)) => {
                // Download in the background so further frames aren't blocked.
                let state = state.clone();
                let events = events.clone();
                let download_dir = download_dir.clone();
                tokio::spawn(async move {
                    handle_blob(blob, peer, state, events, download_dir).await;
                });
            }
            Err(_) => break, // connection closed
        }
    }
}

/// Handle one decoded control frame.
fn handle_frame(
    wire: Wire,
    peer: PeerKey,
    messaging: &Arc<Mutex<MessagingAccount>>,
    state: &Arc<Mutex<State>>,
    events: &mpsc::UnboundedSender<EngineEvent>,
) {
    match wire {
        Wire::Hello { bundle } => {
            state.lock().unwrap().bundles.insert(peer, bundle);
        }
        Wire::Message { ciphertext } => {
            if let Ok(payload) = decrypt_payload(peer, &ciphertext, messaging, state) {
                let message = match payload {
                    Payload::Chat(message) => message,
                    Payload::FileOffer { message, key } => {
                        if let MessageKind::File(ref f) = message.kind {
                            state.lock().unwrap().pending_files.insert(
                                f.transfer_id,
                                PendingFile {
                                    key,
                                    sha256: f.sha256,
                                    name: f.name.clone(),
                                },
                            );
                        }
                        message
                    }
                };
                state
                    .lock()
                    .unwrap()
                    .conversations
                    .entry(peer)
                    .or_default()
                    .apply(message.clone());
                let _ = events.send(EngineEvent::MessageReceived { peer, message });
            }
        }
        Wire::Typing => {
            let _ = events.send(EngineEvent::Typing(peer));
        }
        Wire::Presence { online } => {
            let _ = events.send(EngineEvent::PresenceChanged { peer, online });
        }
        Wire::Read { up_to } => {
            state
                .lock()
                .unwrap()
                .conversations
                .entry(peer)
                .or_default()
                .mark_read(peer, up_to);
            let _ = events.send(EngineEvent::ReadReceipt { peer, up_to });
        }
    }
}

/// Receive a blob stream: wait for the matching offer, decrypt each chunk to a
/// file, verify the content hash, and emit [`EngineEvent::FileReceived`].
async fn handle_blob(
    mut blob: BlobRecv,
    peer: PeerKey,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
    download_dir: PathBuf,
) {
    let transfer_id = blob.transfer_id();
    // The offer frame may be processed after this stream is accepted (QUIC does
    // not order across streams), so wait briefly for it to register.
    let Some((key, sha256, name)) = wait_for_offer(&state, transfer_id).await else {
        return;
    };
    let dest = download_dir.join(format!(
        "{:02x}{:02x}-{}",
        transfer_id[0], transfer_id[1], name
    ));
    let mut sink = match DecryptSink::create(&dest, key) {
        Ok(s) => s,
        Err(_) => return,
    };
    loop {
        match blob.next_chunk().await {
            Ok(Some(chunk)) => {
                if sink.write_chunk(&chunk).is_err() {
                    return; // tampered chunk
                }
            }
            Ok(None) => break,
            Err(_) => return,
        }
    }
    if let Ok(path) = sink.finish(sha256) {
        state.lock().unwrap().pending_files.remove(&transfer_id);
        let _ = events.send(EngineEvent::FileReceived {
            peer,
            transfer_id,
            name,
            path: path.to_string_lossy().into_owned(),
        });
    }
}

/// Poll for a pending file offer to appear, up to ~2 seconds.
async fn wait_for_offer(
    state: &Arc<Mutex<State>>,
    transfer_id: [u8; 16],
) -> Option<([u8; 32], [u8; 32], String)> {
    for _ in 0..40 {
        if let Some(p) = state.lock().unwrap().pending_files.get(&transfer_id) {
            return Some((p.key, p.sha256, p.name.clone()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

/// Decrypt a received ciphertext into a [`Payload`]: continue an existing
/// session, or accept a new inbound session from a pre-key (handshake) message.
fn decrypt_payload(
    peer: PeerKey,
    ciphertext: &[u8],
    messaging: &Arc<Mutex<MessagingAccount>>,
    state: &Arc<Mutex<State>>,
) -> Result<Payload> {
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

    /// Drain events until one matches `pred` (or time out).
    async fn wait_for(
        rx: &mut mpsc::UnboundedReceiver<EngineEvent>,
        pred: impl Fn(&EngineEvent) -> bool,
    ) -> EngineEvent {
        timeout(Duration::from_secs(20), async {
            loop {
                match rx.recv().await {
                    Some(e) if pred(&e) => return e,
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for event")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn presence_typing_and_read_receipts() -> Result<()> {
        let (alice, _alice_rx) = Node::start([13u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([14u8; 32]).await?;
        let alice_id = alice.id();
        let bob_id = bob.id();

        timeout(Duration::from_secs(20), alice.connect(bob_id))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        // Typing indicator propagates.
        alice.notify_typing(bob_id).await?;
        wait_for(
            &mut bob_rx,
            |e| matches!(e, EngineEvent::Typing(p) if *p == alice_id),
        )
        .await;

        // Presence propagates.
        alice.set_presence(bob_id, true).await?;
        wait_for(&mut bob_rx, |e| {
            matches!(e, EngineEvent::PresenceChanged { peer, online } if *peer == alice_id && *online)
        })
        .await;

        // Read receipt propagates and updates Bob's view of Alice's read state.
        alice.mark_read(bob_id, 7).await?;
        wait_for(&mut bob_rx, |e| {
            matches!(e, EngineEvent::ReadReceipt { peer, up_to } if *peer == alice_id && *up_to == 7)
        })
        .await;

        Ok(())
    }

    async fn wait_for_file(rx: &mut mpsc::UnboundedReceiver<EngineEvent>) -> String {
        timeout(Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Some(EngineEvent::FileReceived { path, .. }) => return path,
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for a file")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_nodes_transfer_a_file_e2e() -> Result<()> {
        use std::io::Write;

        // A multi-chunk source file of random bytes.
        let mut src = std::env::temp_dir();
        let n: u64 = rand::random();
        src.push(format!("vartalaap-send-{n}.bin"));
        let mut data = vec![0u8; 200_000];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut data);
        std::fs::File::create(&src)?.write_all(&data)?;

        let (alice, _alice_rx) = Node::start([21u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([23u8; 32]).await?;
        let bob_id = bob.id();

        timeout(Duration::from_secs(20), alice.connect(bob_id))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        alice.send_file(bob_id, &src).await?;

        let path = wait_for_file(&mut bob_rx).await;
        let received = std::fs::read(&path)?;
        assert_eq!(received, data, "received file must match the original");

        // The file also appears in Bob's conversation as a File message.
        let convo = bob.conversation(&alice.id());
        assert!(convo.iter().any(|m| matches!(m.kind, MessageKind::File(_))));

        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&path).ok();
        Ok(())
    }
}
