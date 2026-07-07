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
//!
//! Connection-handling free functions (`setup_connection`, `reader_loop`,
//! `handle_frame`, ...) all take a shared [`Ctx`] instead of individual field
//! clones, so new cross-cutting state (e.g. persistence) is threaded through
//! in one place.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use tokio::sync::mpsc;
use vartalaap_blobs::{prepare, DecryptSink, EncryptStream};
use vartalaap_crypto::ratchet::{MessagingAccount, PreKeyBundle, RatchetSession};
use vartalaap_identity::{Identity, Profile};
use vartalaap_net::{
    peer_id_bytes, peer_id_from_bytes, BlobRecv, Conn, Incoming, IrohTransport, PeerEvent,
};
use vartalaap_sync::{Conversation, FileRef, Message, MessageKind};

use crate::persist::Contact;
pub use crate::protocol::{DeliveryStatus, GroupId, GroupInfo, PeerKey, SyncScope};
use crate::protocol::{Payload, PendingFile, Wire};
use crate::Engine;

/// Events emitted by a [`Node`] for the UI / caller to observe.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// A peer connected and completed the handshake (pinned via TOFU).
    PeerConnected(PeerKey),
    /// A peer's connection closed; the UI should mark it offline and allow a
    /// fresh dial. Emitted once, for the connection that was actually live.
    PeerDisconnected(PeerKey),
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
    /// A file transfer was offered but did not complete (timed out, decrypt
    /// failure, or hash mismatch). Surfaced so the receiver isn't left guessing.
    FileFailed {
        peer: PeerKey,
        transfer_id: [u8; 16],
        name: String,
        reason: String,
    },
    /// We were invited to (or learned about) a group.
    GroupInvited(GroupId),
    /// A message arrived in a group.
    GroupMessageReceived { group: GroupId, message: Message },
    /// A vault read/write problem the user should know about (load quarantine
    /// or write failure). The app keeps running on in-memory state.
    StorageWarning { detail: String },
    /// A contact's stored data (profile/alias/pin/last-seen) changed.
    ContactUpdated(PeerKey),
    /// The peer's messaging key differs from the TOFU pin. Sending remains
    /// enabled; the new key takes effect only after accept_new_key().
    PinWarning {
        peer: PeerKey,
        old_fingerprint: String,
        new_fingerprint: String,
    },
    /// A delta sync with `peer` merged `added` missing messages for `scope`.
    HistorySynced {
        peer: PeerKey,
        scope: SyncScope,
        added: usize,
    },
    /// One of our own messages changed delivery status.
    MessageStatus {
        peer: PeerKey,
        id: vartalaap_sync::MessageId,
        status: DeliveryStatus,
    },
}

#[derive(Default)]
struct State {
    conversations: HashMap<PeerKey, Conversation>,
    sessions: HashMap<PeerKey, RatchetSession>,
    /// The most recent pre-key bundle a peer published to us.
    bundles: HashMap<PeerKey, PreKeyBundle>,
    conns: HashMap<PeerKey, Conn>,
    /// Generation tag of the currently-registered connection per peer, so a
    /// stale reader loop only evicts *its own* connection on exit (and a newer
    /// reconnection is never clobbered by an older one shutting down).
    conn_gen: HashMap<PeerKey, u64>,
    /// Monotonic source for `conn_gen`.
    next_gen: u64,
    /// Peers currently visible on the LAN via mDNS.
    discovered: BTreeSet<PeerKey>,
    /// File transfers offered but not yet received, keyed by transfer id.
    pending_files: HashMap<[u8; 16], PendingFile>,
    /// Groups we belong to, keyed by group id.
    groups: HashMap<GroupId, GroupInfo>,
    /// Per-group message history (CRDT), keyed by group id.
    group_convos: HashMap<GroupId, Conversation>,
    /// Known contacts: peers we've completed at least one handshake with.
    contacts: HashMap<PeerKey, Contact>,
    /// Peers for whom we deferred the post-connect send sequence because no
    /// session existed yet (we are the higher-id side; see `post_connect`).
    pending_post_connect: BTreeSet<PeerKey>,
    /// Message ids each peer has confirmed holding, learned from their
    /// SyncHave frames. Session-learned: repopulated fresh by every SyncHave,
    /// not persisted.
    peer_have: HashMap<PeerKey, BTreeSet<vartalaap_sync::MessageId>>,
    /// Our own messages recorded while a peer had no live connection, not yet
    /// confirmed delivered. Session-transient: the CRDT (`conversations`) is
    /// the durable record; this is only "does the UI still owe a Queued
    /// badge," so it does not need to survive a restart.
    queued: HashMap<PeerKey, BTreeSet<vartalaap_sync::MessageId>>,
    /// Vault load-quarantine warnings recorded at startup, before anything
    /// had subscribed to the event channel (those events are sent too, but
    /// go nowhere for a subscriber that attaches after `start_persistent`
    /// returns). Retained here so a late subscriber — the UI, on mount —
    /// can still learn about them via [`Node::startup_warnings`].
    startup_warnings: Vec<String>,
}

/// Shared connection-handling context: every free function that services a
/// connection takes a `ctx: Arc<Ctx>` (or `&Arc<Ctx>`/`&Ctx`) instead of a
/// fistful of individually-cloned fields, so new cross-cutting state (e.g. a
/// persistence handle) is added in one place instead of every signature.
pub(crate) struct Ctx {
    my_id: PeerKey,
    transport: Arc<IrohTransport>,
    messaging: Arc<Mutex<MessagingAccount>>,
    state: Arc<Mutex<State>>,
    events: mpsc::UnboundedSender<EngineEvent>,
    /// Serializes outbound ratchet-session *creation* so two concurrent
    /// first-sends to the same peer cannot each initiate a distinct session
    /// (the peer would accept only one and silently drop the other's messages).
    session_init: Arc<Mutex<()>>,
    /// Where received files are written.
    download_dir: PathBuf,
    /// Present when started with persistence; owns identity/profile/store.
    engine: Option<Arc<Engine>>,
}

/// A running Vartalaap node.
pub struct Node {
    id: PeerKey,
    ctx: Arc<Ctx>,
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
        let messaging = Arc::new(Mutex::new(match &engine {
            Some(engine) => engine.load_or_create_msg_account()?,
            None => MessagingAccount::new(),
        }));
        let (tx, rx) = mpsc::unbounded_channel();

        // Load the persisted roster/history before any connection can mutate
        // it, so a peer that reconnects immediately sees continuity.
        let mut initial = State::default();
        if let Some(engine) = &engine {
            let mut warn_all = Vec::new();
            let (contacts, w) = engine.load_contacts()?;
            warn_all.extend(w);
            for c in contacts {
                initial.contacts.insert(c.peer, c);
            }
            let (convos, w) = engine.load_convos()?;
            warn_all.extend(w);
            for (peer, snap) in convos {
                initial
                    .conversations
                    .insert(peer, Conversation::from_snapshot(snap));
            }
            let (groups, w) = engine.load_groups()?;
            warn_all.extend(w);
            for g in groups {
                initial.groups.insert(g.id, g);
            }
            let (gconvos, w) = engine.load_group_convos()?;
            warn_all.extend(w);
            for (gid, snap) in gconvos {
                initial
                    .group_convos
                    .insert(gid, Conversation::from_snapshot(snap));
            }
            // Retain a copy in state (for a late subscriber) as well as
            // sending the events (for a subscriber already listening).
            initial.startup_warnings = warn_all.clone();
            for detail in warn_all {
                let _ = tx.send(EngineEvent::StorageWarning { detail });
            }
        }
        let state = Arc::new(Mutex::new(initial));

        let ctx = Arc::new(Ctx {
            my_id: id,
            transport,
            messaging,
            state,
            events: tx.clone(),
            session_init: Arc::new(Mutex::new(())),
            download_dir,
            engine,
        });

        // Accept loop: each incoming connection gets handshaked and serviced.
        {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                while let Ok(Some(conn)) = ctx.transport.accept().await {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let _ = setup_connection(conn, ctx).await;
                    });
                }
            });
        }

        // Discovery loop: surface peers appearing/leaving on the LAN. Raced
        // against `transport.closed()` so `shutdown()` actually drains this
        // task — the mDNS subscription stream otherwise never ends on its own
        // (its actor stays alive as long as this task holds `ctx.transport`),
        // which would leak this node's `Ctx` (and its vault handle) forever.
        {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Some(mut stream) = ctx.transport.peer_events().await {
                    let closed = ctx.transport.closed();
                    tokio::pin!(closed);
                    loop {
                        let ev = tokio::select! {
                            ev = stream.next() => ev,
                            _ = &mut closed => break,
                        };
                        let Some(ev) = ev else { break };
                        match ev {
                            PeerEvent::Discovered(pid) => {
                                let key = peer_id_bytes(&pid);
                                if key == ctx.my_id {
                                    continue; // ignore ourselves
                                }
                                let is_new = ctx.state.lock().unwrap().discovered.insert(key);
                                if is_new {
                                    let _ = ctx.events.send(EngineEvent::PeerDiscovered(key));
                                    // Known contact with no live conn → dial so
                                    // queued messages and history sync promptly.
                                    let should_dial = {
                                        let st = ctx.state.lock().unwrap();
                                        st.contacts.contains_key(&key)
                                            && !st.conns.contains_key(&key)
                                    };
                                    if should_dial {
                                        let ctx2 = ctx.clone();
                                        tokio::spawn(async move {
                                            if let Ok(pid) = peer_id_from_bytes(key) {
                                                if let Ok(conn) =
                                                    ctx2.transport.connect_by_id(pid).await
                                                {
                                                    let _ =
                                                        setup_connection(conn, ctx2.clone()).await;
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                            PeerEvent::Expired(pid) => {
                                ctx.state
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

        Ok((Node { id, ctx }, rx))
    }

    /// This node's Vartalaap ID.
    pub fn id(&self) -> PeerKey {
        self.id
    }

    /// Peers currently visible on the LAN.
    pub fn discovered_peers(&self) -> Vec<PeerKey> {
        self.ctx
            .state
            .lock()
            .unwrap()
            .discovered
            .iter()
            .copied()
            .collect()
    }

    /// mDNS-visible peers that are NOT yet contacts (the "Nearby" list).
    pub fn nearby(&self) -> Vec<PeerKey> {
        let st = self.ctx.state.lock().unwrap();
        st.discovered
            .iter()
            .filter(|p| !st.contacts.contains_key(*p))
            .copied()
            .collect()
    }

    /// Peers with a live registered connection.
    pub fn connected_peers(&self) -> Vec<PeerKey> {
        self.ctx
            .state
            .lock()
            .unwrap()
            .conns
            .keys()
            .copied()
            .collect()
    }

    /// Known contacts (persisted when the node is persistent).
    pub fn contacts(&self) -> Vec<Contact> {
        self.ctx
            .state
            .lock()
            .unwrap()
            .contacts
            .values()
            .cloned()
            .collect()
    }

    /// Vault-quarantine warnings recorded while loading persisted state at
    /// startup. The same warnings are also emitted as `StorageWarning`
    /// events at the time they occur, but that's before the app has had a
    /// chance to subscribe — this lets a caller that subscribes only after
    /// `start_persistent` returns (e.g. the UI, on mount) still see them.
    pub fn startup_warnings(&self) -> Vec<String> {
        self.ctx.state.lock().unwrap().startup_warnings.clone()
    }

    /// A snapshot of the full ordered messages in the conversation with `peer`.
    pub fn conversation(&self, peer: &PeerKey) -> Vec<Message> {
        let st = self.ctx.state.lock().unwrap();
        match st.conversations.get(peer) {
            None => Vec::new(),
            Some(conv) => conv.messages_ordered().into_iter().cloned().collect(),
        }
    }

    /// The human-facing Vartalaap ID fingerprint, if persistence is enabled.
    pub fn fingerprint(&self) -> Option<String> {
        self.ctx.engine.as_ref().map(|e| e.vartalaap_id())
    }

    /// The stored profile, if persistence is enabled and one is set.
    pub fn profile(&self) -> Result<Option<Profile>> {
        match &self.ctx.engine {
            Some(e) => Ok(e.profile()?),
            None => Ok(None),
        }
    }

    /// Persist a new profile (requires persistence).
    pub fn set_profile(&self, profile: Profile) -> Result<()> {
        match &self.ctx.engine {
            Some(e) => {
                e.set_profile(profile)?;
                if let Some(engine) = &self.ctx.engine {
                    if let Ok(Some(signed)) = engine.signed_profile() {
                        let peers: Vec<PeerKey> = {
                            let st = self.ctx.state.lock().unwrap();
                            st.conns.keys().copied().collect()
                        };
                        let ctx = self.ctx.clone();
                        tokio::spawn(async move {
                            for peer in peers {
                                let _ = send_payload_ctx(
                                    &ctx,
                                    peer,
                                    &Payload::Profile(Some(signed.clone())),
                                )
                                .await;
                            }
                        });
                    }
                }
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

    /// Set or clear the local alias for a contact.
    pub fn set_alias(&self, peer: PeerKey, alias: Option<String>) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            if let Some(c) = st.contacts.get_mut(&peer) {
                c.alias = alias;
            } else {
                return;
            }
        }
        persist_contact(&self.ctx, &peer);
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
    }

    /// Forget a contact and its conversation (vault + memory). Also purges
    /// every other per-peer map so nothing stale survives to wedge a later
    /// re-handshake: the live `Conn` (dropping it here is enough — the
    /// reader loop's generation guard tolerates the entry already being
    /// gone when the connection actually closes), the ratchet session, the
    /// last-seen pre-key bundle, the connection generation tag, a deferred
    /// post-connect flag, the peer's learned have-set, and any not-yet-
    /// delivered queued message ids.
    pub fn remove_contact(&self, peer: PeerKey) -> Result<()> {
        {
            let mut st = self.ctx.state.lock().unwrap();
            st.contacts.remove(&peer);
            st.conversations.remove(&peer);
            st.conns.remove(&peer);
            st.sessions.remove(&peer);
            st.bundles.remove(&peer);
            st.conn_gen.remove(&peer);
            st.pending_post_connect.remove(&peer);
            st.peer_have.remove(&peer);
            st.queued.remove(&peer);
        }
        if let Some(e) = &self.ctx.engine {
            e.delete_contact(&peer)?;
        }
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
        Ok(())
    }

    /// Accept a changed messaging key: promote pending → pinned.
    pub fn accept_new_key(&self, peer: PeerKey) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            if let Some(c) = st.contacts.get_mut(&peer) {
                if let Some(k) = c.pending_msg_key.take() {
                    c.pinned_msg_key = Some(k);
                }
            } else {
                return;
            }
        }
        persist_contact(&self.ctx, &peer);
        let _ = self.ctx.events.send(EngineEvent::ContactUpdated(peer));
    }

    /// Connect to a peer by Vartalaap ID, performing the handshake. Resolves the
    /// address over LAN discovery.
    pub async fn connect(&self, peer: PeerKey) -> Result<()> {
        let peer_id = peer_id_from_bytes(peer)?;
        let conn = self.ctx.transport.connect_by_id(peer_id).await?;
        setup_connection(conn, self.ctx.clone()).await?;
        Ok(())
    }

    /// Send a text: deliver on a live connection when possible (one dial
    /// attempt if needed), otherwise record locally as Queued — the message
    /// heals over via delta sync on the next connect.
    pub async fn send_text(&self, peer: PeerKey, body: &str) -> Result<(Message, DeliveryStatus)> {
        let conn = self.live_or_dialed_conn(peer).await;

        let message = {
            let mut st = self.ctx.state.lock().unwrap();
            let m =
                st.conversations
                    .entry(peer)
                    .or_default()
                    .create_text(self.id, now_millis(), body);
            if conn.is_none() {
                st.queued.entry(peer).or_default().insert(m.id);
            }
            m
        };
        persist_convo(&self.ctx, &peer);

        let status = match conn {
            None => DeliveryStatus::Queued,
            Some(conn) => {
                let plaintext = serde_json::to_vec(&Payload::Chat(message.clone()))?;
                match encrypt_for(&self.ctx, peer, &plaintext) {
                    Ok(ciphertext) => {
                        let frame = serde_json::to_vec(&Wire::Message { ciphertext })?;
                        if conn.send_frame(&frame).await.is_ok() {
                            DeliveryStatus::Sent
                        } else {
                            self.ctx
                                .state
                                .lock()
                                .unwrap()
                                .queued
                                .entry(peer)
                                .or_default()
                                .insert(message.id);
                            DeliveryStatus::Queued
                        }
                    }
                    Err(_) => {
                        self.ctx
                            .state
                            .lock()
                            .unwrap()
                            .queued
                            .entry(peer)
                            .or_default()
                            .insert(message.id);
                        DeliveryStatus::Queued
                    }
                }
            }
        };
        let _ = self.ctx.events.send(EngineEvent::MessageStatus {
            peer,
            id: message.id,
            status,
        });
        Ok((message, status))
    }

    /// The registered live connection, or the result of one bounded dial.
    async fn live_or_dialed_conn(&self, peer: PeerKey) -> Option<Conn> {
        if let Some(c) = self.ctx.state.lock().unwrap().conns.get(&peer).cloned() {
            return Some(c);
        }
        let dial = tokio::time::timeout(Duration::from_secs(3), self.connect(peer)).await;
        match dial {
            Ok(Ok(())) => self.ctx.state.lock().unwrap().conns.get(&peer).cloned(),
            _ => None,
        }
    }

    /// Send a file to a connected peer, end-to-end encrypted. The offer (which
    /// carries the per-file key) travels through the ratchet; the bytes stream
    /// separately, sealed with that key.
    pub async fn send_file(&self, peer: PeerKey, path: &Path) -> Result<()> {
        // Resolve the connection up front (see `send_text`), trying the same
        // one-dial-attempt path — but file bytes can't queue, so still a hard
        // error if no connection results.
        let conn = self
            .live_or_dialed_conn(peer)
            .await
            .ok_or_else(|| anyhow!("file transfers need a live peer"))?;

        let meta = prepare(path)?;
        let file_ref = FileRef {
            transfer_id: meta.transfer_id,
            name: meta.name.clone(),
            size: meta.size,
            mime: meta.mime.clone(),
            sha256: meta.sha256,
        };
        let message = {
            let mut st = self.ctx.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .create_file(self.id, now_millis(), file_ref)
        };
        persist_convo(&self.ctx, &peer);
        let payload = serde_json::to_vec(&Payload::FileOffer {
            message,
            key: meta.key,
        })?;
        let ciphertext = encrypt_for(&self.ctx, peer, &payload)?;

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

    /// Send a frame to a connected peer.
    async fn send_to(&self, peer: PeerKey, wire: &Wire) -> Result<()> {
        let conn = {
            let st = self.ctx.state.lock().unwrap();
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
            let mut st = self.ctx.state.lock().unwrap();
            st.conversations
                .entry(peer)
                .or_default()
                .mark_read(self.id, up_to);
        }
        persist_convo(&self.ctx, &peer);
        self.send_to(peer, &Wire::Read { up_to }).await
    }

    /// Unread = messages from others above our own read watermark.
    pub fn unread_direct(&self, peer: &PeerKey) -> usize {
        let st = self.ctx.state.lock().unwrap();
        let Some(c) = st.conversations.get(peer) else {
            return 0;
        };
        let mine = c.read_watermark(&self.id);
        c.messages_ordered()
            .iter()
            .filter(|m| m.author != self.id && m.lamport > mine)
            .count()
    }

    pub fn unread_group(&self, gid: &GroupId) -> usize {
        let st = self.ctx.state.lock().unwrap();
        let Some(c) = st.group_convos.get(gid) else {
            return 0;
        };
        let mine = c.read_watermark(&self.id);
        c.messages_ordered()
            .iter()
            .filter(|m| m.author != self.id && m.lamport > mine)
            .count()
    }

    /// Mark the whole 1:1 conversation read; tell the peer if reachable.
    pub async fn mark_read_direct(&self, peer: PeerKey) {
        let up_to = {
            let mut st = self.ctx.state.lock().unwrap();
            let Some(c) = st.conversations.get_mut(&peer) else {
                return;
            };
            let max = c.messages_ordered().last().map(|m| m.lamport).unwrap_or(0);
            let me = self.id;
            c.mark_read(me, max);
            max
        };
        persist_convo(&self.ctx, &peer);
        let _ = self.send_to(peer, &Wire::Read { up_to }).await; // best-effort
    }

    /// Mark a group conversation read locally (spreads via delta sync).
    pub fn mark_read_group(&self, gid: GroupId) {
        {
            let mut st = self.ctx.state.lock().unwrap();
            let Some(c) = st.group_convos.get_mut(&gid) else {
                return;
            };
            let max = c.messages_ordered().last().map(|m| m.lamport).unwrap_or(0);
            let me = self.id;
            c.mark_read(me, max);
        }
        persist_group_convo(&self.ctx, &gid);
    }

    /// A snapshot of the messages in the conversation with `peer`, ordered.
    pub fn conversation_bodies(&self, peer: &PeerKey) -> Vec<String> {
        let st = self.ctx.state.lock().unwrap();
        match st.conversations.get(peer) {
            None => Vec::new(),
            Some(conv) => conv
                .messages_ordered()
                .iter()
                .map(|m| m.body.clone())
                .collect(),
        }
    }

    /// Ordered messages plus, for own messages, the honest delivery status.
    pub fn conversation_with_status(
        &self,
        peer: &PeerKey,
    ) -> Vec<(Message, Option<DeliveryStatus>)> {
        let st = self.ctx.state.lock().unwrap();
        let Some(conv) = st.conversations.get(peer) else {
            return Vec::new();
        };
        conv.messages_ordered()
            .into_iter()
            .map(|m| {
                let status = if m.author == self.id {
                    Some(if delivered(&st, peer, m) {
                        DeliveryStatus::Delivered
                    } else if st.queued.get(peer).is_some_and(|q| q.contains(&m.id)) {
                        DeliveryStatus::Queued
                    } else {
                        DeliveryStatus::Sent
                    })
                } else {
                    None
                };
                (m.clone(), status)
            })
            .collect()
    }

    /// Encrypt a payload for `peer` and send it as a control frame.
    async fn send_payload(&self, peer: PeerKey, payload: &Payload) -> Result<()> {
        send_payload_ctx(&self.ctx, peer, payload).await
    }

    /// Create a group (you are added automatically) and invite each member.
    /// Members you can currently reach are invited; others heal in on reconnect.
    pub async fn create_group(&self, name: String, members: Vec<PeerKey>) -> Result<GroupId> {
        let mut all = members;
        all.push(self.id);
        all.sort();
        all.dedup();
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let info = GroupInfo {
            id,
            name,
            members: all.clone(),
            creator: self.id,
        };
        {
            let mut st = self.ctx.state.lock().unwrap();
            st.groups.insert(id, info.clone());
            st.group_convos.entry(id).or_default();
        }
        persist_group(&self.ctx, &id);
        persist_group_convo(&self.ctx, &id);
        for m in all {
            if m == self.id {
                continue;
            }
            let _ = self
                .send_payload(m, &Payload::GroupInvite(info.clone()))
                .await;
        }
        Ok(id)
    }

    /// Record a text in the group's CRDT and fan it out to every member we can
    /// currently reach (pairwise, E2E). Unlike `send_text`, there is no dial
    /// attempt per member here: the message is always recorded (queued for the
    /// group, in effect), and members we can't reach right now simply miss the
    /// live send — sync (`GroupAnnounce`/`SyncHave`/`SyncDelta`) heals them on
    /// their next connect to any existing member. That's by design, not an
    /// oversight: dialing every member on every send would not scale and the
    /// CRDT already guarantees eventual convergence.
    pub async fn send_group_text(&self, group: GroupId, body: &str) -> Result<Message> {
        let (members, message) = {
            let mut st = self.ctx.state.lock().unwrap();
            let info = st
                .groups
                .get(&group)
                .cloned()
                .ok_or_else(|| anyhow!("unknown group"))?;
            let message =
                st.group_convos
                    .entry(group)
                    .or_default()
                    .create_text(self.id, now_millis(), body);
            (info.members, message)
        };
        persist_group_convo(&self.ctx, &group);
        for m in members {
            if m == self.id {
                continue;
            }
            let _ = self
                .send_payload(
                    m,
                    &Payload::GroupMessage {
                        group,
                        message: message.clone(),
                    },
                )
                .await;
        }
        Ok(message)
    }

    /// Groups this node belongs to.
    pub fn groups(&self) -> Vec<GroupInfo> {
        self.ctx
            .state
            .lock()
            .unwrap()
            .groups
            .values()
            .cloned()
            .collect()
    }

    /// Ordered messages in a group's conversation.
    pub fn group_conversation(&self, group: &GroupId) -> Vec<Message> {
        let st = self.ctx.state.lock().unwrap();
        match st.group_convos.get(group) {
            None => Vec::new(),
            Some(conv) => conv.messages_ordered().into_iter().cloned().collect(),
        }
    }

    /// The on-disk path of a received file if it has finished downloading, else
    /// `None`. Derived from the deterministic download location, so it works
    /// even across restarts (no in-memory bookkeeping required).
    pub fn received_file_path(&self, transfer_id: [u8; 16], name: &str) -> Option<String> {
        let path = blob_dest(&self.ctx.download_dir, &transfer_id, name);
        path.exists().then(|| path.to_string_lossy().into_owned())
    }

    /// Close the endpoint so the accept loop ends and background tasks drain.
    pub async fn shutdown(&self) {
        self.ctx.transport.close().await;
    }
}

/// Snapshot under the lock, write outside it. Failures warn, never crash.
fn persist_convo(ctx: &Ctx, peer: &PeerKey) {
    let Some(engine) = &ctx.engine else { return };
    let snap = {
        let st = ctx.state.lock().unwrap();
        st.conversations.get(peer).map(|c| c.snapshot())
    };
    if let Some(snap) = snap {
        if let Err(e) = engine.save_convo(peer, &snap) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist conversation: {e}"),
            });
        }
    }
}

fn persist_group_convo(ctx: &Ctx, gid: &GroupId) {
    let Some(engine) = &ctx.engine else { return };
    let snap = {
        let st = ctx.state.lock().unwrap();
        st.group_convos.get(gid).map(|c| c.snapshot())
    };
    if let Some(snap) = snap {
        if let Err(e) = engine.save_group_convo(gid, &snap) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist group conversation: {e}"),
            });
        }
    }
}

fn persist_group(ctx: &Ctx, gid: &GroupId) {
    let Some(engine) = &ctx.engine else { return };
    let info = {
        let st = ctx.state.lock().unwrap();
        st.groups.get(gid).cloned()
    };
    if let Some(info) = info {
        if let Err(e) = engine.save_group(&info) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist group: {e}"),
            });
        }
    }
}

fn persist_contact(ctx: &Ctx, peer: &PeerKey) {
    let Some(engine) = &ctx.engine else { return };
    let contact = {
        let st = ctx.state.lock().unwrap();
        st.contacts.get(peer).cloned()
    };
    if let Some(contact) = contact {
        if let Err(e) = engine.save_contact(&contact) {
            let _ = ctx.events.send(EngineEvent::StorageWarning {
                detail: format!("failed to persist contact: {e}"),
            });
        }
    }
}

/// TOFU: pin the first-seen messaging key; flag any later change.
fn check_pin(ctx: &Arc<Ctx>, peer: PeerKey, bundle_identity_key: [u8; 32]) {
    let event = {
        let mut st = ctx.state.lock().unwrap();
        let Some(c) = st.contacts.get_mut(&peer) else {
            return;
        };
        match c.pinned_msg_key {
            None => {
                c.pinned_msg_key = Some(bundle_identity_key);
                None
            }
            Some(pinned) if pinned == bundle_identity_key => {
                c.pending_msg_key = None;
                None
            }
            Some(pinned) => {
                c.pending_msg_key = Some(bundle_identity_key);
                Some(EngineEvent::PinWarning {
                    peer,
                    old_fingerprint: hex::encode(&pinned[..8]),
                    new_fingerprint: hex::encode(&bundle_identity_key[..8]),
                })
            }
        }
    };
    persist_contact(ctx, &peer);
    if let Some(e) = event {
        let _ = ctx.events.send(e);
    }
}

/// Persist the messaging account after any mutation (bundle generation or a
/// successful inbound session accept). Failures warn, never crash.
fn persist_msg_account(ctx: &Ctx) {
    let Some(engine) = &ctx.engine else { return };
    let bytes = ctx.messaging.lock().unwrap().to_pickle_json();
    if let Err(e) = engine.save_msg_account_bytes(&bytes) {
        let _ = ctx.events.send(EngineEvent::StorageWarning {
            detail: format!("failed to persist messaging account: {e}"),
        });
    }
}

/// Encrypt for `peer` on the existing session, or initiate one from the
/// peer's published bundle. `session_init` serializes concurrent first-sends.
fn encrypt_for(ctx: &Ctx, peer: PeerKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    // Fast path: an established session already exists.
    {
        let mut st = ctx.state.lock().unwrap();
        if let Some(session) = st.sessions.get_mut(&peer) {
            return Ok(session.encrypt(plaintext)?);
        }
    }
    // Slow path: create the outbound session. Hold `session_init` across the
    // whole check-initiate-insert so two concurrent first-sends serialize:
    // the loser re-observes the session the winner installed instead of
    // initiating a *second* session the peer would never accept. (This
    // method is fully synchronous, so no `.await` is held under the lock.)
    let _init = ctx.session_init.lock().unwrap();
    {
        let mut st = ctx.state.lock().unwrap();
        if let Some(session) = st.sessions.get_mut(&peer) {
            return Ok(session.encrypt(plaintext)?);
        }
    }
    let bundle = {
        let st = ctx.state.lock().unwrap();
        st.bundles.get(&peer).copied()
    }
    .ok_or_else(|| anyhow!("no pre-key bundle for peer; handshake incomplete"))?;
    let (session, ciphertext) = {
        let acct = ctx.messaging.lock().unwrap();
        RatchetSession::initiate(&acct, &bundle, plaintext)?
    };
    ctx.state.lock().unwrap().sessions.insert(peer, session);
    Ok(ciphertext)
}

/// Encrypt a payload for `peer` and send it on the registered connection.
async fn send_payload_ctx(ctx: &Arc<Ctx>, peer: PeerKey, payload: &Payload) -> Result<()> {
    let ciphertext = encrypt_for(ctx, peer, &serde_json::to_vec(payload)?)?;
    let conn = {
        let st = ctx.state.lock().unwrap();
        st.conns.get(&peer).cloned()
    }
    .ok_or_else(|| anyhow!("no connection to peer"))?;
    conn.send_frame(&serde_json::to_vec(&Wire::Message { ciphertext })?)
        .await?;
    Ok(())
}

/// Connect-time exchange. The lower-id side runs this immediately; the
/// higher-id side runs it once a session is established (initiator rule).
async fn post_connect(ctx: Arc<Ctx>, peer: PeerKey) {
    // 1) Publish our signed profile (or explicitly "none yet"). This send is
    // unconditional — not just when we have a profile — because it is also
    // the lower-id side's deterministic session-establishing message: the
    // higher side's `maybe_flush_post_connect` only fires once a session
    // exists, so if the lower side stayed silent here (e.g. no profile set),
    // the higher side would defer forever and never flush its own profile.
    let signed = ctx
        .engine
        .as_ref()
        .and_then(|e| e.signed_profile().ok().flatten());
    let _ = send_payload_ctx(&ctx, peer, &Payload::Profile(signed)).await;

    // 2) Announce shared groups + offer sync for every shared scope.
    let (announces, haves) = {
        let st = ctx.state.lock().unwrap();
        let announces: Vec<GroupInfo> = st
            .groups
            .values()
            .filter(|g| g.members.contains(&peer))
            .cloned()
            .collect();
        let mut haves: Vec<(SyncScope, Vec<vartalaap_sync::MessageId>)> = Vec::new();
        let direct_have = st
            .conversations
            .get(&peer)
            .map(|c| c.have().into_iter().collect())
            .unwrap_or_default();
        haves.push((SyncScope::Direct, direct_have));
        for g in &announces {
            let ids = st
                .group_convos
                .get(&g.id)
                .map(|c| c.have().into_iter().collect())
                .unwrap_or_default();
            haves.push((SyncScope::Group(g.id), ids));
        }
        (announces, haves)
    };
    for g in announces {
        let _ = send_payload_ctx(&ctx, peer, &Payload::GroupAnnounce(g)).await;
    }
    for (scope, ids) in haves {
        let _ = send_payload_ctx(&ctx, peer, &Payload::SyncHave { scope, ids }).await;
    }
}

/// The higher-id side defers its post-connect sends until a session
/// exists (the lower side initiates), then flushes exactly once.
fn maybe_flush_post_connect(ctx: &Arc<Ctx>, peer: PeerKey) {
    let should = {
        let mut st = ctx.state.lock().unwrap();
        st.sessions.contains_key(&peer) && st.pending_post_connect.remove(&peer)
    };
    if should {
        let ctx = ctx.clone();
        tokio::spawn(async move { post_connect(ctx, peer).await });
    }
}

/// Perform the Hello handshake on a freshly-opened connection, then spawn a
/// reader loop to service subsequent frames. Returns once the peer is known.
async fn setup_connection(conn: Conn, ctx: Arc<Ctx>) -> Result<PeerKey> {
    // Send our Hello with a fresh pre-key bundle.
    let our_bundle = { ctx.messaging.lock().unwrap().prekey_bundle() };
    persist_msg_account(&ctx);
    let hello = serde_json::to_vec(&Wire::Hello { bundle: our_bundle })?;
    conn.send_frame(&hello).await?;

    // Receive the peer's Hello. Each frame rides its own QUIC stream and QUIC
    // does not order across streams, so an application frame can legally be
    // accepted before the Hello. Process any such early frames best-effort and
    // keep waiting for the Hello instead of aborting the whole connection.
    let peer = conn.remote_id_bytes();
    let bundle = loop {
        let frame = conn.recv_frame().await?;
        match serde_json::from_slice::<Wire>(&frame) {
            Ok(Wire::Hello { bundle }) => break bundle,
            Ok(other) => handle_frame(other, peer, &ctx),
            Err(_) => continue, // skip malformed frames
        }
    };
    let now = now_millis();
    let (generation, is_new_contact) = {
        let mut st = ctx.state.lock().unwrap();
        st.bundles.insert(peer, bundle);
        st.conns.insert(peer, conn.clone());
        let generation = st.next_gen;
        st.next_gen += 1;
        st.conn_gen.insert(peer, generation);
        st.conversations.entry(peer).or_default();
        // Trust-on-first-use: upsert the roster entry for this peer.
        let is_new = !st.contacts.contains_key(&peer);
        let entry = st.contacts.entry(peer).or_insert_with(|| Contact {
            peer,
            profile: None,
            alias: None,
            pinned_msg_key: None, // pinned by check_pin below
            pending_msg_key: None,
            last_seen: now,
            added_at: now,
        });
        entry.last_seen = now;
        (generation, is_new)
    };
    persist_contact(&ctx, &peer);
    check_pin(&ctx, peer, bundle.identity_key);
    if is_new_contact {
        let _ = ctx.events.send(EngineEvent::ContactUpdated(peer));
    }
    let _ = ctx.events.send(EngineEvent::PeerConnected(peer));

    // Initiator rule: the lower-id side sends first, so the higher side
    // always has a session to decrypt into by the time it flushes its own
    // deferred post-connect sends (see `maybe_flush_post_connect`).
    if ctx.my_id < peer {
        let ctx2 = ctx.clone();
        tokio::spawn(async move { post_connect(ctx2, peer).await });
    } else {
        ctx.state.lock().unwrap().pending_post_connect.insert(peer);
    }

    // Service the rest of the connection in the background.
    tokio::spawn(async move {
        reader_loop(conn, peer, generation, ctx).await;
    });

    Ok(peer)
}

/// Receive and process streams (control frames + blob transfers) for the life
/// of a connection.
async fn reader_loop(conn: Conn, peer: PeerKey, generation: u64, ctx: Arc<Ctx>) {
    loop {
        match conn.accept_incoming().await {
            Ok(Incoming::Frame(frame)) => {
                if let Ok(wire) = serde_json::from_slice::<Wire>(&frame) {
                    handle_frame(wire, peer, &ctx);
                }
            }
            Ok(Incoming::Blob(blob)) => {
                // Download in the background so further frames aren't blocked.
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    handle_blob(blob, peer, ctx).await;
                });
            }
            Err(_) => break, // connection closed
        }
    }
    // The connection is gone. Evict it so the next send/dial doesn't reuse a
    // dead `Conn`, but only if it is still the registered one — a newer
    // reconnection (higher generation) must not be torn down by this old loop.
    let was_current = {
        let mut st = ctx.state.lock().unwrap();
        if st.conn_gen.get(&peer).copied() == Some(generation) {
            st.conns.remove(&peer);
            st.conn_gen.remove(&peer);
            st.sessions.remove(&peer); // sessions are per-connection
            if let Some(c) = st.contacts.get_mut(&peer) {
                c.last_seen = now_millis();
            }
            true
        } else {
            false
        }
    };
    if was_current {
        persist_contact(&ctx, &peer);
        let _ = ctx.events.send(EngineEvent::PeerDisconnected(peer));
        let _ = ctx.events.send(EngineEvent::ContactUpdated(peer));
    }
}

/// Handle one decoded control frame.
fn handle_frame(wire: Wire, peer: PeerKey, ctx: &Arc<Ctx>) {
    match wire {
        Wire::Hello { bundle } => {
            let identity_key = bundle.identity_key;
            ctx.state.lock().unwrap().bundles.insert(peer, bundle);
            check_pin(ctx, peer, identity_key);
        }
        Wire::Message { ciphertext } => {
            let Ok(payload) = decrypt_payload(peer, &ciphertext, ctx) else {
                return;
            };
            maybe_flush_post_connect(ctx, peer);
            match payload {
                Payload::Chat(message) => apply_direct_message(peer, message, ctx),
                Payload::FileOffer { message, key } => {
                    if let MessageKind::File(ref f) = message.kind {
                        ctx.state.lock().unwrap().pending_files.insert(
                            f.transfer_id,
                            PendingFile {
                                key,
                                sha256: f.sha256,
                                name: f.name.clone(),
                            },
                        );
                    }
                    apply_direct_message(peer, message, ctx);
                }
                Payload::GroupInvite(info) => {
                    let id = info.id;
                    let inserted = {
                        let mut st = ctx.state.lock().unwrap();
                        let fresh = !st.groups.contains_key(&id);
                        st.groups.entry(id).or_insert(info);
                        st.group_convos.entry(id).or_default();
                        fresh
                    };
                    persist_group(ctx, &id);
                    persist_group_convo(ctx, &id);
                    let _ = ctx.events.send(EngineEvent::GroupInvited(id));
                    if inserted {
                        // A live invite can also arrive after messages we
                        // missed (e.g. we were mid-reconnect); offer sync so
                        // the inviter backfills our history for this group.
                        offer_group_sync(ctx, peer, id);
                    }
                }
                Payload::GroupMessage { group, message } => {
                    // Membership gate: a handshaked peer is not automatically
                    // a group member. Without this check, any connected peer
                    // could inject into a group it was never invited to (or
                    // fabricate a random, never-created GroupId), silently
                    // creating an unbounded number of phantom `gconvo/` vault
                    // blobs. Drop the frame unless we recognize the group and
                    // both ends are members of it.
                    {
                        let mut st = ctx.state.lock().unwrap();
                        if !group_allows(&st, &group, &peer, &ctx.my_id) {
                            return;
                        }
                        st.group_convos
                            .entry(group)
                            .or_default()
                            .apply(message.clone());
                    }
                    persist_group_convo(ctx, &group);
                    let _ = ctx
                        .events
                        .send(EngineEvent::GroupMessageReceived { group, message });
                }
                // `None` means "no profile yet" — the sender still had to
                // transmit *something* to establish the session (see
                // `post_connect`), so there is nothing further to do here.
                Payload::Profile(None) => {}
                Payload::Profile(Some(signed)) => {
                    let Ok((vid, profile)) = signed.verify() else {
                        return;
                    };
                    // The profile must be signed by the connected peer itself.
                    if vid.to_bytes() != peer {
                        return;
                    }
                    let updated = {
                        let mut st = ctx.state.lock().unwrap();
                        let Some(c) = st.contacts.get_mut(&peer) else {
                            return;
                        };
                        let newer = c
                            .profile
                            .as_ref()
                            .map(|p| profile.updated_at > p.updated_at)
                            .unwrap_or(true);
                        if newer {
                            c.profile = Some(profile.clone());
                        }
                        newer
                    };
                    if updated {
                        persist_contact(ctx, &peer);
                        let _ = ctx.events.send(EngineEvent::ContactUpdated(peer));
                    }
                }
                Payload::GroupAnnounce(info) => {
                    // Only meaningful if the sender and we are both members.
                    if !info.members.contains(&peer) || !info.members.contains(&ctx.my_id) {
                        return;
                    }
                    let id = info.id;
                    let inserted = {
                        let mut st = ctx.state.lock().unwrap();
                        let fresh = !st.groups.contains_key(&id);
                        st.groups.entry(id).or_insert(info);
                        st.group_convos.entry(id).or_default();
                        fresh
                    };
                    if inserted {
                        persist_group(ctx, &id);
                        persist_group_convo(ctx, &id);
                        let _ = ctx.events.send(EngineEvent::GroupInvited(id));
                        // We just learned this group exists, so our
                        // post_connect sent no SyncHave for it. Offer one now
                        // so the announcer backfills us — without this, a
                        // late-joining member never receives missed history.
                        offer_group_sync(ctx, peer, id);
                    }
                }
                Payload::SyncHave { scope, ids } => {
                    if matches!(scope, SyncScope::Direct) {
                        absorb_peer_have(ctx, peer, &ids);
                    }
                    if let Some(delta) = build_delta(ctx, peer, scope, &ids) {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            let _ = send_payload_ctx(&ctx2, peer, &delta).await;
                        });
                    }
                }
                Payload::SyncDelta {
                    scope,
                    messages,
                    reactions,
                    read,
                } => {
                    apply_delta(ctx, peer, scope, messages, reactions, read);
                }
            }
        }
        Wire::Typing => {
            let _ = ctx.events.send(EngineEvent::Typing(peer));
        }
        Wire::Presence { online } => {
            let _ = ctx
                .events
                .send(EngineEvent::PresenceChanged { peer, online });
        }
        Wire::Read { up_to } => {
            ctx.state
                .lock()
                .unwrap()
                .conversations
                .entry(peer)
                .or_default()
                .mark_read(peer, up_to);
            persist_convo(ctx, &peer);
            let _ = ctx.events.send(EngineEvent::ReadReceipt { peer, up_to });

            let newly_delivered: Vec<vartalaap_sync::MessageId> = {
                let mut st = ctx.state.lock().unwrap();
                let mine: Vec<_> = st
                    .conversations
                    .get(&peer)
                    .map(|c| {
                        c.messages_ordered()
                            .into_iter()
                            .filter(|m| m.author == ctx.my_id && m.lamport <= up_to)
                            .map(|m| m.id)
                            .collect()
                    })
                    .unwrap_or_default();
                let have = st.peer_have.entry(peer).or_default();
                let fresh: Vec<_> = mine.into_iter().filter(|i| !have.contains(i)).collect();
                have.extend(fresh.iter().copied());
                if let Some(q) = st.queued.get_mut(&peer) {
                    for i in &fresh {
                        q.remove(i);
                    }
                }
                fresh
            };
            for id in newly_delivered {
                let _ = ctx.events.send(EngineEvent::MessageStatus {
                    peer,
                    id,
                    status: DeliveryStatus::Delivered,
                });
            }
        }
    }
}

/// Apply a 1:1 message to the per-peer conversation and notify listeners.
fn apply_direct_message(peer: PeerKey, message: Message, ctx: &Arc<Ctx>) {
    {
        let mut st = ctx.state.lock().unwrap();
        st.conversations
            .entry(peer)
            .or_default()
            .apply(message.clone());
        if let Some(c) = st.contacts.get_mut(&peer) {
            c.last_seen = now_millis();
        }
    }
    persist_convo(ctx, &peer);
    persist_contact(ctx, &peer);
    let _ = ctx
        .events
        .send(EngineEvent::MessageReceived { peer, message });
}

/// Send a SyncHave for one group scope (used when we learn a group exists
/// mid-connection, after post_connect already ran).
fn offer_group_sync(ctx: &Arc<Ctx>, peer: PeerKey, gid: GroupId) {
    let ids: Vec<vartalaap_sync::MessageId> = {
        let st = ctx.state.lock().unwrap();
        st.group_convos
            .get(&gid)
            .map(|c| c.have().into_iter().collect())
            .unwrap_or_default()
    };
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let _ = send_payload_ctx(
            &ctx2,
            peer,
            &Payload::SyncHave {
                scope: SyncScope::Group(gid),
                ids,
            },
        )
        .await;
    });
}

/// Membership gate for anything group-scoped: true only if `gid` names a
/// group we know about and both `peer` and `me` are members of it. Shared by
/// the inbound `Payload::GroupMessage` handler and the `build_delta` /
/// `apply_delta` sync paths, so a peer we've merely handshaked with (but
/// never invited to this group) can neither inject into nor read a group's
/// history — it isn't enough to know the random `GroupId`.
fn group_allows(st: &State, gid: &GroupId, peer: &PeerKey, me: &PeerKey) -> bool {
    match st.groups.get(gid) {
        Some(g) => g.members.contains(peer) && g.members.contains(me),
        None => false,
    }
}

/// Answer a peer's have-list with everything they're missing in `scope`.
/// Returns None only when the scope is invalid (unknown/forbidden group).
fn build_delta(
    ctx: &Arc<Ctx>,
    peer: PeerKey,
    scope: SyncScope,
    their_ids: &[vartalaap_sync::MessageId],
) -> Option<Payload> {
    let have: std::collections::BTreeSet<_> = their_ids.iter().copied().collect();
    let st = ctx.state.lock().unwrap();
    let convo = match scope {
        SyncScope::Direct => st.conversations.get(&peer),
        SyncScope::Group(gid) => {
            // Membership gate: never leak a group convo to a non-member.
            if !group_allows(&st, &gid, &peer, &ctx.my_id) {
                return None;
            }
            st.group_convos.get(&gid)
        }
    }?;
    let snap = convo.snapshot();
    Some(Payload::SyncDelta {
        scope,
        messages: convo.delta_since(&have),
        reactions: snap.reactions,
        read: snap.read,
    })
}

/// Merge a received delta into the right conversation; one event per delta.
fn apply_delta(
    ctx: &Arc<Ctx>,
    peer: PeerKey,
    scope: SyncScope,
    messages: Vec<Message>,
    reactions: Vec<vartalaap_sync::Reaction>,
    read: Vec<([u8; 32], u64)>,
) {
    let added = {
        let mut st = ctx.state.lock().unwrap();
        let convo = match scope {
            SyncScope::Direct => st.conversations.entry(peer).or_default(),
            SyncScope::Group(gid) => {
                if !group_allows(&st, &gid, &peer, &ctx.my_id) {
                    return;
                }
                st.group_convos.entry(gid).or_default()
            }
        };
        let before = convo.len();
        for m in messages {
            convo.apply(m);
        }
        for r in reactions {
            convo.react(r.message, r.author, r.emoji);
        }
        for (author, lamport) in read {
            convo.mark_read(author, lamport);
        }
        convo.len() - before
    };
    match scope {
        SyncScope::Direct => persist_convo(ctx, &peer),
        SyncScope::Group(gid) => persist_group_convo(ctx, &gid),
    }
    let _ = ctx
        .events
        .send(EngineEvent::HistorySynced { peer, scope, added });

    // A non-empty Direct-scope delta just changed OUR have-set. `their_ids`
    // (which drove the delta we just applied) was THEIR have-set, so this
    // exchange alone never tells the sender whether we now hold what they
    // sent — the sender's own queued/own-message bookkeeping needs a fresh
    // SyncHave from us to learn that (see `absorb_peer_have`). Bounded: the
    // reply's own delta against our updated have-set is empty, so this does
    // not loop.
    if matches!(scope, SyncScope::Direct) && added > 0 {
        let ids: Vec<vartalaap_sync::MessageId> = {
            let st = ctx.state.lock().unwrap();
            st.conversations
                .get(&peer)
                .map(|c| c.have().into_iter().collect())
                .unwrap_or_default()
        };
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            let _ = send_payload_ctx(
                &ctx2,
                peer,
                &Payload::SyncHave {
                    scope: SyncScope::Direct,
                    ids,
                },
            )
            .await;
        });
    }
}

/// Single source of truth for "has `peer` confirmed holding our message `m`":
/// either their last SyncHave listed it, or their read watermark reached its
/// lamport. Used by both the `MessageStatus` event emission and
/// `conversation_with_status`.
fn delivered(st: &State, peer: &PeerKey, m: &Message) -> bool {
    st.peer_have.get(peer).is_some_and(|h| h.contains(&m.id))
        || st
            .conversations
            .get(peer)
            .is_some_and(|c| c.read_watermark(peer) >= m.lamport)
}

/// Learn what the peer holds; flip newly-covered own messages to Delivered.
fn absorb_peer_have(ctx: &Arc<Ctx>, peer: PeerKey, ids: &[vartalaap_sync::MessageId]) {
    let newly_delivered: Vec<vartalaap_sync::MessageId> = {
        let mut st = ctx.state.lock().unwrap();
        let have = st.peer_have.entry(peer).or_default();
        let fresh: Vec<_> = ids.iter().filter(|i| !have.contains(*i)).copied().collect();
        have.extend(ids.iter().copied());
        if let Some(q) = st.queued.get_mut(&peer) {
            for i in ids {
                q.remove(i);
            }
        }
        let mine: std::collections::BTreeSet<_> = st
            .conversations
            .get(&peer)
            .map(|c| {
                c.messages_ordered()
                    .into_iter()
                    .filter(|m| m.author == ctx.my_id)
                    .map(|m| m.id)
                    .collect()
            })
            .unwrap_or_default();
        fresh.into_iter().filter(|i| mine.contains(i)).collect()
    };
    for id in newly_delivered {
        let _ = ctx.events.send(EngineEvent::MessageStatus {
            peer,
            id,
            status: DeliveryStatus::Delivered,
        });
    }
}

/// Receive a blob stream: wait for the matching offer, decrypt each chunk to a
/// file, verify the content hash, and emit [`EngineEvent::FileReceived`].
async fn handle_blob(mut blob: BlobRecv, peer: PeerKey, ctx: Arc<Ctx>) {
    let transfer_id = blob.transfer_id();
    // The offer frame may be processed after this stream is accepted (QUIC does
    // not order across streams), so wait briefly for it to register.
    let Some((key, sha256, name)) = wait_for_offer(&ctx.state, transfer_id).await else {
        // No offer arrived, so we have no key/name to even describe it.
        return;
    };
    let dest = blob_dest(&ctx.download_dir, &transfer_id, &name);
    let mut sink = match DecryptSink::create(&dest, key) {
        Ok(s) => s,
        Err(e) => {
            let _ = ctx.events.send(EngineEvent::FileFailed {
                peer,
                transfer_id,
                name,
                reason: format!("cannot create download file: {e}"),
            });
            return;
        }
    };
    loop {
        match blob.next_chunk().await {
            Ok(Some(chunk)) => {
                if sink.write_chunk(&chunk).is_err() {
                    let _ = ctx.events.send(EngineEvent::FileFailed {
                        peer,
                        transfer_id,
                        name,
                        reason: "decryption failed (corrupt or tampered data)".into(),
                    });
                    return;
                }
            }
            Ok(None) => break,
            Err(_) => {
                let _ = ctx.events.send(EngineEvent::FileFailed {
                    peer,
                    transfer_id,
                    name,
                    reason: "connection interrupted mid-transfer".into(),
                });
                return;
            }
        }
    }
    match sink.finish(sha256) {
        Ok(path) => {
            ctx.state.lock().unwrap().pending_files.remove(&transfer_id);
            let _ = ctx.events.send(EngineEvent::FileReceived {
                peer,
                transfer_id,
                name,
                path: path.to_string_lossy().into_owned(),
            });
        }
        Err(_) => {
            let _ = ctx.events.send(EngineEvent::FileFailed {
                peer,
                transfer_id,
                name,
                reason: "integrity check failed (hash mismatch)".into(),
            });
        }
    }
}

/// Deterministic on-disk location for a received blob — used both when writing
/// it and when later looking it up, so the two never drift.
fn blob_dest(download_dir: &Path, transfer_id: &[u8; 16], name: &str) -> PathBuf {
    download_dir.join(format!(
        "{:02x}{:02x}-{}",
        transfer_id[0], transfer_id[1], name
    ))
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
fn decrypt_payload(peer: PeerKey, ciphertext: &[u8], ctx: &Arc<Ctx>) -> Result<Payload> {
    // Look up and use the session in ONE lock scope: sessions are evicted by
    // reader_loop when a connection dies, so a separate "has session" check
    // followed by a second lock + unwrap would race that eviction and panic
    // while holding the state guard (poisoning the mutex node-wide). decrypt
    // is synchronous, so no `.await` runs under the lock.
    let attempt = {
        let mut st = ctx.state.lock().unwrap();
        st.sessions
            .get_mut(&peer)
            .map(|session| session.decrypt(ciphertext))
    };
    let plaintext = match attempt {
        Some(Ok(p)) => p,
        // The peer initiated a competing session (both sides sent first
        // messages concurrently, or the peer restarted). We always try to
        // recover this message via a fresh accept — otherwise its content
        // is silently and permanently lost, which is exactly the bug this
        // task fixes. Deterministic winner for which session survives
        // going forward: the initiation from the lexicographically LOWER
        // id. We adopt theirs as our stored session only if they are the
        // lower side; otherwise we keep our own stored session (so both
        // sides converge on exactly one survivor) but still deliver the
        // content we just recovered. Any remainder heals via delta sync
        // (Task 8).
        Some(Err(_)) if vartalaap_crypto::ratchet::is_prekey(ciphertext) => {
            let their_identity_key = {
                let st = ctx.state.lock().unwrap();
                st.bundles.get(&peer).map(|b| b.identity_key)
            }
            .ok_or_else(|| anyhow!("no bundle for peer; cannot accept session"))?;
            let (session, plaintext) = {
                let mut acct = ctx.messaging.lock().unwrap();
                RatchetSession::accept(&mut acct, their_identity_key, ciphertext)?
            };
            if peer < ctx.my_id {
                ctx.state.lock().unwrap().sessions.insert(peer, session);
            }
            persist_msg_account(ctx);
            plaintext
        }
        Some(Err(e)) => return Err(e.into()),
        // No session yet: accept the inbound handshake unconditionally.
        None => {
            let their_identity_key = {
                let st = ctx.state.lock().unwrap();
                st.bundles.get(&peer).map(|b| b.identity_key)
            }
            .ok_or_else(|| anyhow!("no bundle for peer; cannot accept session"))?;
            let (session, plaintext) = {
                let mut acct = ctx.messaging.lock().unwrap();
                RatchetSession::accept(&mut acct, their_identity_key, ciphertext)?
            };
            ctx.state.lock().unwrap().sessions.insert(peer, session);
            persist_msg_account(ctx);
            plaintext
        }
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

    async fn wait_for_file(
        rx: &mut mpsc::UnboundedReceiver<EngineEvent>,
    ) -> ([u8; 16], String, String) {
        timeout(Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Some(EngineEvent::FileReceived {
                        transfer_id,
                        name,
                        path,
                        ..
                    }) => return (transfer_id, name, path),
                    Some(EngineEvent::FileFailed { reason, .. }) => {
                        panic!("file transfer failed: {reason}")
                    }
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

        let (transfer_id, name, path) = wait_for_file(&mut bob_rx).await;
        let received = std::fs::read(&path)?;
        assert_eq!(received, data, "received file must match the original");

        // The GUI surfaces the download via `received_file_path`; it must resolve
        // to the same on-disk file.
        assert_eq!(
            bob.received_file_path(transfer_id, &name).as_deref(),
            Some(path.as_str()),
            "received_file_path must locate the downloaded file"
        );

        // The file also appears in Bob's conversation as a File message.
        let convo = bob.conversation(&alice.id());
        assert!(convo.iter().any(|m| matches!(m.kind, MessageKind::File(_))));

        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&path).ok();
        Ok(())
    }

    async fn wait_for_group(
        rx: &mut mpsc::UnboundedReceiver<EngineEvent>,
        gid: GroupId,
    ) -> Message {
        timeout(Duration::from_secs(30), async {
            loop {
                match rx.recv().await {
                    Some(EngineEvent::GroupMessageReceived { group, message }) if group == gid => {
                        return message
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .expect("timed out waiting for a group message")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn three_nodes_group_chat() -> Result<()> {
        let (alice, mut alice_rx) = Node::start([31u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([32u8; 32]).await?;
        let (carol, mut carol_rx) = Node::start([33u8; 32]).await?;
        let (aid, bid, cid) = (alice.id(), bob.id(), carol.id());

        // Establish the full mesh (every pair connected).
        let secs = Duration::from_secs(20);
        timeout(secs, alice.connect(bid))
            .await
            .map_err(|_| anyhow!("a-b timeout"))??;
        timeout(secs, alice.connect(cid))
            .await
            .map_err(|_| anyhow!("a-c timeout"))??;
        timeout(secs, bob.connect(cid))
            .await
            .map_err(|_| anyhow!("b-c timeout"))??;

        // Alice creates a group; Bob and Carol receive invites.
        let gid = alice.create_group("study".into(), vec![bid, cid]).await?;
        wait_for(
            &mut bob_rx,
            |e| matches!(e, EngineEvent::GroupInvited(g) if *g == gid),
        )
        .await;
        wait_for(
            &mut carol_rx,
            |e| matches!(e, EngineEvent::GroupInvited(g) if *g == gid),
        )
        .await;

        // Alice → group reaches both.
        alice.send_group_text(gid, "hello team").await?;
        assert_eq!(wait_for_group(&mut bob_rx, gid).await.body, "hello team");
        assert_eq!(wait_for_group(&mut carol_rx, gid).await.body, "hello team");

        // Bob → group reaches Alice and Carol (not just the creator).
        bob.send_group_text(gid, "hi from bob").await?;
        let from_bob_a = wait_for_group(&mut alice_rx, gid).await;
        let from_bob_c = wait_for_group(&mut carol_rx, gid).await;
        assert_eq!(from_bob_a.body, "hi from bob");
        assert_eq!(from_bob_a.author, bid);
        assert_eq!(from_bob_c.body, "hi from bob");

        // All three converge on the same two messages.
        assert_eq!(alice.group_conversation(&gid).len(), 2);
        assert_eq!(bob.group_conversation(&gid).len(), 2);
        assert_eq!(carol.group_conversation(&gid).len(), 2);
        let _ = aid;
        Ok(())
    }

    /// Persistence: messages, groups, and contacts survive an app restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn state_survives_restart() -> Result<()> {
        let dir = {
            let mut p = std::env::temp_dir();
            let n: u64 = rand::random();
            p.push(format!("vartalaap-restart-{n}"));
            p
        };
        let (bob, mut bob_rx) = Node::start([61u8; 32]).await?;
        let bob_id = bob.id();

        let gid;
        {
            let (alice, mut alice_rx) = Node::start_persistent(&dir, "pw").await?;
            timeout(Duration::from_secs(20), alice.connect(bob_id))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            alice.send_text(bob_id, "remember me").await?;
            wait_message(&mut bob_rx).await;
            bob.send_text(alice.id(), "and me").await?;
            wait_message(&mut alice_rx).await;
            gid = alice.create_group("study".into(), vec![bob_id]).await?;
            alice.send_group_text(gid, "group msg").await?;
            alice.shutdown().await;
        }

        // Restart from the same directory: everything must reload, offline.
        let (alice2, _rx) = Node::start_persistent(&dir, "pw").await?;
        let bodies = alice2.conversation_bodies(&bob_id);
        assert!(bodies.contains(&"remember me".to_string()));
        assert!(bodies.contains(&"and me".to_string()));
        let groups = alice2.groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "study");
        assert_eq!(alice2.group_conversation(&gid).len(), 1);
        let contacts = alice2.contacts();
        assert_eq!(contacts.len(), 1, "bob must be a persisted contact");
        assert_eq!(contacts[0].peer, bob_id);
        alice2.shutdown().await;
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// Both sides send their FIRST message concurrently: each initiates its
    /// own session. Without the PreKey fallback + tie-break this deadlocks
    /// (all subsequent messages silently dropped both ways). With it, both
    /// sides converge on one session and later messages flow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_sends_do_not_deadlock() -> Result<()> {
        let (alice, mut alice_rx) = Node::start([71u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([72u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());

        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        // Fire the first messages truly concurrently.
        let (ra, rb) = tokio::join!(alice.send_text(bid, "a1"), bob.send_text(aid, "b1"));
        ra?;
        rb?;

        // Regardless of which first message won, LATER messages must flow
        // both directions (the deadlock symptom is: nothing ever arrives).
        alice.send_text(bid, "a2").await?;
        let got = wait_message(&mut bob_rx).await;
        assert!(got.body == "a1" || got.body == "a2");

        bob.send_text(aid, "b2").await?;
        let got = wait_message(&mut alice_rx).await;
        assert!(got.body == "b1" || got.body == "b2");
        Ok(())
    }

    fn tmp_data_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("vartalaap-{tag}-{n}"));
        p
    }

    /// Profiles propagate on connect; alias overrides the profile name; the
    /// messaging key is pinned on first contact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn profile_exchange_and_alias_precedence() -> Result<()> {
        let dir_a = tmp_data_dir("profile-a");
        let dir_b = tmp_data_dir("profile-b");
        let (alice, _arx) = Node::start_persistent(&dir_a, "pw").await?;
        alice.set_display_name("Asha".into())?;
        let (bob, mut brx) = Node::start_persistent(&dir_b, "pw").await?;
        let aid = alice.id();

        timeout(Duration::from_secs(20), bob.connect(aid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        // Bob emits ContactUpdated both for the new-contact upsert (which
        // fires synchronously during the handshake) and, separately, once
        // Alice's profile lands via post_connect (asynchronous). The first
        // ContactUpdated to arrive may not carry the profile yet, so loop
        // until the display name actually shows up rather than asserting on
        // the first event (adapted from the brief's single `wait_for` to
        // avoid a race between the two ContactUpdated causes).
        timeout(Duration::from_secs(20), async {
            loop {
                wait_for(
                    &mut brx,
                    |e| matches!(e, EngineEvent::ContactUpdated(p) if *p == aid),
                )
                .await;
                let has_profile = bob
                    .contacts()
                    .into_iter()
                    .find(|c| c.peer == aid)
                    .is_some_and(|c| c.display_name().as_deref() == Some("Asha"));
                if has_profile {
                    break;
                }
            }
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for alice's profile to land"))?;

        let contact = bob
            .contacts()
            .into_iter()
            .find(|c| c.peer == aid)
            .expect("alice is a contact");
        assert_eq!(contact.display_name().as_deref(), Some("Asha"));
        assert!(
            contact.pinned_msg_key.is_some(),
            "first bundle key is pinned"
        );

        bob.set_alias(aid, Some("roomie".into()));
        let contact = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_eq!(contact.display_name().as_deref(), Some("roomie"));

        alice.shutdown().await;
        bob.shutdown().await;
        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
        Ok(())
    }

    /// A peer reappearing with the same node id but a different messaging
    /// key (fresh in-memory account, same seed) triggers PinWarning, and
    /// accept_new_key() re-pins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn changed_messaging_key_raises_pin_warning() -> Result<()> {
        let (bob, mut brx) = Node::start([82u8; 32]).await?;
        let seed = [81u8; 32];
        let first_key = {
            let (alice, _arx) = Node::start(seed).await?;
            timeout(Duration::from_secs(20), bob.connect(alice.id()))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            wait_for(
                &mut brx,
                |e| matches!(e, EngineEvent::PeerConnected(p) if *p == alice.id()),
            )
            .await;
            let c = bob
                .contacts()
                .into_iter()
                .find(|c| c.peer == alice.id())
                .unwrap();
            alice.shutdown().await;
            c.pinned_msg_key.expect("pinned on first connect")
        };

        // Same identity seed → same PeerId, but a fresh MessagingAccount.
        let (alice2, _arx) = Node::start(seed).await?;
        let aid = alice2.id();
        timeout(Duration::from_secs(20), bob.connect(aid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        wait_for(
            &mut brx,
            |e| matches!(e, EngineEvent::PinWarning { peer, .. } if *peer == aid),
        )
        .await;
        let c = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_eq!(
            c.pinned_msg_key,
            Some(first_key),
            "old pin kept until accepted"
        );
        assert!(c.pending_msg_key.is_some());

        bob.accept_new_key(aid);
        let c = bob.contacts().into_iter().find(|c| c.peer == aid).unwrap();
        assert_ne!(c.pinned_msg_key, Some(first_key), "accept re-pins");
        assert!(c.pending_msg_key.is_none());
        Ok(())
    }

    /// A text sent while the peer's node was down is delivered by delta sync
    /// when the peer comes back — the CRDT is the outbox.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offline_message_heals_on_reconnect() -> Result<()> {
        let seed_b = [92u8; 32];
        let (alice, mut arx) = Node::start([91u8; 32]).await?;
        let bid = {
            let (bob, mut brx) = Node::start(seed_b).await?;
            let bid = bob.id();
            timeout(Duration::from_secs(20), alice.connect(bid))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            alice.send_text(bid, "seen live").await?;
            wait_message(&mut brx).await;
            bob.shutdown().await;
            // Wait until alice notices the disconnect.
            wait_for(
                &mut arx,
                |e| matches!(e, EngineEvent::PeerDisconnected(p) if *p == bid),
            )
            .await;
            bid
        };

        // Peer is gone: send_text queues instead of erroring.
        let (_m, s) = alice.send_text(bid, "while you were out").await?;
        assert_eq!(s, DeliveryStatus::Queued);

        // Bob restarts with the same identity and reconnects.
        let (bob2, mut brx2) = Node::start(seed_b).await?;
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("reconnect timed out"))??;
        // Delta sync delivers the missed message.
        timeout(Duration::from_secs(20), async {
            loop {
                match brx2.recv().await {
                    Some(EngineEvent::HistorySynced { .. })
                    | Some(EngineEvent::MessageReceived { .. }) => {
                        if bob2
                            .conversation_bodies(&alice.id())
                            .contains(&"while you were out".to_string())
                        {
                            break;
                        }
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("sync never delivered the offline message"))?;
        // And bob's copy of the LIVE message also survived his restart? No —
        // bob2 is in-memory; what matters is the offline message arrived and
        // both replicas converge for it.
        assert!(bob2
            .conversation_bodies(&alice.id())
            .contains(&"while you were out".to_string()));
        Ok(())
    }

    /// A group created while a member was offline reaches them via ANY
    /// member (announce + delta ride every connection).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn group_heals_transitively_for_offline_member() -> Result<()> {
        let seed_c = [95u8; 32];
        let (alice, _arx) = Node::start([93u8; 32]).await?;
        let (bob, mut brx) = Node::start([94u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());
        let cid = {
            let (carol, _crx) = Node::start(seed_c).await?;
            let cid = carol.id();
            carol.shutdown().await; // carol is offline from the start
            cid
        };

        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("a-b timeout"))??;
        // Group created while carol is offline; only bob gets the invite.
        let gid = alice.create_group("study".into(), vec![bid, cid]).await?;
        wait_for(
            &mut brx,
            |e| matches!(e, EngineEvent::GroupInvited(g) if *g == gid),
        )
        .await;
        alice.send_group_text(gid, "carol missed this").await?;
        wait_for(
            &mut brx,
            |e| matches!(e, EngineEvent::GroupMessageReceived { group, .. } if *group == gid),
        )
        .await;

        // Carol returns and connects to BOB (not the creator).
        let (carol2, mut crx2) = Node::start(seed_c).await?;
        timeout(Duration::from_secs(20), carol2.connect(bid))
            .await
            .map_err(|_| anyhow!("c-b timeout"))??;
        timeout(Duration::from_secs(20), async {
            loop {
                match crx2.recv().await {
                    Some(EngineEvent::GroupInvited(g)) if g == gid => {}
                    Some(EngineEvent::HistorySynced { .. })
                    | Some(EngineEvent::GroupMessageReceived { .. }) => {
                        if carol2.group_conversation(&gid).len() == 1 {
                            break;
                        }
                    }
                    Some(_) => continue,
                    None => panic!("event channel closed"),
                }
            }
        })
        .await
        .map_err(|_| anyhow!("group never healed for carol"))?;
        assert_eq!(carol2.groups().len(), 1);
        assert_eq!(carol2.group_conversation(&gid)[0].body, "carol missed this");
        let _ = aid;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unread_counts_and_mark_read() -> Result<()> {
        let (alice, mut arx) = Node::start([111u8; 32]).await?;
        let (bob, mut brx) = Node::start([112u8; 32]).await?;
        let (aid, bid) = (alice.id(), bob.id());
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;

        // Deterministic barrier: the first delta-sync round-trip completing
        // proves the ratchet session converged both ways, so subsequent
        // sends cannot cross-initiate (and thus cannot lose live events).
        wait_for(
            &mut arx,
            |e| matches!(e, EngineEvent::HistorySynced { peer, .. } if *peer == bid),
        )
        .await;

        alice.send_text(bid, "one").await?;
        alice.send_text(bid, "two").await?;
        wait_message(&mut brx).await;
        wait_message(&mut brx).await;

        assert_eq!(bob.unread_direct(&aid), 2);
        assert_eq!(alice.unread_direct(&bid), 0, "own messages are not unread");
        bob.mark_read_direct(aid).await;
        assert_eq!(bob.unread_direct(&aid), 0);
        Ok(())
    }

    /// send_text to an unreachable peer queues instead of erroring, and the
    /// message transitions to Delivered once the peer syncs it down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queued_send_transitions_to_delivered() -> Result<()> {
        let seed_b = [102u8; 32];
        let (alice, mut arx) = Node::start([101u8; 32]).await?;
        let bid = {
            let (bob, _brx) = Node::start(seed_b).await?;
            let bid = bob.id();
            timeout(Duration::from_secs(20), alice.connect(bid))
                .await
                .map_err(|_| anyhow!("connect timed out"))??;
            bob.shutdown().await;
            wait_for(
                &mut arx,
                |e| matches!(e, EngineEvent::PeerDisconnected(p) if *p == bid),
            )
            .await;
            bid
        };

        // Unreachable → queued, not an error.
        let (msg, status) = alice.send_text(bid, "catch up later").await?;
        assert_eq!(status, DeliveryStatus::Queued);
        let statuses = alice.conversation_with_status(&bid);
        assert_eq!(statuses.last().unwrap().1, Some(DeliveryStatus::Queued));

        // Bob returns; alice reconnects; sync delivers; status flips.
        let (bob2, _brx2) = Node::start(seed_b).await?;
        timeout(Duration::from_secs(20), alice.connect(bid))
            .await
            .map_err(|_| anyhow!("reconnect timed out"))??;
        wait_for(&mut arx, |e| {
            matches!(e, EngineEvent::MessageStatus { id, status: DeliveryStatus::Delivered, .. } if *id == msg.id)
        })
        .await;
        assert!(bob2
            .conversation_bodies(&alice.id())
            .contains(&"catch up later".to_string()));
        Ok(())
    }

    /// `group_allows` is the single membership gate shared by the inbound
    /// `Payload::GroupMessage` handler and the `build_delta`/`apply_delta`
    /// sync paths, so a peer we've merely handshaked with (but never
    /// invited to a group, or that fabricates a random `GroupId`) cannot
    /// inject into or read a group's history. Exercised directly at the
    /// unit level: driving it through the real protocol would require
    /// constructing a hostile `Payload` by hand for no added determinism
    /// (the 3 call sites that use it are reviewed by eye instead).
    #[test]
    fn group_allows_gates_on_known_group_and_mutual_membership() {
        let gid: GroupId = [1u8; 16];
        let unknown_gid: GroupId = [2u8; 16];
        let me: PeerKey = [0xAA; 32];
        let member: PeerKey = [0xBB; 32];
        let stranger: PeerKey = [0xCC; 32];

        let mut st = State::default();
        st.groups.insert(
            gid,
            GroupInfo {
                id: gid,
                name: "study".into(),
                members: vec![me, member],
                creator: me,
            },
        );

        // Known group, both peer and me are members.
        assert!(group_allows(&st, &gid, &member, &me));
        // Unknown group id (e.g. a fabricated GroupId nobody ever created).
        assert!(!group_allows(&st, &unknown_gid, &member, &me));
        // Known group, but the sending peer is not a member.
        assert!(!group_allows(&st, &gid, &stranger, &me));
        // Known group, peer is a member, but *we* are not.
        assert!(!group_allows(&st, &gid, &member, &stranger));
    }

    /// `remove_contact` must purge every per-peer session/connection map,
    /// not just `contacts`/`conversations` — otherwise a stale entry could
    /// wedge a later re-handshake with the same peer. Removal happens
    /// while the connection to bob is still live (no explicit disconnect
    /// first), which also proves that dropping the `conns` entry alone —
    /// without capturing and closing the underlying `Conn` — leaves
    /// nothing wedged: a fresh `connect` + `send_text` still converges
    /// end-to-end afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn remove_contact_purges_state_and_allows_rehandshake() -> Result<()> {
        let (alice, _alice_rx) = Node::start([151u8; 32]).await?;
        let (bob, mut bob_rx) = Node::start([152u8; 32]).await?;
        let bob_id = bob.id();

        timeout(Duration::from_secs(20), alice.connect(bob_id))
            .await
            .map_err(|_| anyhow!("connect timed out"))??;
        alice.send_text(bob_id, "before removal").await?;
        wait_message(&mut bob_rx).await;
        assert_eq!(alice.contacts().len(), 1);

        alice.remove_contact(bob_id)?;
        assert!(
            alice.contacts().is_empty(),
            "contact must be forgotten immediately"
        );

        // Fresh connect + send, with bob's original (never torn down)
        // connection still alive in the background: no leftover
        // conn/session/bundle may prevent a clean re-handshake.
        timeout(Duration::from_secs(20), alice.connect(bob_id))
            .await
            .map_err(|_| anyhow!("reconnect timed out"))??;
        alice.send_text(bob_id, "after removal").await?;
        let got = wait_message(&mut bob_rx).await;
        assert_eq!(got.body, "after removal");

        // The re-handshake recreated the contact from scratch.
        let contacts = alice.contacts();
        assert_eq!(contacts.len(), 1, "re-handshake must recreate the contact");
        assert_eq!(contacts[0].peer, bob_id);
        Ok(())
    }

    /// A convo blob that fails to decrypt at load time (wrong-key/corrupt —
    /// same technique as
    /// `persist::tests::corrupt_msg_account_is_quarantined_and_regenerated`)
    /// is quarantined and warned about, and that warning must survive in
    /// `startup_warnings()` — not just fire-and-vanish on the event channel,
    /// which at load time has no subscriber yet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn corrupted_convo_surfaces_in_startup_warnings() -> Result<()> {
        let dir = tmp_data_dir("startup-warn");
        let peer: PeerKey = [201u8; 32];
        {
            let (alice, _rx) = Node::start_persistent(&dir, "pw").await?;
            {
                let mut st = alice.ctx.state.lock().unwrap();
                st.conversations.entry(peer).or_default().create_text(
                    alice.id(),
                    now_millis(),
                    "hi",
                );
            }
            persist_convo(&alice.ctx, &peer);
            alice.shutdown().await;
        }

        // Reseal the persisted convo entry under a different vault key, so
        // the real engine's decrypt fails on reopen.
        {
            let other = vartalaap_store::Store::open(
                &dir.join("vault.redb"),
                vartalaap_crypto::VaultKey::from([77u8; 32]),
            )?;
            other.put_secret(&format!("convo/{}", hex::encode(peer)), b"junk")?;
        }

        let (alice2, _rx2) = Node::start_persistent(&dir, "pw").await?;
        assert_eq!(
            alice2.startup_warnings().len(),
            1,
            "one corrupted convo blob must surface as exactly one startup warning"
        );
        alice2.shutdown().await;
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
