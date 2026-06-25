//! Conflict-free 1:1 conversation state for Vartalaap.
//!
//! A [`Conversation`] is a small purpose-built CRDT:
//! - **messages** are a grow-only set keyed by a unique [`MessageId`]
//!   (union on merge, idempotent), ordered deterministically by
//!   `(lamport, author, id)`;
//! - **read watermarks** are a per-author max-register (monotonic);
//! - **reactions** are a grow-only set of `(message, author, emoji)`.
//!
//! All three are well-known convergent CRDTs, so two replicas that observe the
//! same operations — in any order, with any duplication — reach identical
//! state. Edits/deletes/reaction-removal (which need LWW-registers / OR-sets)
//! are intentionally deferred to a later phase. The public API hides the
//! representation, so the internals could be swapped for a generic CRDT such as
//! Automerge without touching callers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Unique identifier for a message (16 random bytes).
pub type MessageId = [u8; 16];

/// A peer's public identity key, used as the author id.
pub type AuthorId = [u8; 32];

/// A reference to a transferred file (no secret key — that travels separately,
/// end-to-end, at transfer time).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRef {
    pub transfer_id: [u8; 16],
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub sha256: [u8; 32],
}

/// The kind of payload a message carries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageKind {
    Text,
    File(FileRef),
}

/// A single, immutable chat message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: MessageId,
    pub author: AuthorId,
    /// Lamport timestamp for causal ordering.
    pub lamport: u64,
    /// Wall-clock send time (unix millis), for display only.
    pub sent_at: u64,
    pub body: String,
    pub kind: MessageKind,
}

/// A reaction: `author` reacted to `message` with `emoji`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reaction {
    pub message: MessageId,
    pub author: AuthorId,
    pub emoji: String,
}

/// Conflict-free state of one conversation.
#[derive(Clone, Debug, Default)]
pub struct Conversation {
    messages: BTreeMap<MessageId, Message>,
    reactions: BTreeSet<Reaction>,
    /// Per-author highest read lamport (max-register).
    read: BTreeMap<AuthorId, u64>,
    /// Local logical clock.
    lamport: u64,
}

impl Conversation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Author a new local text message, advancing the local clock. The returned
    /// [`Message`] is already applied locally and should be broadcast to peers.
    pub fn create_text(
        &mut self,
        author: AuthorId,
        sent_at: u64,
        body: impl Into<String>,
    ) -> Message {
        self.lamport += 1;
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let msg = Message {
            id,
            author,
            lamport: self.lamport,
            sent_at,
            body: body.into(),
            kind: MessageKind::Text,
        };
        self.messages.insert(id, msg.clone());
        msg
    }

    /// Author a new local file message (the file body is its display name).
    pub fn create_file(&mut self, author: AuthorId, sent_at: u64, file: FileRef) -> Message {
        self.lamport += 1;
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let msg = Message {
            id,
            author,
            lamport: self.lamport,
            sent_at,
            body: file.name.clone(),
            kind: MessageKind::File(file),
        };
        self.messages.insert(id, msg.clone());
        msg
    }

    /// Apply a message received from a peer. Idempotent: applying the same
    /// message twice is a no-op. Advances the local clock past the message.
    pub fn apply(&mut self, msg: Message) {
        self.lamport = self.lamport.max(msg.lamport);
        self.messages.entry(msg.id).or_insert(msg);
    }

    /// Record that `author` has read everything up to `lamport` (monotonic).
    pub fn mark_read(&mut self, author: AuthorId, lamport: u64) {
        let entry = self.read.entry(author).or_insert(0);
        *entry = (*entry).max(lamport);
    }

    /// The read watermark for an author (0 if unknown).
    pub fn read_watermark(&self, author: &AuthorId) -> u64 {
        self.read.get(author).copied().unwrap_or(0)
    }

    /// Add a reaction (idempotent).
    pub fn react(&mut self, message: MessageId, author: AuthorId, emoji: impl Into<String>) {
        self.reactions.insert(Reaction {
            message,
            author,
            emoji: emoji.into(),
        });
    }

    /// Reactions for a given message.
    pub fn reactions_for(&self, message: &MessageId) -> Vec<&Reaction> {
        self.reactions
            .iter()
            .filter(|r| &r.message == message)
            .collect()
    }

    /// All messages in deterministic causal order: `(lamport, author, id)`.
    pub fn messages_ordered(&self) -> Vec<&Message> {
        let mut all: Vec<&Message> = self.messages.values().collect();
        all.sort_by(|a, b| {
            a.lamport
                .cmp(&b.lamport)
                .then_with(|| a.author.cmp(&b.author))
                .then_with(|| a.id.cmp(&b.id))
        });
        all
    }

    /// The set of message ids this replica already has — used to compute deltas.
    pub fn have(&self) -> BTreeSet<MessageId> {
        self.messages.keys().copied().collect()
    }

    /// Messages this replica holds that are absent from `have` — the delta to
    /// send a peer so its history heals.
    pub fn delta_since(&self, have: &BTreeSet<MessageId>) -> Vec<Message> {
        self.messages
            .iter()
            .filter(|(id, _)| !have.contains(*id))
            .map(|(_, m)| m.clone())
            .collect()
    }

    /// Merge another replica's full state into this one (union messages and
    /// reactions, max read watermarks). Commutative, associative, idempotent.
    pub fn merge(&mut self, other: &Conversation) {
        for (id, msg) in &other.messages {
            self.lamport = self.lamport.max(msg.lamport);
            self.messages.entry(*id).or_insert_with(|| msg.clone());
        }
        for r in &other.reactions {
            self.reactions.insert(r.clone());
        }
        for (author, lamport) in &other.read {
            let entry = self.read.entry(*author).or_insert(0);
            *entry = (*entry).max(*lamport);
        }
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: AuthorId = [1u8; 32];
    const BOB: AuthorId = [2u8; 32];

    #[test]
    fn ordered_by_lamport_then_author() {
        let mut c = Conversation::new();
        let m1 = c.create_text(ALICE, 100, "first");
        let m2 = c.create_text(ALICE, 101, "second");
        let ordered = c.messages_ordered();
        assert_eq!(ordered[0].id, m1.id);
        assert_eq!(ordered[1].id, m2.id);
    }

    #[test]
    fn apply_is_idempotent() {
        let mut a = Conversation::new();
        let m = a.create_text(ALICE, 1, "hi");
        let mut b = Conversation::new();
        b.apply(m.clone());
        b.apply(m.clone());
        assert_eq!(b.len(), 1);
    }

    /// Convergence: the same messages applied in different orders, plus a merge,
    /// yield identical ordered state.
    #[test]
    fn converges_regardless_of_order() {
        // Author three messages on three independent replicas.
        let mut src_a = Conversation::new();
        let ma = src_a.create_text(ALICE, 10, "a");
        let mut src_b = Conversation::new();
        let mb = src_b.create_text(BOB, 10, "b");
        let mut src_c = Conversation::new();
        let mc = src_c.create_text(ALICE, 12, "c");

        // Replica 1 sees a, b, c.
        let mut r1 = Conversation::new();
        r1.apply(ma.clone());
        r1.apply(mb.clone());
        r1.apply(mc.clone());

        // Replica 2 sees them in a different order, with a duplicate.
        let mut r2 = Conversation::new();
        r2.apply(mc.clone());
        r2.apply(ma.clone());
        r2.apply(mb.clone());
        r2.apply(mc.clone());

        let ids1: Vec<_> = r1.messages_ordered().iter().map(|m| m.id).collect();
        let ids2: Vec<_> = r2.messages_ordered().iter().map(|m| m.id).collect();
        assert_eq!(ids1, ids2, "replicas must converge to identical order");
    }

    #[test]
    fn read_watermark_is_monotonic_max() {
        let mut c = Conversation::new();
        c.mark_read(BOB, 5);
        c.mark_read(BOB, 3); // older, must not regress
        assert_eq!(c.read_watermark(&BOB), 5);
        c.mark_read(BOB, 9);
        assert_eq!(c.read_watermark(&BOB), 9);
    }

    #[test]
    fn delta_since_returns_missing_messages() {
        let mut a = Conversation::new();
        let m1 = a.create_text(ALICE, 1, "one");
        let _m2 = a.create_text(ALICE, 2, "two");

        let mut b = Conversation::new();
        b.apply(m1.clone());

        // a should offer b everything b doesn't have (just m2).
        let delta = a.delta_since(&b.have());
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].body, "two");

        for m in delta {
            b.apply(m);
        }
        assert_eq!(a.have(), b.have(), "after sync, histories match");
    }

    #[test]
    fn merge_unions_messages_and_reactions() {
        let mut a = Conversation::new();
        let m = a.create_text(ALICE, 1, "hello");
        a.react(m.id, ALICE, "👍");

        let mut b = Conversation::new();
        let n = b.create_text(BOB, 1, "world");
        b.react(n.id, BOB, "🎉");

        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.reactions_for(&m.id).len(), 1);
        assert_eq!(a.reactions_for(&n.id).len(), 1);
    }
}
