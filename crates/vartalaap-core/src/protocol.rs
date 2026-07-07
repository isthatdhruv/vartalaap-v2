//! Wire protocol types for the Vartalaap node: frames, payloads, and group
//! metadata exchanged over the encrypted transport.

use serde::{Deserialize, Serialize};
use vartalaap_crypto::ratchet::PreKeyBundle;
use vartalaap_identity::SignedProfile;
use vartalaap_sync::Message;

/// A peer's stable id: the 32-byte Vartalaap ID / Iroh PeerId.
pub type PeerKey = [u8; 32];

/// Frames exchanged on the wire (JSON-encoded).
///
/// `Hello`/`Message` are the durable protocol; the rest are ephemeral gossip
/// (not persisted to the CRDT), carried inside the already-encrypted transport.
#[derive(Serialize, Deserialize)]
pub(crate) enum Wire {
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

/// A group's stable identifier.
pub type GroupId = [u8; 16];

/// Metadata describing a group conversation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    pub id: GroupId,
    pub name: String,
    /// All members, including the creator (sorted, deduplicated).
    pub members: Vec<PeerKey>,
    pub creator: PeerKey,
}

/// Which conversation a sync frame refers to.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncScope {
    /// The 1:1 conversation between the two connected peers.
    Direct,
    Group(GroupId),
}

/// Lifecycle of an own message, as far as we can honestly know it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Recorded locally; the peer was unreachable at send time.
    Queued,
    /// Written to a live connection without error.
    Sent,
    /// The peer confirmed holding it (their SyncHave contains the id, or
    /// their read watermark reached its lamport).
    Delivered,
}

/// The plaintext carried inside a ratchet-encrypted [`Wire::Message`].
#[derive(Serialize, Deserialize)]
pub(crate) enum Payload {
    /// A 1:1 chat message (text or a file reference).
    Chat(Message),
    /// A file offer: the chat message plus the secret key for the upcoming blob
    /// stream. The key travels end-to-end and never touches the persisted CRDT.
    FileOffer { message: Message, key: [u8; 32] },
    /// An invitation announcing a group and its membership.
    GroupInvite(GroupInfo),
    /// A message addressed to a group (fanned out pairwise to each member).
    GroupMessage { group: GroupId, message: Message },
    /// The sender's signed profile, published on connect and on change.
    /// `None` when the sender has not set a profile yet — still sent (rather
    /// than omitted) so the connect-time send from the lower-id peer (see the
    /// initiator rule in `node.rs`) unconditionally establishes a session,
    /// regardless of whether that peer has a profile to publish.
    Profile(Option<SignedProfile>),
    /// A group this connection's peers share; heals members who were
    /// offline at creation time. Idempotent.
    GroupAnnounce(GroupInfo),
    /// The message ids the sender already holds for `scope`.
    SyncHave {
        scope: SyncScope,
        ids: Vec<vartalaap_sync::MessageId>,
    },
    /// Everything the receiver was missing for `scope`.
    SyncDelta {
        scope: SyncScope,
        messages: Vec<Message>,
        reactions: Vec<vartalaap_sync::Reaction>,
        read: Vec<([u8; 32], u64)>,
    },
}

/// A file we've been offered and expect a blob stream for.
pub(crate) struct PendingFile {
    pub key: [u8; 32],
    pub sha256: [u8; 32],
    pub name: String,
}
