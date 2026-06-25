//! P2P transport for Vartalaap, backed by [Iroh](https://docs.rs/iroh) 1.0.
//!
//! Uses the `Minimal` preset: QUIC + TLS only, with **no relays, no DNS, and no
//! external infrastructure**. Peers connect directly by [`EndpointAddr`] (a
//! public key plus direct socket addresses), which is exactly the campus/LAN
//! model — discovery of those addresses is layered on top (see `discovery`).
//!
//! The engine talks to this crate's types, never to `iroh` directly, so the
//! transport can be swapped later without touching application logic.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh::address_lookup::{AddressLookup, AddressLookupBuilder, AddressLookupBuilderError};
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};

/// Application-layer protocol identifier negotiated on every connection.
pub const ALPN: &[u8] = b"vartalaap/0";

/// Re-exported so consumers can address peers without importing `iroh`.
pub use iroh::{EndpointAddr as PeerAddr, EndpointId as PeerId};

/// An Iroh-backed peer-to-peer endpoint.
pub struct IrohTransport {
    endpoint: Endpoint,
    /// Present when LAN discovery is enabled; used to subscribe to peer events.
    mdns: Option<MdnsAddressLookup>,
}

/// A discovery event observed on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// A peer appeared (or refreshed) on the LAN.
    Discovered(PeerId),
    /// A peer went away (timed out / unreachable).
    Expired(PeerId),
}

/// Adapter that lets a pre-built [`MdnsAddressLookup`] be installed on an
/// endpoint, so the same instance both advertises/resolves AND can be
/// subscribed to for a live peer list.
#[derive(Debug)]
struct PreBuilt(MdnsAddressLookup);

impl AddressLookupBuilder for PreBuilt {
    fn into_address_lookup(
        self,
        _endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        Ok(self.0)
    }
}

impl IrohTransport {
    /// Bind a new endpoint using the given 32-byte identity seed. The seed
    /// fixes the node's [`PeerId`], so the same identity always has the same id.
    pub async fn bind(secret_seed: [u8; 32]) -> Result<Self> {
        let sk = SecretKey::from_bytes(&secret_seed);
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(any)?;
        Ok(Self {
            endpoint,
            mdns: None,
        })
    }

    /// Bind a new endpoint with **mDNS LAN discovery** enabled: it advertises
    /// itself and resolves peers by id on the local network, so two peers find
    /// each other with no server, no DNS, and no knowledge of each other's IPs.
    pub async fn bind_with_discovery(secret_seed: [u8; 32]) -> Result<Self> {
        let sk = SecretKey::from_bytes(&secret_seed);
        let endpoint_id = sk.public();
        let mdns = MdnsAddressLookup::builder()
            .build(endpoint_id)
            .map_err(any)?;
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(sk)
            .alpns(vec![ALPN.to_vec()])
            .address_lookup(PreBuilt(mdns.clone()))
            .bind()
            .await
            .map_err(any)?;
        Ok(Self {
            endpoint,
            mdns: Some(mdns),
        })
    }

    /// This endpoint's public id.
    pub fn node_id(&self) -> PeerId {
        self.endpoint.id()
    }

    /// Dial a peer by id alone, relying on LAN discovery to resolve its
    /// address. Requires the endpoint to have been bound with
    /// [`IrohTransport::bind_with_discovery`].
    pub async fn connect_by_id(&self, peer: PeerId) -> Result<Conn> {
        let conn = self
            .endpoint
            .connect(EndpointAddr::new(peer), ALPN)
            .await
            .map_err(any)?;
        Ok(Conn { conn })
    }

    /// A live stream of peers appearing/disappearing on the LAN, or `None` if
    /// discovery was not enabled for this endpoint.
    pub async fn peer_events(&self) -> Option<impl Stream<Item = PeerEvent>> {
        let mdns = self.mdns.as_ref()?;
        let stream = mdns.subscribe().await;
        Some(stream.filter_map(|ev| match ev {
            DiscoveryEvent::Discovered { endpoint_info, .. } => {
                Some(PeerEvent::Discovered(endpoint_info.endpoint_id))
            }
            DiscoveryEvent::Expired { endpoint_id } => Some(PeerEvent::Expired(endpoint_id)),
            _ => None,
        }))
    }

    /// A directly-dialable address for this endpoint on the loopback interface.
    /// Used by tests and same-host scenarios; LAN discovery supplies real
    /// interface addresses in production.
    pub fn loopback_addr(&self) -> PeerAddr {
        let sockets = self.endpoint.bound_sockets();
        let port = sockets
            .iter()
            .find(|s| s.is_ipv4())
            .or_else(|| sockets.first())
            .map(|s| s.port())
            .expect("endpoint is bound to at least one socket");
        EndpointAddr::new(self.endpoint.id())
            .with_ip_addr(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
    }

    /// Dial a peer by address and return an open [`Conn`].
    pub async fn connect(&self, addr: PeerAddr) -> Result<Conn> {
        let conn = self.endpoint.connect(addr, ALPN).await.map_err(any)?;
        Ok(Conn { conn })
    }

    /// Await the next incoming connection. Returns `None` when the endpoint is
    /// shutting down.
    pub async fn accept(&self) -> Result<Option<Conn>> {
        match self.endpoint.accept().await {
            None => Ok(None),
            Some(incoming) => {
                let conn = incoming.await.map_err(any)?;
                Ok(Some(Conn { conn }))
            }
        }
    }

    /// Gracefully close the endpoint, flushing any queued close frames.
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// Construct a [`PeerId`] from its raw 32 bytes (e.g. a stored Vartalaap ID).
pub fn peer_id_from_bytes(bytes: [u8; 32]) -> Result<PeerId> {
    iroh::PublicKey::from_bytes(&bytes).map_err(any)
}

/// The raw 32 bytes of a [`PeerId`].
pub fn peer_id_bytes(id: &PeerId) -> [u8; 32] {
    *id.as_bytes()
}

const TAG_FRAME: u8 = 0;
const TAG_BLOB: u8 = 1;

/// An incoming stream, classified by its leading tag byte.
pub enum Incoming {
    /// A length-delimited control frame (chat protocol).
    Frame(Vec<u8>),
    /// A bulk blob transfer (file bytes).
    Blob(BlobRecv),
}

/// An open connection to a peer. Each QUIC bidirectional stream begins with a
/// 1-byte tag: a control frame (length-delimited bytes) or a blob transfer
/// (length-delimited chunks, 0-length terminator).
#[derive(Clone)]
pub struct Conn {
    conn: Connection,
}

impl Conn {
    /// The peer on the other end of this connection.
    pub fn remote_id(&self) -> PeerId {
        self.conn.remote_id()
    }

    /// The raw 32 bytes of the remote peer's id.
    pub fn remote_id_bytes(&self) -> [u8; 32] {
        *self.conn.remote_id().as_bytes()
    }

    /// Send one length-delimited control frame on a fresh stream.
    pub async fn send_frame(&self, data: &[u8]) -> Result<()> {
        let (mut send, _recv) = self.conn.open_bi().await.map_err(any)?;
        send.write_all(&[TAG_FRAME]).await.map_err(any)?;
        let len = (data.len() as u32).to_le_bytes();
        send.write_all(&len).await.map_err(any)?;
        send.write_all(data).await.map_err(any)?;
        send.finish().map_err(any)?;
        Ok(())
    }

    /// Open a fresh stream for a bulk blob transfer tagged with `transfer_id`.
    pub async fn open_blob(&self, transfer_id: [u8; 16]) -> Result<BlobSend> {
        let (mut send, _recv) = self.conn.open_bi().await.map_err(any)?;
        send.write_all(&[TAG_BLOB]).await.map_err(any)?;
        send.write_all(&transfer_id).await.map_err(any)?;
        Ok(BlobSend { send })
    }

    /// Accept the next incoming stream and classify it as a frame or a blob.
    pub async fn accept_incoming(&self) -> Result<Incoming> {
        let (_send, mut recv) = self.conn.accept_bi().await.map_err(any)?;
        let mut tag = [0u8; 1];
        recv.read_exact(&mut tag).await.map_err(any)?;
        match tag[0] {
            TAG_FRAME => {
                let mut len_buf = [0u8; 4];
                recv.read_exact(&mut len_buf).await.map_err(any)?;
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut buf = vec![0u8; len];
                recv.read_exact(&mut buf).await.map_err(any)?;
                Ok(Incoming::Frame(buf))
            }
            TAG_BLOB => {
                let mut transfer_id = [0u8; 16];
                recv.read_exact(&mut transfer_id).await.map_err(any)?;
                Ok(Incoming::Blob(BlobRecv { transfer_id, recv }))
            }
            other => Err(anyhow::anyhow!("unknown stream tag {other}")),
        }
    }

    /// Convenience for callers that only expect control frames.
    pub async fn recv_frame(&self) -> Result<Vec<u8>> {
        match self.accept_incoming().await? {
            Incoming::Frame(data) => Ok(data),
            Incoming::Blob(_) => Err(anyhow::anyhow!("expected a frame, got a blob stream")),
        }
    }
}

/// The send half of a blob transfer.
pub struct BlobSend {
    send: SendStream,
}

impl BlobSend {
    /// Write one chunk (length-delimited).
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let len = (chunk.len() as u32).to_le_bytes();
        self.send.write_all(&len).await.map_err(any)?;
        self.send.write_all(chunk).await.map_err(any)?;
        Ok(())
    }

    /// Write the 0-length terminator and finish the stream.
    pub async fn finish(mut self) -> Result<()> {
        self.send
            .write_all(&0u32.to_le_bytes())
            .await
            .map_err(any)?;
        self.send.finish().map_err(any)?;
        Ok(())
    }
}

/// The receive half of a blob transfer.
pub struct BlobRecv {
    transfer_id: [u8; 16],
    recv: RecvStream,
}

impl BlobRecv {
    /// The transfer id this stream is carrying.
    pub fn transfer_id(&self) -> [u8; 16] {
        self.transfer_id
    }

    /// The next chunk, or `None` at the terminator.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        self.recv.read_exact(&mut len_buf).await.map_err(any)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; len];
        self.recv.read_exact(&mut buf).await.map_err(any)?;
        Ok(Some(buf))
    }
}

/// Convert any displayable error into an `anyhow::Error`. Iroh's error types
/// come from the `n0_error` framework; this keeps our surface on `anyhow`.
fn any<E: std::fmt::Display>(e: E) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_and_send_frame_loopback() -> Result<()> {
        // Bob binds and waits for a frame.
        let bob = IrohTransport::bind([2u8; 32]).await?;
        let bob_id = bob.node_id();
        let bob_addr = bob.loopback_addr();

        let bob_task = tokio::spawn(async move {
            let conn = bob.accept().await?.expect("an incoming connection");
            let frame = conn.recv_frame().await?;
            anyhow::Ok((conn.remote_id(), frame))
        });

        // Alice dials Bob by address and sends a frame.
        let alice = IrohTransport::bind([1u8; 32]).await?;
        let alice_id = alice.node_id();
        let conn = alice.connect(bob_addr).await?;
        conn.send_frame(b"hello vartalaap").await?;

        let (seen_remote, received) = bob_task.await??;
        assert_eq!(received, b"hello vartalaap");
        assert_eq!(seen_remote, alice_id, "bob sees alice's id");
        assert_ne!(alice_id, bob_id);

        alice.close().await;
        Ok(())
    }

    /// Two endpoints with mDNS enabled: Alice connects to Bob by id ALONE,
    /// relying on LAN discovery to resolve his address. Exercises the real
    /// campus-network path (no server, no IPs shared out of band).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lan_discovery_connect_by_id() -> Result<()> {
        use std::time::Duration;
        use tokio::time::timeout;

        let bob = IrohTransport::bind_with_discovery([22u8; 32]).await?;
        let bob_id = bob.node_id();
        let bob_task = tokio::spawn(async move {
            let conn = bob.accept().await?.expect("an incoming connection");
            let frame = conn.recv_frame().await?;
            anyhow::Ok(frame)
        });

        let alice = IrohTransport::bind_with_discovery([11u8; 32]).await?;
        let conn = timeout(Duration::from_secs(20), alice.connect_by_id(bob_id))
            .await
            .map_err(|_| anyhow::anyhow!("mDNS resolve/connect timed out"))??;
        conn.send_frame(b"discovered!").await?;

        let received = timeout(Duration::from_secs(20), bob_task).await???;
        assert_eq!(received, b"discovered!");
        alice.close().await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blob_stream_transfer() -> Result<()> {
        let bob = IrohTransport::bind([4u8; 32]).await?;
        let bob_addr = bob.loopback_addr();
        let bob_task = tokio::spawn(async move {
            let conn = bob.accept().await?.expect("an incoming connection");
            match conn.accept_incoming().await? {
                Incoming::Blob(mut b) => {
                    let id = b.transfer_id();
                    let mut data = Vec::new();
                    while let Some(c) = b.next_chunk().await? {
                        data.extend_from_slice(&c);
                    }
                    anyhow::Ok((id, data))
                }
                Incoming::Frame(_) => anyhow::bail!("expected a blob, got a frame"),
            }
        });

        let alice = IrohTransport::bind([5u8; 32]).await?;
        let conn = alice.connect(bob_addr).await?;
        let tid = [7u8; 16];
        let mut blob = conn.open_blob(tid).await?;
        blob.write_chunk(b"hello ").await?;
        blob.write_chunk(b"world").await?;
        blob.finish().await?;

        let (got_id, got) = bob_task.await??;
        assert_eq!(got_id, tid);
        assert_eq!(got, b"hello world");
        alice.close().await;
        Ok(())
    }
}
