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
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, SecretKey};

/// Application-layer protocol identifier negotiated on every connection.
pub const ALPN: &[u8] = b"vartalaap/0";

/// Re-exported so consumers can address peers without importing `iroh`.
pub use iroh::{EndpointAddr as PeerAddr, EndpointId as PeerId};

/// An Iroh-backed peer-to-peer endpoint.
pub struct IrohTransport {
    endpoint: Endpoint,
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
        Ok(Self { endpoint })
    }

    /// This endpoint's public id.
    pub fn node_id(&self) -> PeerId {
        self.endpoint.id()
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

/// An open connection to a peer. Frames are length-delimited (u32 LE length
/// prefix) and each is carried on its own QUIC bidirectional stream.
pub struct Conn {
    conn: Connection,
}

impl Conn {
    /// The peer on the other end of this connection.
    pub fn remote_id(&self) -> PeerId {
        self.conn.remote_id()
    }

    /// Send one length-delimited frame on a fresh bidirectional stream.
    pub async fn send_frame(&self, data: &[u8]) -> Result<()> {
        let (mut send, _recv) = self.conn.open_bi().await.map_err(any)?;
        let len = (data.len() as u32).to_le_bytes();
        send.write_all(&len).await.map_err(any)?;
        send.write_all(data).await.map_err(any)?;
        send.finish().map_err(any)?;
        Ok(())
    }

    /// Receive one length-delimited frame from the next incoming stream.
    pub async fn recv_frame(&self) -> Result<Vec<u8>> {
        let (_send, mut recv) = self.conn.accept_bi().await.map_err(any)?;
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await.map_err(any)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        recv.read_exact(&mut buf).await.map_err(any)?;
        Ok(buf)
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
}
