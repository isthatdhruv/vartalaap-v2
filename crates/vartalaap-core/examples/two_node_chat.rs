//! Headless demo: two Vartalaap nodes discover each other on the LAN and
//! exchange end-to-end-encrypted messages — no server, no configuration.
//!
//! Run with: `cargo run --example two_node_chat`

use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use vartalaap_core::node::{EngineEvent, Node};

fn short(id: &[u8; 32]) -> String {
    hex_prefix(id)
}

fn hex_prefix(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

async fn next_message(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<EngineEvent>,
) -> Result<(String, [u8; 32])> {
    timeout(Duration::from_secs(20), async {
        loop {
            match rx.recv().await {
                Some(EngineEvent::MessageReceived { peer, message }) => {
                    return Ok((message.body, peer))
                }
                Some(_) => continue,
                None => return Err(anyhow!("channel closed")),
            }
        }
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for a message"))?
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting two Vartalaap nodes on the local network...\n");

    let (alice, mut alice_rx) = Node::start([1u8; 32]).await?;
    let (bob, mut bob_rx) = Node::start([2u8; 32]).await?;
    let alice_id = alice.id();
    let bob_id = bob.id();

    println!("  Alice  id={}", short(&alice_id));
    println!("  Bob    id={}", short(&bob_id));
    println!("\nAlice connects to Bob by id alone (mDNS resolves the address)...");
    timeout(Duration::from_secs(20), alice.connect(bob_id))
        .await
        .map_err(|_| anyhow!("connect timed out"))??;
    println!("  ✔ connected + handshaked (TOFU pinned)\n");

    println!("Alice → Bob: \"Hello from Alice 👋\"");
    alice.send_text(bob_id, "Hello from Alice 👋").await?;
    let (body, from) = next_message(&mut bob_rx).await?;
    println!("  ✔ Bob decrypted from {}: \"{}\"\n", short(&from), body);

    println!("Bob → Alice: \"Hi Alice, this is end-to-end encrypted 🔒\"");
    bob.send_text(alice_id, "Hi Alice, this is end-to-end encrypted 🔒")
        .await?;
    let (body, from) = next_message(&mut alice_rx).await?;
    println!("  ✔ Alice decrypted from {}: \"{}\"\n", short(&from), body);

    let a = alice.conversation_bodies(&bob_id);
    let b = bob.conversation_bodies(&alice_id);
    println!("Conversation converged on both sides: {}", a == b);
    println!("  history: {a:?}");

    Ok(())
}
