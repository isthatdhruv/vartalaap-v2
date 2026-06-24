//! Vartalaap desktop app: bridges the headless `vartalaap-core` engine to the
//! web UI via Tauri commands (UI → Rust) and an event stream (Rust → UI).

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, Manager, State};
use vartalaap_core::node::{EngineEvent, Node};

type NodeState = Arc<Node>;

fn hexkey(k: &[u8; 32]) -> String {
    hex::encode(k)
}

fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    v.as_slice()
        .try_into()
        .map_err(|_| "invalid id length".to_string())
}

#[derive(Serialize)]
struct WhoAmI {
    id: String,
    fingerprint: String,
    display_name: String,
}

#[derive(Serialize)]
struct PeerDto {
    id: String,
}

#[derive(Serialize)]
struct MessageDto {
    id: String,
    author: String,
    body: String,
    sent_at: u64,
    mine: bool,
}

#[tauri::command]
fn whoami(state: State<'_, NodeState>) -> WhoAmI {
    WhoAmI {
        id: hexkey(&state.id()),
        fingerprint: state.fingerprint().unwrap_or_default(),
        display_name: state.display_name(),
    }
}

#[tauri::command]
fn set_display_name(name: String, state: State<'_, NodeState>) -> Result<(), String> {
    state.set_display_name(name).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_peers(state: State<'_, NodeState>) -> Vec<PeerDto> {
    state
        .discovered_peers()
        .iter()
        .map(|k| PeerDto { id: hexkey(k) })
        .collect()
}

#[tauri::command]
fn history(peer: String, state: State<'_, NodeState>) -> Result<Vec<MessageDto>, String> {
    let key = parse_key(&peer)?;
    let me = state.id();
    Ok(state
        .conversation(&key)
        .into_iter()
        .map(|m| MessageDto {
            id: hex::encode(m.id),
            author: hexkey(&m.author),
            mine: m.author == me,
            body: m.body,
            sent_at: m.sent_at,
        })
        .collect())
}

#[tauri::command]
async fn connect(id: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&id)?;
    let node = state.inner().clone();
    node.connect(key).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send(peer: String, body: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    let node = state.inner().clone();
    node.send_text(key, &body).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn notify_typing(peer: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    let node = state.inner().clone();
    node.notify_typing(key).await.map_err(|e| e.to_string())
}

/// Convert an engine event into a UI-friendly JSON payload and emit it.
fn emit_event(handle: &tauri::AppHandle, me: &[u8; 32], ev: EngineEvent) {
    let payload = match ev {
        EngineEvent::PeerDiscovered(p) => {
            serde_json::json!({ "kind": "peer_discovered", "id": hexkey(&p) })
        }
        EngineEvent::PeerConnected(p) => {
            serde_json::json!({ "kind": "peer_connected", "id": hexkey(&p) })
        }
        EngineEvent::MessageReceived { peer, message } => serde_json::json!({
            "kind": "message",
            "peer": hexkey(&peer),
            "id": hex::encode(message.id),
            "author": hexkey(&message.author),
            "body": message.body,
            "sent_at": message.sent_at,
            "mine": &message.author == me,
        }),
        EngineEvent::Typing(p) => serde_json::json!({ "kind": "typing", "peer": hexkey(&p) }),
        EngineEvent::PresenceChanged { peer, online } => {
            serde_json::json!({ "kind": "presence", "peer": hexkey(&peer), "online": online })
        }
        EngineEvent::ReadReceipt { peer, up_to } => {
            serde_json::json!({ "kind": "read", "peer": hexkey(&peer), "up_to": up_to })
        }
    };
    let _ = handle.emit("engine://event", payload);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let data_dir = app.path().app_data_dir().expect("resolve app data dir");
            std::fs::create_dir_all(&data_dir).ok();

            // Start the headless engine (binds LAN transport + discovery).
            let (node, mut rx) = tauri::async_runtime::block_on(Node::start_persistent(
                &data_dir,
                "vartalaap-dev-passphrase",
            ))
            .expect("failed to start Vartalaap node");
            let node = Arc::new(node);
            let me = node.id();
            app.manage(node);

            // Forward engine events to the web UI.
            tauri::async_runtime::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    emit_event(&handle, &me, ev);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            whoami,
            set_display_name,
            list_peers,
            history,
            connect,
            send,
            notify_typing
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vartalaap");
}
