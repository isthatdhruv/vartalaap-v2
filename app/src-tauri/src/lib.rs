//! Vartalaap desktop app: bridges the headless `vartalaap-core` engine to the
//! web UI via Tauri commands (UI → Rust) and an event stream (Rust → UI).

use std::sync::Arc;

use serde::Serialize;
use tauri::{Emitter, Manager, State};
use vartalaap_core::node::{DeliveryStatus, EngineEvent, Node, SyncScope};
use vartalaap_core::{Message, MessageKind};

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

fn hexgroup(g: &[u8; 16]) -> String {
    hex::encode(g)
}

fn parse_group(s: &str) -> Result<[u8; 16], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    v.as_slice()
        .try_into()
        .map_err(|_| "invalid group id".to_string())
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
struct FileDto {
    name: String,
    size: u64,
    mime: String,
    transfer_id: String,
    /// Local path if this file has been received & saved (receiver side only).
    received_path: Option<String>,
}

#[derive(Serialize)]
struct MessageDto {
    id: String,
    author: String,
    body: String,
    sent_at: u64,
    mine: bool,
    file: Option<FileDto>,
    status: Option<String>,
}

#[derive(Serialize)]
struct GroupDto {
    id: String,
    name: String,
    members: Vec<String>,
    creator: String,
}

#[derive(Serialize)]
struct ContactDto {
    id: String,
    name: String,
    online: bool,
    last_seen: u64,
    unread: usize,
    pin_pending: bool,
}

#[derive(Serialize)]
struct NearbyDto {
    id: String,
}

/// Lowercase wire representation of a [`DeliveryStatus`].
fn status_str(s: DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Queued => "queued",
        DeliveryStatus::Sent => "sent",
        DeliveryStatus::Delivered => "delivered",
    }
}

fn message_dto(
    m: Message,
    me: &[u8; 32],
    status: Option<DeliveryStatus>,
    node: &Node,
) -> MessageDto {
    let file = match &m.kind {
        MessageKind::File(f) => {
            // Only the receiver looks up a downloaded copy; the sender already
            // has the original file.
            let received_path = if m.author != *me {
                node.received_file_path(f.transfer_id, &f.name)
            } else {
                None
            };
            Some(FileDto {
                name: f.name.clone(),
                size: f.size,
                mime: f.mime.clone(),
                transfer_id: hex::encode(f.transfer_id),
                received_path,
            })
        }
        MessageKind::Text => None,
    };
    MessageDto {
        id: hex::encode(m.id),
        author: hexkey(&m.author),
        mine: m.author == *me,
        body: m.body,
        sent_at: m.sent_at,
        file,
        status: status.map(status_str).map(str::to_string),
    }
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
        .conversation_with_status(&key)
        .into_iter()
        .map(|(m, status)| message_dto(m, &me, status, state.inner()))
        .collect())
}

#[tauri::command]
async fn connect(id: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&id)?;
    let node = state.inner().clone();
    node.connect(key).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn send(
    peer: String,
    body: String,
    state: State<'_, NodeState>,
) -> Result<MessageDto, String> {
    let key = parse_key(&peer)?;
    let node = state.inner().clone();
    let me = node.id();
    let (message, status) = node
        .send_text(key, &body)
        .await
        .map_err(|e| e.to_string())?;
    Ok(message_dto(message, &me, Some(status), &node))
}

#[tauri::command]
async fn send_file(peer: String, path: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    let node = state.inner().clone();
    node.send_file(key, std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn notify_typing(peer: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    let node = state.inner().clone();
    node.notify_typing(key).await.map_err(|e| e.to_string())
}

/// Copy a received file from its auto-saved location to a user-chosen path.
#[tauri::command]
fn save_file_as(src: String, dest: String) -> Result<(), String> {
    std::fs::copy(&src, &dest)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Open a path with the system default application.
#[tauri::command]
fn open_path(path: String, app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(path, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_groups(state: State<'_, NodeState>) -> Vec<GroupDto> {
    state
        .groups()
        .into_iter()
        .map(|g| GroupDto {
            id: hexgroup(&g.id),
            name: g.name,
            members: g.members.iter().map(hexkey).collect(),
            creator: hexkey(&g.creator),
        })
        .collect()
}

#[tauri::command]
async fn create_group(
    name: String,
    members: Vec<String>,
    state: State<'_, NodeState>,
) -> Result<String, String> {
    let mut keys = Vec::with_capacity(members.len());
    for m in &members {
        keys.push(parse_key(m)?);
    }
    let node = state.inner().clone();
    let id = node.create_group(name, keys).await.map_err(|e| e.to_string())?;
    Ok(hexgroup(&id))
}

#[tauri::command]
fn group_history(group: String, state: State<'_, NodeState>) -> Result<Vec<MessageDto>, String> {
    let g = parse_group(&group)?;
    let me = state.id();
    Ok(state
        .group_conversation(&g)
        .into_iter()
        .map(|m| message_dto(m, &me, None, state.inner()))
        .collect())
}

#[tauri::command]
async fn send_group(
    group: String,
    body: String,
    state: State<'_, NodeState>,
) -> Result<(), String> {
    let g = parse_group(&group)?;
    let node = state.inner().clone();
    node.send_group_text(g, &body)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_contacts(state: State<'_, NodeState>) -> Vec<ContactDto> {
    let node = state.inner();
    let online: std::collections::HashSet<String> = node
        .connected_peers()
        .into_iter()
        .map(|p| hexkey(&p))
        .collect();
    node.contacts()
        .into_iter()
        .map(|c| {
            let name = c.display_name().unwrap_or_else(|| {
                vartalaap_identity::VartalaapId::from_bytes(c.peer)
                    .map(|v| v.fingerprint().chars().take(8).collect())
                    .unwrap_or_else(|_| hexkey(&c.peer).chars().take(8).collect())
            });
            ContactDto {
                id: hexkey(&c.peer),
                name,
                online: online.contains(&hexkey(&c.peer)),
                last_seen: c.last_seen,
                unread: node.unread_direct(&c.peer),
                pin_pending: c.pending_msg_key.is_some(),
            }
        })
        .collect()
}

#[tauri::command]
fn list_nearby(state: State<'_, NodeState>) -> Vec<NearbyDto> {
    state
        .nearby()
        .into_iter()
        .map(|p| NearbyDto { id: hexkey(&p) })
        .collect()
}

#[tauri::command]
fn set_alias(
    peer: String,
    alias: Option<String>,
    state: State<'_, NodeState>,
) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.set_alias(key, alias);
    Ok(())
}

#[tauri::command]
fn remove_contact(peer: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.remove_contact(key).map_err(|e| e.to_string())
}

#[tauri::command]
fn accept_new_key(peer: String, state: State<'_, NodeState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.accept_new_key(key);
    Ok(())
}

#[tauri::command]
async fn mark_read(kind: String, id: String, state: State<'_, NodeState>) -> Result<(), String> {
    match kind.as_str() {
        "peer" => {
            let key = parse_key(&id)?;
            let node = state.inner().clone();
            node.mark_read_direct(key).await;
            Ok(())
        }
        "group" => {
            // Parse the 16-byte group id the same way `group_history` already
            // does, via the same `parse_group` helper.
            let gid = parse_group(&id)?;
            state.mark_read_group(gid);
            Ok(())
        }
        _ => Err("kind must be 'peer' or 'group'".into()),
    }
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
        EngineEvent::PeerDisconnected(p) => {
            serde_json::json!({ "kind": "peer_disconnected", "id": hexkey(&p) })
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
        EngineEvent::FileReceived {
            peer,
            transfer_id,
            name,
            path,
        } => serde_json::json!({
            "kind": "file_received",
            "peer": hexkey(&peer),
            "transfer_id": hex::encode(transfer_id),
            "name": name,
            "path": path,
        }),
        EngineEvent::FileFailed {
            peer,
            transfer_id,
            name,
            reason,
        } => serde_json::json!({
            "kind": "file_failed",
            "peer": hexkey(&peer),
            "transfer_id": hex::encode(transfer_id),
            "name": name,
            "reason": reason,
        }),
        EngineEvent::GroupInvited(g) => {
            serde_json::json!({ "kind": "group_invited", "group": hexgroup(&g) })
        }
        EngineEvent::GroupMessageReceived { group, message } => serde_json::json!({
            "kind": "group_message",
            "group": hexgroup(&group),
            "id": hex::encode(message.id),
            "author": hexkey(&message.author),
            "body": message.body,
            "sent_at": message.sent_at,
            "mine": &message.author == me,
        }),
        EngineEvent::StorageWarning { detail } => {
            serde_json::json!({ "kind": "storage_warning", "detail": detail })
        }
        EngineEvent::ContactUpdated(peer) => {
            serde_json::json!({ "kind": "contact_updated", "id": hexkey(&peer) })
        }
        EngineEvent::PinWarning {
            peer,
            old_fingerprint,
            new_fingerprint,
        } => serde_json::json!({
            "kind": "pin_warning",
            "id": hexkey(&peer),
            "old": old_fingerprint,
            "new": new_fingerprint,
        }),
        EngineEvent::HistorySynced { peer, scope, added } => {
            let (scope_str, id) = match scope {
                SyncScope::Direct => ("peer", hexkey(&peer)),
                SyncScope::Group(gid) => ("group", hexgroup(&gid)),
            };
            serde_json::json!({
                "kind": "history_synced",
                "scope": scope_str,
                "id": id,
                "added": added,
            })
        }
        EngineEvent::MessageStatus { peer, id, status } => serde_json::json!({
            "kind": "message_status",
            "peer": hexkey(&peer),
            "id": hex::encode(id),
            "status": status_str(status),
        }),
    };
    let _ = handle.emit("engine://event", payload);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
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
            send_file,
            save_file_as,
            open_path,
            notify_typing,
            list_groups,
            create_group,
            group_history,
            send_group,
            list_contacts,
            list_nearby,
            set_alias,
            remove_contact,
            accept_new_key,
            mark_read
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vartalaap");
}
