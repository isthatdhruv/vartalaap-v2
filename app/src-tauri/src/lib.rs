//! Vartalaap desktop app: bridges the headless `vartalaap-core` engine to the
//! web UI via Tauri commands (UI → Rust) and an event stream (Rust → UI).
//!
//! The engine does not start with the app. Everything the node touches lives in
//! a vault sealed under a passphrase-derived key, so the node can only be built
//! once the user has supplied that passphrase — see [`unlock`]. Until then
//! [`AppState::node`] is empty and every engine-backed command reports the
//! vault as locked rather than operating on a half-initialised world.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tauri::{Emitter, Manager, State};
use vartalaap_core::node::{DeliveryStatus, EngineEvent, Node, SyncScope};
use vartalaap_core::{CoreError, Message, MessageKind};

/// Shortest passphrase we will accept for a *new* vault. Existing vaults are
/// never re-judged — that would lock people out of their own data.
const MIN_PASSPHRASE_LEN: usize = 8;

/// Service name for the OS credential store (macOS Keychain, Windows
/// Credential Manager, freedesktop Secret Service).
const KEYRING_SERVICE: &str = "com.vartalaap.app";

/// The keychain entry for one vault.
///
/// Keyed by data directory rather than a fixed name: two vaults on one login
/// account (the `VARTALAAP_DATA_DIR` override used for running a second
/// instance) must not fight over a single saved passphrase.
fn keyring_entry(data_dir: &std::path::Path) -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, &data_dir.to_string_lossy()).ok()
}

/// Fetch a saved passphrase, if the user asked us to remember one.
///
/// Every failure here is soft. A keychain can be locked, absent (a headless
/// Linux box with no Secret Service), or refused by the user at the OS prompt
/// — none of which should stop them typing the passphrase in themselves.
fn saved_passphrase(data_dir: &std::path::Path) -> Option<String> {
    keyring_entry(data_dir)?.get_password().ok()
}

fn remember_passphrase(data_dir: &std::path::Path, passphrase: &str) -> Result<(), String> {
    keyring_entry(data_dir)
        .ok_or_else(|| "no OS credential store available on this system".to_string())?
        .set_password(passphrase)
        .map_err(|e| e.to_string())
}

fn forget_passphrase(data_dir: &std::path::Path) {
    if let Some(e) = keyring_entry(data_dir) {
        // Not-found is the expected case when nothing was ever saved.
        let _ = e.delete_credential();
    }
}

/// App-wide state. The node is optional because it does not exist until the
/// vault is unlocked, and `unlock` is the only thing that ever fills it in.
struct AppState {
    node: RwLock<Option<Arc<Node>>>,
    data_dir: PathBuf,
    /// Serialises unlock attempts so a double-submit cannot start two nodes
    /// against the same vault file (redb takes an exclusive lock; the loser
    /// would fail with a confusing database error).
    unlocking: tauri::async_runtime::Mutex<()>,
}

impl AppState {
    /// The running node, or a locked-vault error. Commands use `?` on this
    /// instead of assuming the engine exists.
    fn node(&self) -> Result<Arc<Node>, String> {
        self.node
            .read()
            .map_err(|_| "app state poisoned".to_string())?
            .clone()
            .ok_or_else(|| "vault is locked".to_string())
    }
}

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

/// What the unlock screen needs to decide what to render: a vault that does
/// not exist yet asks the user to *choose* a passphrase (with confirmation);
/// an existing one asks them to enter it.
#[derive(Serialize)]
struct VaultStatus {
    exists: bool,
    unlocked: bool,
    /// Surfaced so the UI can state the rule before the user submits.
    min_passphrase_len: usize,
    /// Whether a passphrase is waiting in the OS credential store, so the UI
    /// can offer to unlock without asking.
    has_saved_passphrase: bool,
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

fn whoami_of(node: &Node) -> WhoAmI {
    WhoAmI {
        id: hexkey(&node.id()),
        fingerprint: node.fingerprint().unwrap_or_default(),
        display_name: node.display_name(),
    }
}

// ---------------------------------------------------------------- vault ----

#[tauri::command]
fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    let exists = vartalaap_core::Engine::vault_exists(&state.data_dir);
    VaultStatus {
        exists,
        unlocked: state.node().is_ok(),
        min_passphrase_len: MIN_PASSPHRASE_LEN,
        // Only meaningful for a vault that exists; a saved passphrase for a
        // deleted vault is stale and must not drive the UI.
        has_saved_passphrase: exists && saved_passphrase(&state.data_dir).is_some(),
    }
}

/// Unlock using the passphrase held in the OS credential store.
///
/// A saved passphrase that no longer opens the vault is forgotten rather than
/// retried forever — otherwise someone who changed it elsewhere would be stuck
/// on a screen that fails every time it loads.
#[tauri::command]
async fn unlock_with_saved(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<WhoAmI, String> {
    let Some(pw) = saved_passphrase(&state.data_dir) else {
        return Err("no saved passphrase".to_string());
    };
    match unlock_inner(pw, false, &app, &state).await {
        Ok(w) => Ok(w),
        Err(e) => {
            forget_passphrase(&state.data_dir);
            Err(e)
        }
    }
}

/// Drop any saved passphrase, so the next launch asks again.
#[tauri::command]
fn forget_saved_passphrase(state: State<'_, AppState>) {
    forget_passphrase(&state.data_dir);
}

/// Unlock (or, on first run, create) the vault and start the engine.
///
/// This is the only path that constructs a [`Node`]. On success the node is
/// installed in [`AppState`] and an event-forwarding task is spawned; both
/// happen exactly once, guarded by `unlocking`.
#[tauri::command]
async fn unlock(
    passphrase: String,
    remember: bool,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<WhoAmI, String> {
    unlock_inner(passphrase, remember, &app, &state).await
}

async fn unlock_inner(
    passphrase: String,
    remember: bool,
    app: &tauri::AppHandle,
    state: &State<'_, AppState>,
) -> Result<WhoAmI, String> {
    let _guard = state.unlocking.lock().await;
    // A concurrent caller may have won the race while we waited.
    if let Ok(node) = state.node() {
        return Ok(whoami_of(&node));
    }

    let creating = !vartalaap_core::Engine::vault_exists(&state.data_dir);
    if creating && passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        ));
    }

    let (node, mut rx) = Node::start_persistent(&state.data_dir, &passphrase)
        .await
        .map_err(|e| match e.downcast_ref::<CoreError>() {
            // The one failure the user can actually fix, so name it plainly
            // instead of leaking an AEAD error.
            Some(CoreError::WrongPassphrase) => "Wrong passphrase.".to_string(),
            _ => e.to_string(),
        })?;

    // Only now that the passphrase is proven good. Saving it on the way in
    // would persist a wrong one. A keychain that refuses the write is not
    // worth failing an otherwise-successful unlock over — the vault is open;
    // the user simply gets asked again next time.
    if remember {
        if let Err(e) = remember_passphrase(&state.data_dir, &passphrase) {
            eprintln!("vartalaap: could not save passphrase to the OS keychain: {e}");
        }
    } else {
        forget_passphrase(&state.data_dir);
    }

    let node = Arc::new(node);
    let me = node.id();
    *state
        .node
        .write()
        .map_err(|_| "app state poisoned".to_string())? = Some(node.clone());

    // Forward engine events to the web UI for the life of the process.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            emit_event(&handle, &me, ev);
        }
    });

    Ok(whoami_of(&node))
}

// --------------------------------------------------------------- engine ----

#[tauri::command]
fn whoami(state: State<'_, AppState>) -> Result<WhoAmI, String> {
    let node = state.node()?;
    Ok(whoami_of(&node))
}

#[tauri::command]
fn set_display_name(name: String, state: State<'_, AppState>) -> Result<(), String> {
    state.node()?.set_display_name(name).map_err(|e| e.to_string())
}

#[tauri::command]
fn history(peer: String, state: State<'_, AppState>) -> Result<Vec<MessageDto>, String> {
    let node = state.node()?;
    let key = parse_key(&peer)?;
    let me = node.id();
    Ok(node
        .conversation_with_status(&key)
        .into_iter()
        .map(|(m, status)| message_dto(m, &me, status, &node))
        .collect())
}

#[tauri::command]
async fn connect(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let node = state.node()?;
    let key = parse_key(&id)?;
    node.connect(key).await.map_err(|e| e.to_string())
}

/// This device's connect code, for the case where mDNS never arrives.
#[tauri::command]
fn my_connect_code(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.node()?.connect_code())
}

/// Dial a peer from a pasted connect code, bypassing LAN discovery.
#[tauri::command]
async fn connect_by_code(code: String, state: State<'_, AppState>) -> Result<String, String> {
    let node = state.node()?;
    node.connect_with_code(&code)
        .await
        .map(|p| hexkey(&p))
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn send(
    peer: String,
    body: String,
    state: State<'_, AppState>,
) -> Result<MessageDto, String> {
    let node = state.node()?;
    let key = parse_key(&peer)?;
    let me = node.id();
    let (message, status) = node
        .send_text(key, &body)
        .await
        .map_err(|e| e.to_string())?;
    Ok(message_dto(message, &me, Some(status), &node))
}

#[tauri::command]
async fn send_file(peer: String, path: String, state: State<'_, AppState>) -> Result<(), String> {
    let node = state.node()?;
    let key = parse_key(&peer)?;
    node.send_file(key, std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn notify_typing(peer: String, state: State<'_, AppState>) -> Result<(), String> {
    let node = state.node()?;
    let key = parse_key(&peer)?;
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
fn list_groups(state: State<'_, AppState>) -> Result<Vec<GroupDto>, String> {
    Ok(state
        .node()?
        .groups()
        .into_iter()
        .map(|g| GroupDto {
            id: hexgroup(&g.id),
            name: g.name,
            members: g.members.iter().map(hexkey).collect(),
            creator: hexkey(&g.creator),
        })
        .collect())
}

#[tauri::command]
async fn create_group(
    name: String,
    members: Vec<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let node = state.node()?;
    let mut keys = Vec::with_capacity(members.len());
    for m in &members {
        keys.push(parse_key(m)?);
    }
    let id = node.create_group(name, keys).await.map_err(|e| e.to_string())?;
    Ok(hexgroup(&id))
}

#[tauri::command]
fn group_history(group: String, state: State<'_, AppState>) -> Result<Vec<MessageDto>, String> {
    let node = state.node()?;
    let g = parse_group(&group)?;
    let me = node.id();
    Ok(node
        .group_conversation(&g)
        .into_iter()
        .map(|m| message_dto(m, &me, None, &node))
        .collect())
}

#[tauri::command]
async fn send_group(group: String, body: String, state: State<'_, AppState>) -> Result<(), String> {
    let node = state.node()?;
    let g = parse_group(&group)?;
    node.send_group_text(g, &body)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_contacts(state: State<'_, AppState>) -> Result<Vec<ContactDto>, String> {
    let node = state.node()?;
    let online: std::collections::HashSet<String> = node
        .connected_peers()
        .into_iter()
        .map(|p| hexkey(&p))
        .collect();
    Ok(node
        .contacts()
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
        .collect())
}

#[tauri::command]
fn list_nearby(state: State<'_, AppState>) -> Result<Vec<NearbyDto>, String> {
    Ok(state
        .node()?
        .nearby()
        .into_iter()
        .map(|p| NearbyDto { id: hexkey(&p) })
        .collect())
}

#[tauri::command]
fn set_alias(peer: String, alias: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.node()?.set_alias(key, alias);
    Ok(())
}

#[tauri::command]
fn remove_contact(peer: String, state: State<'_, AppState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.node()?.remove_contact(key).map_err(|e| e.to_string())
}

#[tauri::command]
fn accept_new_key(peer: String, state: State<'_, AppState>) -> Result<(), String> {
    let key = parse_key(&peer)?;
    state.node()?.accept_new_key(key);
    Ok(())
}

/// Vault load-quarantine warnings recorded before the frontend had a chance
/// to subscribe to the event stream, so they aren't just silently dropped.
#[tauri::command]
fn startup_warnings(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.node()?.startup_warnings())
}

#[tauri::command]
async fn mark_read(kind: String, id: String, state: State<'_, AppState>) -> Result<(), String> {
    let node = state.node()?;
    match kind.as_str() {
        "peer" => {
            let key = parse_key(&id)?;
            node.mark_read_direct(key).await;
            Ok(())
        }
        "group" => {
            // Parse the 16-byte group id the same way `group_history` already
            // does, via the same `parse_group` helper.
            let gid = parse_group(&id)?;
            node.mark_read_group(gid);
            Ok(())
        }
        _ => Err("kind must be 'peer' or 'group'".into()),
    }
}

/// Convert an engine event into a UI-friendly JSON payload and emit it.
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
            let data_dir = std::env::var("VARTALAAP_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| app.path().app_data_dir().expect("resolve app data dir"));
            std::fs::create_dir_all(&data_dir).ok();

            // No engine yet: it cannot exist until the user unlocks the vault.
            app.manage(AppState {
                node: RwLock::new(None),
                data_dir,
                unlocking: tauri::async_runtime::Mutex::new(()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            unlock,
            unlock_with_saved,
            forget_saved_passphrase,
            whoami,
            set_display_name,
            history,
            connect,
            my_connect_code,
            connect_by_code,
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
            mark_read,
            startup_warnings
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vartalaap");
}
