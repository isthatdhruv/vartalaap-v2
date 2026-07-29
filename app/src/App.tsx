import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import Unlock from "./Unlock";
import "./App.css";

type WhoAmI = { id: string; fingerprint: string; display_name: string };
type Contact = {
  id: string;
  name: string;
  online: boolean;
  last_seen: number;
  unread: number;
  pin_pending: boolean;
};
type Nearby = { id: string };
type Group = { id: string; name: string; members: string[]; creator: string };
type FileInfo = {
  name: string;
  size: number;
  mime: string;
  transfer_id: string;
  received_path: string | null;
};
type Message = {
  id: string;
  author: string;
  body: string;
  sent_at: number;
  mine: boolean;
  file: FileInfo | null;
  status: "queued" | "sent" | "delivered" | null;
};
type Banner = { kind: "error" | "warn"; text: string; peer?: string };
type Target = { kind: "peer" | "group"; id: string; name?: string };

const shortId = (id: string) => id.slice(0, 10);
const fmtSize = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1024 * 1024
      ? `${(n / 1024).toFixed(1)} KB`
      : `${(n / 1024 / 1024).toFixed(1)} MB`;

// last_seen / sent_at are millisecond Unix timestamps from the engine.
const fmtLastSeen = (ms: number) => {
  const diff = Date.now() - ms;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return new Date(ms).toLocaleDateString();
};

const glyph = (s: Message["status"]) =>
  s === "queued" ? "🕓" : s === "sent" ? "✓" : s === "delivered" ? "✓✓" : "";

export default function App() {
  const [me, setMe] = useState<WhoAmI | null>(null);
  // Nothing below can talk to the engine until the vault is open, so every
  // engine-touching effect waits on this.
  const [unlocked, setUnlocked] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [nearby, setNearby] = useState<Nearby[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [selected, setSelected] = useState<Target | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState("");
  const [typingPeer, setTypingPeer] = useState<string | null>(null);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupPicks, setGroupPicks] = useState<Set<string>>(new Set());
  // transfer_id -> failure reason, for received files that didn't complete.
  const [fileErrors, setFileErrors] = useState<Record<string, string>>({});
  const [banners, setBanners] = useState<Banner[]>([]);
  const [editingAlias, setEditingAlias] = useState(false);
  const [aliasDraft, setAliasDraft] = useState("");

  const selectedRef = useRef<Target | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  // Throttle outgoing "typing" pings (one QUIC stream each) to ~1/s, and keep a
  // single pending timeout for clearing the *incoming* typing indicator.
  const lastTypingRef = useRef(0);
  const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  selectedRef.current = selected;

  const pushBanner = useCallback((b: Banner) => {
    setBanners((prev) =>
      prev.some((x) => x.kind === b.kind && x.text === b.text && x.peer === b.peer)
        ? prev
        : [...prev, b],
    );
  }, []);

  const refreshRoster = useCallback(async () => {
    const [c, n] = await Promise.all([
      invoke<Contact[]>("list_contacts"),
      invoke<Nearby[]>("list_nearby"),
    ]);
    setContacts(c);
    setNearby(n);
  }, []);

  const refreshGroups = useCallback(async () => {
    setGroups(await invoke<Group[]>("list_groups"));
  }, []);

  const loadHistory = useCallback(async (t: Target) => {
    const msgs =
      t.kind === "peer"
        ? await invoke<Message[]>("history", { peer: t.id })
        : await invoke<Message[]>("group_history", { group: t.id });
    if (selectedRef.current?.id === t.id) setMessages(msgs);
  }, []);

  useEffect(() => {
    if (!unlocked) return;
    invoke<WhoAmI>("whoami").then((w) => {
      setMe(w);
      setNameDraft(w.display_name);
    });
    refreshRoster();
    refreshGroups();
    // Vault-quarantine warnings from loading persisted state at startup are
    // emitted on the event channel too, but before this effect subscribes —
    // pull them explicitly so they aren't silently lost.
    invoke<string[]>("startup_warnings")
      .then((warnings) => warnings.forEach((text) => pushBanner({ kind: "warn", text })))
      .catch(() => {});

    const unlisten = listen<any>("engine://event", (e) => {
      const p = e.payload;
      const sel = selectedRef.current;
      switch (p.kind) {
        case "peer_discovered":
        case "peer_connected":
        case "peer_disconnected":
        case "contact_updated":
          refreshRoster();
          break;
        case "message":
        case "file_received":
          if (sel?.kind === "peer" && sel.id === p.peer) loadHistory(sel);
          break;
        case "file_failed":
          setFileErrors((prev) => ({ ...prev, [p.transfer_id]: p.reason }));
          break;
        case "group_message":
          if (sel?.kind === "group" && sel.id === p.group) loadHistory(sel);
          break;
        case "group_invited":
          refreshGroups();
          break;
        case "typing":
          if (sel?.kind === "peer" && sel.id === p.peer) {
            setTypingPeer(p.peer);
            if (typingTimer.current) clearTimeout(typingTimer.current);
            typingTimer.current = setTimeout(
              () => setTypingPeer((t) => (t === p.peer ? null : t)),
              2500,
            );
          }
          break;
        case "history_synced":
          refreshRoster();
          if (
            sel &&
            ((p.scope === "peer" && sel.kind === "peer" && sel.id === p.id) ||
              (p.scope === "group" && sel.kind === "group" && sel.id === p.id))
          )
            loadHistory(sel);
          break;
        case "message_status":
          setMessages((prev) =>
            prev.map((m) => (m.id === p.id ? { ...m, status: p.status } : m)),
          );
          break;
        case "storage_warning":
          pushBanner({ kind: "warn", text: p.detail });
          break;
        case "pin_warning":
          pushBanner({
            kind: "warn",
            text: `Identity changed for this contact (was ${p.old}, now ${p.new}). Accept only if you trust it.`,
            peer: p.id,
          });
          refreshRoster();
          break;
        default:
          break;
      }
    });

    const poll = setInterval(refreshRoster, 4000);
    return () => {
      unlisten.then((f) => f());
      clearInterval(poll);
      if (typingTimer.current) clearTimeout(typingTimer.current);
    };
  }, [unlocked, refreshRoster, refreshGroups, loadHistory, pushBanner]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Mark the open conversation read whenever it changes or gains messages.
  useEffect(() => {
    if (!selected) return;
    invoke("mark_read", { kind: selected.kind, id: selected.id }).catch(() => {});
  }, [selected, messages.length]);

  const selectPeer = (id: string) => {
    setSelected({ kind: "peer", id });
    setMessages([]);
    setEditingAlias(false);
    loadHistory({ kind: "peer", id });
  };

  const selectGroup = (g: Group) => {
    const t: Target = { kind: "group", id: g.id, name: g.name };
    setSelected(t);
    setMessages([]);
    loadHistory(t);
  };

  // Nearby entries aren't contacts yet; an explicit connect performs the
  // handshake that promotes them (the backend auto-dials known contacts).
  const connectNearby = async (id: string) => {
    try {
      await invoke("connect", { id });
    } catch (e) {
      pushBanner({ kind: "error", text: `Connect failed: ${e}` });
    }
    refreshRoster();
  };

  const sendMessage = async () => {
    const body = draft.trim();
    if (!body || !selected) return;
    setDraft("");
    try {
      if (selected.kind === "peer") {
        const msg = await invoke<Message>("send", { peer: selected.id, body });
        setMessages((prev) => [...prev, msg]);
      } else {
        await invoke("send_group", { group: selected.id, body });
        loadHistory(selected);
      }
    } catch (e) {
      pushBanner({ kind: "error", text: `Send failed: ${e}` });
    }
  };

  const sendFile = async () => {
    if (!selected || selected.kind !== "peer") return;
    const path = await open({ multiple: false, directory: false });
    if (typeof path !== "string") return;
    try {
      await invoke("send_file", { peer: selected.id, path });
      loadHistory(selected);
    } catch (e) {
      pushBanner({ kind: "error", text: `Send file failed: ${e}` });
    }
  };

  // Receiver: copy a downloaded file to a location of the user's choosing.
  const saveFileAs = async (file: FileInfo) => {
    if (!file.received_path) return;
    const dest = await save({ defaultPath: file.name });
    if (typeof dest !== "string") return;
    try {
      await invoke("save_file_as", { src: file.received_path, dest });
    } catch (e) {
      pushBanner({ kind: "error", text: `Save failed: ${e}` });
    }
  };

  // Receiver: open the downloaded file with the system default app.
  const openFile = async (file: FileInfo) => {
    if (!file.received_path) return;
    try {
      await invoke("open_path", { path: file.received_path });
    } catch (e) {
      pushBanner({ kind: "error", text: `Open failed: ${e}` });
    }
  };

  const createGroup = async () => {
    const name = groupName.trim();
    const members = [...groupPicks];
    if (!name || members.length === 0) return;
    try {
      // create_group invites reachable members directly; delta-sync heals
      // the rest, so there's no need to pre-connect here.
      const id = await invoke<string>("create_group", { name, members });
      setShowNewGroup(false);
      setGroupName("");
      setGroupPicks(new Set());
      await refreshGroups();
      setSelected({ kind: "group", id, name });
      loadHistory({ kind: "group", id, name });
    } catch (e) {
      pushBanner({ kind: "error", text: `Create group failed: ${e}` });
    }
  };

  const saveName = async () => {
    await invoke("set_display_name", { name: nameDraft.trim() });
    setMe((m) => (m ? { ...m, display_name: nameDraft.trim() } : m));
    setEditingName(false);
  };

  const togglePick = (id: string) =>
    setGroupPicks((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });

  const isSelected = (kind: Target["kind"], id: string) =>
    selected?.kind === kind && selected.id === id;

  const selectedContact =
    selected?.kind === "peer" ? contacts.find((c) => c.id === selected.id) : undefined;

  const saveAlias = async () => {
    if (!selected || selected.kind !== "peer") return;
    const alias = aliasDraft.trim();
    try {
      await invoke("set_alias", { peer: selected.id, alias: alias === "" ? null : alias });
      refreshRoster();
    } catch (e) {
      pushBanner({ kind: "error", text: `Set alias failed: ${e}` });
    }
    setEditingAlias(false);
  };

  const removeContact = async () => {
    if (!selected || selected.kind !== "peer") return;
    const label = selectedContact?.name ?? shortId(selected.id);
    if (
      !window.confirm(`Remove ${label}? This deletes your local message history with them.`)
    )
      return;
    try {
      await invoke("remove_contact", { peer: selected.id });
      setSelected(null);
      setMessages([]);
      refreshRoster();
    } catch (e) {
      pushBanner({ kind: "error", text: `Remove contact failed: ${e}` });
    }
  };

  if (!unlocked) {
    return (
      <Unlock
        onUnlocked={(w) => {
          setMe(w);
          setNameDraft(w.display_name);
          setUnlocked(true);
        }}
      />
    );
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="me">
          <div className="avatar">
            {(me?.display_name || "?")[0]?.toUpperCase()}
          </div>
          <div className="me-info">
            {editingName ? (
              <div className="name-edit">
                <input
                  value={nameDraft}
                  autoFocus
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && saveName()}
                  placeholder="Your name"
                />
                <button onClick={saveName}>Save</button>
              </div>
            ) : (
              <div className="name-row" onClick={() => setEditingName(true)}>
                <span className="display-name">
                  {me?.display_name || "Set your name"}
                </span>
                <span className="edit-hint">edit</span>
              </div>
            )}
            <code className="vid" title={me?.id}>
              {me ? me.fingerprint.slice(0, 16) : "…"}
            </code>
          </div>
        </div>

        <div className="section-label">Contacts</div>
        <ul className="peers">
          {contacts.length === 0 && <li className="empty">No contacts yet</li>}
          {contacts.map((c) => (
            <li
              key={c.id}
              className={`peer ${isSelected("peer", c.id) ? "active" : ""}`}
              onClick={() => selectPeer(c.id)}
            >
              <span className={`dot ${c.online ? "on" : ""}`} />
              <span className="peer-name">{c.name}</span>
              {c.pin_pending && (
                <span className="pin-flag" title="Identity changed">
                  ⚠
                </span>
              )}
              {c.unread > 0 && <span className="unread">{c.unread}</span>}
            </li>
          ))}
        </ul>

        <div className="section-label">Nearby</div>
        <ul className="peers">
          {nearby.length === 0 && <li className="empty">Searching the LAN…</li>}
          {nearby.map((n) => (
            <li key={n.id} className="peer" onClick={() => connectNearby(n.id)}>
              <span className="dot on" />
              <span className="peer-name">{shortId(n.id)}…</span>
              <span className="hint">tap to connect</span>
            </li>
          ))}
        </ul>

        <div className="section-title">
          Groups
          <button className="mini" onClick={() => setShowNewGroup((s) => !s)}>
            +
          </button>
        </div>
        {showNewGroup && (
          <div className="new-group">
            <input
              value={groupName}
              placeholder="Group name"
              onChange={(e) => setGroupName(e.target.value)}
            />
            <div className="pick-list">
              {contacts.length === 0 && (
                <div className="empty">No contacts to add yet</div>
              )}
              {contacts.map((c) => (
                <label key={c.id} className="pick">
                  <input
                    type="checkbox"
                    checked={groupPicks.has(c.id)}
                    onChange={() => togglePick(c.id)}
                  />
                  {c.name}
                </label>
              ))}
            </div>
            <button onClick={createGroup}>Create group</button>
          </div>
        )}
        <ul className="peers">
          {groups.map((g) => (
            <li
              key={g.id}
              className={`peer ${isSelected("group", g.id) ? "active" : ""}`}
              onClick={() => selectGroup(g)}
            >
              <span className="group-glyph">#</span>
              <span className="peer-id">{g.name}</span>
              <span className="member-count">{g.members.length}</span>
            </li>
          ))}
        </ul>

        <div className="brand">Vartalaap · P2P · E2E encrypted</div>
      </aside>

      <main className="chat">
        {selected ? (
          <>
            <header className="chat-header">
              {selected.kind === "peer" ? (
                <div className="chat-title">
                  {editingAlias ? (
                    <div className="name-edit">
                      <input
                        value={aliasDraft}
                        autoFocus
                        placeholder="Alias (blank to clear)"
                        onChange={(e) => setAliasDraft(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && saveAlias()}
                      />
                      <button onClick={saveAlias}>Save</button>
                    </div>
                  ) : (
                    <span
                      className="peer-id chat-name"
                      onClick={() => {
                        setAliasDraft(selectedContact?.name ?? "");
                        setEditingAlias(true);
                      }}
                    >
                      {selectedContact?.name ?? shortId(selected.id)}
                      <span className="edit-hint">✎</span>
                    </span>
                  )}
                  {selectedContact && !selectedContact.online && (
                    <span className="last-seen">
                      last seen {fmtLastSeen(selectedContact.last_seen)}
                    </span>
                  )}
                </div>
              ) : (
                <span className="peer-id">{`# ${selected.name}`}</span>
              )}
              <div className="chat-actions">
                <span className="enc-badge">🔒 end-to-end encrypted</span>
                {selected.kind === "peer" && (
                  <button className="danger" onClick={removeContact}>
                    Remove contact
                  </button>
                )}
              </div>
            </header>

            {banners.length > 0 && (
              <div className="banners">
                {banners.map((b, i) => (
                  <div key={i} className={`banner ${b.kind}`}>
                    <span className="banner-text">{b.text}</span>
                    {b.peer && selected.kind === "peer" && selected.id === b.peer && (
                      <button
                        className="banner-action"
                        onClick={() => {
                          invoke("accept_new_key", { peer: b.peer })
                            .then(() => {
                              setBanners((prev) => prev.filter((x) => x !== b));
                              refreshRoster();
                            })
                            .catch((e) =>
                              pushBanner({ kind: "error", text: `Accept failed: ${e}` }),
                            );
                        }}
                      >
                        Accept new identity
                      </button>
                    )}
                    <button
                      className="banner-dismiss"
                      onClick={() => setBanners((prev) => prev.filter((x) => x !== b))}
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div className="messages">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`bubble ${m.mine ? "mine" : "theirs"}`}
                >
                  {m.file ? (
                    <div className="file-msg">
                      <span className="file-chip">
                        📎 {m.file.name}
                        <span className="file-size">{fmtSize(m.file.size)}</span>
                      </span>
                      {!m.mine &&
                        (fileErrors[m.file.transfer_id] ? (
                          <span className="file-error">
                            ⚠ {fileErrors[m.file.transfer_id]}
                          </span>
                        ) : m.file.received_path ? (
                          <span className="file-actions">
                            <button onClick={() => saveFileAs(m.file!)}>
                              Save as…
                            </button>
                            <button onClick={() => openFile(m.file!)}>Open</button>
                          </span>
                        ) : (
                          <span className="file-receiving">receiving…</span>
                        ))}
                    </div>
                  ) : (
                    m.body
                  )}
                  {m.mine && glyph(m.status) && (
                    <span className="status-glyph">{glyph(m.status)}</span>
                  )}
                </div>
              ))}
              {typingPeer && selected.kind === "peer" && selected.id === typingPeer && (
                <div className="bubble theirs typing">typing…</div>
              )}
              <div ref={endRef} />
            </div>
            <div className="composer">
              {selected.kind === "peer" && (
                <button className="attach" title="Send a file" onClick={sendFile}>
                  📎
                </button>
              )}
              <input
                value={draft}
                placeholder="Type a message…"
                onChange={(e) => {
                  setDraft(e.target.value);
                  if (selected.kind === "peer") {
                    const now = Date.now();
                    if (now - lastTypingRef.current > 1500) {
                      lastTypingRef.current = now;
                      invoke("notify_typing", { peer: selected.id }).catch(() => {});
                    }
                  }
                }}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
              />
              <button onClick={sendMessage}>Send</button>
            </div>
          </>
        ) : (
          <div className="placeholder">
            <h1>Vartalaap</h1>
            <p>Pick someone — or a group — to start a private, encrypted chat.</p>
            <p className="muted">No servers. No accounts. Just peers.</p>
          </div>
        )}
      </main>
    </div>
  );
}
