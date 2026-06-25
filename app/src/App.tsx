import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

type WhoAmI = { id: string; fingerprint: string; display_name: string };
type Peer = { id: string; connected: boolean };
type Group = { id: string; name: string; members: string[]; creator: string };
type FileInfo = { name: string; size: number; mime: string };
type Message = {
  id: string;
  author: string;
  body: string;
  sent_at: number;
  mine: boolean;
  file: FileInfo | null;
};
type Target = { kind: "peer" | "group"; id: string; name?: string };

const shortId = (id: string) => id.slice(0, 10);
const fmtSize = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1024 * 1024
      ? `${(n / 1024).toFixed(1)} KB`
      : `${(n / 1024 / 1024).toFixed(1)} MB`;

export default function App() {
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [selected, setSelected] = useState<Target | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState("");
  const [typingPeer, setTypingPeer] = useState<string | null>(null);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupPicks, setGroupPicks] = useState<Set<string>>(new Set());

  const selectedRef = useRef<Target | null>(null);
  const connectedRef = useRef<Set<string>>(new Set());
  const meRef = useRef<WhoAmI | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  selectedRef.current = selected;
  meRef.current = me;

  const refreshPeers = useCallback(async () => {
    const list = await invoke<{ id: string }[]>("list_peers");
    setPeers(
      list.map((p) => ({ id: p.id, connected: connectedRef.current.has(p.id) })),
    );
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

  const ensureConnected = useCallback(async (id: string) => {
    if (connectedRef.current.has(id) || id === meRef.current?.id) return;
    try {
      await invoke("connect", { id });
      connectedRef.current.add(id);
      setPeers((prev) =>
        prev.map((p) => (p.id === id ? { ...p, connected: true } : p)),
      );
    } catch (e) {
      console.error("connect failed", id, e);
    }
  }, []);

  // Establish the member mesh for a group (only initiate where our id is
  // larger, to avoid both sides connecting at once; the creator already
  // connected to us).
  const joinMesh = useCallback(
    async (g: Group) => {
      const myId = meRef.current?.id ?? "";
      for (const m of g.members) {
        if (m === myId || m === g.creator) continue;
        if (myId > m) await ensureConnected(m);
      }
    },
    [ensureConnected],
  );

  useEffect(() => {
    invoke<WhoAmI>("whoami").then((w) => {
      setMe(w);
      setNameDraft(w.display_name);
    });
    refreshPeers();
    refreshGroups();

    const unlisten = listen<any>("engine://event", (e) => {
      const p = e.payload;
      const sel = selectedRef.current;
      switch (p.kind) {
        case "peer_discovered":
          setPeers((prev) =>
            prev.some((x) => x.id === p.id)
              ? prev
              : [...prev, { id: p.id, connected: connectedRef.current.has(p.id) }],
          );
          break;
        case "peer_connected":
          connectedRef.current.add(p.id);
          setPeers((prev) =>
            prev.map((x) => (x.id === p.id ? { ...x, connected: true } : x)),
          );
          break;
        case "message":
        case "file_received":
          if (sel?.kind === "peer" && sel.id === p.peer) loadHistory(sel);
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
            setTimeout(
              () => setTypingPeer((t) => (t === p.peer ? null : t)),
              2500,
            );
          }
          break;
        default:
          break;
      }
    });

    const poll = setInterval(refreshPeers, 4000);
    return () => {
      unlisten.then((f) => f());
      clearInterval(poll);
    };
  }, [refreshPeers, refreshGroups, loadHistory]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const selectPeer = async (id: string) => {
    setSelected({ kind: "peer", id });
    setMessages([]);
    await ensureConnected(id);
    loadHistory({ kind: "peer", id });
  };

  const selectGroup = async (g: Group) => {
    const t: Target = { kind: "group", id: g.id, name: g.name };
    setSelected(t);
    setMessages([]);
    joinMesh(g);
    loadHistory(t);
  };

  const sendMessage = async () => {
    const body = draft.trim();
    if (!body || !selected) return;
    setDraft("");
    try {
      if (selected.kind === "peer")
        await invoke("send", { peer: selected.id, body });
      else await invoke("send_group", { group: selected.id, body });
      loadHistory(selected);
    } catch (e) {
      console.error("send failed", e);
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
      console.error("send_file failed", e);
    }
  };

  const createGroup = async () => {
    const name = groupName.trim();
    const members = [...groupPicks];
    if (!name || members.length === 0) return;
    for (const m of members) await ensureConnected(m);
    const id = await invoke<string>("create_group", { name, members });
    setShowNewGroup(false);
    setGroupName("");
    setGroupPicks(new Set());
    await refreshGroups();
    setSelected({ kind: "group", id, name });
    loadHistory({ kind: "group", id, name });
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

        <div className="section-title">On the network</div>
        <ul className="peers">
          {peers.length === 0 && <li className="empty">Searching the LAN…</li>}
          {peers.map((p) => (
            <li
              key={p.id}
              className={`peer ${selected?.kind === "peer" && selected.id === p.id ? "active" : ""}`}
              onClick={() => selectPeer(p.id)}
            >
              <span className={`dot ${p.connected ? "on" : ""}`} />
              <span className="peer-id">{shortId(p.id)}</span>
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
              {peers.length === 0 && (
                <div className="empty">No peers to add yet</div>
              )}
              {peers.map((p) => (
                <label key={p.id} className="pick">
                  <input
                    type="checkbox"
                    checked={groupPicks.has(p.id)}
                    onChange={() => togglePick(p.id)}
                  />
                  {shortId(p.id)}
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
              className={`peer ${selected?.kind === "group" && selected.id === g.id ? "active" : ""}`}
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
              <span className="peer-id">
                {selected.kind === "group"
                  ? `# ${selected.name}`
                  : shortId(selected.id)}
              </span>
              <span className="enc-badge">🔒 end-to-end encrypted</span>
            </header>
            <div className="messages">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`bubble ${m.mine ? "mine" : "theirs"}`}
                >
                  {m.file ? (
                    <span className="file-chip">
                      📎 {m.file.name}
                      <span className="file-size">{fmtSize(m.file.size)}</span>
                    </span>
                  ) : (
                    m.body
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
                  if (selected.kind === "peer")
                    invoke("notify_typing", { peer: selected.id }).catch(() => {});
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
