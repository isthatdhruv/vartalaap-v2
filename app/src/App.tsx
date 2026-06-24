import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

type WhoAmI = { id: string; fingerprint: string; display_name: string };
type Peer = { id: string; connected: boolean };
type Message = {
  id: string;
  author: string;
  body: string;
  sent_at: number;
  mine: boolean;
};

const shortId = (id: string) => id.slice(0, 10);

export default function App() {
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState("");
  const [typingPeer, setTypingPeer] = useState<string | null>(null);
  const selectedRef = useRef<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  selectedRef.current = selected;

  const refreshPeers = useCallback(async () => {
    const list = await invoke<{ id: string }[]>("list_peers");
    setPeers((prev) => {
      const connected = new Set(prev.filter((p) => p.connected).map((p) => p.id));
      return list.map((p) => ({ id: p.id, connected: connected.has(p.id) }));
    });
  }, []);

  const loadHistory = useCallback(async (peer: string) => {
    const msgs = await invoke<Message[]>("history", { peer });
    if (selectedRef.current === peer) setMessages(msgs);
  }, []);

  // Initial load + event subscription.
  useEffect(() => {
    invoke<WhoAmI>("whoami").then((w) => {
      setMe(w);
      setNameDraft(w.display_name);
    });
    refreshPeers();

    const unlisten = listen<any>("engine://event", (e) => {
      const p = e.payload;
      switch (p.kind) {
        case "peer_discovered":
          setPeers((prev) =>
            prev.some((x) => x.id === p.id)
              ? prev
              : [...prev, { id: p.id, connected: false }],
          );
          break;
        case "peer_connected":
          setPeers((prev) =>
            prev.map((x) => (x.id === p.id ? { ...x, connected: true } : x)),
          );
          break;
        case "message":
          if (selectedRef.current === p.peer) loadHistory(p.peer);
          break;
        case "typing":
          if (selectedRef.current === p.peer) {
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
  }, [refreshPeers, loadHistory]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const selectPeer = async (id: string) => {
    setSelected(id);
    setMessages([]);
    try {
      await invoke("connect", { id });
      setPeers((prev) =>
        prev.map((x) => (x.id === id ? { ...x, connected: true } : x)),
      );
    } catch (err) {
      console.error("connect failed", err);
    }
    loadHistory(id);
  };

  const sendMessage = async () => {
    const body = draft.trim();
    if (!body || !selected) return;
    setDraft("");
    try {
      await invoke("send", { peer: selected, body });
      loadHistory(selected);
    } catch (err) {
      console.error("send failed", err);
    }
  };

  const saveName = async () => {
    await invoke("set_display_name", { name: nameDraft.trim() });
    setMe((m) => (m ? { ...m, display_name: nameDraft.trim() } : m));
    setEditingName(false);
  };

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
              className={`peer ${selected === p.id ? "active" : ""}`}
              onClick={() => selectPeer(p.id)}
            >
              <span className={`dot ${p.connected ? "on" : ""}`} />
              <span className="peer-id">{shortId(p.id)}</span>
            </li>
          ))}
        </ul>
        <div className="brand">Vartalaap · P2P · E2E encrypted</div>
      </aside>

      <main className="chat">
        {selected ? (
          <>
            <header className="chat-header">
              <span className="peer-id">{shortId(selected)}</span>
              <span className="enc-badge">🔒 end-to-end encrypted</span>
            </header>
            <div className="messages">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`bubble ${m.mine ? "mine" : "theirs"}`}
                >
                  {m.body}
                </div>
              ))}
              {typingPeer === selected && (
                <div className="bubble theirs typing">typing…</div>
              )}
              <div ref={endRef} />
            </div>
            <div className="composer">
              <input
                value={draft}
                placeholder="Type a message…"
                onChange={(e) => {
                  setDraft(e.target.value);
                  if (selected)
                    invoke("notify_typing", { peer: selected }).catch(() => {});
                }}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
              />
              <button onClick={sendMessage}>Send</button>
            </div>
          </>
        ) : (
          <div className="placeholder">
            <h1>Vartalaap</h1>
            <p>Pick someone on your network to start a private, encrypted chat.</p>
            <p className="muted">No servers. No accounts. Just peers.</p>
          </div>
        )}
      </main>
    </div>
  );
}
