import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export type WhoAmI = { id: string; fingerprint: string; display_name: string };

type VaultStatus = {
  exists: boolean;
  unlocked: boolean;
  min_passphrase_len: number;
};

/**
 * Gate in front of the chat UI. Nothing in the app can run before this
 * resolves: the engine's identity, roster and history all live in a vault
 * sealed under a key derived from this passphrase, so there is no node to talk
 * to until the user supplies it.
 *
 * Two modes, decided by whether a vault already exists on disk:
 *  - create: choose a passphrase, typed twice, minimum length enforced
 *  - unlock: enter the existing one
 */
export default function Unlock({
  onUnlocked,
}: {
  onUnlocked: (me: WhoAmI) => void;
}) {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    invoke<VaultStatus>("vault_status")
      .then((s) => {
        setStatus(s);
        // An already-unlocked vault means the window was reloaded while the
        // engine kept running; skip straight through rather than asking again.
        if (s.unlocked) invoke<WhoAmI>("whoami").then(onUnlocked).catch(() => {});
      })
      .catch((e) => setError(String(e)));
  }, [onUnlocked]);

  useEffect(() => {
    inputRef.current?.focus();
  }, [status]);

  if (!status) return <div className="unlock-shell" />;

  const creating = !status.exists;
  const tooShort = creating && passphrase.length < status.min_passphrase_len;
  const mismatch = creating && confirm.length > 0 && passphrase !== confirm;
  const canSubmit =
    !busy &&
    passphrase.length > 0 &&
    (!creating || (!tooShort && passphrase === confirm));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const me = await invoke<WhoAmI>("unlock", { passphrase });
      onUnlocked(me);
    } catch (err) {
      setError(String(err));
      setPassphrase("");
      setConfirm("");
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="unlock-shell">
      <form className="unlock-card" onSubmit={submit}>
        <div className="unlock-brand">Vartalaap</div>
        <h1 className="unlock-title">
          {creating ? "Choose a passphrase" : "Unlock your vault"}
        </h1>
        <p className="unlock-sub">
          {creating
            ? "This encrypts your identity, contacts and message history on this device. There is no way to recover it — no server has a copy."
            : "Your messages and contacts are encrypted on this device."}
        </p>

        <input
          ref={inputRef}
          className="unlock-input"
          type="password"
          value={passphrase}
          autoComplete={creating ? "new-password" : "current-password"}
          placeholder="Passphrase"
          disabled={busy}
          onChange={(e) => {
            setPassphrase(e.target.value);
            setError(null);
          }}
        />

        {creating && (
          <input
            className="unlock-input"
            type="password"
            value={confirm}
            autoComplete="new-password"
            placeholder="Confirm passphrase"
            disabled={busy}
            onChange={(e) => setConfirm(e.target.value)}
          />
        )}

        {creating && tooShort && passphrase.length > 0 && (
          <div className="unlock-hint">
            At least {status.min_passphrase_len} characters.
          </div>
        )}
        {mismatch && <div className="unlock-hint">Passphrases don't match.</div>}
        {error && <div className="unlock-error">{error}</div>}

        <button className="unlock-button" type="submit" disabled={!canSubmit}>
          {busy ? "Unlocking…" : creating ? "Create vault" : "Unlock"}
        </button>

        {creating && (
          <p className="unlock-footnote">
            Forgetting this passphrase means losing this identity — you'd start
            over with a new Vartalaap ID.
          </p>
        )}
      </form>
    </div>
  );
}
