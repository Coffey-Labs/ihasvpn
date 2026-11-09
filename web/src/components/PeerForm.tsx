import { useEffect, useState, type FormEvent } from "react";
import { api, type Peer, type PeerInput, type Settings, type User } from "../api";
import { fromLocalInput, toLocalInput } from "../format";
import { errorMessage } from "../state";
import { Check, Field, Modal } from "./ui";

// One form for create and edit. On create the key mode is chosen here; on
// edit keys and addresses are fixed (rotate keys from the detail view).
export function PeerForm({ peer, settings, onClose, onSaved }: { peer?: Peer; settings: Settings; onClose: () => void; onSaved: (p: Peer & { config?: string }) => void }) {
  const editing = !!peer;
  const [name, setName] = useState(peer?.name ?? "");
  const [keyMode, setKeyMode] = useState<"server" | "client">("server");
  const [publicKey, setPublicKey] = useState("");
  const [ipv4, setIpv4] = useState("");
  const [ipv6, setIpv6] = useState("");
  const [routes, setRoutes] = useState(peer?.clientRoutes ?? settings.clientRoutes);
  const [dns, setDns] = useState(peer?.dns ?? "");
  const [keepalive, setKeepalive] = useState(peer ? String(peer.keepalive) : "0");
  const [mtu, setMtu] = useState(peer ? String(peer.mtu) : "0");
  const [expires, setExpires] = useState(toLocalInput(peer?.expiresAt));
  const [notes, setNotes] = useState(peer?.notes ?? "");
  const [enabled, setEnabled] = useState(peer?.enabled ?? true);
  const [ownerId, setOwnerId] = useState(peer?.ownerId ?? 0);
  const [users, setUsers] = useState<User[]>([]);
  useEffect(() => {
    api.users().then(setUsers).catch(() => {});
  }, []);
  const [advanced, setAdvanced] = useState(editing);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    const body: PeerInput = {
      name,
      clientRoutes: routes,
      dns,
      keepalive: keepalive === "" ? null : Number(keepalive),
      mtu: mtu === "" ? null : Number(mtu),
      enabled,
      expiresAt: expires ? fromLocalInput(expires) : "1970-01-01T00:00:00Z",
      notes,
      ownerId,
    };
    if (!editing) {
      if (keyMode === "client") body.publicKey = publicKey.trim();
      if (ipv4.trim()) body.ipv4 = ipv4.trim();
      if (ipv6.trim()) body.ipv6 = ipv6.trim();
    }
    try {
      const saved = editing ? await api.updatePeer(peer.id, body) : await api.createPeer(body);
      onSaved(saved);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={editing ? `Edit ${peer.name}` : "New peer"}
      onClose={onClose}
      footer={
        <>
          <button className="btn" type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" type="submit" form="peer-form" disabled={busy}>
            {busy ? "…" : editing ? "Save" : "Create peer"}
          </button>
        </>
      }
    >
      <form id="peer-form" onSubmit={submit}>
        {error && <div className="error">{error}</div>}
        <Field label="Name" hint="A device or a person: “Laptop”, “Phone”, “Office router”.">
          <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} />
        </Field>
        <Field label="Belongs to" hint="Its owner sees it under My devices and can set it up, rotate its keys or delete it.">
          <select className="input" value={ownerId} onChange={(e) => setOwnerId(Number(e.target.value))}>
            <option value={0}>Nobody in particular</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.username}
              </option>
            ))}
          </select>
        </Field>
        {!editing && (
          <div className="field">
            <label>Keys</label>
            <div className="btn-row">
              <label className="btn sm" style={{ cursor: "pointer" }}>
                <input type="radio" name="keys" checked={keyMode === "server"} onChange={() => setKeyMode("server")} /> Generate here (QR code)
              </label>
              <label className="btn sm" style={{ cursor: "pointer" }}>
                <input type="radio" name="keys" checked={keyMode === "client"} onChange={() => setKeyMode("client")} /> Client brings its own public key
              </label>
            </div>
            <span className="hint">Generating here lets you scan a QR code. Bringing a key means the private key never leaves the client, but there is no QR code.</span>
          </div>
        )}
        {!editing && keyMode === "client" && (
          <Field label="Client public key">
            <input className="input mono" value={publicKey} onChange={(e) => setPublicKey(e.target.value)} placeholder="base64, 44 characters" required />
          </Field>
        )}
        {!advanced && (
          <button type="button" className="btn sm ghost" onClick={() => setAdvanced(true)} style={{ marginLeft: -8 }}>
            More options…
          </button>
        )}
        {advanced && (
          <>
            <Field label="Client routes (AllowedIPs)" hint="What the client sends through the tunnel. 0.0.0.0/0, ::/0 is everything; the tunnel subnet alone is split tunnelling.">
              <input className="input mono" value={routes} onChange={(e) => setRoutes(e.target.value)} />
            </Field>
            <div className="form-cols">
              <Field label="DNS" hint={`Blank uses the server default (${settings.dns || "none"}).`}>
                <input className="input" value={dns} onChange={(e) => setDns(e.target.value)} placeholder={settings.dns} />
              </Field>
              <Field label="Keepalive (s)" hint={`0 uses the server default (${settings.keepalive}).`}>
                <input className="input" type="number" min={0} max={65535} value={keepalive} onChange={(e) => setKeepalive(e.target.value)} />
              </Field>
              <Field label="MTU" hint={`0 uses the server default (${settings.mtu}).`}>
                <input className="input" type="number" min={0} max={9000} value={mtu} onChange={(e) => setMtu(e.target.value)} />
              </Field>
              <Field label="Expires" hint="The peer is disconnected at this time. Blank never expires.">
                <input className="input" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
              </Field>
              {!editing && (
                <>
                  <Field label="IPv4 address" hint="Blank picks the next free one.">
                    <input className="input mono" value={ipv4} onChange={(e) => setIpv4(e.target.value)} placeholder="auto" />
                  </Field>
                  <Field label="IPv6 address" hint="Only when the server has an IPv6 subnet.">
                    <input className="input mono" value={ipv6} onChange={(e) => setIpv6(e.target.value)} placeholder="auto" />
                  </Field>
                </>
              )}
            </div>
            <Field label="Notes">
              <textarea className="input" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={2000} />
            </Field>
            <Check label="Enabled" hint="A disabled peer is removed from the interface and cannot connect." checked={enabled} onChange={setEnabled} />
          </>
        )}
      </form>
    </Modal>
  );
}
