import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Copy, Download, KeyRound, Plus, QrCode, Trash2 } from "lucide-react";
import { api, type Device, type MyDevices } from "../api";
import { ago, bytes } from "../format";
import { errorMessage, useNow, useToast } from "../state";
import { Confirm, Field, Modal, copyText } from "../components/ui";

// The devices that belong to whoever is signed in. For a user this is the
// whole console; administrators and viewers have it alongside everything
// else. There is no live stream here (that covers the whole server), so the
// list refreshes itself every few seconds instead.
export function DevicesPage() {
  const toast = useToast();
  const now = useNow();
  const [data, setData] = useState<MyDevices | null>(null);
  const [adding, setAdding] = useState(false);
  const [showing, setShowing] = useState<{ device: Device; config?: string } | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "rotate" | "delete"; device: Device } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => api.myDevices().then(setData).catch((e) => toast(errorMessage(e), "bad")), [toast]);
  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 10000);
    return () => clearInterval(t);
  }, [load]);

  if (!data) return <div className="empty">Loading…</div>;
  const { devices, limit } = data;
  const atLimit = limit !== null && devices.length >= limit;

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      void load();
    } catch (e) {
      toast(errorMessage(e), "bad");
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>My devices</h1>
          <p>{limit === null ? "Devices that belong to you." : limit === 0 ? "An administrator adds devices for you on this server." : `${devices.length} of ${limit} device${limit === 1 ? "" : "s"}.`}</p>
        </div>
        {limit !== 0 && (
          <button className="btn primary" onClick={() => setAdding(true)} disabled={atLimit} title={atLimit ? "You have as many devices as this server allows. Delete one to add another." : undefined}>
            <Plus /> Add device
          </button>
        )}
      </div>

      <div className="card">
        {devices.length === 0 ? (
          <div className="empty">{limit === 0 ? "No devices yet. Ask an administrator to add one for you." : "No devices yet. Add one, then scan its QR code with the WireGuard app."}</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th className="hide-sm">Address</th>
                  <th>Handshake</th>
                  <th className="right hide-sm">Transfer</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => {
                  const state = !d.enabled ? "disabled" : d.expired ? "expired" : d.live.connected ? "on" : "off";
                  return (
                    <tr key={d.id}>
                      <td>
                        <span className={`dot ${state}`} title={state} />
                        {d.name}
                        {!d.enabled && (
                          <span className="badge bad" style={{ marginLeft: 8 }} title="An administrator turned this device off">
                            turned off
                          </span>
                        )}
                        {d.enabled && d.expired && <span className="badge warn" style={{ marginLeft: 8 }}>expired</span>}
                      </td>
                      <td className="mono nowrap hide-sm">{d.ipv4}</td>
                      <td className="nowrap">{ago(d.live.lastHandshake, now)}</td>
                      <td className="num right hide-sm">
                        {bytes(d.live.rx)} <span className="faint">/</span> {bytes(d.live.tx)}
                      </td>
                      <td className="actions nowrap">
                        <button className="btn sm" onClick={() => setShowing({ device: d })} aria-label={`Set up ${d.name}`}>
                          <QrCode /> <span className="hide-sm">Set up</span>
                        </button>{" "}
                        {d.enabled && d.serverKeys && (
                          <button className="btn sm" onClick={() => setConfirm({ kind: "rotate", device: d })} disabled={busy} title="New keys; the old configuration stops working" aria-label={`Rotate keys of ${d.name}`}>
                            <KeyRound /> <span className="hide-sm">Rotate keys</span>
                          </button>
                        )}{" "}
                        {d.enabled && (
                          <button className="btn sm danger" onClick={() => setConfirm({ kind: "delete", device: d })} disabled={busy} aria-label={`Delete ${d.name}`}>
                            <Trash2 /> <span className="hide-sm">Delete</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {adding && (
        <AddDevice
          onClose={() => setAdding(false)}
          onSaved={(d) => {
            setAdding(false);
            toast(`${d.name} added`);
            void load();
            setShowing({ device: d, config: d.config });
          }}
        />
      )}
      {showing && <DeviceConfig device={showing.device} initialConfig={showing.config} onClose={() => setShowing(null)} />}
      {confirm?.kind === "delete" && (
        <Confirm
          title="Delete device"
          danger
          confirmLabel="Delete"
          busy={busy}
          onClose={() => setConfirm(null)}
          onConfirm={() => act(() => api.deleteMyDevice(confirm.device.id), "Device deleted")}
          text={
            <>
              Delete <b>{confirm.device.name}</b>? It disconnects now and its configuration stops working for good.
            </>
          }
        />
      )}
      {confirm?.kind === "rotate" && (
        <Confirm
          title="Rotate keys"
          confirmLabel="Rotate"
          busy={busy}
          onClose={() => setConfirm(null)}
          onConfirm={() =>
            act(
              () => api.rotateMyDevice(confirm.device.id).then((d) => setShowing({ device: d, config: d.config })),
              "Keys rotated; set the device up again",
            )
          }
          text={
            <>
              Give <b>{confirm.device.name}</b> new keys? Do this if the device or its configuration file may have fallen into someone else's hands. The configuration it has now stops working at once.
            </>
          }
        />
      )}
    </>
  );
}

function AddDevice({ onClose, onSaved }: { onClose: () => void; onSaved: (d: Device & { config: string }) => void }) {
  const [name, setName] = useState("");
  const [keyMode, setKeyMode] = useState<"server" | "client">("server");
  const [publicKey, setPublicKey] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      onSaved(await api.createMyDevice(keyMode === "client" ? { name, publicKey: publicKey.trim() } : { name }));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Add device"
      onClose={onClose}
      footer={
        <>
          <button className="btn" type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" type="submit" form="device-form" disabled={busy}>
            {busy ? "…" : "Add device"}
          </button>
        </>
      }
    >
      <form id="device-form" onSubmit={submit}>
        {error && <div className="error">{error}</div>}
        <Field label="Name" hint="Something you will recognise: “Phone”, “Work laptop”.">
          <input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} />
        </Field>
        <div className="field">
          <label>Keys</label>
          <div className="btn-row">
            <label className="btn sm" style={{ cursor: "pointer" }}>
              <input type="radio" name="keys" checked={keyMode === "server"} onChange={() => setKeyMode("server")} /> Make them here (QR code)
            </label>
            <label className="btn sm" style={{ cursor: "pointer" }}>
              <input type="radio" name="keys" checked={keyMode === "client"} onChange={() => setKeyMode("client")} /> My device made its own
            </label>
          </div>
          <span className="hint">Most people want a QR code. If your WireGuard app made a key pair, paste its public key and the private key never leaves the device.</span>
        </div>
        {keyMode === "client" && (
          <Field label="Public key">
            <input className="input mono" value={publicKey} onChange={(e) => setPublicKey(e.target.value)} placeholder="base64, 44 characters" required />
          </Field>
        )}
      </form>
    </Modal>
  );
}

function DeviceConfig({ device, initialConfig, onClose }: { device: Device; initialConfig?: string; onClose: () => void }) {
  const toast = useToast();
  const [config, setConfig] = useState(initialConfig ?? "");
  const [qrKey, setQrKey] = useState(0);
  useEffect(() => {
    if (!config) api.myDeviceConfig(device.id).then(setConfig).catch((e) => toast(errorMessage(e), "bad"));
  }, [config, device.id, toast]);

  return (
    <Modal title={`Set up ${device.name}`} onClose={onClose} wide>
      <div className="qr">
        {device.serverKeys ? (
          <>
            <p className="muted">Open the WireGuard app, add a tunnel from a QR code and scan this. On a computer, download the file and import it instead.</p>
            <img key={qrKey} src={`/api/me/devices/${device.id}/qr.png?size=384&v=${device.updatedAt}`} alt="QR code of the device's configuration" width={320} height={320} onError={() => setQrKey((k) => k + 1)} />
          </>
        ) : (
          <div className="notice">This device holds its own private key, so there is no QR code. Put your private key on the PrivateKey line.</div>
        )}
        <pre className="config">{config || "…"}</pre>
        <div className="btn-row">
          <button className="btn" onClick={() => copyText(config).then((ok) => toast(ok ? "Configuration copied" : "Could not copy", ok ? "ok" : "bad"))} disabled={!config}>
            <Copy /> Copy
          </button>
          <a className="btn" href={`/api/me/devices/${device.id}/config?download=1`}>
            <Download /> Download .conf
          </a>
          <span className="small faint">Anyone with this file can connect as this device, so keep it to yourself.</span>
        </div>
      </div>
    </Modal>
  );
}
