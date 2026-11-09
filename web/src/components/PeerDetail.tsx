import { useEffect, useState } from "react";
import { Copy, Download, KeyRound, Pencil, Power, RefreshCw, Trash2 } from "lucide-react";
import { api, type Live, type Peer, type Range, type Settings, type TrafficPoint } from "../api";
import { ago, bytes, dateTime, duration, rate, shortKey } from "../format";
import { errorMessage, useNow, useToast } from "../state";
import { Legend, TrafficChart } from "./charts";
import { Confirm, Modal, Segmented, copyText } from "./ui";
import { PeerForm } from "./PeerForm";

const rangeMs: Record<Range, number> = { "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3 };

export function PeerDetail({ peer, live, settings, isAdmin, onClose, onChanged, initialTab = "overview", initialConfig }: { peer: Peer; live: Live; settings: Settings; isAdmin: boolean; onClose: () => void; onChanged: (p?: Peer) => void; initialTab?: "overview" | "config"; initialConfig?: string }) {
  const toast = useToast();
  const now = useNow(1000);
  const [tab, setTab] = useState<"overview" | "config">(initialTab);
  const [config, setConfig] = useState<string>(initialConfig ?? "");
  const [range, setRange] = useState<Range>("24h");
  const [series, setSeries] = useState<TrafficPoint[]>([]);
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<null | "delete" | "rotate" | "disable">(null);
  const [busy, setBusy] = useState(false);
  const [qrKey, setQrKey] = useState(0);

  useEffect(() => {
    if (tab === "config" && !config) api.peerConfig(peer.id).then(setConfig).catch((e) => toast(errorMessage(e), "bad"));
  }, [tab, config, peer.id, toast]);
  useEffect(() => {
    api.peerUsage(peer.id, range).then(setSeries).catch(() => {});
  }, [peer.id, range, peer.updatedAt]);

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done);
      onChanged();
    } catch (e) {
      toast(errorMessage(e), "bad");
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  }

  const state = !peer.enabled ? "disabled" : peer.expired ? "expired" : live.connected ? "on" : "off";
  const stateLabel = { disabled: "Disabled", expired: "Expired", on: "Connected", off: "Not connected" }[state];

  return (
    <>
      <Modal
        title={peer.name}
        onClose={onClose}
        wide
        footer={
          isAdmin ? (
            <div className="btn-row" style={{ justifyContent: "flex-end", width: "100%" }}>
              <button className="btn sm" onClick={() => setEditing(true)} disabled={busy}>
                <Pencil /> Edit
              </button>
              {peer.enabled ? (
                <button className="btn sm" onClick={() => setConfirm("disable")} disabled={busy} title="Remove from the interface; drops the session">
                  <Power /> Disconnect
                </button>
              ) : (
                <button className="btn sm" onClick={() => act(() => api.enablePeer(peer.id), "Peer enabled")} disabled={busy}>
                  <Power /> Enable
                </button>
              )}
              <button className="btn sm" onClick={() => act(() => api.resetPeer(peer.id), "Session reset")} disabled={busy || !peer.enabled} title="Drop the current session; a client that is sending traffic handshakes again within about 15 seconds">
                <RefreshCw /> Reset session
              </button>
              {peer.serverKeys && (
                <button className="btn sm" onClick={() => setConfirm("rotate")} disabled={busy} title="New key pair; the old config stops working">
                  <KeyRound /> Rotate keys
                </button>
              )}
              <button className="btn sm danger" onClick={() => setConfirm("delete")} disabled={busy}>
                <Trash2 /> Delete
              </button>
            </div>
          ) : undefined
        }
      >
        <div className="tabs">
          <button className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>
            Overview
          </button>
          <button className={tab === "config" ? "active" : ""} onClick={() => setTab("config")}>
            Configuration
          </button>
        </div>
        {tab === "overview" && (
          <>
            <div className="grid grid-2">
              <dl className="kv">
                <dt>Status</dt>
                <dd>
                  <span className={`dot ${state}`} />
                  {stateLabel}
                  {live.connected && live.connectedSince && <span className="faint"> for {duration(live.connectedSince, now)}</span>}
                </dd>
                <dt>Tunnel address</dt>
                <dd className="mono">
                  {peer.ipv4}
                  {peer.ipv6 ? `, ${peer.ipv6}` : ""}
                </dd>
                <dt>Endpoint</dt>
                <dd className="mono">{live.endpoint || "—"}</dd>
                <dt>Last handshake</dt>
                <dd>
                  {ago(live.lastHandshake, now)} <span className="faint">{dateTime(live.lastHandshake)}</span>
                </dd>
                <dt>Rate</dt>
                <dd className="num">
                  ↓ {rate(live.rxRate)} · ↑ {rate(live.txRate)}
                </dd>
                <dt>Transfer</dt>
                <dd className="num">
                  ↓ {bytes(live.rx)} · ↑ {bytes(live.tx)}
                </dd>
              </dl>
              <dl className="kv">
                <dt>Public key</dt>
                <dd className="mono" title={peer.publicKey}>
                  {shortKey(peer.publicKey)}{" "}
                  <button className="btn icon ghost sm" title="Copy" onClick={() => copyText(peer.publicKey).then((ok) => toast(ok ? "Copied" : "Could not copy", ok ? "ok" : "bad"))}>
                    <Copy />
                  </button>
                </dd>
                <dt>Keys</dt>
                <dd>
                  {peer.serverKeys ? "generated by the server" : "held by the client"}
                  {peer.presharedKey ? " · preshared key" : ""}
                </dd>
                <dt>Client routes</dt>
                <dd className="mono">{peer.clientRoutes}</dd>
                <dt>DNS</dt>
                <dd>{peer.dns || <span className="faint">server default ({settings.dns || "none"})</span>}</dd>
                <dt>Keepalive / MTU</dt>
                <dd>
                  {peer.keepalive || settings.keepalive}s / {peer.mtu || settings.mtu}
                </dd>
                <dt>Expires</dt>
                <dd>{peer.expiresAt ? dateTime(peer.expiresAt) : <span className="faint">never</span>}</dd>
                <dt>Belongs to</dt>
                <dd>{peer.owner || <span className="faint">nobody in particular</span>}</dd>
                <dt>Created</dt>
                <dd>{dateTime(peer.createdAt)}</dd>
              </dl>
            </div>
            {peer.notes && <p className="mt muted" style={{ whiteSpace: "pre-wrap" }}>{peer.notes}</p>}
            <div className="mt" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <Legend />
              <Segmented value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }, { value: "30d", label: "30d" }]} />
            </div>
            <TrafficChart points={series} from={now - rangeMs[range]} to={now} bucketSeconds={range === "30d" ? 3600 : 300} />
          </>
        )}
        {tab === "config" && (
          <div className="qr">
            {peer.serverKeys ? (
              <img key={qrKey} src={`/api/peers/${peer.id}/qr.png?size=384&v=${peer.updatedAt}`} alt="QR code of the client configuration" width={320} height={320} onError={() => setQrKey((k) => k + 1)} />
            ) : (
              <div className="notice">This peer holds its own private key, so there is no QR code. Fill in the PrivateKey line on the client.</div>
            )}
            <pre className="config">{config || "…"}</pre>
            <div className="btn-row">
              <button className="btn" onClick={() => copyText(config).then((ok) => toast(ok ? "Configuration copied" : "Could not copy", ok ? "ok" : "bad"))} disabled={!config}>
                <Copy /> Copy
              </button>
              <a className="btn" href={`/api/peers/${peer.id}/config?download=1`}>
                <Download /> Download .conf
              </a>
              <span className="small faint">Anyone with this file can connect as this peer. Viewing it is recorded in the audit log.</span>
            </div>
          </div>
        )}
      </Modal>
      {editing && (
        <PeerForm
          peer={peer}
          settings={settings}
          onClose={() => setEditing(false)}
          onSaved={(p) => {
            setEditing(false);
            setConfig("");
            toast("Peer saved");
            onChanged(p);
          }}
        />
      )}
      {confirm === "delete" && <Confirm title="Delete peer" danger confirmLabel="Delete" busy={busy} onClose={() => setConfirm(null)} onConfirm={() => act(() => api.deletePeer(peer.id).then(() => onClose()), "Peer deleted")} text={<>Delete <b>{peer.name}</b>? Its keys, address and traffic history are gone for good.</>} />}
      {confirm === "disable" && <Confirm title="Disconnect peer" confirmLabel="Disconnect" busy={busy} onClose={() => setConfirm(null)} onConfirm={() => act(() => api.disablePeer(peer.id), "Peer disconnected")} text={<>Remove <b>{peer.name}</b> from the interface? Its session drops now and it cannot reconnect until you enable it again.</>} />}
      {confirm === "rotate" && (
        <Confirm
          title="Rotate keys"
          confirmLabel="Rotate"
          busy={busy}
          onClose={() => setConfirm(null)}
          onConfirm={() =>
            act(
              () =>
                api.rotatePeer(peer.id).then((p) => {
                  setConfig(p.config);
                  setTab("config");
                }),
              "Keys rotated; hand out the new configuration",
            )
          }
          text={<>Give <b>{peer.name}</b> a new key pair? The configuration it has now stops working the moment you confirm.</>}
        />
      )}
    </>
  );
}
