import { useEffect, useState, type FormEvent } from "react";
import { api, type Settings } from "../api";
import { errorMessage, useAuth, useLive, useToast } from "../state";
import { Check, Field } from "../components/ui";

export function SettingsPage() {
  const { me } = useAuth();
  const { settingsVersion } = useLive();
  const toast = useToast();
  const [s, setS] = useState<Settings | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const readOnly = me?.role !== "admin";

  useEffect(() => {
    api.settings().then(setS).catch((e) => setError(errorMessage(e)));
  }, [settingsVersion]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!s) return;
    setError("");
    setBusy(true);
    try {
      setS(await api.saveSettings(s));
      toast("Settings saved");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (!s) return <div className="empty">{error || "Loading…"}</div>;
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Changes apply at once. New client configurations use the new values; existing clients keep what they have.</p>
        </div>
      </div>
      <form onSubmit={submit} className="stack">
        {error && <div className="error">{error}</div>}
        {readOnly && <div className="notice">You have the viewer role; settings are read-only.</div>}
        <div className="card">
          <div className="card-head">
            <h2>Endpoint</h2>
          </div>
          <div className="card-body">
            <div className="form-cols">
              <Field label="Public host" hint="Hostname or IP address clients connect to.">
                <input className="input" value={s.endpointHost} onChange={(e) => set("endpointHost", e.target.value)} disabled={readOnly} required />
              </Field>
              <Field label="Public port" hint="What clients dial. Usually the listen port; change it if the container's UDP port is remapped.">
                <input className="input" type="number" min={1} max={65535} value={s.endpointPort} onChange={(e) => set("endpointPort", Number(e.target.value))} disabled={readOnly} required />
              </Field>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <h2>Client defaults</h2>
          </div>
          <div className="card-body">
            <div className="form-cols">
              <Field label="DNS" hint="Comma separated. Clients use these while connected. Blank hands out none.">
                <input className="input" value={s.dns} onChange={(e) => set("dns", e.target.value)} disabled={readOnly} />
              </Field>
              <Field label="Client routes (AllowedIPs)" hint="0.0.0.0/0, ::/0 sends everything through the tunnel.">
                <input className="input mono" value={s.clientRoutes} onChange={(e) => set("clientRoutes", e.target.value)} disabled={readOnly} required />
              </Field>
              <Field label="MTU" hint="1420 fits an IPv4 underlay at 1500; use 1412 for PPPoE, 1400 or less for IPv6-over-IPv6 or when downloads stall.">
                <input className="input" type="number" min={1280} max={9000} value={s.mtu} onChange={(e) => set("mtu", Number(e.target.value))} disabled={readOnly} required />
              </Field>
              <Field label="Persistent keepalive (s)" hint="25 keeps NAT mappings open on home routers. 0 disables it.">
                <input className="input" type="number" min={0} max={65535} value={s.keepalive} onChange={(e) => set("keepalive", Number(e.target.value))} disabled={readOnly} required />
              </Field>
            </div>
            <Check label="Preshared keys" hint="Add a per-peer preshared key to new peers: a symmetric layer on top of the key exchange." checked={s.presharedKeys} onChange={(v) => set("presharedKeys", v)} disabled={readOnly} />
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <h2>Network</h2>
          </div>
          <div className="card-body">
            <Check label="Peer isolation" hint="Drop traffic between peers. Each device can reach the server and the internet, but not the other devices." checked={s.peerIsolation} onChange={(v) => set("peerIsolation", v)} disabled={readOnly} />
            <Check label="Clamp TCP MSS" hint="Rewrite the MSS of forwarded connections to fit the tunnel MTU. Leave on unless you know why not: it is the fix for “connected but pages hang”." checked={s.clampMSS} onChange={(v) => set("clampMSS", v)} disabled={readOnly} />
            <Field label="Connected window (s)" hint="A peer counts as connected this long after its last handshake. WireGuard rejects a session after 180 s.">
              <input className="input" type="number" min={30} max={3600} value={s.connectedWindow} onChange={(e) => set("connectedWindow", Number(e.target.value))} disabled={readOnly} required style={{ maxWidth: 160 }} />
            </Field>
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <h2>People's own devices</h2>
          </div>
          <div className="card-body">
            <Field label="Devices per user" hint="How many devices someone with the user role can add for themselves under My devices. 0 means only an administrator adds them. Administrators have no limit.">
              <input className="input" type="number" min={0} max={1000} value={s.deviceLimit} onChange={(e) => set("deviceLimit", Number(e.target.value))} disabled={readOnly} required style={{ maxWidth: 160 }} />
            </Field>
          </div>
        </div>
        {!readOnly && (
          <div>
            <button className="btn primary" type="submit" disabled={busy}>
              {busy ? "…" : "Save settings"}
            </button>
          </div>
        )}
      </form>
    </>
  );
}
