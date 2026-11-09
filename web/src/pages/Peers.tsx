import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useRoute } from "wouter";
import { Plus, Search } from "lucide-react";
import { api, type Peer, type Settings } from "../api";
import { ago, bytes, rate } from "../format";
import { errorMessage, useAuth, useLive, useNow, useToast } from "../state";
import { Sparkline } from "../components/charts";
import { Segmented } from "../components/ui";
import { PeerForm } from "../components/PeerForm";
import { PeerDetail } from "../components/PeerDetail";

type Filter = "all" | "connected" | "offline" | "disabled";

export function Peers() {
  const { me } = useAuth();
  const { snapshot, peersVersion } = useLive();
  const toast = useToast();
  const now = useNow();
  const [, navigate] = useLocation();
  const [, params] = useRoute("/peers/:id");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<(Peer & { config: string }) | null>(null);
  const isAdmin = me?.role === "admin";

  // Recent throughput per peer for the sparklines: one sample per snapshot.
  const history = useRef<Map<string, number[]>>(new Map());
  useEffect(() => {
    if (!snapshot) return;
    for (const [id, l] of Object.entries(snapshot.peers)) {
      const h = history.current.get(id) ?? [];
      h.push(l.rxRate + l.txRate);
      if (h.length > 40) h.shift();
      history.current.set(id, h);
    }
  }, [snapshot]);

  const load = () =>
    Promise.all([api.peers(), api.settings()])
      .then(([p, s]) => {
        setPeers(p);
        setSettings(s);
      })
      .catch((e) => toast(errorMessage(e), "bad"));
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peersVersion]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return peers
      .map((p) => ({ p, l: snapshot?.peers[p.id] ?? p.live }))
      .filter(({ p, l }) => {
        if (q && !(p.name.toLowerCase().includes(q) || p.ipv4.includes(q) || (p.ipv6 ?? "").includes(q) || p.publicKey.toLowerCase().startsWith(q) || (l.endpoint ?? "").includes(q) || p.notes.toLowerCase().includes(q) || (p.owner ?? "").toLowerCase().includes(q))) return false;
        switch (filter) {
          case "connected":
            return l.connected;
          case "offline":
            return !l.connected && p.enabled && !p.expired;
          case "disabled":
            return !p.enabled || p.expired;
          default:
            return true;
        }
      })
      .sort((a, b) => {
        // Connected first, then by name.
        if (a.l.connected !== b.l.connected) return a.l.connected ? -1 : 1;
        return a.p.name.localeCompare(b.p.name);
      });
  }, [peers, snapshot, query, filter]);

  const selected = params?.id ? peers.find((p) => p.id === params.id) : undefined;
  const counts = useMemo(() => {
    let connected = 0;
    let disabled = 0;
    for (const p of peers) {
      const l = snapshot?.peers[p.id] ?? p.live;
      if (l.connected) connected++;
      if (!p.enabled || p.expired) disabled++;
    }
    return { connected, disabled, offline: peers.length - connected - disabled };
  }, [peers, snapshot]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Peers</h1>
          <p>
            {peers.length} peer{peers.length === 1 ? "" : "s"} · {counts.connected} connected
          </p>
        </div>
        <div className="toolbar">
          <div className="search-wrap" style={{ position: "relative" }}>
            <Search size={14} style={{ position: "absolute", left: 9, top: 10, color: "var(--fg-faint)" }} />
            <input className="input search" style={{ paddingLeft: 28 }} placeholder="Search name, owner, address, key…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <Segmented
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All" },
              { value: "connected", label: `Connected ${counts.connected}` },
              { value: "offline", label: `Offline ${counts.offline}` },
              { value: "disabled", label: `Disabled ${counts.disabled}` },
            ]}
          />
          {isAdmin && (
            <button className="btn primary" onClick={() => setCreating(true)}>
              <Plus /> New peer
            </button>
          )}
        </div>
      </div>

      <div className="card">
        {rows.length === 0 ? (
          <div className="empty">{peers.length === 0 ? "No peers yet. Create one and scan the QR code with the WireGuard app." : "Nothing matches."}</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Peer</th>
                  <th>Address</th>
                  <th className="hide-md">Endpoint</th>
                  <th>Handshake</th>
                  <th className="right hide-sm">Rate</th>
                  <th className="hide-md"></th>
                  <th className="right">Transfer</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ p, l }) => {
                  const state = !p.enabled ? "disabled" : p.expired ? "expired" : l.connected ? "on" : "off";
                  return (
                    <tr key={p.id} className="clickable" onClick={() => navigate(`/peers/${p.id}`)}>
                      <td>
                        <span className={`dot ${state}`} title={state} />
                        {p.name}
                        {!p.enabled && <span className="badge bad" style={{ marginLeft: 8 }}>disabled</span>}
                        {p.enabled && p.expired && <span className="badge warn" style={{ marginLeft: 8 }}>expired</span>}
                        {!p.serverKeys && <span className="badge" style={{ marginLeft: 8 }} title="The client holds its own private key">client key</span>}
                        {p.owner && <span className="small faint" style={{ marginLeft: 8 }}>{p.owner}</span>}
                      </td>
                      <td className="mono nowrap">{p.ipv4}</td>
                      <td className="mono nowrap hide-md">{l.endpoint || <span className="faint">—</span>}</td>
                      <td className="nowrap">{ago(l.lastHandshake, now)}</td>
                      <td className="num right hide-sm">{l.connected ? `↓ ${rate(l.rxRate)} ↑ ${rate(l.txRate)}` : <span className="faint">—</span>}</td>
                      <td className="hide-md">{l.connected && <Sparkline values={history.current.get(p.id) ?? []} />}</td>
                      <td className="num right">
                        {bytes(l.rx)} <span className="faint">/</span> {bytes(l.tx)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {creating && settings && (
        <PeerForm
          settings={settings}
          onClose={() => setCreating(false)}
          onSaved={(p) => {
            setCreating(false);
            toast(`Peer ${p.name} created`);
            void load().then(() => {
              setCreated(p as Peer & { config: string });
              navigate(`/peers/${p.id}`);
            });
          }}
        />
      )}
      {selected && settings && (
        <PeerDetail
          key={selected.id + selected.updatedAt}
          peer={selected}
          live={snapshot?.peers[selected.id] ?? selected.live}
          settings={settings}
          isAdmin={!!isAdmin}
          initialTab={created?.id === selected.id ? "config" : "overview"}
          initialConfig={created?.id === selected.id ? created.config : undefined}
          onClose={() => {
            setCreated(null);
            navigate("/peers");
          }}
          onChanged={() => void load()}
        />
      )}
    </>
  );
}
