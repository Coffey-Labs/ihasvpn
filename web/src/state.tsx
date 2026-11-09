import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, ApiError, isStaff, type Me, type Snapshot } from "./api";

// --- auth -------------------------------------------------------------------

interface AuthState {
  me: Me | null;
  loading: boolean;
  needsSetup: boolean;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const setup = await api.setupStatus();
      setNeedsSetup(setup.needsSetup);
      if (setup.needsSetup) {
        setMe(null);
        return;
      }
      setMe(await api.me());
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setMe(null);
      else setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo(() => ({ me, loading, needsSetup, refresh, signOut }), [me, loading, needsSetup, refresh, signOut]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}

// --- live updates ----------------------------------------------------------

interface LiveState {
  snapshot: Snapshot | null;
  connected: boolean;
  // Bumps whenever the peer list changed on the server.
  peersVersion: number;
  settingsVersion: number;
}

const LiveCtx = createContext<LiveState>({ snapshot: null, connected: false, peersVersion: 0, settingsVersion: 0 });

export function LiveProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [connected, setConnected] = useState(false);
  const [peersVersion, setPeersVersion] = useState(0);
  const [settingsVersion, setSettingsVersion] = useState(0);

  // Live updates cover the whole server, so only staff get them.
  const staff = !!me && isStaff(me.role);
  useEffect(() => {
    if (!staff) {
      setSnapshot(null);
      setConnected(false);
      return;
    }
    const es = new EventSource("/api/events");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("status", (ev) => {
      try {
        setSnapshot(JSON.parse((ev as MessageEvent).data) as Snapshot);
      } catch {
        /* ignore malformed frames */
      }
    });
    es.addEventListener("peers", () => setPeersVersion((v) => v + 1));
    es.addEventListener("settings", () => setSettingsVersion((v) => v + 1));
    return () => es.close();
  }, [staff]);

  const value = useMemo(() => ({ snapshot, connected, peersVersion, settingsVersion }), [snapshot, connected, peersVersion, settingsVersion]);
  return <LiveCtx.Provider value={value}>{children}</LiveCtx.Provider>;
}

export function useLive(): LiveState {
  return useContext(LiveCtx);
}

// A ticking clock so relative times ("2m ago") stay honest.
export function useNow(intervalMs = 5000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

// --- toasts -----------------------------------------------------------------

interface Toast {
  id: number;
  text: string;
  kind: "ok" | "bad";
}

const ToastCtx = createContext<(text: string, kind?: "ok" | "bad") => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);
  const push = useCallback((text: string, kind: "ok" | "bad" = "ok") => {
    const id = ++counter.current;
    setToasts((t) => [...t, { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "bad" ? 6000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}
