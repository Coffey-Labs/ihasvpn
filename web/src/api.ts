// Thin client for the ihasvpn API. Every call goes through `request`, which
// turns non-2xx answers into ApiError so pages can show the server's message.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? res.statusText ?? "request failed";
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const get = <T>(url: string) => request<T>("GET", url);
export const post = <T>(url: string, body?: unknown) => request<T>("POST", url, body ?? {});
export const put = <T>(url: string, body: unknown) => request<T>("PUT", url, body);
export const del = <T>(url: string) => request<T>("DELETE", url);

export async function getText(url: string): Promise<string> {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.text();
}

// --- types ------------------------------------------------------------------

export type Role = "admin" | "viewer" | "user";

// Administrators and viewers see the whole server; a user sees only the
// devices that belong to them.
export const isStaff = (role?: Role) => role === "admin" || role === "viewer";

export interface Me {
  id: number;
  username: string;
  role: Role;
  totpEnabled: boolean;
  recoveryCodesLeft: number;
  createdAt: string;
  lastLoginAt?: string;
}

export interface Live {
  id: string;
  connected: boolean;
  endpoint?: string;
  lastHandshake?: string;
  rx: number;
  tx: number;
  rxRate: number;
  txRate: number;
  connectedSince?: string;
}

export interface Peer {
  id: string;
  name: string;
  publicKey: string;
  serverKeys: boolean;
  presharedKey: boolean;
  ipv4: string;
  ipv6?: string;
  clientRoutes: string;
  dns: string;
  keepalive: number;
  mtu: number;
  enabled: boolean;
  expired: boolean;
  expiresAt?: string;
  notes: string;
  ownerId?: number;
  owner?: string;
  createdAt: string;
  updatedAt: string;
  live: Live;
}

// A device as its owner sees it.
export interface Device {
  id: string;
  name: string;
  ipv4: string;
  ipv6?: string;
  serverKeys: boolean;
  enabled: boolean;
  expired: boolean;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
  live: Live;
}

export interface MyDevices {
  devices: Device[];
  // null: no limit (administrators).
  limit: number | null;
}

export interface PeerInput {
  name: string;
  publicKey?: string;
  ipv4?: string;
  ipv6?: string;
  clientRoutes: string;
  dns: string;
  keepalive: number | null;
  mtu: number | null;
  enabled?: boolean;
  expiresAt: string | null;
  notes: string;
  // Absent keeps the owner; 0 means nobody.
  ownerId?: number;
}

export interface Settings {
  endpointHost: string;
  endpointPort: number;
  dns: string;
  clientRoutes: string;
  mtu: number;
  keepalive: number;
  peerIsolation: boolean;
  clampMSS: boolean;
  presharedKeys: boolean;
  connectedWindow: number;
  deviceLimit: number;
}

export interface Totals {
  peers: number;
  active: number;
  connected: number;
  rx: number;
  tx: number;
  rxRate: number;
  txRate: number;
}

export interface Snapshot {
  at: string;
  totals: Totals;
  peers: Record<string, Live>;
}

export interface SysctlStatus {
  key: string;
  wanted: string;
  current: string;
  applied: boolean;
  required: boolean;
  why: string;
  error?: string;
}

export interface Status {
  version: string;
  backend: "kernel" | "userspace" | "mock";
  interface: string;
  publicKey: string;
  listenPort: number;
  addresses: string[];
  subnet4: string;
  subnet6?: string;
  egress?: string;
  firewallError?: string;
  firewallManaged: boolean;
  startedAt: string;
  sysctls: SysctlStatus[];
  totals: Totals;
  settings: Settings;
}

export interface TrafficPoint {
  t: string;
  rx: number;
  tx: number;
}

export interface PeerUsage {
  peerId: string;
  rx: number;
  tx: number;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
  ip: string;
}

export interface User {
  id: number;
  username: string;
  role: Role;
  totpEnabled: boolean;
  devices: number;
  createdAt: string;
  lastLoginAt?: string;
}

export interface SessionInfo {
  current: boolean;
  createdAt: string;
  lastSeenAt: string;
  ip: string;
  userAgent: string;
}

export type Range = "1h" | "24h" | "7d" | "30d";

// --- endpoints --------------------------------------------------------------

export const api = {
  setupStatus: () => get<{ needsSetup: boolean }>("/api/setup"),
  setup: (body: { username: string; password: string; endpointHost: string }) => post<Me>("/api/setup", body),
  login: (username: string, password: string) => post<{ totpRequired: boolean }>("/api/auth/login", { username, password }),
  loginTotp: (code: string) => post<{ totpRequired: boolean }>("/api/auth/totp", { code }),
  logout: () => post<{ ok: boolean }>("/api/auth/logout"),
  me: () => get<Me>("/api/auth/me"),
  changePassword: (current: string, next: string) => post<{ ok: boolean }>("/api/auth/password", { current, new: next }),
  totpSetup: () => post<{ secret: string; uri: string }>("/api/auth/totp/setup"),
  totpConfirm: (code: string) => post<{ recoveryCodes: string[] }>("/api/auth/totp/confirm", { code }),
  totpDisable: (password: string) => post<{ ok: boolean }>("/api/auth/totp/disable", { password }),
  sessions: () => get<SessionInfo[]>("/api/auth/sessions"),
  revokeSessions: () => post<{ ok: boolean }>("/api/auth/sessions/revoke"),

  myDevices: () => get<MyDevices>("/api/me/devices"),
  createMyDevice: (body: { name: string; publicKey?: string }) => post<Device & { config: string }>("/api/me/devices", body),
  rotateMyDevice: (id: string) => post<Device & { config: string }>(`/api/me/devices/${id}/rotate`),
  deleteMyDevice: (id: string) => del<{ ok: boolean }>(`/api/me/devices/${id}`),
  myDeviceConfig: (id: string) => getText(`/api/me/devices/${id}/config`),

  status: () => get<Status>("/api/status"),
  peers: () => get<Peer[]>("/api/peers"),
  peer: (id: string) => get<Peer>(`/api/peers/${id}`),
  createPeer: (body: PeerInput) => post<Peer & { config: string }>("/api/peers", body),
  updatePeer: (id: string, body: PeerInput) => put<Peer>(`/api/peers/${id}`, body),
  deletePeer: (id: string) => del<{ ok: boolean }>(`/api/peers/${id}`),
  enablePeer: (id: string) => post<Peer>(`/api/peers/${id}/enable`),
  disablePeer: (id: string) => post<Peer>(`/api/peers/${id}/disable`),
  resetPeer: (id: string) => post<{ ok: boolean }>(`/api/peers/${id}/reset`),
  rotatePeer: (id: string) => post<Peer & { config: string }>(`/api/peers/${id}/rotate`),
  peerConfig: (id: string) => getText(`/api/peers/${id}/config`),
  peerUsage: (id: string, range: Range) => get<TrafficPoint[]>(`/api/peers/${id}/usage?range=${range}`),
  usage: (range: Range) => get<TrafficPoint[]>(`/api/usage?range=${range}`),
  usageByPeer: (range: Range) => get<PeerUsage[]>(`/api/usage/peers?range=${range}`),
  settings: () => get<Settings>("/api/settings"),
  saveSettings: (body: Settings) => put<Settings>("/api/settings", body),
  audit: (limit = 200) => get<AuditEntry[]>(`/api/audit?limit=${limit}`),
  users: () => get<User[]>("/api/users"),
  createUser: (body: { username: string; password: string; role: string }) => post<User>("/api/users", body),
  updateUser: (id: number, body: { role?: string; password?: string; resetTotp?: boolean }) => put<User>(`/api/users/${id}`, body),
  deleteUser: (id: number) => del<{ ok: boolean }>(`/api/users/${id}`),
};
