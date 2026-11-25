import { useState, type FormEvent } from "react";
import { api } from "../api";
import { errorMessage, useAuth } from "../state";
import { Field } from "../components/ui";
import { Mark } from "../components/Mark";
import { Legal } from "../components/Legal";

// The setup token from the server's log. The address the log prints carries
// it as ?token=; it is read once and taken out of the address bar, so it
// doesn't stay in the browser's history.
function tokenFromAddress(): string {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token") ?? "";
  if (token) {
    params.delete("token");
    const rest = params.toString();
    window.history.replaceState(null, "", window.location.pathname + (rest ? "?" + rest : "") + window.location.hash);
  }
  return token;
}

export function Setup() {
  const { refresh } = useAuth();
  const [token, setToken] = useState(tokenFromAddress);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [endpointHost, setEndpointHost] = useState(window.location.hostname === "localhost" ? "" : window.location.hostname);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.setup({ token: token.trim(), username, password, endpointHost });
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <form className="card" onSubmit={submit}>
        <div className="card-body">
          <div className="brand">
            <div className="brand-mark">
              <Mark size={44} />
            </div>
            <div className="brand-name">ihasvpn</div>
          </div>
          <h1>Welcome</h1>
          <p className="muted" style={{ textAlign: "center", marginBottom: 16 }}>
            Create the first administrator. This form only works once.
          </p>
          {error && <div className="error">{error}</div>}
          <Field label="Setup token" hint="Printed in the server's log when it starts. With Docker: docker logs ihasvpn">
            <input className="input" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value)} required />
          </Field>
          <Field label="Username">
            <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </Field>
          <Field label="Password" hint="At least 12 characters. Length beats complexity.">
            <input className="input" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} />
          </Field>
          <Field label="Confirm password">
            <input className="input" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
          </Field>
          <Field label="Public endpoint" hint="The hostname or IP address clients will connect to. You can change it later in Settings.">
            <input className="input" value={endpointHost} onChange={(e) => setEndpointHost(e.target.value)} placeholder="vpn.example.com" required />
          </Field>
          <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%", justifyContent: "center" }}>
            {busy ? "…" : "Create administrator"}
          </button>
          <Legal center />
        </div>
      </form>
    </div>
  );
}
