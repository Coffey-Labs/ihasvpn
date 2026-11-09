import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { errorMessage, useAuth } from "../state";
import { Field } from "../components/ui";
import { Mark } from "../components/Mark";
import { Legal } from "../components/Legal";

export function Login() {
  const { refresh } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [stage, setStage] = useState<"password" | "totp">("password");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [provider, setProvider] = useState<string | null>(null);

  // Which sign-in methods there are, and why a trip to the provider came
  // back without signing in (?signin=reason).
  useEffect(() => {
    api
      .authMethods()
      .then((m) => {
        const name = m.oidc?.name ?? null;
        setProvider(name);
        const reason = new URLSearchParams(window.location.search).get("signin");
        if (reason) {
          const refusal = reason === "not-allowed" ? takeRefusal() : null;
          setError(refusal ? refusalMessage(refusal, name ?? "your provider") : signInMessage(reason, name ?? "your provider"));
          window.history.replaceState(null, "", window.location.pathname);
        }
      })
      .catch(() => {});
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (stage === "password") {
        const r = await api.login(username, password);
        if (r.totpRequired) {
          setStage("totp");
          return;
        }
      } else {
        await api.loginTotp(code);
      }
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
          <h1>{stage === "password" ? "Sign in" : "Second factor"}</h1>
          {error && <div className="error">{error}</div>}
          {stage === "password" && provider && (
            <>
              <a className="btn primary" href="/api/auth/oidc/start" style={{ width: "100%", justifyContent: "center" }}>
                Sign in with {provider}
              </a>
              <div className="or">or with a username and password</div>
            </>
          )}
          {stage === "password" ? (
            <>
              <Field label="Username">
                <input className="input" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
              </Field>
              <Field label="Password">
                <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </Field>
            </>
          ) : (
            <Field label="Authenticator code" hint="Or one of your recovery codes.">
              <input className="input" autoFocus autoComplete="one-time-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required />
            </Field>
          )}
          <button className={`btn${provider && stage === "password" ? "" : " primary"}`} type="submit" disabled={busy} style={{ width: "100%", justifyContent: "center" }}>
            {busy ? "…" : stage === "password" ? "Sign in" : "Verify"}
          </button>
          <Legal center />
        </div>
      </form>
    </div>
  );
}

function signInMessage(reason: string, provider: string): string {
  switch (reason) {
    case "denied":
      return `The sign-in was cancelled at ${provider}.`;
    case "expired":
      return "That sign-in took too long or was already used. Try again.";
    case "not-allowed":
      return `Your account at ${provider} is not allowed on this server.`;
    case "setup":
      return "This server has not been set up yet.";
    case "busy":
      return "Too many sign-in attempts. Wait a few minutes and try again.";
    case "provider":
      return `Signing in through ${provider} did not work. Try again; if it keeps failing, the server's log says why.`;
    default:
      return "Something went wrong signing you in. Try again.";
  }
}

// Why the email check turned someone away, from a cookie the server sets for
// two minutes. Read once, then cleared.
type Refusal = { email: string; domains: string[]; unverified: boolean };

const refusalCookie = "ihasvpn_signin_refused";

function takeRefusal(): Refusal | null {
  const m = document.cookie.match(new RegExp(`(?:^|;\\s*)${refusalCookie}=([^;]*)`));
  if (!m) return null;
  document.cookie = `${refusalCookie}=; Path=/; Max-Age=0; SameSite=Lax${window.location.protocol === "https:" ? "; Secure" : ""}`;
  try {
    const bin = atob(m[1].replace(/-/g, "+").replace(/_/g, "/"));
    const r = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    if (typeof r?.email !== "string" || !Array.isArray(r.domains) || !r.domains.every((d: unknown) => typeof d === "string")) return null;
    return { email: r.email, domains: r.domains, unverified: r.unverified === true };
  } catch {
    return null;
  }
}

function refusalMessage(r: Refusal, provider: string): string {
  const allowed = orList(r.domains);
  if (r.unverified) return `${provider} hasn't confirmed that ${r.email} is yours, so it can't be used to sign in here.`;
  if (!r.email) return `${provider} didn't share an email address, and this server only takes addresses at ${allowed}.`;
  return `${provider} signed you in as ${r.email}, but this server only takes addresses at ${allowed}.`;
}

function orList(items: string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`;
}
