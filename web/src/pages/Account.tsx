import { useEffect, useState, type FormEvent } from "react";
import { api, type SessionInfo } from "../api";
import { ago, dateTime } from "../format";
import { errorMessage, useAuth, useNow, useToast } from "../state";
import { Field, Modal, copyText } from "../components/ui";
import { ThemeSwitch } from "../components/ThemeSwitch";

export function Account() {
  const { me, refresh } = useAuth();
  const toast = useToast();
  const now = useNow();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwError, setPwError] = useState("");
  const [busy, setBusy] = useState(false);
  const [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [totpError, setTotpError] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [disablePw, setDisablePw] = useState("");
  const [disabling, setDisabling] = useState(false);

  const loadSessions = () => api.sessions().then(setSessions).catch(() => {});
  useEffect(() => {
    void loadSessions();
  }, []);

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    setPwError("");
    if (next !== confirm) {
      setPwError("The new passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast("Password changed; other sessions were signed out");
      void loadSessions();
    } catch (err) {
      setPwError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function startTotp() {
    try {
      setTotp(await api.totpSetup());
      setCode("");
      setTotpError("");
    } catch (err) {
      toast(errorMessage(err), "bad");
    }
  }

  async function confirmTotp(e: FormEvent) {
    e.preventDefault();
    setTotpError("");
    try {
      const r = await api.totpConfirm(code);
      setTotp(null);
      setRecovery(r.recoveryCodes);
      await refresh();
    } catch (err) {
      setTotpError(errorMessage(err));
    }
  }

  async function disableTotp(e: FormEvent) {
    e.preventDefault();
    try {
      await api.totpDisable(disablePw);
      setDisabling(false);
      setDisablePw("");
      toast("Two-factor authentication turned off");
      await refresh();
    } catch (err) {
      toast(errorMessage(err), "bad");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Account</h1>
          <p>
            Signed in as <b>{me?.username}</b> ({me?.role}).
          </p>
        </div>
      </div>
      {me?.signIn === "oidc" ? (
        <div className="card">
          <div className="card-head">
            <h2>Sign-in</h2>
          </div>
          <div className="card-body">
            <p>
              You sign in through <b>{me.provider}</b>{me.email ? <> as {me.email}</> : null}. Your password and second factor are looked after there, not here.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-2">
          <form className="card" onSubmit={changePassword}>
            <div className="card-head">
              <h2>Password</h2>
            </div>
            <div className="card-body">
              {pwError && <div className="error">{pwError}</div>}
              <Field label="Current password">
                <input className="input" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoComplete="current-password" />
              </Field>
              <Field label="New password" hint="At least 12 characters.">
                <input className="input" type="password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={12} autoComplete="new-password" />
              </Field>
              <Field label="Confirm new password">
                <input className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password" />
              </Field>
              <button className="btn primary" type="submit" disabled={busy}>
                Change password
              </button>
            </div>
          </form>
          <div className="card">
            <div className="card-head">
              <h2>Two-factor authentication</h2>
              {me?.totpEnabled ? <span className="badge ok">on</span> : <span className="badge">off</span>}
            </div>
            <div className="card-body">
              {me?.totpEnabled ? (
                <>
                  <p>A code from your authenticator app is required at every sign-in.</p>
                  <p className="muted small">
                    {me.recoveryCodesLeft} recovery code{me.recoveryCodesLeft === 1 ? "" : "s"} left.
                  </p>
                  {!disabling ? (
                    <button className="btn" onClick={() => setDisabling(true)}>
                      Turn off
                    </button>
                  ) : (
                    <form onSubmit={disableTotp}>
                      <Field label="Confirm with your password">
                        <input className="input" type="password" value={disablePw} onChange={(e) => setDisablePw(e.target.value)} required autoComplete="current-password" autoFocus />
                      </Field>
                      <div className="btn-row">
                        <button className="btn danger" type="submit">
                          Turn off two-factor
                        </button>
                        <button className="btn" type="button" onClick={() => setDisabling(false)}>
                          Cancel
                        </button>
                      </div>
                    </form>
                  )}
                </>
              ) : (
                <>
                  <p>Add a time-based one-time code from an authenticator app (Aegis, Google Authenticator, 1Password, and so on).</p>
                  <button className="btn primary" onClick={startTotp}>
                    Set up
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      <div className="card mt">
        <div className="card-head">
          <h2>Appearance</h2>
        </div>
        <div className="card-body">
          <p className="muted small" style={{ marginBottom: 10 }}>
            Dark is the default. The choice is remembered in this browser only.
          </p>
          <ThemeSwitch />
        </div>
      </div>
      <div className="card mt">
        <div className="card-head">
          <h2>Sessions</h2>
          {sessions.length > 1 && (
            <button
              className="btn sm"
              onClick={() =>
                api
                  .revokeSessions()
                  .then(() => {
                    toast("Other sessions signed out");
                    void loadSessions();
                  })
                  .catch((e) => toast(errorMessage(e), "bad"))
              }
            >
              Sign out everywhere else
            </button>
          )}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Signed in</th>
                <th>Last seen</th>
                <th>From</th>
                <th>Browser</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s, i) => (
                <tr key={i}>
                  <td>{s.current && <span className="badge accent">this one</span>}</td>
                  <td className="nowrap">{dateTime(s.createdAt)}</td>
                  <td className="nowrap">{ago(s.lastSeenAt, now)}</td>
                  <td className="mono">{s.ip}</td>
                  <td className="muted small" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {s.userAgent}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {totp && (
        <Modal title="Set up two-factor authentication" onClose={() => setTotp(null)}>
          <form onSubmit={confirmTotp}>
            <div className="qr">
              <img src="/api/auth/totp/qr.png" alt="QR code for your authenticator app" width={256} height={256} style={{ maxWidth: 256 }} />
              <p className="small muted">
                Cannot scan? Enter this key by hand: <code>{totp.secret}</code>{" "}
                <button type="button" className="btn sm ghost" onClick={() => copyText(totp.secret).then((ok) => toast(ok ? "Copied" : "Could not copy", ok ? "ok" : "bad"))}>
                  copy
                </button>
              </p>
            </div>
            {totpError && <div className="error">{totpError}</div>}
            <Field label="Enter the six-digit code the app shows">
              <input className="input" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required autoFocus />
            </Field>
            <button className="btn primary" type="submit">
              Turn on
            </button>
          </form>
        </Modal>
      )}
      {recovery && (
        <Modal title="Recovery codes" onClose={() => setRecovery(null)}>
          <p>Each of these signs you in once if you lose your authenticator. Keep them somewhere safe; they are not shown again.</p>
          <ul className="recovery">
            {recovery.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <div className="btn-row mt">
            <button className="btn" onClick={() => copyText(recovery.join("\n")).then((ok) => toast(ok ? "Copied" : "Could not copy", ok ? "ok" : "bad"))}>
              Copy all
            </button>
            <button className="btn primary" onClick={() => setRecovery(null)}>
              I have saved them
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
