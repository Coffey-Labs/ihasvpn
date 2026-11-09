import { useEffect, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { api, type User } from "../api";
import { ago, dateTime } from "../format";
import { errorMessage, useAuth, useNow, useToast } from "../state";
import { Confirm, Field, Modal } from "../components/ui";

export function UsersPage() {
  const { me } = useAuth();
  const toast = useToast();
  const now = useNow();
  const [users, setUsers] = useState<User[]>([]);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [busy, setBusy] = useState(false);
  const isAdmin = me?.role === "admin";

  const load = () => api.users().then(setUsers).catch((e) => toast(errorMessage(e), "bad"));
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Users</h1>
          <p>Administrators manage everything, viewers can look but not touch, and users see only their own devices.</p>
        </div>
        {isAdmin && (
          <button className="btn primary" onClick={() => setCreating(true)}>
            <Plus /> New user
          </button>
        )}
      </div>
      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Devices</th>
                <th>Two-factor</th>
                <th>Last sign-in</th>
                <th>Created</th>
                {isAdmin && <th></th>}
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.username} {u.id === me?.id && <span className="badge accent">you</span>}
                    {u.signIn === "oidc" && (
                      <span className="badge" style={{ marginLeft: 6 }} title={u.email ? `Signs in through the provider as ${u.email}` : "Signs in through the provider"}>
                        provider
                      </span>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${u.role === "admin" ? "accent" : ""}`}>{u.role}</span>
                  </td>
                  <td className="num">{u.devices}</td>
                  <td>{u.signIn === "oidc" ? <span className="faint small">at the provider</span> : u.totpEnabled ? <span className="badge ok">on</span> : <span className="badge">off</span>}</td>
                  <td>{ago(u.lastLoginAt, now)}</td>
                  <td>{dateTime(u.createdAt)}</td>
                  {isAdmin && (
                    <td className="actions">
                      <button className="btn sm" onClick={() => setEditing(u)}>
                        Edit
                      </button>{" "}
                      {u.id !== me?.id && (
                        <button className="btn sm danger" onClick={() => setDeleting(u)}>
                          Delete
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {creating && (
        <UserForm
          onClose={() => setCreating(false)}
          onSaved={() => {
            setCreating(false);
            toast("User created");
            void load();
          }}
        />
      )}
      {editing && (
        <UserEdit
          user={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            toast("User updated");
            void load();
          }}
        />
      )}
      {deleting && (
        <Confirm
          title="Delete user"
          danger
          confirmLabel="Delete"
          busy={busy}
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            setBusy(true);
            try {
              await api.deleteUser(deleting.id);
              toast("User deleted");
              setDeleting(null);
              void load();
            } catch (e) {
              toast(errorMessage(e), "bad");
            } finally {
              setBusy(false);
            }
          }}
          text={
            <>
              Delete <b>{deleting.username}</b>? Their sessions end immediately
              {deleting.devices > 0 ? (
                <>
                  , and their {deleting.devices === 1 ? "device is" : `${deleting.devices} devices are`} deleted with them and stop working.
                </>
              ) : (
                "."
              )}
            </>
          }
        />
      )}
    </>
  );
}

function UserForm({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.createUser({ username, password, role });
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title="New user"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" type="submit" form="user-form" disabled={busy}>
            Create
          </button>
        </>
      }
    >
      <form id="user-form" onSubmit={submit}>
        {error && <div className="error">{error}</div>}
        <Field label="Username">
          <input className="input" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" />
        </Field>
        <Field label="Password" hint="At least 12 characters. Tell them to change it after signing in.">
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete="new-password" />
        </Field>
        <Field label="Role">
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="admin">Administrator</option>
            <option value="viewer">Viewer (read-only)</option>
            <option value="user">User (own devices only)</option>
          </select>
        </Field>
      </form>
    </Modal>
  );
}

function UserEdit({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const { me } = useAuth();
  const [role, setRole] = useState(user.role);
  const [password, setPassword] = useState("");
  const [resetTotp, setResetTotp] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.updateUser(user.id, { role: role !== user.role ? role : undefined, password: password || undefined, resetTotp });
      onSaved();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={`Edit ${user.username}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" type="submit" form="user-edit" disabled={busy}>
            Save
          </button>
        </>
      }
    >
      <form id="user-edit" onSubmit={submit}>
        {error && <div className="error">{error}</div>}
        <Field label="Role" hint={user.id === me?.id ? "You cannot change your own role." : undefined}>
          <select className="input" value={role} onChange={(e) => setRole(e.target.value as User["role"])} disabled={user.id === me?.id}>
            <option value="admin">Administrator</option>
            <option value="viewer">Viewer (read-only)</option>
            <option value="user">User (own devices only)</option>
          </select>
        </Field>
        {user.signIn === "oidc" ? (
          <p className="muted small">{user.username} signs in through the provider, so there is no password or second factor to manage here.</p>
        ) : (
          <Field label="New password" hint="Leave blank to keep it. Setting one signs them out everywhere.">
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={12} autoComplete="new-password" />
          </Field>
        )}
        {user.totpEnabled && (
          <div className="check">
            <input id="reset-totp" type="checkbox" checked={resetTotp} onChange={(e) => setResetTotp(e.target.checked)} />
            <label htmlFor="reset-totp">
              Reset two-factor authentication
              <span className="hint">For a lost authenticator. They can set it up again from their account page.</span>
            </label>
          </div>
        )}
      </form>
    </Modal>
  );
}
