import { Route, Switch } from "wouter";
import { AuthProvider, LiveProvider, ToastProvider, useAuth } from "./state";
import { Layout } from "./components/Layout";
import { Login } from "./pages/Login";
import { Setup } from "./pages/Setup";
import { Dashboard } from "./pages/Dashboard";
import { Peers } from "./pages/Peers";
import { SettingsPage } from "./pages/Settings";
import { UsersPage } from "./pages/Users";
import { Audit } from "./pages/Audit";
import { Account } from "./pages/Account";
import { DevicesPage } from "./pages/Devices";
import { isStaff } from "./api";

function Gate() {
  const { me, loading, needsSetup } = useAuth();
  if (loading) return <div className="auth">Loading…</div>;
  if (needsSetup) return <Setup />;
  if (!me) return <Login />;
  if (!isStaff(me.role)) {
    // A user's console is their own devices and their account.
    return (
      <LiveProvider>
        <Layout>
          <Switch>
            <Route path="/" component={DevicesPage} />
            <Route path="/account" component={Account} />
            <Route>
              <div className="empty">Nothing here.</div>
            </Route>
          </Switch>
        </Layout>
      </LiveProvider>
    );
  }
  return (
    <LiveProvider>
      <Layout>
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/devices" component={DevicesPage} />
          <Route path="/peers" component={Peers} />
          <Route path="/peers/:id" component={Peers} />
          <Route path="/settings" component={SettingsPage} />
          <Route path="/users" component={UsersPage} />
          <Route path="/audit" component={Audit} />
          <Route path="/account" component={Account} />
          <Route>
            <div className="empty">Nothing here.</div>
          </Route>
        </Switch>
      </Layout>
    </LiveProvider>
  );
}

export function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </ToastProvider>
  );
}
