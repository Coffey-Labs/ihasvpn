package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"context"
	"github.com/Coffey-Labs/ihasvpn/internal/config"
	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
	"github.com/Coffey-Labs/ihasvpn/internal/wg"
)

// fakeProvider is just enough of an OpenID provider: discovery and a token
// endpoint that checks the client secret, redirect and PKCE verifier.
type fakeProvider struct {
	srv *httptest.Server
	mu  sync.Mutex
	// codes maps an authorization code to what the token endpoint checks
	// and returns.
	codes map[string]fakeGrant
}

type fakeGrant struct {
	challenge, nonce, sub, email string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	f := &fakeProvider{codes: map[string]fakeGrant{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token"})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, _ := r.BasicAuth()
		_ = r.ParseForm()
		f.mu.Lock()
		g, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if id != "vpn" || secret != "s3cret" || !ok || r.PostForm.Get("grant_type") != "authorization_code" ||
			!strings.HasSuffix(r.PostForm.Get("redirect_uri"), "/api/auth/oidc/callback") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		h, _ := json.Marshal(map[string]string{"alg": "HS256"})
		c, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "sub": g.sub, "aud": "vpn", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": g.nonce, "preferred_username": g.email, "email": g.email})
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + ".sig", "access_token": "x", "token_type": "Bearer"})
	})
	return f
}

func newOIDCServer(t *testing.T, f *fakeProvider, domains ...string) *httptest.Server {
	cfg := &config.Config{
		DBPath: ":memory:", Backend: "mock", Iface: "wg0", ListenPort: 51820,
		Subnet4: netip.MustParsePrefix("10.8.0.0/24"), HTTP: "127.0.0.1:0",
		SessionIdle: time.Hour, SessionMax: 24 * time.Hour, TrafficRetention: time.Hour, PollInterval: time.Hour,
		InitialEndpoint: "vpn.example.com", InitialDNS: "1.1.1.1",
		PublicURL: "http://127.0.0.1", OIDCIssuer: f.srv.URL, OIDCClientID: "vpn", OIDCClientSecret: "s3cret", OIDCName: "Example ID",
		OIDCEmailDomains: domains,
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(cfg, st, wg.NewMock("wg0", false), log)
	if err := eng.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	srv := httptest.NewServer(New(cfg, eng, log).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func browser(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// signIn runs the whole round trip as the provider's subject sub and
// returns where ihasvpn sent the browser at the end.
func (f *fakeProvider) signIn(t *testing.T, b *client, sub, email string) string {
	t.Helper()
	res, _ := b.do("GET", "/api/auth/oidc/start", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Path != "/authorize" {
		return res.Header.Get("Location")
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "vpn" || q.Get("nonce") == "" {
		t.Fatalf("authorize request: %s", loc)
	}
	f.mu.Lock()
	f.codes["code-"+sub] = fakeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), sub: sub, email: email}
	f.mu.Unlock()
	res, _ = b.do("GET", "/api/auth/oidc/callback?code=code-"+sub+"&state="+url.QueryEscape(q.Get("state")), nil)
	return res.Header.Get("Location")
}

func TestOIDCSignIn(t *testing.T) {
	f := newFakeProvider(t)
	srv := newOIDCServer(t, f)
	admin := browser(t, srv)
	out := admin.expect("GET", "/api/auth/methods", nil, 200)
	if !strings.Contains(string(out), `"name":"Example ID"`) {
		t.Fatal(string(out))
	}

	// Not before the first administrator exists.
	if loc := f.signIn(t, browser(t, srv), "1", "sam@example.org"); loc != "/?signin=setup" {
		t.Fatalf("before setup: %s", loc)
	}
	admin.expect("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)

	sam := browser(t, srv)
	if loc := f.signIn(t, sam, "1", "sam@example.org"); loc != "/" {
		t.Fatalf("sign-in: %s", loc)
	}
	out = sam.expect("GET", "/api/auth/me", nil, 200)
	var me struct {
		ID       int64
		Username string
		Role     string
		SignIn   string
	}
	_ = json.Unmarshal(out, &me)
	if me.Username != "sam@example.org" || me.Role != "user" || me.SignIn != "oidc" {
		t.Fatal(string(out))
	}
	sam.expect("GET", "/api/peers", nil, 403)
	sam.expect("POST", "/api/me/devices", map[string]string{"name": "Phone"}, 201)
	sam.expect("POST", "/api/auth/password", map[string]string{"current": "", "new": "a-long-enough-password"}, 400)
	sam.expect("POST", "/api/auth/totp/setup", nil, 400)
	// No password means no password sign-in.
	sam.expect("POST", "/api/auth/login", map[string]string{"username": "sam@example.org", "password": ""}, 401)

	// The same subject comes back to the same account.
	again := browser(t, srv)
	f.signIn(t, again, "1", "sam@example.org")
	out = again.expect("GET", "/api/me/devices", nil, 200)
	if !strings.Contains(string(out), `"name":"Phone"`) {
		t.Fatal(string(out))
	}
	// Another subject with the same name is another person.
	other := browser(t, srv)
	f.signIn(t, other, "2", "sam@example.org")
	out = other.expect("GET", "/api/auth/me", nil, 200)
	if !strings.Contains(string(out), `"username":"sam@example.org-2"`) {
		t.Fatal(string(out))
	}
	// A provider account named like a local one does not become it.
	admin2 := browser(t, srv)
	f.signIn(t, admin2, "3", "admin")
	out = admin2.expect("GET", "/api/auth/me", nil, 200)
	if !strings.Contains(string(out), `"username":"admin-2"`) || !strings.Contains(string(out), `"role":"user"`) {
		t.Fatal(string(out))
	}

	// An administrator can't give a provider account a password.
	admin.expect("PUT", "/api/users/"+jsonInt(me.ID), map[string]any{"password": "a-long-enough-password"}, 400)
	out = admin.expect("GET", "/api/users", nil, 200)
	if !strings.Contains(string(out), `"signIn":"oidc"`) {
		t.Fatal(string(out))
	}
}

func TestOIDCStateChecks(t *testing.T) {
	f := newFakeProvider(t)
	srv := newOIDCServer(t, f)
	admin := browser(t, srv)
	admin.expect("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)

	b := browser(t, srv)
	res, _ := b.do("GET", "/api/auth/oidc/start", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	state := loc.Query().Get("state")
	f.codes["c"] = fakeGrant{challenge: loc.Query().Get("code_challenge"), nonce: loc.Query().Get("nonce"), sub: "9", email: "x@example.org"}

	// A callback from another browser (no state cookie) is refused.
	res, _ = browser(t, srv).do("GET", "/api/auth/oidc/callback?code=c&state="+url.QueryEscape(state), nil)
	if res.Header.Get("Location") != "/?signin=expired" {
		t.Fatalf("no cookie: %s", res.Header.Get("Location"))
	}
	// The provider saying no.
	res, _ = b.do("GET", "/api/auth/oidc/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	if res.Header.Get("Location") != "/?signin=denied" {
		t.Fatalf("denied: %s", res.Header.Get("Location"))
	}
	// That used the attempt up: the code can't be replayed with it.
	res, _ = b.do("GET", "/api/auth/oidc/callback?code=c&state="+url.QueryEscape(state), nil)
	if res.Header.Get("Location") != "/?signin=expired" {
		t.Fatalf("replay: %s", res.Header.Get("Location"))
	}
	b.expect("GET", "/api/auth/me", nil, 401)
}

func TestOIDCEmailDomains(t *testing.T) {
	f := newFakeProvider(t)
	srv := newOIDCServer(t, f, "example.org")
	admin := browser(t, srv)
	admin.expect("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	if loc := f.signIn(t, browser(t, srv), "1", "eve@elsewhere.net"); loc != "/?signin=not-allowed" {
		t.Fatalf("other domain: %s", loc)
	}
	if loc := f.signIn(t, browser(t, srv), "2", "sam@EXAMPLE.org"); loc != "/" {
		t.Fatalf("allowed domain: %s", loc)
	}
}

func TestOIDCOff(t *testing.T) {
	c, _ := newClient(t)
	out := c.expect("GET", "/api/auth/methods", nil, 200)
	if !strings.Contains(string(out), `"oidc":null`) {
		t.Fatal(string(out))
	}
	c.expect("GET", "/api/auth/oidc/start", nil, 404)
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }
