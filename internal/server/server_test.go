package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/config"
	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
	"github.com/Coffey-Labs/ihasvpn/internal/wg"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newClient(t *testing.T) (*client, *engine.Engine) {
	t.Helper()
	cfg := &config.Config{
		DBPath: ":memory:", Backend: "mock", Iface: "wg0", ListenPort: 51820,
		Subnet4: netip.MustParsePrefix("10.8.0.0/24"), HTTP: "127.0.0.1:0",
		SessionIdle: time.Hour, SessionMax: 24 * time.Hour, TrafficRetention: time.Hour, PollInterval: time.Hour,
		InitialEndpoint: "vpn.example.com", InitialDNS: "1.1.1.1", MetricsToken: "metrics-secret", SetupToken: testSetupToken,
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
	s := New(cfg, eng, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, c: &http.Client{Jar: jar}}, eng
}

func (c *client) do(method, path string, body any, headers ...string) (*http.Response, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res, out
}

func (c *client) expect(method, path string, body any, status int) []byte {
	c.t.Helper()
	res, out := c.do(method, path, body)
	if res.StatusCode != status {
		c.t.Fatalf("%s %s: got %d, want %d: %s", method, path, res.StatusCode, status, out)
	}
	return out
}

func TestSetupLoginAndPeers(t *testing.T) {
	c, _ := newClient(t)

	// Before setup: nothing works, setup is announced.
	out := c.expect("GET", "/api/setup", nil, 200)
	if !strings.Contains(string(out), `"needsSetup":true`) {
		t.Fatal(out)
	}
	c.expect("GET", "/api/peers", nil, 401)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "admin", "password": "short"}, 400)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "x", "password": "a-long-enough-password"}, 409)

	// Setup signed us in.
	out = c.expect("GET", "/api/auth/me", nil, 200)
	if !strings.Contains(string(out), `"username":"admin"`) || !strings.Contains(string(out), `"role":"admin"`) {
		t.Fatal(string(out))
	}
	c.expect("POST", "/api/auth/logout", nil, 200)
	c.expect("GET", "/api/auth/me", nil, 401)

	c.expect("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password-here"}, 401)
	c.expect("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-long-enough-password"}, 200)

	// Cross-site state change refused.
	res, _ := c.do("POST", "/api/peers", map[string]string{"name": "x"}, "Sec-Fetch-Site", "cross-site")
	if res.StatusCode != 403 {
		t.Fatalf("cross-site request got %d", res.StatusCode)
	}

	out = c.expect("POST", "/api/peers", map[string]any{"name": "Laptop", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": ""}, 201)
	var created struct {
		ID     string `json:"id"`
		IPv4   string `json:"ipv4"`
		Config string `json:"config"`
	}
	_ = json.Unmarshal(out, &created)
	if created.IPv4 != "10.8.0.2" || !strings.Contains(created.Config, "Endpoint = vpn.test:51820") {
		t.Fatalf("%+v", created)
	}
	if strings.Contains(string(out), `"privateKey"`) {
		t.Fatal("private key leaked in peer body")
	}
	out = c.expect("GET", "/api/peers", nil, 200)
	if !strings.Contains(string(out), `"name":"Laptop"`) {
		t.Fatal(string(out))
	}
	res, out = c.do("GET", "/api/peers/"+created.ID+"/config?download=1", nil)
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Disposition"), `Laptop.conf`) || !strings.Contains(string(out), "[Interface]") {
		t.Fatalf("config download: %d %s", res.StatusCode, res.Header)
	}
	res, out = c.do("GET", "/api/peers/"+created.ID+"/qr.png", nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" || !bytes.HasPrefix(out, []byte("\x89PNG")) {
		t.Fatalf("qr: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	c.expect("POST", "/api/peers/"+created.ID+"/disable", nil, 200)
	out = c.expect("GET", "/api/peers/"+created.ID, nil, 200)
	if !strings.Contains(string(out), `"enabled":false`) {
		t.Fatal(string(out))
	}
	c.expect("POST", "/api/peers/"+created.ID+"/enable", nil, 200)
	c.expect("POST", "/api/peers/"+created.ID+"/reset", nil, 200)
	c.expect("POST", "/api/peers/"+created.ID+"/rotate", nil, 200)
	c.expect("PUT", "/api/peers/"+created.ID, map[string]any{"name": "Laptop 2", "clientRoutes": "10.8.0.0/24", "dns": "9.9.9.9", "keepalive": 15, "mtu": 1380, "expiresAt": nil, "notes": "n"}, 200)
	c.expect("GET", "/api/peers/"+created.ID+"/usage?range=24h", nil, 200)
	c.expect("GET", "/api/usage?range=7d", nil, 200)
	c.expect("GET", "/api/status", nil, 200)
	c.expect("GET", "/api/audit", nil, 200)
	c.expect("DELETE", "/api/peers/"+created.ID, nil, 200)
	c.expect("GET", "/api/peers/"+created.ID, nil, 404)

	// Settings round trip.
	out = c.expect("GET", "/api/settings", nil, 200)
	var s engine.Settings
	_ = json.Unmarshal(out, &s)
	s.MTU = 1400
	c.expect("PUT", "/api/settings", s, 200)
	s.MTU = 10
	c.expect("PUT", "/api/settings", s, 400)

	// Metrics: token or session.
	res, _ = c.do("GET", "/metrics", nil)
	if res.StatusCode != 200 {
		t.Fatalf("metrics with session: %d", res.StatusCode)
	}
	anon := &http.Client{}
	req, _ := http.NewRequest("GET", c.srv.URL+"/metrics", nil)
	if r, _ := anon.Do(req); r.StatusCode != 401 {
		t.Fatalf("anonymous metrics: %d", r.StatusCode)
	}
	req.Header.Set("Authorization", "Bearer metrics-secret")
	r, _ := anon.Do(req)
	b, _ := io.ReadAll(r.Body)
	if r.StatusCode != 200 || !strings.Contains(string(b), "ihasvpn_peers ") {
		t.Fatalf("token metrics: %d %s", r.StatusCode, b)
	}
}

func TestViewerRoleAndUsers(t *testing.T) {
	c, _ := newClient(t)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	c.expect("POST", "/api/users", map[string]string{"username": "eve", "password": "another-long-password", "role": "viewer"}, 201)
	c.expect("POST", "/api/users", map[string]string{"username": "eve", "password": "another-long-password", "role": "viewer"}, 409)
	c.expect("POST", "/api/auth/logout", nil, 200)
	c.expect("POST", "/api/auth/login", map[string]string{"username": "eve", "password": "another-long-password"}, 200)
	c.expect("GET", "/api/peers", nil, 200)
	c.expect("POST", "/api/peers", map[string]any{"name": "x", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": ""}, 403)
	c.expect("GET", "/api/users", nil, 200)
	c.expect("DELETE", "/api/users/1", nil, 403)
}

func TestTOTPFlow(t *testing.T) {
	c, _ := newClient(t)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	out := c.expect("POST", "/api/auth/totp/setup", nil, 200)
	var setup struct{ Secret string }
	_ = json.Unmarshal(out, &setup)
	c.expect("GET", "/api/auth/totp/qr.png", nil, 200)
	c.expect("POST", "/api/auth/totp/confirm", map[string]string{"code": "000000"}, 400)
	code, _ := auth.TOTPNow(setup.Secret, time.Now())
	out = c.expect("POST", "/api/auth/totp/confirm", map[string]string{"code": code}, 200)
	var conf struct{ RecoveryCodes []string }
	_ = json.Unmarshal(out, &conf)
	if len(conf.RecoveryCodes) != 8 {
		t.Fatal("no recovery codes")
	}
	c.expect("POST", "/api/auth/logout", nil, 200)

	// Login now stops half way.
	out = c.expect("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-long-enough-password"}, 200)
	if !strings.Contains(string(out), `"totpRequired":true`) {
		t.Fatal(string(out))
	}
	c.expect("GET", "/api/peers", nil, 401)
	c.expect("POST", "/api/auth/totp", map[string]string{"code": "123456"}, 401)
	code, _ = auth.TOTPNow(setup.Secret, time.Now())
	c.expect("POST", "/api/auth/totp", map[string]string{"code": code}, 200)
	c.expect("GET", "/api/peers", nil, 200)

	// A recovery code works once.
	c.expect("POST", "/api/auth/logout", nil, 200)
	c.expect("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-long-enough-password"}, 200)
	c.expect("POST", "/api/auth/totp", map[string]string{"code": conf.RecoveryCodes[0]}, 200)
	c.expect("POST", "/api/auth/logout", nil, 200)
	c.expect("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-long-enough-password"}, 200)
	c.expect("POST", "/api/auth/totp", map[string]string{"code": conf.RecoveryCodes[0]}, 401)
}

func TestLoginRateLimit(t *testing.T) {
	c, _ := newClient(t)
	c.expect("POST", "/api/setup", map[string]string{"token": testSetupToken, "username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	c.expect("POST", "/api/auth/logout", nil, 200)
	var last int
	for i := 0; i < 10; i++ {
		res, _ := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password-here"})
		last = res.StatusCode
	}
	if last != 429 {
		t.Fatalf("expected 429 after repeated failures, got %d", last)
	}
}

func TestSecurityHeadersAndSPA(t *testing.T) {
	c, _ := newClient(t)
	res, _ := c.do("GET", "/api/health", nil)
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("api responses must be no-store")
	}
	res, _ = c.do("GET", "/api/nope", nil)
	if res.StatusCode != 404 {
		t.Errorf("unknown api path: %d", res.StatusCode)
	}
}
