package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/config"
	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
	"github.com/Coffey-Labs/ihasvpn/internal/wg"
)

const testSetupToken = "test-setup-token-0123456789"

// newSetupClient is newClient with the setup token left to the test, and the
// log kept so the test can read what the server printed.
func newSetupClient(t *testing.T, token, publicURL string) (*client, *Server, *bytes.Buffer) {
	t.Helper()
	cfg := &config.Config{
		DBPath: ":memory:", Backend: "mock", Iface: "wg0", ListenPort: 51820,
		Subnet4: netip.MustParsePrefix("10.8.0.0/24"), HTTP: "127.0.0.1:0",
		SessionIdle: time.Hour, SessionMax: 24 * time.Hour, TrafficRetention: time.Hour, PollInterval: time.Hour,
		InitialEndpoint: "vpn.example.com", InitialDNS: "1.1.1.1", SetupToken: token, PublicURL: publicURL,
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	eng := engine.New(cfg, st, wg.NewMock("wg0", false), log)
	if err := eng.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(context.Background()) })
	s := New(cfg, eng, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t: t, srv: srv, c: &http.Client{Jar: jar}}, s, &logs
}

func setupBody(token string) map[string]string {
	return map[string]string{"token": token, "username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}
}

func TestSetupNeedsTheToken(t *testing.T) {
	c, s, logs := newSetupClient(t, testSetupToken, "")
	if out := c.expect("GET", "/api/setup", nil, 200); !strings.Contains(string(out), `"tokenRequired":true`) || strings.Contains(string(out), testSetupToken) {
		t.Fatalf("setup status: %s", out)
	}
	// IHASVPN_SETUP_TOKEN is used as given, and never printed.
	if strings.Contains(logs.String(), testSetupToken) || !strings.Contains(logs.String(), "IHASVPN_SETUP_TOKEN") {
		t.Fatalf("log: %s", logs)
	}
	c.expect("POST", "/api/setup", setupBody(""), 403)
	c.expect("POST", "/api/setup", setupBody("not-the-token-at-all"), 403)
	c.expect("GET", "/api/auth/me", nil, 401)
	c.expect("POST", "/api/setup", setupBody(testSetupToken), 201)
	if s.setupToken != "" {
		t.Fatal("the token outlived setup")
	}
	// Setup is done: the token no longer matters.
	c.expect("POST", "/api/setup", setupBody(testSetupToken), 409)
	if out := c.expect("GET", "/api/setup", nil, 200); !strings.Contains(string(out), `"tokenRequired":false`) {
		t.Fatalf("setup status after setup: %s", out)
	}
}

func TestSetupTokenIsMadeUpAndLogged(t *testing.T) {
	c, s, logs := newSetupClient(t, "", "")
	tok := s.setupToken
	if len(tok) < config.MinSetupToken {
		t.Fatalf("made-up token %q is too short", tok)
	}
	if !strings.Contains(logs.String(), "token="+tok) {
		t.Fatalf("token not in the log: %s", logs)
	}
	c.expect("POST", "/api/setup", setupBody(tok), 201)
}

func TestSetupTokenLogsTheAddress(t *testing.T) {
	_, s, logs := newSetupClient(t, "", "https://vpn.example.org/")
	if want := `url="https://vpn.example.org/?token=` + s.setupToken + `"`; !strings.Contains(logs.String(), want) {
		t.Fatalf("want %q in the log: %s", want, logs)
	}
}

func TestWrongSetupTokensAreRateLimited(t *testing.T) {
	c, _, _ := newSetupClient(t, testSetupToken, "")
	for i := 0; i < 20; i++ {
		c.expect("POST", "/api/setup", setupBody("wrong-wrong-wrong-wrong"), 403)
	}
	// The same limit as failed sign-ins: now even the right token waits.
	res, _ := c.do("POST", "/api/setup", setupBody(testSetupToken))
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("got %d, want 429 with Retry-After", res.StatusCode)
	}
}

func TestNoTokenOnceUsersExist(t *testing.T) {
	c, s, _ := newSetupClient(t, testSetupToken, "")
	c.expect("POST", "/api/setup", setupBody(testSetupToken), 201)
	// A restart with users finds nothing to set up.
	s2 := New(s.cfg, s.eng, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s2.setupToken != "" {
		t.Fatal("a server with users made a setup token")
	}
}
