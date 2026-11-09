package oidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func token(alg string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": alg})
	c, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + ".sig"
}

func TestCheckIDToken(t *testing.T) {
	p := New(Config{Issuer: "https://id.example.org", ClientID: "vpn"}, nil)
	now := time.Unix(1_800_000_000, 0)
	good := func() map[string]any {
		return map[string]any{"iss": "https://id.example.org", "sub": "42", "aud": "vpn", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nonce": "n1", "email": "sam@example.org"}
	}
	id, err := p.checkIDToken(token("HS256", good()), "n1", now)
	if err != nil || id.Subject != "42" || id.Email != "sam@example.org" || !id.EmailVerified {
		t.Fatalf("%v %+v", err, id)
	}
	bad := []struct {
		name string
		edit func(map[string]any)
		alg  string
		want string
	}{
		{"unsigned", func(map[string]any) {}, "none", "unsigned"},
		{"issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }, "", "is from"},
		{"audience", func(c map[string]any) { c["aud"] = "other" }, "", "not meant"},
		{"azp", func(c map[string]any) { c["aud"] = []string{"vpn", "other"}; c["azp"] = "other" }, "", "authorized party"},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }, "", "expired"},
		{"future", func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }, "", "future"},
		{"nonce", func(c map[string]any) { c["nonce"] = "other" }, "", "nonce"},
		{"subject", func(c map[string]any) { delete(c, "sub") }, "", "subject"},
	}
	for _, b := range bad {
		c := good()
		b.edit(c)
		alg := b.alg
		if alg == "" {
			alg = "RS256"
		}
		if _, err := p.checkIDToken(token(alg, c), "n1", now); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("%s: %v", b.name, err)
		}
	}
	// A list audience with this client as azp is fine.
	c := good()
	c["aud"], c["azp"] = []string{"vpn", "other"}, "vpn"
	if _, err := p.checkIDToken(token("ES256", c), "n1", now); err != nil {
		t.Error(err)
	}
	c = good()
	c["email_verified"] = false
	if id, _ := p.checkIDToken(token("ES256", c), "n1", now); id.EmailVerified {
		t.Error("email_verified=false ignored")
	}
}

func TestSecureURL(t *testing.T) {
	for u, want := range map[string]bool{
		"https://id.example.org": true, "http://127.0.0.1:9000": true, "http://localhost": true, "http://[::1]:80": true,
		"http://id.example.org": false, "ftp://id.example.org": false, "https://": false, "": false,
	} {
		if SecureURL(u) != want {
			t.Errorf("%s: want %v", u, want)
		}
	}
}
