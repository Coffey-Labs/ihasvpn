// Package oidc signs people in through an OpenID Connect provider with the
// authorization code flow and PKCE. It is a relying party and nothing more:
// discovery, the authorization redirect, the code exchange and the checks on
// the ID token.
//
// The ID token's signature is not checked. OpenID Connect Core 1.0, section
// 3.1.3.7, step 6 allows that when the token comes straight from the token
// endpoint over TLS, as it does here: TLS vouches for who sent it. That keeps
// this package to the standard library and works with providers that sign
// with a key only they hold (HS256 with a server secret, for one). Issuer,
// audience, expiry and nonce are all checked.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config is what an administrator sets.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Provider talks to one OpenID provider. Discovery happens on first use and
// is cached, so ihasvpn starts even while the provider is down.
type Provider struct {
	cfg  Config
	http *http.Client

	mu      sync.Mutex
	meta    *metadata
	fetched time.Time
}

type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// New returns a provider. client may be nil for a default with timeouts.
func New(cfg Config, client *http.Client) *Provider {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return &Provider{cfg: cfg, http: client}
}

// Issuer returns the configured issuer.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// SecureURL reports whether u may carry credentials: https, or plain http to
// a loopback address (a provider on the same machine, or a test).
func SecureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// discover fetches and caches the provider's metadata for an hour.
func (p *Provider) discover(ctx context.Context) (*metadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meta != nil && time.Since(p.fetched) < time.Hour {
		return p.meta, nil
	}
	u := strings.TrimSuffix(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	var m metadata
	if err := p.getJSON(ctx, u, &m); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// The issuer in the document must be the one we were given, exactly
	// (OpenID Connect Discovery 1.0, section 4.3).
	if m.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("discovery: provider says its issuer is %q, configured %q", m.Issuer, p.cfg.Issuer)
	}
	if !SecureURL(m.AuthorizationEndpoint) || !SecureURL(m.TokenEndpoint) {
		return nil, errors.New("discovery: the provider's endpoints must be https")
	}
	p.meta, p.fetched = &m, time.Now()
	return p.meta, nil
}

func (p *Provider) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

// Attempt is one sign-in in flight: what the callback needs to finish it.
type Attempt struct {
	State    string
	Nonce    string
	Verifier string
}

func random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Start begins a sign-in: it returns where to send the browser and what to
// remember until it comes back.
func (p *Provider) Start(ctx context.Context) (string, Attempt, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return "", Attempt{}, err
	}
	var a Attempt
	for _, f := range []*string{&a.State, &a.Nonce, &a.Verifier} {
		if *f, err = random(); err != nil {
			return "", Attempt{}, err
		}
	}
	challenge := sha256.Sum256([]byte(a.Verifier))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", a.State)
	q.Set("nonce", a.Nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(m.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return m.AuthorizationEndpoint + sep + q.Encode(), a, nil
}

// Identity is who the provider says signed in.
type Identity struct {
	Issuer            string
	Subject           string
	PreferredUsername string
	Email             string
	// EmailVerified is false only when the provider said so; a provider
	// that does not send the claim leaves it true.
	EmailVerified bool
	Name          string
}

type tokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Finish exchanges the code for an ID token and checks it against the
// attempt that started the sign-in.
func (p *Provider) Finish(ctx context.Context, code string, a Attempt) (*Identity, error) {
	m, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("code_verifier", a.Verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic, the default method (RFC 6749, section 2.3.1:
	// both parts form-encoded first).
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	res, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer res.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("token response (%s): %w", res.Status, err)
	}
	if res.StatusCode != http.StatusOK || tr.Error != "" {
		return nil, fmt.Errorf("token request refused (%s): %s %s", res.Status, tr.Error, tr.ErrorDescription)
	}
	return p.checkIDToken(tr.IDToken, a.Nonce, time.Now())
}

// Leeway allows for clocks that disagree a little.
const Leeway = 2 * time.Minute

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud is neither a string nor a list")
	}
	*a = many
	return nil
}

type idClaims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               audience `json:"aud"`
	Azp               string   `json:"azp"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
	Nonce             string   `json:"nonce"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	EmailVerified     *bool    `json:"email_verified"`
	Name              string   `json:"name"`
}

func (p *Provider) checkIDToken(token, nonce string, now time.Time) (*Identity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("no usable ID token in the token response")
	}
	var head struct {
		Alg string `json:"alg"`
	}
	if raw, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil || json.Unmarshal(raw, &head) != nil {
		return nil, errors.New("ID token header is unreadable")
	}
	if head.Alg == "" || strings.EqualFold(head.Alg, "none") {
		return nil, errors.New("ID token is unsigned")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("ID token claims are unreadable")
	}
	var c idClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("ID token claims: %w", err)
	}
	if c.Iss != p.cfg.Issuer {
		return nil, fmt.Errorf("ID token is from %q, not %q", c.Iss, p.cfg.Issuer)
	}
	found := false
	for _, a := range c.Aud {
		if a == p.cfg.ClientID {
			found = true
		}
	}
	if !found {
		return nil, errors.New("ID token is not meant for this client")
	}
	if len(c.Aud) > 1 && c.Azp != p.cfg.ClientID {
		return nil, errors.New("ID token names another authorized party")
	}
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(Leeway)) {
		return nil, errors.New("ID token has expired")
	}
	if c.Iat != 0 && time.Unix(c.Iat, 0).After(now.Add(Leeway)) {
		return nil, errors.New("ID token was issued in the future; check the clocks")
	}
	if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("ID token nonce does not match this sign-in")
	}
	if c.Sub == "" {
		return nil, errors.New("ID token has no subject")
	}
	id := &Identity{Issuer: c.Iss, Subject: c.Sub, PreferredUsername: c.PreferredUsername, Email: c.Email, EmailVerified: true, Name: c.Name}
	if c.EmailVerified != nil {
		id.EmailVerified = *c.EmailVerified
	}
	return id, nil
}
