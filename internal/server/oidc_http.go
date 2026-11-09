package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/oidc"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
)

// Sign-in through an OpenID Connect provider. The browser goes to
// /api/auth/oidc/start, on to the provider, and back to
// /api/auth/oidc/callback, which starts an ordinary session.
//
// An account is found by the provider's issuer and subject and by nothing
// else: never by username or email, so an account at the provider cannot
// take over a local one. The first sign-in creates an account with the user
// role, which sees only its own devices.

const (
	oidcCookie     = "ihasvpn_oidc"
	oidcAttemptTTL = 10 * time.Minute
	// maxOIDCAttempts bounds the sign-ins in flight, which live in memory.
	maxOIDCAttempts = 1000
	// refusalCookie tells the sign-in page why the email check turned
	// someone away. The page reads it once and clears it.
	refusalCookie = "ihasvpn_signin_refused"
)

type oidcAttempt struct {
	attempt oidc.Attempt
	expires time.Time
}

func (s *Server) rememberAttempt(a oidc.Attempt) bool {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if len(s.oidcAttempts) >= maxOIDCAttempts {
		now := time.Now()
		for k, v := range s.oidcAttempts {
			if now.After(v.expires) {
				delete(s.oidcAttempts, k)
			}
		}
		if len(s.oidcAttempts) >= maxOIDCAttempts {
			return false
		}
	}
	s.oidcAttempts[auth.HashToken(a.State)] = oidcAttempt{attempt: a, expires: time.Now().Add(oidcAttemptTTL)}
	return true
}

// takeAttempt returns and forgets an attempt: each one is good once.
func (s *Server) takeAttempt(state string) (oidc.Attempt, bool) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	key := auth.HashToken(state)
	v, ok := s.oidcAttempts[key]
	delete(s.oidcAttempts, key)
	if !ok || time.Now().After(v.expires) {
		return oidc.Attempt{}, false
	}
	return v.attempt, true
}

type authMethods struct {
	OIDC *oidcMethod `json:"oidc"`
}

type oidcMethod struct {
	Name string `json:"name"`
}

// handleAuthMethods tells the sign-in page which buttons to show.
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	var m authMethods
	if s.oidc != nil {
		m.OIDC = &oidcMethod{Name: s.cfg.OIDCName}
	}
	writeJSON(w, http.StatusOK, m)
}

// signInFailed sends the browser back to the sign-in page with a reason the
// page knows how to word. Details go to the log, not the address bar.
func (s *Server) signInFailed(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/?signin="+reason, http.StatusSeeOther)
}

// oidcCookieSecure: the console is reached over https whenever a provider is
// configured (IHASVPN_PUBLIC_URL must say so), unless it is a local test.
func (s *Server) oidcCookieSecure() bool {
	return s.cfg.TLSEnabled() || s.cfg.SecureCookies || strings.HasPrefix(s.cfg.PublicURL, "https://")
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "sign-in through a provider is not set up")
		return
	}
	ctx := r.Context()
	if n, err := s.eng.Store().CountUsers(ctx); err != nil || n == 0 {
		// The first administrator comes from the setup wizard, not from
		// whoever reaches the provider first.
		s.signInFailed(w, r, "setup")
		return
	}
	dest, a, err := s.oidc.Start(ctx)
	if err != nil {
		s.log.Warn("oidc start", "error", err)
		s.signInFailed(w, r, "provider")
		return
	}
	if !s.rememberAttempt(a) {
		s.log.Warn("oidc start: too many sign-ins in progress")
		s.signInFailed(w, r, "busy")
		return
	}
	// Lax, not Strict: the provider sends the browser back with a cross-site
	// navigation, and the state cookie has to come with it.
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: a.State, Path: "/api/auth/oidc", HttpOnly: true,
		Secure: s.oidcCookieSecure(), SameSite: http.SameSiteLaxMode, MaxAge: int(oidcAttemptTTL.Seconds()),
	})
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "sign-in through a provider is not set up")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/api/auth/oidc", HttpOnly: true, Secure: s.oidcCookieSecure(), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	ctx := r.Context()
	ip := s.clientIP(r)
	if ok, _ := s.ipLimit.Allowed(ip); !ok {
		s.signInFailed(w, r, "busy")
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	c, err := r.Cookie(oidcCookie)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.ipLimit.Fail(ip)
		s.signInFailed(w, r, "expired")
		return
	}
	a, ok := s.takeAttempt(state)
	if !ok {
		s.signInFailed(w, r, "expired")
		return
	}
	if e := q.Get("error"); e != "" {
		s.log.Info("oidc: provider refused", "error", e, "description", q.Get("error_description"), "ip", ip)
		if e == "access_denied" {
			s.signInFailed(w, r, "denied")
		} else {
			s.signInFailed(w, r, "provider")
		}
		return
	}
	id, err := s.oidc.Finish(ctx, q.Get("code"), a)
	if err != nil {
		s.ipLimit.Fail(ip)
		s.log.Warn("oidc: sign-in failed", "error", err, "ip", ip)
		s.signInFailed(w, r, "provider")
		return
	}
	if !s.emailAllowed(id) {
		s.log.Warn("oidc: email domain not allowed", "email", id.Email, "subject", id.Subject, "ip", ip)
		_ = s.eng.Store().Audit(ctx, store.AuditEntry{Actor: id.Email, Action: "login.refused", Detail: "email domain not allowed", IP: ip})
		s.setRefusal(w, id)
		s.signInFailed(w, r, "not-allowed")
		return
	}
	u, err := s.eng.Store().UserByOIDC(ctx, id.Issuer, id.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if u, err = s.createOIDCUser(ctx, id); err != nil {
			s.log.Error("oidc: create account", "error", err)
			s.signInFailed(w, r, "server")
			return
		}
		r = r.WithContext(context.WithValue(ctx, ctxUser, u))
		s.audit(r, "user.created", u.Username, "first sign-in through "+s.cfg.OIDCName+", role user")
	case err != nil:
		s.log.Error("oidc: find account", "error", err)
		s.signInFailed(w, r, "server")
		return
	case id.Email != u.Email:
		_ = s.eng.Store().SetEmail(ctx, u.ID, id.Email)
	}
	if err := s.startSession(w, r, u, false); err != nil {
		s.log.Error("oidc: start session", "error", err)
		s.signInFailed(w, r, "server")
		return
	}
	s.ipLimit.Reset(ip)
	_ = s.eng.Store().TouchLogin(ctx, u.ID)
	r = r.WithContext(context.WithValue(ctx, ctxUser, u))
	s.audit(r, "login", u.Username, "through "+s.cfg.OIDCName)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// emailAllowed applies IHASVPN_OIDC_EMAIL_DOMAINS, when set.
func (s *Server) emailAllowed(id *oidc.Identity) bool {
	if len(s.cfg.OIDCEmailDomains) == 0 {
		return true
	}
	return id.EmailVerified && s.domainListed(id.Email)
}

// domainListed reports whether email is at one of the allowed domains.
func (s *Server) domainListed(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range s.cfg.OIDCEmailDomains {
		if domain == d {
			return true
		}
	}
	return false
}

// refusal is what the sign-in page shows when the email check turns someone
// away: the address the provider sent and the domains this server takes. It
// goes in a short-lived cookie rather than the address bar, so the address
// stays out of browser history and access logs.
type refusal struct {
	Email      string   `json:"email"`
	Domains    []string `json:"domains"`
	Unverified bool     `json:"unverified,omitempty"`
}

func (s *Server) setRefusal(w http.ResponseWriter, id *oidc.Identity) {
	email := id.Email
	if len(email) > 254 {
		email = email[:254]
	}
	b, err := json.Marshal(refusal{
		Email:   email,
		Domains: s.cfg.OIDCEmailDomains,
		// The address is at an allowed domain; the provider just hasn't
		// confirmed it belongs to them.
		Unverified: !id.EmailVerified && s.domainListed(id.Email),
	})
	if err != nil {
		return
	}
	// Not HttpOnly: the sign-in page reads it.
	http.SetCookie(w, &http.Cookie{
		Name: refusalCookie, Value: base64.RawURLEncoding.EncodeToString(b), Path: "/",
		Secure: s.oidcCookieSecure(), SameSite: http.SameSiteLaxMode, MaxAge: 120,
	})
}

// createOIDCUser makes the account for a first sign-in. The username is the
// provider's preferred username or email, cleaned up and made unique; it is
// only a label, since the account is found by issuer and subject.
func (s *Server) createOIDCUser(ctx context.Context, id *oidc.Identity) (*store.User, error) {
	base := oidcUsername(id)
	for i := 1; i <= 100; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		if _, err := s.eng.Store().UserByName(ctx, name); errors.Is(err, store.ErrNotFound) {
			return s.eng.Store().CreateOIDCUser(ctx, name, "user", id.Issuer, id.Subject, id.Email)
		} else if err != nil {
			return nil, err
		}
	}
	suffix, err := auth.NewID()
	if err != nil {
		return nil, err
	}
	return s.eng.Store().CreateOIDCUser(ctx, base+"-"+suffix[:6], "user", id.Issuer, id.Subject, id.Email)
}

func oidcUsername(id *oidc.Identity) string {
	for _, cand := range []string{id.PreferredUsername, id.Email, id.Name} {
		var b strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(cand)) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@', r == '+':
				b.WriteRune(r)
			case r == ' ':
				b.WriteByte('.')
			}
		}
		name := b.String()
		if len(name) > 60 {
			name = name[:60]
		}
		if len(name) >= 2 {
			return name
		}
	}
	return "user"
}
