// Package server is the admin HTTP API and the host for the embedded UI.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/config"
	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/server/static"
)

// Server serves the API and UI.
type Server struct {
	cfg     *config.Config
	eng     *engine.Engine
	log     *slog.Logger
	mux     *http.ServeMux
	ipLimit *auth.Limiter
	usrLimit *auth.Limiter
	http    *http.Server
	// deviceMu makes a user's limit check and device creation one step.
	deviceMu sync.Mutex
}

// New builds the router.
func New(cfg *config.Config, eng *engine.Engine, log *slog.Logger) *Server {
	s := &Server{
		cfg:      cfg,
		eng:      eng,
		log:      log,
		mux:      http.NewServeMux(),
		ipLimit:  auth.NewLimiter(20, 15*time.Minute),
		usrLimit: auth.NewLimiter(8, 15*time.Minute),
	}
	s.routes()
	return s
}

// Handler returns the full middleware chain, for tests and for ListenAndServe.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.securityHeaders(s.mux))
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.http = &http.Server{
		Addr:              s.cfg.HTTP,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout: the SSE stream is long-lived. Handlers that
		// matter bound themselves.
		IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	var tlsCfg *tls.Config
	if s.cfg.TLSEnabled() {
		cert, err := s.loadCertificate()
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		}
		s.http.TLSConfig = tlsCfg
	}
	ln, err := net.Listen("tcp", s.cfg.HTTP)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.HTTP, err)
	}
	errCh := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			errCh <- s.http.ServeTLS(ln, "", "")
		} else {
			errCh <- s.http.Serve(ln)
		}
	}()
	s.log.Info("admin UI listening", "addr", ln.Addr().String(), "tls", tlsCfg != nil)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdown)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) routes() {
	m := s.mux
	// Unauthenticated.
	m.HandleFunc("GET /api/health", s.handleHealth)
	m.HandleFunc("GET /api/setup", s.handleSetupStatus)
	m.HandleFunc("POST /api/setup", s.handleSetup)
	m.HandleFunc("POST /api/auth/login", s.handleLogin)
	m.HandleFunc("POST /api/auth/totp", s.handleLoginTOTP)
	m.HandleFunc("GET /metrics", s.handleMetrics)

	// Session required.
	m.Handle("GET /api/auth/me", s.authed(s.handleMe))
	m.Handle("POST /api/auth/logout", s.authed(s.handleLogout))
	m.Handle("POST /api/auth/password", s.authed(s.handleChangePassword))
	m.Handle("POST /api/auth/totp/setup", s.authed(s.handleTOTPSetup))
	m.Handle("GET /api/auth/totp/qr.png", s.authed(s.handleTOTPQR))
	m.Handle("POST /api/auth/totp/confirm", s.authed(s.handleTOTPConfirm))
	m.Handle("POST /api/auth/totp/disable", s.authed(s.handleTOTPDisable))
	m.Handle("GET /api/auth/sessions", s.authed(s.handleSessions))
	m.Handle("POST /api/auth/sessions/revoke", s.authed(s.handleRevokeSessions))

	// Your own devices, whatever your role.
	m.Handle("GET /api/me/devices", s.authed(s.handleMyDevices))
	m.Handle("POST /api/me/devices", s.authed(s.handleCreateMyDevice))
	m.Handle("GET /api/me/devices/{id}/config", s.authed(s.handleMyDeviceConfig))
	m.Handle("GET /api/me/devices/{id}/qr.png", s.authed(s.handleMyDeviceQR))
	m.Handle("POST /api/me/devices/{id}/rotate", s.authed(s.handleRotateMyDevice))
	m.Handle("DELETE /api/me/devices/{id}", s.authed(s.handleDeleteMyDevice))

	// Administrators and viewers: the whole server.
	m.Handle("GET /api/status", s.staff(s.handleStatus))
	m.Handle("GET /api/events", s.staff(s.handleEvents))
	m.Handle("GET /api/peers", s.staff(s.handlePeers))
	m.Handle("GET /api/peers/{id}", s.staff(s.handlePeer))
	m.Handle("GET /api/peers/{id}/config", s.staff(s.handlePeerConfig))
	m.Handle("GET /api/peers/{id}/qr.png", s.staff(s.handlePeerQR))
	m.Handle("GET /api/peers/{id}/usage", s.staff(s.handlePeerUsage))
	m.Handle("GET /api/usage", s.staff(s.handleUsage))
	m.Handle("GET /api/usage/peers", s.staff(s.handleUsageByPeer))
	m.Handle("GET /api/settings", s.staff(s.handleGetSettings))
	m.Handle("GET /api/audit", s.staff(s.handleAudit))
	m.Handle("GET /api/users", s.staff(s.handleUsers))

	// Admin role required.
	m.Handle("POST /api/peers", s.admin(s.handleCreatePeer))
	m.Handle("PUT /api/peers/{id}", s.admin(s.handleUpdatePeer))
	m.Handle("DELETE /api/peers/{id}", s.admin(s.handleDeletePeer))
	m.Handle("POST /api/peers/{id}/enable", s.admin(s.handleEnablePeer))
	m.Handle("POST /api/peers/{id}/disable", s.admin(s.handleDisablePeer))
	m.Handle("POST /api/peers/{id}/reset", s.admin(s.handleResetPeer))
	m.Handle("POST /api/peers/{id}/rotate", s.admin(s.handleRotatePeer))
	m.Handle("PUT /api/settings", s.admin(s.handlePutSettings))
	m.Handle("POST /api/users", s.admin(s.handleCreateUser))
	m.Handle("PUT /api/users/{id}", s.admin(s.handleUpdateUser))
	m.Handle("DELETE /api/users/{id}", s.admin(s.handleDeleteUser))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint")
	})
	m.Handle("/", s.spa())
}

// spa serves the embedded UI, falling back to index.html for client routes.
func (s *Server) spa() http.Handler {
	files := static.FS()
	fileServer := http.FileServerFS(files)
	index, _ := fs.ReadFile(files, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		p := path.Clean(r.URL.Path)
		if p != "/" {
			if f, err := files.Open(strings.TrimPrefix(p, "/")); err == nil {
				f.Close()
				if strings.HasPrefix(p, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		if index == nil {
			http.Error(w, "the admin UI has not been built; run `npm run build` in web/", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(index)
	})
}

// --- middleware ------------------------------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("panic", "path", r.URL.Path, "error", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.cfg.TLSEnabled() || s.cfg.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin rejects cross-site state changes. Cookies are SameSite=Strict
// already; this is the belt to that brace, for browsers that send
// Sec-Fetch-Site or Origin.
func (s *Server) sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		host := r.Host
		return strings.EqualFold(strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://"), host)
	}
	// Neither header: not a modern browser. A non-browser client cannot be
	// tricked by a third-party page, so allow it.
	return true
}

// clientIP returns the caller's address, honouring proxy headers only from
// trusted proxies.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !s.trusted(addr) {
		return addr.String()
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk from the right, skipping trusted hops, to the first address
		// that is not one of our proxies.
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break
			}
			if !s.trusted(a) {
				return a.String()
			}
		}
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		if a, err := netip.ParseAddr(real); err == nil {
			return a.String()
		}
	}
	return addr.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// --- helpers ---------------------------------------------------------------

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// readJSON decodes a small JSON body strictly.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

// engineError maps engine errors to status codes.
func engineError(w http.ResponseWriter, err error) {
	var ve engine.ErrValidation
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, ve.Msg)
	case errors.Is(err, engine.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
