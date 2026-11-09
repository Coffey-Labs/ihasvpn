package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
)

const cookieName = "ihasvpn_session"

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
)

// userOf returns the authenticated user for a request.
func userOf(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func sessionOf(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxSession).(*store.Session)
	return s
}

func (s *Server) setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled() || s.cfg.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.cfg.TLSEnabled() || s.cfg.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// loadSession resolves the cookie to a user, if the session is valid.
func (s *Server) loadSession(r *http.Request) (*store.User, *store.Session) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	ctx := r.Context()
	sess, err := s.eng.Store().SessionByHash(ctx, auth.HashToken(c.Value))
	if err != nil {
		return nil, nil
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.cfg.SessionMax {
		_ = s.eng.Store().DeleteSession(ctx, sess.TokenHash)
		return nil, nil
	}
	u, err := s.eng.Store().UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil
	}
	// Slide the idle expiry, but not on every request: once a minute is
	// plenty and keeps the write load off SQLite.
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.eng.Store().TouchSession(ctx, sess.TokenHash, now.Add(s.cfg.SessionIdle))
	}
	return u, sess
}

// authed requires a fully authenticated session.
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		u, sess := s.loadSession(r)
		if u == nil || sess.TOTPPending {
			writeError(w, http.StatusUnauthorized, "not signed in")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxSession, sess)
		next(w, r.WithContext(ctx))
	})
}

// staff requires an administrator or a viewer: the people who may see the
// whole server. A user sees only their own devices.
func (s *Server) staff(next http.HandlerFunc) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if !isStaff(userOf(r)) {
			writeError(w, http.StatusForbidden, "administrator or viewer role required")
			return
		}
		next(w, r)
	})
}

func isStaff(u *store.User) bool { return u.Role == "admin" || u.Role == "viewer" }

// admin additionally requires the admin role.
func (s *Server) admin(next http.HandlerFunc) http.Handler {
	return s.authed(func(w http.ResponseWriter, r *http.Request) {
		if userOf(r).Role != "admin" {
			writeError(w, http.StatusForbidden, "administrator role required")
			return
		}
		next(w, r)
	})
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	actor := "-"
	if u := userOf(r); u != nil {
		actor = u.Username
	}
	if err := s.eng.Store().Audit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Target: target, Detail: detail, IP: s.clientIP(r)}); err != nil {
		s.log.Warn("audit write failed", "error", err)
	}
	s.log.Info("audit", "actor", actor, "action", action, "target", target, "detail", detail, "ip", s.clientIP(r))
}

// --- setup -----------------------------------------------------------------

type setupStatus struct {
	NeedsSetup bool `json:"needsSetup"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.eng.Store().CountUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, setupStatus{NeedsSetup: n == 0})
}

type setupRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	EndpointHost string `json:"endpointHost"`
}

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		if !(r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// handleSetup creates the first administrator. It only works while there
// are no users at all, so a running server cannot be taken over by it.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	ctx := r.Context()
	n, err := s.eng.Store().CountUsers(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		writeError(w, http.StatusConflict, "setup has already been completed")
		return
	}
	var req setupRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 2-32 characters: letters, digits, dot, dash or underscore")
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	settings := s.eng.Settings()
	if host := strings.TrimSpace(req.EndpointHost); host != "" {
		settings.EndpointHost = host
	}
	if err := settings.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := s.eng.Store().CreateUser(ctx, req.Username, hash, "admin")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.eng.UpdateSettings(ctx, settings); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.startSession(w, r, u, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	r = r.WithContext(context.WithValue(ctx, ctxUser, u))
	s.audit(r, "setup", u.Username, "first administrator created")
	writeJSON(w, http.StatusCreated, s.meBody(ctx, u))
}

// --- login -----------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	TOTPRequired bool `json:"totpRequired"`
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User, totpPending bool) error {
	token, hash, err := auth.NewToken()
	if err != nil {
		return err
	}
	now := time.Now()
	expires := now.Add(s.cfg.SessionIdle)
	if totpPending {
		expires = now.Add(10 * time.Minute)
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	if err := s.eng.Store().CreateSession(r.Context(), store.Session{
		TokenHash: hash, UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: expires,
		IP: s.clientIP(r), UserAgent: ua, TOTPPending: totpPending,
	}); err != nil {
		return err
	}
	s.setCookie(w, token, now.Add(s.cfg.SessionMax))
	return nil
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	ip := s.clientIP(r)
	if ok, wait := s.ipLimit.Allowed(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	var req loginRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if ok, wait := s.usrLimit.Allowed(strings.ToLower(req.Username)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	ctx := r.Context()
	u, err := s.eng.Store().UserByName(ctx, req.Username)
	if err != nil {
		auth.EqualiseTiming()
		s.ipLimit.Fail(ip)
		s.usrLimit.Fail(strings.ToLower(req.Username))
		s.log.Warn("login failed", "user", req.Username, "ip", ip)
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.ipLimit.Fail(ip)
		s.usrLimit.Fail(strings.ToLower(req.Username))
		s.log.Warn("login failed", "user", req.Username, "ip", ip)
		_ = s.eng.Store().Audit(ctx, store.AuditEntry{Actor: u.Username, Action: "login.failed", IP: ip})
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	s.ipLimit.Reset(ip)
	s.usrLimit.Reset(strings.ToLower(req.Username))
	if err := s.startSession(w, r, u, u.TOTPEnabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if u.TOTPEnabled {
		writeJSON(w, http.StatusOK, loginResponse{TOTPRequired: true})
		return
	}
	_ = s.eng.Store().TouchLogin(ctx, u.ID)
	r = r.WithContext(context.WithValue(ctx, ctxUser, u))
	s.audit(r, "login", u.Username, "")
	writeJSON(w, http.StatusOK, loginResponse{})
}

type totpRequest struct {
	Code string `json:"code"`
}

// handleLoginTOTP completes a login that is waiting on a second factor.
// A recovery code is accepted in place of a TOTP code.
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	u, sess := s.loadSession(r)
	if u == nil || !sess.TOTPPending {
		writeError(w, http.StatusUnauthorized, "no login in progress")
		return
	}
	ip := s.clientIP(r)
	if ok, wait := s.ipLimit.Allowed(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	var req totpRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	ok := auth.VerifyTOTP(u.TOTPSecret, req.Code, time.Now())
	usedRecovery := false
	if !ok {
		used, err := s.eng.Store().UseRecoveryCode(ctx, u.ID, auth.HashToken(auth.NormaliseRecoveryCode(req.Code)))
		if err == nil && used {
			ok, usedRecovery = true, true
		}
	}
	if !ok {
		s.ipLimit.Fail(ip)
		_ = s.eng.Store().Audit(ctx, store.AuditEntry{Actor: u.Username, Action: "login.totp_failed", IP: ip})
		writeError(w, http.StatusUnauthorized, "wrong code")
		return
	}
	s.ipLimit.Reset(ip)
	if err := s.eng.Store().ClearTOTPPending(ctx, sess.TokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.eng.Store().TouchSession(ctx, sess.TokenHash, time.Now().Add(s.cfg.SessionIdle))
	_ = s.eng.Store().TouchLogin(ctx, u.ID)
	r = r.WithContext(context.WithValue(ctx, ctxUser, u))
	detail := ""
	if usedRecovery {
		detail = "recovery code used"
	}
	s.audit(r, "login", u.Username, detail)
	writeJSON(w, http.StatusOK, loginResponse{})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := sessionOf(r); sess != nil {
		_ = s.eng.Store().DeleteSession(r.Context(), sess.TokenHash)
	}
	s.clearCookie(w)
	s.audit(r, "logout", userOf(r).Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- account ---------------------------------------------------------------

type meBody struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	Role          string    `json:"role"`
	TOTPEnabled   bool      `json:"totpEnabled"`
	RecoveryCodes int       `json:"recoveryCodesLeft"`
	CreatedAt     time.Time `json:"createdAt"`
	LastLoginAt   time.Time `json:"lastLoginAt,omitempty"`
}

func (s *Server) meBody(ctx context.Context, u *store.User) meBody {
	left, _ := s.eng.Store().RecoveryCodesLeft(ctx, u.ID)
	return meBody{ID: u.ID, Username: u.Username, Role: u.Role, TOTPEnabled: u.TOTPEnabled, RecoveryCodes: left, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.meBody(r.Context(), userOf(r)))
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if !readJSON(w, r, &req) {
		return
	}
	u := userOf(r)
	if !auth.VerifyPassword(u.PasswordHash, req.Current) {
		writeError(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := auth.ValidatePassword(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.eng.Store().SetPassword(r.Context(), u.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Every other browser is signed out; this one keeps its session.
	sess := sessionOf(r)
	_ = s.eng.Store().DeleteUserSessions(r.Context(), u.ID)
	if err := s.startSession(w, r, u, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = sess
	s.audit(r, "password.changed", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type totpSetupResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// handleTOTPSetup issues a pending secret; it becomes active on confirm.
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "two-factor authentication is already on")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.eng.Store().SetTOTP(r.Context(), u.ID, secret, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, totpSetupResponse{Secret: secret, URI: auth.TOTPURI("ihasvpn", u.Username, secret)})
}

// handleTOTPQR renders the pending secret's otpauth URI as a QR code. Only a
// secret that is not yet active is shown: an enabled one must never leave
// the server again.
func (s *Server) handleTOTPQR(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u.TOTPEnabled || u.TOTPSecret == "" {
		writeError(w, http.StatusNotFound, "no two-factor setup in progress")
		return
	}
	png, err := qrcode.Encode(auth.TOTPURI("ihasvpn", u.Username, u.TOTPSecret), qrcode.Medium, 256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

type totpConfirmResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	var req totpRequest
	if !readJSON(w, r, &req) {
		return
	}
	u := userOf(r)
	if u.TOTPEnabled || u.TOTPSecret == "" {
		writeError(w, http.StatusConflict, "start two-factor setup first")
		return
	}
	if !auth.VerifyTOTP(u.TOTPSecret, req.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "wrong code; check the time on your device")
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes(8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx := r.Context()
	if err := s.eng.Store().SetTOTP(ctx, u.ID, u.TOTPSecret, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.eng.Store().ReplaceRecoveryCodes(ctx, u.ID, hashes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "totp.enabled", u.Username, "")
	writeJSON(w, http.StatusOK, totpConfirmResponse{RecoveryCodes: codes})
}

type totpDisableRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req totpDisableRequest
	if !readJSON(w, r, &req) {
		return
	}
	u := userOf(r)
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		writeError(w, http.StatusForbidden, "password is wrong")
		return
	}
	ctx := r.Context()
	if err := s.eng.Store().SetTOTP(ctx, u.ID, "", false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.eng.Store().ReplaceRecoveryCodes(ctx, u.ID, nil)
	s.audit(r, "totp.disabled", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type sessionBody struct {
	Current    bool      `json:"current"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"userAgent"`
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	cur := sessionOf(r)
	rows, err := s.eng.Store().DB().QueryContext(r.Context(), `SELECT token_hash, created_at, last_seen_at, ip, user_agent FROM sessions WHERE user_id = ? AND totp_pending = 0 ORDER BY last_seen_at DESC`, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []sessionBody{}
	for rows.Next() {
		var hash, ip, ua string
		var created, seen int64
		if err := rows.Scan(&hash, &created, &seen, &ip, &ua); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, sessionBody{Current: hash == cur.TokenHash, CreatedAt: time.Unix(created, 0), LastSeenAt: time.Unix(seen, 0), IP: ip, UserAgent: ua})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeSessions signs the user out everywhere but here.
func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	cur := sessionOf(r)
	if _, err := s.eng.Store().DB().ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, u.ID, cur.TokenHash); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "sessions.revoked", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- users -----------------------------------------------------------------

type userBody struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	TOTPEnabled bool      `json:"totpEnabled"`
	Devices     int       `json:"devices"`
	CreatedAt   time.Time `json:"createdAt"`
	LastLoginAt time.Time `json:"lastLoginAt,omitempty"`
}

func (s *Server) toUserBody(u *store.User) userBody {
	return userBody{ID: u.ID, Username: u.Username, Role: u.Role, TOTPEnabled: u.TOTPEnabled, Devices: len(s.eng.PeersOwnedBy(u.ID)), CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.eng.Store().ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]userBody, 0, len(users))
	for _, u := range users {
		out = append(out, s.toUserBody(u))
	}
	writeJSON(w, http.StatusOK, out)
}

type userRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func validRole(role string) bool { return role == "admin" || role == "viewer" || role == "user" }

const roleHint = "role must be admin, viewer or user"

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req userRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !validUsername(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 2-32 characters: letters, digits, dot, dash or underscore")
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, roleHint)
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := s.eng.Store().CreateUser(r.Context(), req.Username, hash, req.Role)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "that username is taken")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "user.created", u.Username, "role "+u.Role)
	writeJSON(w, http.StatusCreated, s.toUserBody(u))
}

type userUpdateRequest struct {
	Role      string `json:"role,omitempty"`
	Password  string `json:"password,omitempty"`
	ResetTOTP bool   `json:"resetTotp,omitempty"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad user id")
		return
	}
	var req userUpdateRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	target, err := s.eng.Store().UserByID(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	var changes []string
	if req.Role != "" && req.Role != target.Role {
		if !validRole(req.Role) {
			writeError(w, http.StatusBadRequest, roleHint)
			return
		}
		if target.ID == userOf(r).ID {
			writeError(w, http.StatusBadRequest, "you cannot change your own role")
			return
		}
		if err := s.eng.Store().SetRole(ctx, id, req.Role); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		changes = append(changes, "role "+req.Role)
	}
	if req.Password != "" {
		if err := auth.ValidatePassword(req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.eng.Store().SetPassword(ctx, id, hash); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.eng.Store().DeleteUserSessions(ctx, id)
		changes = append(changes, "password reset")
	}
	if req.ResetTOTP && target.TOTPEnabled {
		if err := s.eng.Store().SetTOTP(ctx, id, "", false); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.eng.Store().ReplaceRecoveryCodes(ctx, id, nil)
		changes = append(changes, "two-factor reset")
	}
	if len(changes) > 0 {
		s.audit(r, "user.updated", target.Username, strings.Join(changes, ", "))
	}
	u, _ := s.eng.Store().UserByID(ctx, id)
	writeJSON(w, http.StatusOK, s.toUserBody(u))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad user id")
		return
	}
	if id == userOf(r).ID {
		writeError(w, http.StatusBadRequest, "you cannot delete yourself")
		return
	}
	ctx := r.Context()
	target, err := s.eng.Store().UserByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Their devices go first: a deleted person's phone must not keep working.
	devices, err := s.eng.DeletePeersOwnedBy(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.eng.Store().DeleteUser(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	detail := ""
	if devices > 0 {
		detail = fmt.Sprintf("%d device(s) deleted with them", devices)
	}
	s.audit(r, "user.deleted", target.Username, detail)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
