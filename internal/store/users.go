package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// User is an account that can sign in: an administrator, a viewer, or a
// user who looks after their own devices.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
	LastLoginAt  time.Time
	// OIDCIssuer and OIDCSubject are set for an account that signs in
	// through an OpenID provider; it then has no password.
	OIDCIssuer  string
	OIDCSubject string
	Email       string
}

// OIDC reports whether the account signs in through a provider.
func (u *User) OIDC() bool { return u.OIDCSubject != "" }

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var secret sql.NullString
	var totp int
	var created int64
	var last sql.NullInt64
	var iss, sub sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &secret, &totp, &created, &last, &iss, &sub, &u.Email); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.TOTPSecret = secret.String
	u.OIDCIssuer, u.OIDCSubject = iss.String, sub.String
	u.TOTPEnabled = totp == 1
	u.CreatedAt = time.Unix(created, 0)
	if last.Valid {
		u.LastLoginAt = time.Unix(last.Int64, 0)
	}
	return &u, nil
}

const userCols = `id, username, password_hash, role, totp_secret, totp_enabled, created_at, last_login_at, oidc_issuer, oidc_subject, email`

// CountUsers returns how many users exist; zero means first-run setup is due.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a user and returns it.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (*User, error) {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)`, username, passwordHash, role, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

// CreateOIDCUser inserts an account that signs in through a provider. It
// has no password: VerifyPassword never accepts an empty hash.
func (s *Store) CreateOIDCUser(ctx context.Context, username, role, issuer, subject, email string) (*User, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO users(username, password_hash, role, created_at, oidc_issuer, oidc_subject, email) VALUES(?, '', ?, ?, ?, ?, ?)`,
		username, role, time.Now().Unix(), issuer, subject, email)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

// UserByOIDC finds the account for a provider's subject.
func (s *Store) UserByOIDC(ctx context.Context, issuer, subject string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE oidc_issuer = ? AND oidc_subject = ?`, issuer, subject))
}

// SetEmail records the address a provider gave for an account.
func (s *Store) SetEmail(ctx context.Context, id int64, email string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, email, id)
	return err
}

// UserByID looks a user up by id.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByName looks a user up by username (case-insensitive).
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// ListUsers returns every user ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetPassword replaces a user's password hash.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

// SetRole changes a user's role.
func (s *Store) SetRole(ctx context.Context, id int64, role string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

// SetTOTP stores a secret and whether it is active. An empty secret clears it.
func (s *Store) SetTOTP(ctx context.Context, id int64, secret string, enabled bool) error {
	var sec any
	if secret != "" {
		sec = secret
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, sec, en, id)
	return err
}

// TouchLogin records a successful login.
func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// DeleteUser removes a user and, through cascades, their sessions and codes.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// ReplaceRecoveryCodes replaces a user's recovery codes with the given hashes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, id int64, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_id, code_hash) VALUES(?, ?)`, id, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UseRecoveryCode marks a code used if it exists and is unused; it reports
// whether it did.
func (s *Store) UseRecoveryCode(ctx context.Context, id int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`, time.Now().Unix(), id, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecoveryCodesLeft counts a user's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, id).Scan(&n)
	return n, err
}

// Session is one logged-in browser.
type Session struct {
	TokenHash   string
	UserID      int64
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	IP          string
	UserAgent   string
	TOTPPending bool
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	pending := 0
	if sess.TOTPPending {
		pending = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent, totp_pending) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.CreatedAt.Unix(), sess.LastSeenAt.Unix(), sess.ExpiresAt.Unix(), sess.IP, sess.UserAgent, pending)
	return err
}

// SessionByHash loads a session.
func (s *Store) SessionByHash(ctx context.Context, hash string) (*Session, error) {
	var sess Session
	var created, seen, exp int64
	var pending int
	err := s.db.QueryRowContext(ctx, `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent, totp_pending FROM sessions WHERE token_hash = ?`, hash).
		Scan(&sess.TokenHash, &sess.UserID, &created, &seen, &exp, &sess.IP, &sess.UserAgent, &pending)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt = time.Unix(created, 0)
	sess.LastSeenAt = time.Unix(seen, 0)
	sess.ExpiresAt = time.Unix(exp, 0)
	sess.TOTPPending = pending == 1
	return &sess, nil
}

// TouchSession bumps last_seen and the sliding expiry.
func (s *Store) TouchSession(ctx context.Context, hash string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?`, time.Now().Unix(), expires.Unix(), hash)
	return err
}

// ClearTOTPPending marks a session fully authenticated.
func (s *Store) ClearTOTPPending(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET totp_pending = 0 WHERE token_hash = ?`, hash)
	return err
}

// DeleteSession logs one browser out.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash)
	return err
}

// DeleteUserSessions logs a user out everywhere.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// PruneSessions drops expired sessions.
func (s *Store) PruneSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}
