// Package store is the SQLite persistence layer. Everything ihasvpn remembers --
// peers and their keys, admin users, sessions, traffic history and the audit
// log -- lives in one file under the data directory.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path and applies the schema.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}
	dsn := path
	if path != ":memory:" {
		// The file holds private keys, so it is created unreadable to anyone
		// but the owner. `_pragma` options ride along in the DSN.
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open database: %w", err)
		}
		f.Close()
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	} else {
		dsn = "file::memory:?cache=shared&_pragma=foreign_keys(ON)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serialises writers anyway and a single handle
	// avoids "database is locked" surprises under WAL with the pure-Go driver.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for the rare caller that needs raw SQL (tests).
func (s *Store) DB() *sql.DB { return s.db }

const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL DEFAULT 'admin',
	totp_secret   TEXT,
	totp_enabled  INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS recovery_codes (
	user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS recovery_codes_user ON recovery_codes(user_id);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash   TEXT PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	ip           TEXT NOT NULL DEFAULT '',
	user_agent   TEXT NOT NULL DEFAULT '',
	totp_pending INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS peers (
	id             TEXT PRIMARY KEY,
	name           TEXT NOT NULL,
	public_key     TEXT NOT NULL UNIQUE,
	private_key    TEXT,
	preshared_key  TEXT,
	ipv4           TEXT NOT NULL UNIQUE,
	ipv6           TEXT UNIQUE,
	client_routes  TEXT NOT NULL,
	dns            TEXT NOT NULL DEFAULT '',
	keepalive      INTEGER NOT NULL DEFAULT 0,
	mtu            INTEGER NOT NULL DEFAULT 0,
	enabled        INTEGER NOT NULL DEFAULT 1,
	expires_at     INTEGER,
	notes          TEXT NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	rx_total       INTEGER NOT NULL DEFAULT 0,
	tx_total       INTEGER NOT NULL DEFAULT 0,
	last_handshake INTEGER,
	last_endpoint  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS traffic (
	peer_id      TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
	bucket_start INTEGER NOT NULL,
	rx           INTEGER NOT NULL DEFAULT 0,
	tx           INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (peer_id, bucket_start)
);
CREATE INDEX IF NOT EXISTS traffic_bucket ON traffic(bucket_start);
CREATE TABLE IF NOT EXISTS audit (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	at      INTEGER NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL DEFAULT '',
	detail  TEXT NOT NULL DEFAULT '',
	ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	// Columns added after the first release. CREATE TABLE IF NOT EXISTS
	// leaves an existing table alone, so they are added here, once.
	if err := s.addColumn(ctx, "peers", "owner_id", "INTEGER REFERENCES users(id) ON DELETE SET NULL"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS peers_owner ON peers(owner_id)`); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	// Accounts that sign in through an OpenID provider: the provider's
	// issuer and subject name the person, and nothing else does.
	for _, c := range [][2]string{{"oidc_issuer", "TEXT"}, {"oidc_subject", "TEXT"}, {"email", "TEXT NOT NULL DEFAULT ''"}} {
		if err := s.addColumn(ctx, "users", c[0], c[1]); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS users_oidc ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL`); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

// addColumn adds a column unless the table already has it.
func (s *Store) addColumn(ctx context.Context, table, column, decl string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return fmt.Errorf("read %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+decl); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

// GetSetting returns the raw value of a key, or "" when unset.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSetting writes a key.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
