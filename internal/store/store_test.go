package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// A database from before peers had owners opens, gains the column and keeps
// its rows.
func TestMigrateAddsOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE peers (
		id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, private_key TEXT, preshared_key TEXT,
		ipv4 TEXT NOT NULL UNIQUE, ipv6 TEXT UNIQUE, client_routes TEXT NOT NULL, dns TEXT NOT NULL DEFAULT '',
		keepalive INTEGER NOT NULL DEFAULT 0, mtu INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
		expires_at INTEGER, notes TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
		rx_total INTEGER NOT NULL DEFAULT 0, tx_total INTEGER NOT NULL DEFAULT 0, last_handshake INTEGER,
		last_endpoint TEXT NOT NULL DEFAULT '');
		INSERT INTO peers(id, name, public_key, ipv4, client_routes, created_at, updated_at) VALUES('a', 'Old', 'k', '10.8.0.2', '0.0.0.0/0', 1, 1);`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	for i := 0; i < 2; i++ { // the second open must find the column and leave it
		st, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		peers, err := st.ListPeers(context.Background())
		if err != nil || len(peers) != 1 || peers[0].Name != "Old" || peers[0].OwnerID != 0 {
			t.Fatalf("%v %+v", err, peers)
		}
		st.Close()
	}
}
