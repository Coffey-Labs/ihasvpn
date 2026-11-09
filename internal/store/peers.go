package store

import (
	"context"
	"database/sql"
	"time"
)

// Peer is a client device.
type Peer struct {
	ID           string
	Name         string
	PublicKey    string
	PrivateKey   string // empty when the client generated its own key pair
	PresharedKey string
	IPv4         string // tunnel address without prefix, e.g. 10.8.0.2
	IPv6         string // may be empty
	ClientRoutes string // AllowedIPs the *client* routes into the tunnel
	DNS          string // override; empty means the server default
	Keepalive    int    // seconds; 0 means the server default
	MTU          int    // 0 means the server default
	Enabled      bool
	ExpiresAt    time.Time
	Notes        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	RxTotal      int64
	TxTotal      int64
	LastHandshake time.Time
	LastEndpoint string
	// OwnerID is the user the device belongs to; 0 means nobody in
	// particular (an administrator looks after it).
	OwnerID int64
}

const peerCols = `id, name, public_key, private_key, preshared_key, ipv4, ipv6, client_routes, dns, keepalive, mtu, enabled, expires_at, notes, created_at, updated_at, rx_total, tx_total, last_handshake, last_endpoint, owner_id`

func scanPeer(row interface{ Scan(...any) error }) (*Peer, error) {
	var p Peer
	var priv, psk, v6 sql.NullString
	var enabled int
	var exp, created, updated int64
	var expN, hsN, ownerN sql.NullInt64
	if err := row.Scan(&p.ID, &p.Name, &p.PublicKey, &priv, &psk, &p.IPv4, &v6, &p.ClientRoutes, &p.DNS, &p.Keepalive, &p.MTU, &enabled, &expN, &p.Notes, &created, &updated, &p.RxTotal, &p.TxTotal, &hsN, &p.LastEndpoint, &ownerN); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = exp
	p.PrivateKey = priv.String
	p.PresharedKey = psk.String
	p.IPv6 = v6.String
	p.Enabled = enabled == 1
	p.OwnerID = ownerN.Int64
	if expN.Valid {
		p.ExpiresAt = time.Unix(expN.Int64, 0)
	}
	p.CreatedAt = time.Unix(created, 0)
	p.UpdatedAt = time.Unix(updated, 0)
	if hsN.Valid && hsN.Int64 > 0 {
		p.LastHandshake = time.Unix(hsN.Int64, 0)
	}
	return &p, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreatePeer inserts a peer.
func (s *Store) CreatePeer(ctx context.Context, p *Peer) error {
	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO peers(`+peerCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.PublicKey, nullStr(p.PrivateKey), nullStr(p.PresharedKey), p.IPv4, nullStr(p.IPv6), p.ClientRoutes, p.DNS, p.Keepalive, p.MTU, boolInt(p.Enabled), nullTime(p.ExpiresAt), p.Notes, now.Unix(), now.Unix(), p.RxTotal, p.TxTotal, nullTime(p.LastHandshake), p.LastEndpoint, nullID(p.OwnerID))
	return err
}

// UpdatePeer writes every editable column of a peer.
func (s *Store) UpdatePeer(ctx context.Context, p *Peer) error {
	p.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `UPDATE peers SET name=?, public_key=?, private_key=?, preshared_key=?, ipv4=?, ipv6=?, client_routes=?, dns=?, keepalive=?, mtu=?, enabled=?, expires_at=?, notes=?, updated_at=?, owner_id=? WHERE id=?`,
		p.Name, p.PublicKey, nullStr(p.PrivateKey), nullStr(p.PresharedKey), p.IPv4, nullStr(p.IPv6), p.ClientRoutes, p.DNS, p.Keepalive, p.MTU, boolInt(p.Enabled), nullTime(p.ExpiresAt), p.Notes, p.UpdatedAt.Unix(), nullID(p.OwnerID), p.ID)
	return err
}

// PeerByID loads one peer.
func (s *Store) PeerByID(ctx context.Context, id string) (*Peer, error) {
	return scanPeer(s.db.QueryRowContext(ctx, `SELECT `+peerCols+` FROM peers WHERE id = ?`, id))
}

// ListPeers returns every peer, newest first.
func (s *Store) ListPeers(ctx context.Context) ([]*Peer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+peerCols+` FROM peers ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePeer removes a peer and its traffic history.
func (s *Store) DeletePeer(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, id)
	return err
}

// UsedAddresses returns every tunnel address in use, for allocation.
func (s *Store) UsedAddresses(ctx context.Context) (v4, v6 []string, err error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ipv4, ipv6 FROM peers`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		var b sql.NullString
		if err := rows.Scan(&a, &b); err != nil {
			return nil, nil, err
		}
		v4 = append(v4, a)
		if b.Valid {
			v6 = append(v6, b.String)
		}
	}
	return v4, v6, rows.Err()
}

// PeerCounters is the running total the collector flushes.
type PeerCounters struct {
	ID            string
	RxTotal       int64
	TxTotal       int64
	LastHandshake time.Time
	LastEndpoint  string
}

// TrafficSample is one bucket increment.
type TrafficSample struct {
	PeerID string
	Bucket time.Time
	Rx, Tx int64
}

// FlushCounters writes peer totals and traffic buckets in one transaction.
func (s *Store) FlushCounters(ctx context.Context, counters []PeerCounters, samples []TrafficSample) error {
	if len(counters) == 0 && len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, c := range counters {
		if _, err := tx.ExecContext(ctx, `UPDATE peers SET rx_total=?, tx_total=?, last_handshake=?, last_endpoint=? WHERE id=?`, c.RxTotal, c.TxTotal, nullTime(c.LastHandshake), c.LastEndpoint, c.ID); err != nil {
			return err
		}
	}
	for _, t := range samples {
		if t.Rx == 0 && t.Tx == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic(peer_id, bucket_start, rx, tx) VALUES(?,?,?,?) ON CONFLICT(peer_id, bucket_start) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx`, t.PeerID, t.Bucket.Unix(), t.Rx, t.Tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TrafficPoint is one row of a usage series.
type TrafficPoint struct {
	Bucket time.Time `json:"t"`
	Rx     int64     `json:"rx"`
	Tx     int64     `json:"tx"`
}

// TrafficSeries returns a peer's buckets since a time; peerID "" means all
// peers summed.
func (s *Store) TrafficSeries(ctx context.Context, peerID string, since time.Time) ([]TrafficPoint, error) {
	var rows *sql.Rows
	var err error
	if peerID == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT bucket_start, SUM(rx), SUM(tx) FROM traffic WHERE bucket_start >= ? GROUP BY bucket_start ORDER BY bucket_start`, since.Unix())
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT bucket_start, rx, tx FROM traffic WHERE peer_id = ? AND bucket_start >= ? ORDER BY bucket_start`, peerID, since.Unix())
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPoint
	for rows.Next() {
		var b, rx, tx int64
		if err := rows.Scan(&b, &rx, &tx); err != nil {
			return nil, err
		}
		out = append(out, TrafficPoint{Bucket: time.Unix(b, 0), Rx: rx, Tx: tx})
	}
	return out, rows.Err()
}

// PeerUsage is a per-peer total over a window.
type PeerUsage struct {
	PeerID string `json:"peerId"`
	Rx     int64  `json:"rx"`
	Tx     int64  `json:"tx"`
}

// UsageSince sums traffic per peer since a time.
func (s *Store) UsageSince(ctx context.Context, since time.Time) ([]PeerUsage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, SUM(rx), SUM(tx) FROM traffic WHERE bucket_start >= ? GROUP BY peer_id`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerUsage
	for rows.Next() {
		var u PeerUsage
		if err := rows.Scan(&u.PeerID, &u.Rx, &u.Tx); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PruneTraffic deletes buckets older than the cutoff.
func (s *Store) PruneTraffic(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM traffic WHERE bucket_start < ?`, before.Unix())
	return err
}

// AuditEntry is one administrative action.
type AuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// Audit appends an entry.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit(at, actor, action, target, detail, ip) VALUES(?,?,?,?,?,?)`, e.At.Unix(), e.Actor, e.Action, e.Target, e.Detail, e.IP)
	return err
}

// ListAudit returns the newest entries.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, target, detail, ip FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit keeps the newest n entries.
func (s *Store) PruneAudit(ctx context.Context, keep int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT ?)`, keep)
	return err
}
