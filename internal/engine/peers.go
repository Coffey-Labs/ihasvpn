package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
	"github.com/Coffey-Labs/ihasvpn/internal/wg"
)

// PeerInput is what the API accepts when creating or editing a peer.
type PeerInput struct {
	Name string `json:"name"`
	// PublicKey, when set on create, means the client generated its own key
	// pair and the server never sees the private key.
	PublicKey string `json:"publicKey,omitempty"`
	// IPv4 / IPv6 may pin addresses; empty means allocate.
	IPv4         string `json:"ipv4,omitempty"`
	IPv6         string `json:"ipv6,omitempty"`
	ClientRoutes string `json:"clientRoutes"`
	DNS          string `json:"dns"`
	Keepalive    *int   `json:"keepalive"`
	MTU          *int   `json:"mtu"`
	Enabled      *bool  `json:"enabled"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	Notes        string `json:"notes"`
	// OwnerID hands the device to a user. Absent leaves it as it is; 0 means
	// it belongs to nobody in particular.
	OwnerID *int64 `json:"ownerId,omitempty"`
}

// ErrValidation marks user errors so the API can answer 400.
type ErrValidation struct{ Msg string }

func (e ErrValidation) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return ErrValidation{Msg: fmt.Sprintf(format, a...)} }

// ErrNotFound is returned for unknown peer ids.
var ErrNotFound = store.ErrNotFound

// Peer returns a copy of one peer.
func (e *Engine) Peer(id string) (*store.Peer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.peers[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

// Peers returns copies of every peer, newest first.
func (e *Engine) Peers() []*store.Peer {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*store.Peer, 0, len(e.peers))
	for _, p := range e.peers {
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// PeersOwnedBy returns copies of a user's devices, newest first.
func (e *Engine) PeersOwnedBy(userID int64) []*store.Peer {
	var out []*store.Peer
	for _, p := range e.Peers() {
		if p.OwnerID == userID {
			out = append(out, p)
		}
	}
	return out
}

// DeletePeersOwnedBy removes every device a user has, for when the user is
// deleted: their devices must stop working with them. It returns how many
// went.
func (e *Engine) DeletePeersOwnedBy(ctx context.Context, userID int64) (int, error) {
	n := 0
	for _, p := range e.PeersOwnedBy(userID) {
		if err := e.DeletePeer(ctx, p.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// checkOwner resolves an owner from the API: nil keeps cur, 0 clears it, and
// anything else must be an existing user.
func (e *Engine) checkOwner(ctx context.Context, in *int64, cur int64) (int64, error) {
	if in == nil {
		return cur, nil
	}
	if *in == 0 {
		return 0, nil
	}
	if _, err := e.st.UserByID(ctx, *in); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, invalid("owner: no such user")
		}
		return 0, err
	}
	return *in, nil
}

// Live returns the live state for a peer.
func (e *Engine) Live(id string) (Live, bool) { return e.col.LiveFor(id) }

// Snapshot returns the last poll.
func (e *Engine) Snapshot() Snapshot { return e.col.Snapshot() }

func (e *Engine) usedAddresses() (v4, v6 map[string]bool) {
	v4, v6 = map[string]bool{}, map[string]bool{}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range e.peers {
		v4[p.IPv4] = true
		if p.IPv6 != "" {
			v6[p.IPv6] = true
		}
	}
	return
}

func validateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", invalid("name is required")
	}
	if len(name) > 64 {
		return "", invalid("name must be 64 characters or fewer")
	}
	return name, nil
}

// CreatePeer allocates addresses, generates keys and adds the peer to the
// interface. The returned peer includes the private key when the server
// generated it.
func (e *Engine) CreatePeer(ctx context.Context, in PeerInput) (*store.Peer, error) {
	name, err := validateName(in.Name)
	if err != nil {
		return nil, err
	}
	settings := e.Settings()
	p := &store.Peer{Name: name, Enabled: true, Notes: strings.TrimSpace(in.Notes)}
	if p.ID, err = auth.NewID(); err != nil {
		return nil, err
	}
	if in.PublicKey != "" {
		pub, err := wg.ParseKey(strings.TrimSpace(in.PublicKey))
		if err != nil {
			return nil, invalid("public key: %v", err)
		}
		p.PublicKey = pub.String()
	} else {
		priv, err := wg.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		p.PrivateKey = priv.String()
		p.PublicKey = priv.PublicKey().String()
	}
	if p.PublicKey == e.ServerPublicKey() {
		return nil, invalid("that is the server's own public key")
	}
	e.mu.RLock()
	_, dup := e.byKey[p.PublicKey]
	e.mu.RUnlock()
	if dup {
		return nil, invalid("a peer with that public key already exists")
	}
	if settings.PresharedKeys {
		psk, err := wg.GeneratePresharedKey()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk.String()
	}
	used4, used6 := e.usedAddresses()
	var a4 netip.Addr
	if in.IPv4 != "" {
		if a4, err = checkAddress(e.cfg.Subnet4, in.IPv4, used4); err != nil {
			return nil, invalid("IPv4: %v", err)
		}
	} else if a4, err = allocate(e.cfg.Subnet4, used4); err != nil {
		return nil, invalid("%v", err)
	}
	p.IPv4 = a4.String()
	if e.cfg.Subnet6.IsValid() {
		var a6 netip.Addr
		if in.IPv6 != "" {
			if a6, err = checkAddress(e.cfg.Subnet6, in.IPv6, used6); err != nil {
				return nil, invalid("IPv6: %v", err)
			}
		} else if a6, err = allocate(e.cfg.Subnet6, used6); err != nil {
			return nil, invalid("%v", err)
		}
		p.IPv6 = a6.String()
	} else if in.IPv6 != "" {
		return nil, invalid("IPv6 is not enabled on this server (set IHASVPN_SUBNET6)")
	}
	if err := applyEditable(p, in, settings); err != nil {
		return nil, err
	}
	if p.OwnerID, err = e.checkOwner(ctx, in.OwnerID, 0); err != nil {
		return nil, err
	}
	if err := e.st.CreatePeer(ctx, p); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.peers[p.ID] = p
	e.byKey[p.PublicKey] = p
	e.mu.Unlock()
	if err := e.applyPeer(ctx, p); err != nil {
		e.log.Error("apply new peer", "peer", p.ID, "error", err)
	}
	e.hub.Publish("peers", "changed")
	cp := *p
	return &cp, nil
}

// applyEditable copies the fields that may change after creation.
func applyEditable(p *store.Peer, in PeerInput, settings Settings) error {
	routes := strings.TrimSpace(in.ClientRoutes)
	if routes == "" {
		routes = settings.ClientRoutes
	}
	ps, err := ParsePrefixes(routes)
	if err != nil {
		return invalid("client routes: %v", err)
	}
	p.ClientRoutes = JoinPrefixes(ps)
	if _, err := ParseDNS(in.DNS); err != nil {
		return invalid("%v", err)
	}
	p.DNS = strings.TrimSpace(in.DNS)
	if in.Keepalive != nil {
		if *in.Keepalive < 0 || *in.Keepalive > 65535 {
			return invalid("keepalive must be 0-65535 seconds")
		}
		p.Keepalive = *in.Keepalive
	}
	if in.MTU != nil {
		if *in.MTU != 0 && (*in.MTU < 1280 || *in.MTU > 9000) {
			return invalid("MTU must be 0 (server default) or 1280-9000")
		}
		p.MTU = *in.MTU
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.ExpiresAt != nil {
		p.ExpiresAt = in.ExpiresAt.UTC()
		if p.ExpiresAt.Unix() <= 0 {
			p.ExpiresAt = time.Time{}
		}
	}
	p.Notes = strings.TrimSpace(in.Notes)
	if len(p.Notes) > 2000 {
		return invalid("notes must be 2000 characters or fewer")
	}
	return nil
}

// UpdatePeer edits a peer. Keys and addresses do not change here.
func (e *Engine) UpdatePeer(ctx context.Context, id string, in PeerInput) (*store.Peer, error) {
	e.mu.RLock()
	cur, ok := e.peers[id]
	e.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	p := *cur
	name, err := validateName(in.Name)
	if err != nil {
		return nil, err
	}
	p.Name = name
	if err := applyEditable(&p, in, e.Settings()); err != nil {
		return nil, err
	}
	if p.OwnerID, err = e.checkOwner(ctx, in.OwnerID, p.OwnerID); err != nil {
		return nil, err
	}
	if err := e.st.UpdatePeer(ctx, &p); err != nil {
		return nil, err
	}
	e.mu.Lock()
	*cur = p
	e.mu.Unlock()
	if err := e.applyPeer(ctx, cur); err != nil {
		e.log.Error("apply peer", "peer", id, "error", err)
	}
	e.hub.Publish("peers", "changed")
	return &p, nil
}

// SetEnabled turns a peer on or off. Off removes it from the interface at
// once, which drops any session it has: this is "disconnect".
func (e *Engine) SetEnabled(ctx context.Context, id string, enabled bool) (*store.Peer, error) {
	e.mu.RLock()
	cur, ok := e.peers[id]
	e.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	p := *cur
	p.Enabled = enabled
	if err := e.st.UpdatePeer(ctx, &p); err != nil {
		return nil, err
	}
	e.mu.Lock()
	*cur = p
	e.mu.Unlock()
	if err := e.applyPeer(ctx, cur); err != nil {
		return nil, err
	}
	e.hub.Publish("peers", "changed")
	return &p, nil
}

// ResetSession drops a peer's current session without disabling it. The
// client will handshake again on its next packet.
func (e *Engine) ResetSession(ctx context.Context, id string) error {
	e.mu.RLock()
	cur, ok := e.peers[id]
	e.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	pub, err := wg.ParseKey(cur.PublicKey)
	if err != nil {
		return err
	}
	if err := e.be.RemovePeer(ctx, pub); err != nil {
		return err
	}
	e.col.rekey(cur.PublicKey)
	return e.applyPeer(ctx, cur)
}

// RotateKeys gives a server-managed peer a new key pair (and preshared key).
// The old configuration stops working immediately.
func (e *Engine) RotateKeys(ctx context.Context, id string) (*store.Peer, error) {
	e.mu.RLock()
	cur, ok := e.peers[id]
	e.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if cur.PrivateKey == "" {
		return nil, invalid("this peer's keys are managed by the client; create a new peer instead")
	}
	priv, err := wg.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	p := *cur
	oldKey := p.PublicKey
	p.PrivateKey = priv.String()
	p.PublicKey = priv.PublicKey().String()
	if e.Settings().PresharedKeys {
		psk, err := wg.GeneratePresharedKey()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk.String()
	} else {
		p.PresharedKey = ""
	}
	if err := e.st.UpdatePeer(ctx, &p); err != nil {
		return nil, err
	}
	if old, err := wg.ParseKey(oldKey); err == nil {
		_ = e.be.RemovePeer(ctx, old)
	}
	e.col.rekey(oldKey)
	e.mu.Lock()
	delete(e.byKey, oldKey)
	*cur = p
	e.byKey[p.PublicKey] = cur
	e.mu.Unlock()
	if err := e.applyPeer(ctx, cur); err != nil {
		e.log.Error("apply rotated peer", "peer", id, "error", err)
	}
	e.hub.Publish("peers", "changed")
	return &p, nil
}

// DeletePeer removes a peer for good.
func (e *Engine) DeletePeer(ctx context.Context, id string) error {
	e.mu.RLock()
	cur, ok := e.peers[id]
	e.mu.RUnlock()
	if !ok {
		return ErrNotFound
	}
	if pub, err := wg.ParseKey(cur.PublicKey); err == nil {
		if err := e.be.RemovePeer(ctx, pub); err != nil {
			e.log.Warn("remove peer from interface", "peer", id, "error", err)
		}
	}
	if err := e.st.DeletePeer(ctx, id); err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.peers, id)
	delete(e.byKey, cur.PublicKey)
	e.mu.Unlock()
	e.col.forget(id, cur.PublicKey)
	e.hub.Publish("peers", "changed")
	return nil
}

// applyPeer adds or removes one peer on the interface according to whether
// it should be active.
func (e *Engine) applyPeer(ctx context.Context, p *store.Peer) error {
	pc, err := e.peerConfig(p)
	if err != nil {
		return err
	}
	if active(p, time.Now()) {
		return e.be.SetPeer(ctx, pc)
	}
	return e.be.RemovePeer(ctx, pc.PublicKey)
}

// ClientConfig renders the WireGuard configuration file for a peer. When the
// client holds its own private key the placeholder is left for them.
func (e *Engine) ClientConfig(p *store.Peer) string {
	s := e.Settings()
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if p.PrivateKey != "" {
		fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
	} else {
		b.WriteString("PrivateKey = <your private key>\n")
	}
	addrs := []string{fmt.Sprintf("%s/%d", p.IPv4, e.cfg.Subnet4.Bits())}
	if p.IPv6 != "" && e.cfg.Subnet6.IsValid() {
		addrs = append(addrs, fmt.Sprintf("%s/%d", p.IPv6, e.cfg.Subnet6.Bits()))
	}
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	dns := p.DNS
	if dns == "" {
		dns = s.DNS
	}
	if d, _ := ParseDNS(dns); len(d) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(d, ", "))
	}
	mtu := p.MTU
	if mtu == 0 {
		mtu = s.MTU
	}
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", e.ServerPublicKey())
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", p.ClientRoutes)
	fmt.Fprintf(&b, "Endpoint = %s\n", net.JoinHostPort(s.EndpointHost, strconv.Itoa(s.EndpointPort)))
	ka := p.Keepalive
	if ka == 0 {
		ka = s.Keepalive
	}
	if ka > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	}
	return b.String()
}

// QRCode renders the client configuration as a PNG.
func (e *Engine) QRCode(p *store.Peer, size int) ([]byte, error) {
	if p.PrivateKey == "" {
		return nil, errors.New("no QR code: the private key is held by the client")
	}
	if size < 128 || size > 1024 {
		size = 384
	}
	return qrcode.Encode(e.ClientConfig(p), qrcode.Medium, size)
}

// Usage returns a peer's traffic series since a time.
func (e *Engine) Usage(ctx context.Context, peerID string, since time.Time) ([]store.TrafficPoint, error) {
	if peerID != "" {
		if _, err := e.Peer(peerID); err != nil {
			return nil, err
		}
	}
	// Pending buckets are flushed first so the last few minutes show.
	if err := e.col.flush(ctx); err != nil {
		return nil, err
	}
	pts, err := e.st.TrafficSeries(ctx, peerID, since)
	if err != nil {
		return nil, err
	}
	if pts == nil {
		pts = []store.TrafficPoint{}
	}
	return pts, nil
}

// UsageByPeer sums traffic per peer since a time.
func (e *Engine) UsageByPeer(ctx context.Context, since time.Time) ([]store.PeerUsage, error) {
	if err := e.col.flush(ctx); err != nil {
		return nil, err
	}
	u, err := e.st.UsageSince(ctx, since)
	if err != nil {
		return nil, err
	}
	if u == nil {
		u = []store.PeerUsage{}
	}
	return u, nil
}
