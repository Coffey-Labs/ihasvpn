package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
)

type healthBody struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthBody{OK: true, Version: engine.Version})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.Status())
}

// peerBody is a peer as the API presents it: never the private or preshared
// key (those only leave through the config and QR endpoints).
type peerBody struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	PublicKey    string     `json:"publicKey"`
	ServerKeys   bool       `json:"serverKeys"`
	PresharedKey bool       `json:"presharedKey"`
	IPv4         string     `json:"ipv4"`
	IPv6         string     `json:"ipv6,omitempty"`
	ClientRoutes string     `json:"clientRoutes"`
	DNS          string     `json:"dns"`
	Keepalive    int        `json:"keepalive"`
	MTU          int        `json:"mtu"`
	Enabled      bool       `json:"enabled"`
	Expired      bool       `json:"expired"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	Notes        string     `json:"notes"`
	OwnerID      int64      `json:"ownerId,omitempty"`
	Owner        string     `json:"owner,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	Live         engine.Live `json:"live"`
}

// ownerNames maps user ids to usernames, for showing who a device belongs to.
func (s *Server) ownerNames(r *http.Request) map[int64]string {
	names := map[int64]string{}
	users, err := s.eng.Store().ListUsers(r.Context())
	if err != nil {
		s.log.Warn("list users", "error", err)
		return names
	}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	return names
}

// toPeerBodyFor is toPeerBody with the owner's name filled in.
func (s *Server) toPeerBodyFor(r *http.Request, p *store.Peer) peerBody {
	b := s.toPeerBody(p)
	if p.OwnerID != 0 {
		b.Owner = s.ownerNames(r)[p.OwnerID]
	}
	return b
}

func (s *Server) toPeerBody(p *store.Peer) peerBody {
	b := peerBody{
		ID: p.ID, Name: p.Name, PublicKey: p.PublicKey, ServerKeys: p.PrivateKey != "", PresharedKey: p.PresharedKey != "",
		IPv4: p.IPv4, IPv6: p.IPv6, ClientRoutes: p.ClientRoutes, DNS: p.DNS, Keepalive: p.Keepalive, MTU: p.MTU,
		Enabled: p.Enabled, Notes: p.Notes, OwnerID: p.OwnerID, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if !p.ExpiresAt.IsZero() {
		t := p.ExpiresAt
		b.ExpiresAt = &t
		b.Expired = time.Now().After(t)
	}
	if l, ok := s.eng.Live(p.ID); ok {
		b.Live = l
	} else {
		b.Live = engine.Live{PeerID: p.ID, Rx: p.RxTotal, Tx: p.TxTotal, LastHandshake: p.LastHandshake, Endpoint: p.LastEndpoint}
	}
	return b
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := s.eng.Peers()
	names := s.ownerNames(r)
	out := make([]peerBody, 0, len(peers))
	for _, p := range peers {
		b := s.toPeerBody(p)
		b.Owner = names[p.OwnerID]
		out = append(out, b)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePeer(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.Peer(r.PathValue("id"))
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.toPeerBodyFor(r, p))
}

type createPeerResponse struct {
	peerBody
	Config string `json:"config"`
}

func (s *Server) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	var in engine.PeerInput
	if !readJSON(w, r, &in) {
		return
	}
	p, err := s.eng.CreatePeer(r.Context(), in)
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.created", p.Name, fmt.Sprintf("%s %s", p.ID, p.IPv4))
	writeJSON(w, http.StatusCreated, createPeerResponse{peerBody: s.toPeerBodyFor(r, p), Config: s.eng.ClientConfig(p)})
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	var in engine.PeerInput
	if !readJSON(w, r, &in) {
		return
	}
	p, err := s.eng.UpdatePeer(r.Context(), r.PathValue("id"), in)
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.updated", p.Name, p.ID)
	writeJSON(w, http.StatusOK, s.toPeerBodyFor(r, p))
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.eng.Peer(id)
	if err != nil {
		engineError(w, err)
		return
	}
	if err := s.eng.DeletePeer(r.Context(), id); err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.deleted", p.Name, id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleEnablePeer(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.SetEnabled(r.Context(), r.PathValue("id"), true)
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.enabled", p.Name, p.ID)
	writeJSON(w, http.StatusOK, s.toPeerBody(p))
}

// handleDisablePeer is "disconnect": the peer leaves the interface and its
// session dies with it.
func (s *Server) handleDisablePeer(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.SetEnabled(r.Context(), r.PathValue("id"), false)
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.disabled", p.Name, p.ID)
	writeJSON(w, http.StatusOK, s.toPeerBody(p))
}

func (s *Server) handleResetPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.eng.Peer(id)
	if err != nil {
		engineError(w, err)
		return
	}
	if err := s.eng.ResetSession(r.Context(), id); err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.session_reset", p.Name, id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRotatePeer(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.RotateKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.keys_rotated", p.Name, p.ID)
	writeJSON(w, http.StatusOK, createPeerResponse{peerBody: s.toPeerBodyFor(r, p), Config: s.eng.ClientConfig(p)})
}

func safeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '.':
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		out = "ihasvpn"
	}
	if len(out) > 15 {
		// wg-quick derives the interface name from the file name and caps it
		// at 15 characters.
		out = out[:15]
	}
	return out
}

func (s *Server) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.Peer(r.PathValue("id"))
	if err != nil {
		engineError(w, err)
		return
	}
	cfg := s.eng.ClientConfig(p)
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, safeFilename(p.Name)))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.audit(r, "peer.config_viewed", p.Name, p.ID)
	_, _ = w.Write([]byte(cfg))
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	p, err := s.eng.Peer(r.PathValue("id"))
	if err != nil {
		engineError(w, err)
		return
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	png, err := s.eng.QRCode(p, size)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func sinceParam(r *http.Request) time.Time {
	switch r.URL.Query().Get("range") {
	case "1h":
		return time.Now().Add(-time.Hour)
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	case "90d":
		return time.Now().Add(-90 * 24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}

func (s *Server) handlePeerUsage(w http.ResponseWriter, r *http.Request) {
	pts, err := s.eng.Usage(r.Context(), r.PathValue("id"), sinceParam(r))
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pts)
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	pts, err := s.eng.Usage(r.Context(), "", sinceParam(r))
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pts)
}

func (s *Server) handleUsageByPeer(w http.ResponseWriter, r *http.Request) {
	u, err := s.eng.UsageByPeer(r.Context(), sinceParam(r))
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in engine.Settings
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.eng.UpdateSettings(r.Context(), in); err != nil {
		if strings.Contains(err.Error(), "firewall") {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "settings.updated", "", "")
	writeJSON(w, http.StatusOK, s.eng.Settings())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	entries, err := s.eng.Store().ListAudit(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleEvents streams status snapshots and change notices as SSE.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Send the current picture at once rather than waiting for the next poll.
	snap := s.eng.Snapshot()
	if !snap.At.IsZero() {
		s.eng.Hub().Publish("status", snap)
	}
	ch, leave := s.eng.Hub().Subscribe()
	defer leave()
	fmt.Fprintf(w, "retry: 3000\n\n")
	flusher.Flush()
	keep := time.NewTicker(25 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case ev := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Name, ev.Data)
			flusher.Flush()
		}
	}
}

// handleMetrics exposes Prometheus metrics, protected by a bearer token or
// an admin session.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	allowed := false
	if s.cfg.MetricsToken != "" {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.MetricsToken)) == 1 {
			allowed = true
		}
	}
	if !allowed {
		if u, sess := s.loadSession(r); u != nil && !sess.TOTPPending && isStaff(u) {
			allowed = true
		}
	}
	if !allowed {
		writeError(w, http.StatusUnauthorized, "metrics require a bearer token or a session")
		return
	}
	snap := s.eng.Snapshot()
	peers := s.eng.Peers()
	names := map[string]string{}
	for _, p := range peers {
		names[p.ID] = p.Name
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP ihasvpn_peers Number of configured peers.\n# TYPE ihasvpn_peers gauge\nihasvpn_peers %d\n", snap.Totals.Peers)
	fmt.Fprintf(&b, "# HELP ihasvpn_peers_connected Peers with a recent handshake.\n# TYPE ihasvpn_peers_connected gauge\nihasvpn_peers_connected %d\n", snap.Totals.Connected)
	fmt.Fprintf(&b, "# HELP ihasvpn_receive_bytes_total Bytes received from peers.\n# TYPE ihasvpn_receive_bytes_total counter\n")
	for id, l := range snap.Peers {
		fmt.Fprintf(&b, "ihasvpn_receive_bytes_total{peer=%q,name=%q} %d\n", id, names[id], l.Rx)
	}
	fmt.Fprintf(&b, "# HELP ihasvpn_transmit_bytes_total Bytes sent to peers.\n# TYPE ihasvpn_transmit_bytes_total counter\n")
	for id, l := range snap.Peers {
		fmt.Fprintf(&b, "ihasvpn_transmit_bytes_total{peer=%q,name=%q} %d\n", id, names[id], l.Tx)
	}
	fmt.Fprintf(&b, "# HELP ihasvpn_peer_connected Whether the peer has a recent handshake.\n# TYPE ihasvpn_peer_connected gauge\n")
	for id, l := range snap.Peers {
		v := 0
		if l.Connected {
			v = 1
		}
		fmt.Fprintf(&b, "ihasvpn_peer_connected{peer=%q,name=%q} %d\n", id, names[id], v)
	}
	fmt.Fprintf(&b, "# HELP ihasvpn_peer_last_handshake_seconds Unix time of the last handshake.\n# TYPE ihasvpn_peer_last_handshake_seconds gauge\n")
	for id, l := range snap.Peers {
		if !l.LastHandshake.IsZero() {
			fmt.Fprintf(&b, "ihasvpn_peer_last_handshake_seconds{peer=%q,name=%q} %d\n", id, names[id], l.LastHandshake.Unix())
		}
	}
	_, _ = w.Write([]byte(b.String()))
}
