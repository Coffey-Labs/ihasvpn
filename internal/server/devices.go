package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
)

// The /api/me/devices endpoints are self-service: anyone signed in sees and
// manages the devices that belong to them, and nothing else. A device that is
// not theirs answers 404, the same as one that does not exist.

// deviceBody is a device as its owner sees it. Routing, DNS and the
// administrator's notes are left out: they are the administrator's business.
type deviceBody struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	IPv4       string      `json:"ipv4"`
	IPv6       string      `json:"ipv6,omitempty"`
	ServerKeys bool        `json:"serverKeys"`
	Enabled    bool        `json:"enabled"`
	Expired    bool        `json:"expired"`
	ExpiresAt  *time.Time  `json:"expiresAt,omitempty"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	Live       engine.Live `json:"live"`
}

func (s *Server) toDeviceBody(p *store.Peer) deviceBody {
	full := s.toPeerBody(p)
	return deviceBody{
		ID: full.ID, Name: full.Name, IPv4: full.IPv4, IPv6: full.IPv6, ServerKeys: full.ServerKeys,
		Enabled: full.Enabled, Expired: full.Expired, ExpiresAt: full.ExpiresAt,
		CreatedAt: full.CreatedAt, UpdatedAt: full.UpdatedAt, Live: full.Live,
	}
}

type myDevicesBody struct {
	Devices []deviceBody `json:"devices"`
	// Limit is how many devices this account may have; null means no limit
	// (administrators).
	Limit *int `json:"limit"`
}

// deviceLimit returns the caller's limit, or -1 for none.
func (s *Server) deviceLimit(u *store.User) int {
	if u.Role == "admin" {
		return -1
	}
	return s.eng.Settings().DeviceLimit
}

func (s *Server) handleMyDevices(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	peers := s.eng.PeersOwnedBy(u.ID)
	out := myDevicesBody{Devices: make([]deviceBody, 0, len(peers))}
	for _, p := range peers {
		out.Devices = append(out.Devices, s.toDeviceBody(p))
	}
	if n := s.deviceLimit(u); n >= 0 {
		out.Limit = &n
	}
	writeJSON(w, http.StatusOK, out)
}

type myDeviceRequest struct {
	Name string `json:"name"`
	// PublicKey, when set, means the device made its own key pair.
	PublicKey string `json:"publicKey,omitempty"`
}

type myDeviceCreated struct {
	deviceBody
	Config string `json:"config"`
}

func (s *Server) handleCreateMyDevice(w http.ResponseWriter, r *http.Request) {
	var req myDeviceRequest
	if !readJSON(w, r, &req) {
		return
	}
	u := userOf(r)
	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()
	switch limit := s.deviceLimit(u); {
	case limit == 0:
		writeError(w, http.StatusForbidden, "on this server an administrator adds devices for you")
		return
	case limit > 0 && len(s.eng.PeersOwnedBy(u.ID)) >= limit:
		writeError(w, http.StatusConflict, fmt.Sprintf("you already have %d device(s), the most this server allows; delete one first", limit))
		return
	}
	// Everything but the name and key comes from the server's defaults: how
	// a device routes and resolves is the administrator's call.
	owner := u.ID
	p, err := s.eng.CreatePeer(r.Context(), engine.PeerInput{Name: req.Name, PublicKey: req.PublicKey, OwnerID: &owner})
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.created", p.Name, fmt.Sprintf("%s %s, own device", p.ID, p.IPv4))
	writeJSON(w, http.StatusCreated, myDeviceCreated{deviceBody: s.toDeviceBody(p), Config: s.eng.ClientConfig(p)})
}

// myDevice loads a device the caller owns, answering 404 otherwise.
func (s *Server) myDevice(w http.ResponseWriter, r *http.Request) (*store.Peer, bool) {
	p, err := s.eng.Peer(r.PathValue("id"))
	if err != nil || p.OwnerID != userOf(r).ID {
		writeError(w, http.StatusNotFound, "no such device")
		return nil, false
	}
	return p, true
}

// turnedOff refuses changes to a device an administrator disabled, so its
// owner cannot get round that by rotating or deleting and starting again.
func (s *Server) turnedOff(w http.ResponseWriter, r *http.Request, p *store.Peer) bool {
	if !p.Enabled && userOf(r).Role != "admin" {
		writeError(w, http.StatusForbidden, "an administrator has turned this device off; ask them about it")
		return true
	}
	return false
}

func (s *Server) handleMyDeviceConfig(w http.ResponseWriter, r *http.Request) {
	p, ok := s.myDevice(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, safeFilename(p.Name)))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.audit(r, "peer.config_viewed", p.Name, p.ID)
	_, _ = w.Write([]byte(s.eng.ClientConfig(p)))
}

func (s *Server) handleMyDeviceQR(w http.ResponseWriter, r *http.Request) {
	p, ok := s.myDevice(w, r)
	if !ok {
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

func (s *Server) handleRotateMyDevice(w http.ResponseWriter, r *http.Request) {
	p, ok := s.myDevice(w, r)
	if !ok || s.turnedOff(w, r, p) {
		return
	}
	p, err := s.eng.RotateKeys(r.Context(), p.ID)
	if err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.keys_rotated", p.Name, p.ID+", own device")
	writeJSON(w, http.StatusOK, myDeviceCreated{deviceBody: s.toDeviceBody(p), Config: s.eng.ClientConfig(p)})
}

func (s *Server) handleDeleteMyDevice(w http.ResponseWriter, r *http.Request) {
	p, ok := s.myDevice(w, r)
	if !ok || s.turnedOff(w, r, p) {
		return
	}
	if err := s.eng.DeletePeer(r.Context(), p.ID); err != nil {
		engineError(w, err)
		return
	}
	s.audit(r, "peer.deleted", p.Name, p.ID+", own device")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
