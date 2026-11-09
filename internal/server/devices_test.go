package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"testing"

	"github.com/Coffey-Labs/ihasvpn/internal/engine"
)

// as returns a second client on the same server with its own cookies.
func (c *client) as(t *testing.T, username, password string) *client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	o := &client{t: t, srv: c.srv, c: &http.Client{Jar: jar}}
	o.expect("POST", "/api/auth/login", map[string]string{"username": username, "password": password}, 200)
	return o
}

func TestOwnDevices(t *testing.T) {
	admin, eng := newClient(t)
	admin.expect("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	out := admin.expect("POST", "/api/users", map[string]string{"username": "sam", "password": "sams-long-password", "role": "user"}, 201)
	var sam struct{ ID int64 }
	_ = json.Unmarshal(out, &sam)
	u := admin.as(t, "sam", "sams-long-password")

	// A user sees nothing of the server.
	for _, p := range []string{"/api/peers", "/api/status", "/api/events", "/api/settings", "/api/users", "/api/audit", "/api/usage"} {
		u.expect("GET", p, nil, 403)
	}
	if res, _ := u.do("GET", "/metrics", nil); res.StatusCode != 401 {
		t.Fatalf("metrics for a user: %d", res.StatusCode)
	}

	out = u.expect("GET", "/api/me/devices", nil, 200)
	if !strings.Contains(string(out), `"devices":[]`) || !strings.Contains(string(out), `"limit":5`) {
		t.Fatal(string(out))
	}
	out = u.expect("POST", "/api/me/devices", map[string]string{"name": "Phone"}, 201)
	var phone struct {
		ID     string
		Config string
	}
	_ = json.Unmarshal(out, &phone)
	if !strings.Contains(phone.Config, "PrivateKey = ") || strings.Contains(string(out), "notes") {
		t.Fatal(string(out))
	}
	// The owner may not set routes or anything else.
	u.expect("POST", "/api/me/devices", map[string]string{"name": "x", "clientRoutes": "10.0.0.0/8"}, 400)
	u.expect("GET", "/api/me/devices/"+phone.ID+"/config", nil, 200)
	if res, b := u.do("GET", "/api/me/devices/"+phone.ID+"/qr.png", nil); res.StatusCode != 200 || !strings.HasPrefix(string(b), "\x89PNG") {
		t.Fatalf("qr: %d", res.StatusCode)
	}

	// The administrator sees whose it is.
	out = admin.expect("GET", "/api/peers/"+phone.ID, nil, 200)
	if !strings.Contains(string(out), `"owner":"sam"`) {
		t.Fatal(string(out))
	}

	// Someone else's device does not exist, as far as a user can tell.
	out = admin.expect("POST", "/api/peers", map[string]any{"name": "Router", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": ""}, 201)
	var router struct{ ID string }
	_ = json.Unmarshal(out, &router)
	for _, m := range [][2]string{{"GET", "/config"}, {"GET", "/qr.png"}, {"POST", "/rotate"}, {"DELETE", ""}} {
		u.expect(m[0], "/api/me/devices/"+router.ID+m[1], nil, 404)
	}

	// The limit holds.
	var s engine.Settings
	_ = json.Unmarshal(admin.expect("GET", "/api/settings", nil, 200), &s)
	s.DeviceLimit = 1
	admin.expect("PUT", "/api/settings", s, 200)
	u.expect("POST", "/api/me/devices", map[string]string{"name": "Laptop"}, 409)

	// A device the administrator turned off stays off.
	admin.expect("POST", "/api/peers/"+phone.ID+"/disable", nil, 200)
	u.expect("POST", "/api/me/devices/"+phone.ID+"/rotate", nil, 403)
	u.expect("DELETE", "/api/me/devices/"+phone.ID, nil, 403)
	admin.expect("POST", "/api/peers/"+phone.ID+"/enable", nil, 200)
	out = u.expect("POST", "/api/me/devices/"+phone.ID+"/rotate", nil, 200)
	if strings.Contains(string(out), phone.Config) {
		t.Fatal("rotation kept the old config")
	}
	u.expect("DELETE", "/api/me/devices/"+phone.ID, nil, 200)

	// Limit 0: only an administrator adds devices.
	s.DeviceLimit = 0
	admin.expect("PUT", "/api/settings", s, 200)
	u.expect("POST", "/api/me/devices", map[string]string{"name": "Laptop"}, 403)

	// An administrator can hand a device over.
	admin.expect("PUT", "/api/peers/"+router.ID, map[string]any{"name": "Router", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": "", "ownerId": 999}, 400)
	admin.expect("PUT", "/api/peers/"+router.ID, map[string]any{"name": "Router", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": "", "ownerId": sam.ID}, 200)
	out = u.expect("GET", "/api/me/devices", nil, 200)
	if !strings.Contains(string(out), router.ID) {
		t.Fatal(string(out))
	}
	// Leaving ownerId out keeps the owner.
	admin.expect("PUT", "/api/peers/"+router.ID, map[string]any{"name": "Router 2", "clientRoutes": "", "dns": "", "keepalive": nil, "mtu": nil, "expiresAt": nil, "notes": ""}, 200)
	if p, _ := eng.Peer(router.ID); p.OwnerID != sam.ID {
		t.Fatalf("owner lost on edit: %d", p.OwnerID)
	}

	// Deleting the user deletes their devices.
	out = admin.expect("GET", "/api/users", nil, 200)
	if !strings.Contains(string(out), `"devices":1`) {
		t.Fatal(string(out))
	}
	admin.expect("DELETE", "/api/users/"+strconv.FormatInt(sam.ID, 10), nil, 200)
	if _, err := eng.Peer(router.ID); err == nil {
		t.Fatal("device outlived its owner")
	}
	u.expect("GET", "/api/me/devices", nil, 401)
}

func TestViewerHasNoDeviceLimitBypass(t *testing.T) {
	admin, _ := newClient(t)
	admin.expect("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-enough-password", "endpointHost": "vpn.test"}, 201)
	admin.expect("POST", "/api/users", map[string]string{"username": "vic", "password": "vics-long-password", "role": "viewer"}, 201)
	var s engine.Settings
	_ = json.Unmarshal(admin.expect("GET", "/api/settings", nil, 200), &s)
	s.DeviceLimit = 0
	admin.expect("PUT", "/api/settings", s, 200)
	v := admin.as(t, "vic", "vics-long-password")
	v.expect("POST", "/api/me/devices", map[string]string{"name": "Phone"}, 403)
	// Administrators are not limited.
	admin.expect("POST", "/api/me/devices", map[string]string{"name": "Phone"}, 201)
	out := admin.expect("GET", "/api/me/devices", nil, 200)
	if !strings.Contains(string(out), `"limit":null`) {
		t.Fatal(string(out))
	}
}

