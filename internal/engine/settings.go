package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Coffey-Labs/ihasvpn/internal/store"
)

// Settings are the administrator-editable server options. They persist in the
// database and can be changed from the UI without restarting the container.
type Settings struct {
	// EndpointHost is the public name or address clients connect to.
	EndpointHost string `json:"endpointHost"`
	// EndpointPort is what clients dial; usually the listen port, but
	// different when the container's UDP port is remapped.
	EndpointPort int `json:"endpointPort"`
	// DNS handed to clients, comma separated. Empty means none.
	DNS string `json:"dns"`
	// ClientRoutes is the default AllowedIPs written into client configs.
	ClientRoutes string `json:"clientRoutes"`
	// MTU for the server interface and, by default, client configs.
	MTU int `json:"mtu"`
	// Keepalive is the default PersistentKeepalive for clients, in seconds.
	Keepalive int `json:"keepalive"`
	// PeerIsolation stops peers reaching one another.
	PeerIsolation bool `json:"peerIsolation"`
	// ClampMSS rewrites TCP MSS on forwarded SYNs to fit the tunnel MTU.
	ClampMSS bool `json:"clampMSS"`
	// PresharedKeys adds a per-peer preshared key to every new peer.
	PresharedKeys bool `json:"presharedKeys"`
	// ConnectedWindow is how many seconds since the last handshake still
	// counts as connected. WireGuard rejects sessions after 180 s.
	ConnectedWindow int `json:"connectedWindow"`
	// DeviceLimit is how many devices a user may add for themselves. 0 means
	// only an administrator adds devices. Administrators are not limited.
	DeviceLimit int `json:"deviceLimit"`
}

// DefaultSettings returns what a fresh install starts with.
func DefaultSettings(endpointHost, dns string, port int) Settings {
	return Settings{
		EndpointHost:    endpointHost,
		EndpointPort:    port,
		DNS:             dns,
		ClientRoutes:    "0.0.0.0/0, ::/0",
		MTU:             1420,
		Keepalive:       25,
		PeerIsolation:   false,
		ClampMSS:        true,
		PresharedKeys:   true,
		ConnectedWindow: 180,
		DeviceLimit:     5,
	}
}

// Validate checks settings coming in from the API.
func (s *Settings) Validate() error {
	var errs []error
	s.EndpointHost = strings.TrimSpace(s.EndpointHost)
	if s.EndpointHost == "" {
		errs = append(errs, errors.New("endpoint host is required"))
	} else if strings.ContainsAny(s.EndpointHost, " /\\:") && !strings.HasPrefix(s.EndpointHost, "[") {
		if _, err := netip.ParseAddr(s.EndpointHost); err != nil {
			errs = append(errs, errors.New("endpoint host must be a hostname or IP address without a port"))
		}
	}
	if s.EndpointPort < 1 || s.EndpointPort > 65535 {
		errs = append(errs, errors.New("endpoint port must be 1-65535"))
	}
	if _, err := ParseDNS(s.DNS); err != nil {
		errs = append(errs, err)
	}
	if _, err := ParsePrefixes(s.ClientRoutes); err != nil {
		errs = append(errs, fmt.Errorf("client routes: %w", err))
	}
	if s.MTU < 1280 || s.MTU > 9000 {
		errs = append(errs, errors.New("MTU must be between 1280 and 9000"))
	}
	if s.Keepalive < 0 || s.Keepalive > 65535 {
		errs = append(errs, errors.New("keepalive must be 0-65535 seconds"))
	}
	if s.ConnectedWindow < 30 || s.ConnectedWindow > 3600 {
		errs = append(errs, errors.New("connected window must be 30-3600 seconds"))
	}
	if s.DeviceLimit < 0 || s.DeviceLimit > 1000 {
		errs = append(errs, errors.New("device limit must be 0-1000"))
	}
	return errors.Join(errs...)
}

// ParseDNS validates a comma-separated list of resolvers (addresses, or a
// search domain which WireGuard clients also accept in the DNS field).
func ParseDNS(s string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParseAddr(part); err != nil {
			// Allow search domains: letters, digits, dots and dashes only.
			for _, r := range part {
				if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					return nil, fmt.Errorf("DNS entry %q is neither an address nor a domain", part)
				}
			}
		}
		out = append(out, part)
	}
	return out, nil
}

// ParsePrefixes parses a comma-separated CIDR list; bare addresses become
// host prefixes.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			a, err2 := netip.ParseAddr(part)
			if err2 != nil {
				return nil, fmt.Errorf("%q is not a CIDR", part)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("at least one route is required")
	}
	return out, nil
}

// JoinPrefixes renders prefixes the way a WireGuard config expects.
func JoinPrefixes(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

const settingsKey = "server"

func loadSettings(ctx context.Context, st *store.Store) (*Settings, bool, error) {
	raw, err := st.GetSetting(ctx, settingsKey)
	if err != nil {
		return nil, false, err
	}
	if raw == "" {
		return nil, false, nil
	}
	// Start from the defaults so a setting added after this row was saved
	// gets its default rather than zero.
	s := DefaultSettings("", "", 0)
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, false, fmt.Errorf("settings are corrupt: %w", err)
	}
	return &s, true, nil
}

func saveSettings(ctx context.Context, st *store.Store, s *Settings) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, settingsKey, string(raw))
}
