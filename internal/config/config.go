// Package config reads the environment. Everything here is infrastructure
// that has to be known before the database opens; anything an administrator
// might change while the server runs lives in the database instead (see
// engine.Settings).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Coffey-Labs/ihasvpn/internal/oidc"
)

// Config is the process configuration.
type Config struct {
	DataDir  string
	DBPath   string
	Backend  string // auto | kernel | userspace | mock
	Iface    string
	// Listen is the UDP port WireGuard listens on.
	ListenPort int
	// Subnet4 / Subnet6 are the tunnel networks. The server takes the first
	// usable address of each.
	Subnet4 netip.Prefix
	Subnet6 netip.Prefix // may be invalid (unset)
	// Egress is the interface to masquerade on; empty means auto-detect.
	Egress string
	// HTTP is the admin listener address.
	HTTP string
	// TLSCert/TLSKey enable HTTPS from files; TLSSelfSigned generates and
	// persists a certificate in the data directory.
	TLSCert, TLSKey string
	TLSSelfSigned   bool
	// SecureCookies forces the Secure flag on when TLS terminates elsewhere.
	SecureCookies bool
	// TrustedProxies are CIDRs whose X-Forwarded-For / X-Real-IP is believed.
	TrustedProxies []netip.Prefix
	// MetricsToken protects /metrics; empty disables the endpoint.
	MetricsToken string
	// SessionIdle / SessionMax bound admin sessions.
	SessionIdle time.Duration
	SessionMax  time.Duration
	// TrafficRetention bounds the usage history.
	TrafficRetention time.Duration
	// PollInterval is how often the data plane is read.
	PollInterval time.Duration
	// LogLevel is debug, info, warn or error.
	LogLevel string
	// LogJSON switches the log format.
	LogJSON bool
	// Initial* seed the settings on first run only.
	InitialEndpoint string
	InitialDNS      string
	// ManageFirewall may be turned off when the host owns the NAT rules.
	ManageFirewall bool
	// ManageSysctl may be turned off when the host has already tuned itself.
	ManageSysctl bool
	// PublicURL is where people reach the console, e.g.
	// https://vpn.example.org. Sign-in through a provider needs it to build
	// the address the provider sends people back to.
	PublicURL string
	// OIDC* turn on sign-in through an OpenID Connect provider. All three of
	// issuer, client ID and secret, or none.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	// OIDCName labels the sign-in button.
	OIDCName string
	// OIDCEmailDomains, when set, admits only people whose email is in one
	// of these domains.
	OIDCEmailDomains []string
}

// OIDCEnabled reports whether sign-in through a provider is configured.
func (c *Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }

// OIDCRedirectURL is the callback the provider must have registered.
func (c *Config) OIDCRedirectURL() string {
	return strings.TrimSuffix(c.PublicURL, "/") + "/api/auth/oidc/callback"
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", key, v)
	}
	return n, nil
}

func envBool(key string, def bool) (bool, error) {
	v := strings.ToLower(env(key, ""))
	switch v {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s: %q is not a boolean", key, v)
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration (try 12h, 30m)", key, v)
	}
	return d, nil
}

// FromEnv builds the configuration from IHASVPN_* variables.
func FromEnv() (*Config, error) {
	var errs []error
	c := &Config{}
	c.DataDir = env("IHASVPN_DATA_DIR", "/data")
	c.DBPath = env("IHASVPN_DB", c.DataDir+"/ihasvpn.db")
	c.Backend = strings.ToLower(env("IHASVPN_BACKEND", "auto"))
	switch c.Backend {
	case "auto", "kernel", "userspace", "mock":
	default:
		errs = append(errs, fmt.Errorf("IHASVPN_BACKEND: %q is not auto, kernel, userspace or mock", c.Backend))
	}
	c.Iface = env("IHASVPN_INTERFACE", "wg0")
	if len(c.Iface) == 0 || len(c.Iface) > 15 || strings.ContainsAny(c.Iface, " /\t\n") {
		errs = append(errs, errors.New("IHASVPN_INTERFACE: must be 1-15 characters with no spaces or slashes"))
	}
	var err error
	if c.ListenPort, err = envInt("IHASVPN_PORT", 51820); err != nil {
		errs = append(errs, err)
	} else if c.ListenPort < 1 || c.ListenPort > 65535 {
		errs = append(errs, errors.New("IHASVPN_PORT: must be 1-65535"))
	}
	if c.Subnet4, err = netip.ParsePrefix(env("IHASVPN_SUBNET", "10.8.0.0/24")); err != nil || !c.Subnet4.Addr().Is4() {
		errs = append(errs, errors.New("IHASVPN_SUBNET: must be an IPv4 CIDR such as 10.8.0.0/24"))
	} else if c.Subnet4.Bits() > 30 {
		errs = append(errs, errors.New("IHASVPN_SUBNET: needs room for at least two hosts (/30 or larger)"))
	}
	if v := env("IHASVPN_SUBNET6", ""); v != "" {
		if c.Subnet6, err = netip.ParsePrefix(v); err != nil || !c.Subnet6.Addr().Is6() {
			errs = append(errs, errors.New("IHASVPN_SUBNET6: must be an IPv6 CIDR such as fd42:42:42::/64"))
		}
	}
	c.Egress = env("IHASVPN_EGRESS_INTERFACE", "")
	c.HTTP = env("IHASVPN_HTTP_LISTEN", ":51821")
	c.TLSCert = env("IHASVPN_TLS_CERT", "")
	c.TLSKey = env("IHASVPN_TLS_KEY", "")
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, errors.New("IHASVPN_TLS_CERT and IHASVPN_TLS_KEY must be set together"))
	}
	if c.TLSSelfSigned, err = envBool("IHASVPN_TLS_SELF_SIGNED", false); err != nil {
		errs = append(errs, err)
	}
	if c.SecureCookies, err = envBool("IHASVPN_SECURE_COOKIES", false); err != nil {
		errs = append(errs, err)
	}
	for _, p := range strings.Split(env("IHASVPN_TRUSTED_PROXIES", ""), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			if a, err2 := netip.ParseAddr(p); err2 == nil {
				pfx = netip.PrefixFrom(a, a.BitLen())
			} else {
				errs = append(errs, fmt.Errorf("IHASVPN_TRUSTED_PROXIES: %q is not an address or CIDR", p))
				continue
			}
		}
		c.TrustedProxies = append(c.TrustedProxies, pfx)
	}
	c.MetricsToken = env("IHASVPN_METRICS_TOKEN", "")
	if c.SessionIdle, err = envDuration("IHASVPN_SESSION_IDLE", 12*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if c.SessionMax, err = envDuration("IHASVPN_SESSION_MAX", 7*24*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if c.TrafficRetention, err = envDuration("IHASVPN_TRAFFIC_RETENTION", 90*24*time.Hour); err != nil {
		errs = append(errs, err)
	}
	if c.PollInterval, err = envDuration("IHASVPN_POLL_INTERVAL", 2*time.Second); err != nil {
		errs = append(errs, err)
	} else if c.PollInterval < 500*time.Millisecond {
		errs = append(errs, errors.New("IHASVPN_POLL_INTERVAL: must be at least 500ms"))
	}
	c.LogLevel = strings.ToLower(env("IHASVPN_LOG_LEVEL", "info"))
	if c.LogJSON, err = envBool("IHASVPN_LOG_JSON", false); err != nil {
		errs = append(errs, err)
	}
	c.InitialEndpoint = env("IHASVPN_ENDPOINT", "")
	c.InitialDNS = env("IHASVPN_DNS", "1.1.1.1, 1.0.0.1")
	if c.ManageFirewall, err = envBool("IHASVPN_MANAGE_FIREWALL", true); err != nil {
		errs = append(errs, err)
	}
	if c.ManageSysctl, err = envBool("IHASVPN_MANAGE_SYSCTL", true); err != nil {
		errs = append(errs, err)
	}
	c.PublicURL = env("IHASVPN_PUBLIC_URL", "")
	c.OIDCIssuer = env("IHASVPN_OIDC_ISSUER", "")
	c.OIDCClientID = env("IHASVPN_OIDC_CLIENT_ID", "")
	c.OIDCClientSecret = env("IHASVPN_OIDC_CLIENT_SECRET", "")
	c.OIDCName = env("IHASVPN_OIDC_NAME", "single sign-on")
	for _, d := range strings.Split(env("IHASVPN_OIDC_EMAIL_DOMAINS", ""), ",") {
		if d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@")); d != "" {
			c.OIDCEmailDomains = append(c.OIDCEmailDomains, d)
		}
	}
	if set := btoi(c.OIDCIssuer != "") + btoi(c.OIDCClientID != "") + btoi(c.OIDCClientSecret != ""); set != 0 && set != 3 {
		errs = append(errs, errors.New("IHASVPN_OIDC_ISSUER, IHASVPN_OIDC_CLIENT_ID and IHASVPN_OIDC_CLIENT_SECRET must be set together"))
	} else if set == 3 {
		if !oidc.SecureURL(c.OIDCIssuer) {
			errs = append(errs, errors.New("IHASVPN_OIDC_ISSUER: must be an https URL"))
		}
		if !oidc.SecureURL(c.PublicURL) {
			errs = append(errs, errors.New("IHASVPN_PUBLIC_URL: sign-in through a provider needs the console's https address, such as https://vpn.example.org"))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// TLSEnabled reports whether the admin listener speaks HTTPS itself.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" || c.TLSSelfSigned }

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

