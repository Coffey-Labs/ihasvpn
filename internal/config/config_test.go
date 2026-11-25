package config

import (
	"strings"
	"testing"
)

func TestSetupTokenFromEnv(t *testing.T) {
	t.Setenv("IHASVPN_SETUP_TOKEN", "  a-token-long-enough-1234  ")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.SetupToken != "a-token-long-enough-1234" {
		t.Fatalf("SetupToken = %q", c.SetupToken)
	}
}

func TestSetupTokenTooShort(t *testing.T) {
	for _, bad := range []string{"short", "has a space in it 1234"} {
		t.Setenv("IHASVPN_SETUP_TOKEN", bad)
		if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "IHASVPN_SETUP_TOKEN") {
			t.Fatalf("%q: got %v, want an IHASVPN_SETUP_TOKEN error", bad, err)
		}
	}
}
