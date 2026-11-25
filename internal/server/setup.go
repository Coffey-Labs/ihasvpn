package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// First-run setup needs a token, so that whoever reaches a fresh console
// first cannot make themselves its administrator. The token comes from
// IHASVPN_SETUP_TOKEN or is made up at start; either way it is kept in memory
// only and written to the log, which only the person running the server can
// read. It stops working once the first administrator exists.

// prepareSetup makes the token if no user exists yet.
func (s *Server) prepareSetup(ctx context.Context) {
	n, err := s.eng.Store().CountUsers(ctx)
	if err != nil || n > 0 {
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	s.ensureSetupTokenLocked()
}

// ensureSetupTokenLocked makes and logs a token if there is none. setupMu
// must be held.
func (s *Server) ensureSetupTokenLocked() {
	if s.setupToken != "" {
		return
	}
	if s.cfg.SetupToken != "" {
		s.setupToken = s.cfg.SetupToken
		s.log.Info("first-run setup: no administrator yet; open the console and enter the token from IHASVPN_SETUP_TOKEN to create one")
		return
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("ihasvpn: no randomness for the setup token: " + err.Error())
	}
	s.setupToken = base64.RawURLEncoding.EncodeToString(b)
	if u := strings.TrimRight(s.cfg.PublicURL, "/"); u != "" {
		s.log.Info("first-run setup: no administrator yet; open this address to create one", "url", u+"/?token="+s.setupToken)
		return
	}
	s.log.Info("first-run setup: no administrator yet; open the console and enter this setup token to create one", "token", s.setupToken)
}

// setupTokenOK reports whether token is the current setup token. setupMu
// must be held.
func (s *Server) setupTokenOK(token string) bool {
	return s.setupToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.setupToken)) == 1
}
