// Command ihasvpn runs the WireGuard server and its admin UI.
//
//	ihasvpn                    run the server (the container's default)
//	ihasvpn reset-password U   set a new password for admin user U and drop
//	                       their sessions and second factor; for lockouts
//	ihasvpn version            print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Coffey-Labs/ihasvpn/internal/auth"
	"github.com/Coffey-Labs/ihasvpn/internal/config"
	"github.com/Coffey-Labs/ihasvpn/internal/engine"
	"github.com/Coffey-Labs/ihasvpn/internal/server"
	"github.com/Coffey-Labs/ihasvpn/internal/store"
	"github.com/Coffey-Labs/ihasvpn/internal/wg"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println("ihasvpn", engine.Version)
			return
		case "reset-password":
			if err := resetPassword(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "serve", "run":
		case "help", "--help", "-h":
			fmt.Print(usage)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n%s", os.Args[1], usage)
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ihasvpn:", err)
		os.Exit(1)
	}
}

const usage = `usage: ihasvpn [serve | reset-password <user> | version]

Configuration is read from IHASVPN_* environment variables; see the README.
`

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogJSON {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func openBackend(cfg *config.Config, log *slog.Logger) (wg.Backend, error) {
	switch cfg.Backend {
	case "mock":
		log.Warn("using the mock data plane: no real tunnel will be created")
		return wg.NewMock(cfg.Iface, true), nil
	case "kernel":
		return wg.NewKernel(cfg.Iface, log)
	case "userspace":
		return wg.NewUserspace(cfg.Iface, log)
	}
	if wg.KernelAvailable() {
		return wg.NewKernel(cfg.Iface, log)
	}
	log.Warn("the kernel has no WireGuard support; falling back to wireguard-go, which is slower. Load the wireguard module on the host for full speed.")
	return wg.NewUserspace(cfg.Iface, log)
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	log.Info("starting ihasvpn", "version", engine.Version)
	if cfg.OIDCEnabled() {
		log.Info("sign-in through an OpenID provider is on", "issuer", cfg.OIDCIssuer, "redirect", cfg.OIDCRedirectURL(), "emailDomains", strings.Join(cfg.OIDCEmailDomains, ","))
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	be, err := openBackend(cfg, log)
	if err != nil {
		return err
	}
	eng := engine.New(cfg, st, be, log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := eng.Start(ctx); err != nil {
		_ = eng.Stop(context.Background())
		return err
	}
	srv := server.New(cfg, eng, log)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-serveErr:
		if err != nil {
			log.Error("admin server failed", "error", err)
		}
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Stop(shutdown); err != nil {
		log.Warn("shutdown", "error", err)
	}
	return nil
}

// resetPassword is the way back in when every administrator is locked out.
// It runs inside the container against the same database.
func resetPassword(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ihasvpn reset-password <username>")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	u, err := st.UserByName(ctx, args[0])
	if err != nil {
		return fmt.Errorf("no user named %q", args[0])
	}
	if u.OIDC() {
		return fmt.Errorf("%s signs in through an OpenID provider and has no password here; sign in with a local administrator instead", u.Username)
	}
	var pw string
	if v := os.Getenv("IHASVPN_NEW_PASSWORD"); v != "" {
		pw = v
	} else {
		fmt.Fprint(os.Stderr, "New password: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pw = strings.TrimSpace(string(b))
	}
	if err := auth.ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := st.SetPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := st.SetTOTP(ctx, u.ID, "", false); err != nil {
		return err
	}
	_ = st.ReplaceRecoveryCodes(ctx, u.ID, nil)
	_ = st.DeleteUserSessions(ctx, u.ID)
	_ = st.Audit(ctx, store.AuditEntry{Actor: "cli", Action: "password.reset", Target: u.Username, Detail: "two-factor cleared, sessions dropped"})
	fmt.Fprintf(os.Stderr, "password for %s reset; two-factor cleared and sessions dropped\n", u.Username)
	return nil
}
