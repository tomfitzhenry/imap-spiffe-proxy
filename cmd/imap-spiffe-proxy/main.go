// Command imap-spiffe-proxy terminates SPIFFE mTLS in front of one shared
// upstream IMAP account, enforces an exact SPIFFE-ID allowlist, and injects the
// account password (read from a systemd LoadCredential) on LOGIN.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/tomfitzhenry/imap-spiffe-proxy/internal/proxy"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "imap-spiffe-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen      = flag.String("listen", ":1430", "TCP address for the SPIFFE mTLS listener")
		upstream    = flag.String("upstream", "", "upstream IMAP server host:port (always reached over implicit TLS)")
		upstreamSNI = flag.String("upstream-server-name", "", "upstream TLS server name (default: host part of -upstream)")
		username    = flag.String("username", "", "the one shared upstream IMAP username")
		readWrite   multiFlag
		readOnly    multiFlag
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&readWrite, "rw", "exact client SPIFFE ID allowed to issue any IMAP command (repeatable)")
	flag.Var(&readOnly, "ro", "exact client SPIFFE ID restricted to non-mutating IMAP commands (repeatable)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("imap-spiffe-proxy %s\n", version)
		return nil
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if *upstream == "" {
		return errors.New("-upstream is required")
	}
	if *username == "" {
		return errors.New("-username is required")
	}
	if len(readWrite) == 0 && len(readOnly) == 0 {
		return errors.New("at least one -rw or -ro SPIFFE ID is required")
	}

	password, err := proxy.LoadPassword()
	if err != nil {
		return fmt.Errorf("load IMAP password: %w", err)
	}
	cfg := proxy.Config{
		ListenAddress:         *listen,
		UpstreamAddress:       *upstream,
		UpstreamTLSServerName: *upstreamSNI,
		Username:              *username,
		ReadWriteIdentities:   readWrite,
		ReadOnlyIdentities:    readOnly,
		Password:              password,
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	source, err := workloadapi.NewX509Source(srcCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("create SPIFFE X509 source (is SPIFFE_ENDPOINT_SOCKET set to the agent Workload API socket?): %w", err)
	}
	defer source.Close()

	srv, err := proxy.New(cfg, source, logger)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddress, err)
	}
	logger.Info("imap-spiffe-proxy listening",
		"address", cfg.ListenAddress,
		"upstream", cfg.UpstreamAddress,
		"upstream_tls_server_name", cfg.UpstreamTLSServerName,
		"imap_username", cfg.Username,
		"read_write_identities", len(cfg.ReadWriteIdentities),
		"read_only_identities", len(cfg.ReadOnlyIdentities),
		"imap_password_source", "systemd LoadCredential",
	)
	if err := srv.Serve(ctx, ln); err != nil {
		return err
	}
	logger.Info("imap-spiffe-proxy stopped")
	return nil
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint(*m) }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}
