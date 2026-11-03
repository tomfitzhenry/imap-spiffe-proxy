// Package proxy implements an IMAP front door that authenticates clients with
// SPIFFE mTLS, enforces an exact SPIFFE-ID allowlist, and injects one shared
// upstream IMAP account's password on LOGIN.
//
// The client leg terminates TLS with a server X509-SVID obtained from the local
// SPIRE agent Workload API. The upstream leg is always implicit TLS with
// certificate and hostname verification against the system trust store; there
// is no plaintext or STARTTLS fallback. Every command except LOGIN is proxied
// byte-for-byte to the upstream, and the LOGIN password is read from a systemd
// credential rather than a flag or config file.
package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Config is the validated proxy configuration. It contains no IMAP password:
// load that from the systemd credentials directory with LoadPassword and set
// Password before calling New.
type Config struct {
	// ListenAddress is the TCP address the SPIFFE mTLS listener binds to.
	ListenAddress string
	// UpstreamAddress is the upstream IMAP server as host:port. It is always
	// reached over implicit TLS.
	UpstreamAddress string
	// UpstreamTLSServerName is the name checked against the upstream
	// certificate. It defaults to the host part of UpstreamAddress.
	UpstreamTLSServerName string
	// Username is the single upstream IMAP account username. A client must
	// send exactly this username on LOGIN.
	Username string
	// AllowedIdentities is the exact SPIFFE-ID allowlist enforced during the
	// TLS handshake.
	AllowedIdentities []string
	// Password is the single upstream IMAP account password. It is never read
	// from flags; main sets it from the systemd credential. It is never logged
	// and error messages never contain it.
	Password string
}

// Validate checks the configuration and fills in defaults. It canonicalizes
// AllowedIdentities. The password is validated without ever echoing its bytes.
func (c *Config) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen address is required")
	}
	if c.UpstreamAddress == "" {
		return errors.New("upstream address is required")
	}
	host, _, err := net.SplitHostPort(c.UpstreamAddress)
	if err != nil {
		return fmt.Errorf("upstream address %q must be host:port: %w", c.UpstreamAddress, err)
	}
	if host == "" {
		return fmt.Errorf("upstream address %q has an empty host", c.UpstreamAddress)
	}
	if c.UpstreamTLSServerName == "" {
		c.UpstreamTLSServerName = host
	}
	if err := validatePrintableASCII("upstream TLS server name", c.UpstreamTLSServerName); err != nil {
		return err
	}
	if err := validatePrintableASCII("IMAP username", c.Username); err != nil {
		return err
	}
	if err := validatePrintableASCII("IMAP password", c.Password); err != nil {
		return err
	}
	if len(c.AllowedIdentities) == 0 {
		return errors.New("at least one allowed SPIFFE ID is required")
	}
	seen := make(map[string]struct{}, len(c.AllowedIdentities))
	canonical := make([]string, 0, len(c.AllowedIdentities))
	for _, raw := range c.AllowedIdentities {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return fmt.Errorf("invalid allowed SPIFFE ID %q: %w", raw, err)
		}
		if _, dup := seen[id.String()]; dup {
			return fmt.Errorf("duplicate allowed SPIFFE ID %q", id.String())
		}
		seen[id.String()] = struct{}{}
		canonical = append(canonical, id.String())
	}
	sort.Strings(canonical)
	c.AllowedIdentities = canonical
	return nil
}

// AllowedIDs returns the allowlisted SPIFFE IDs. Validate must have been
// called first; invalid entries are skipped here so that a bug cannot silently
// widen the allowlist.
func (c Config) AllowedIDs() []spiffeid.ID {
	ids := make([]spiffeid.ID, 0, len(c.AllowedIdentities))
	for _, raw := range c.AllowedIdentities {
		if id, err := spiffeid.FromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// UpstreamTLSConfig builds the TLS configuration for the upstream IMAP hop.
// Certificate chain and hostname verification are always on and always use the
// system trust store: RootCAs is nil and InsecureSkipVerify is false. There is
// deliberately no custom-CA option and no plaintext path.
func (c Config) UpstreamTLSConfig() *tls.Config {
	return &tls.Config{
		ServerName: c.UpstreamTLSServerName,
		MinVersion: tls.VersionTLS12,
	}
}

// validatePrintableASCII rejects empty values and bytes outside printable
// ASCII (0x20..0x7e). Errors never include the value because it may be a
// secret.
func validatePrintableASCII(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	for i := 0; i < len(value); i++ {
		if b := value[i]; b < 0x20 || b > 0x7e {
			return fmt.Errorf("%s contains a non-printable-ASCII byte at offset %d", field, i)
		}
	}
	return nil
}
