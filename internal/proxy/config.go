// Package proxy implements an IMAP front door that authenticates clients with
// SPIFFE mTLS, enforces an exact SPIFFE-ID allowlist, and injects one shared
// upstream IMAP account's password on LOGIN.
//
// The client leg terminates TLS with a server X509-SVID obtained from the local
// SPIRE agent Workload API. The upstream leg is always implicit TLS with
// certificate and hostname verification against the system trust store; there
// is no plaintext or STARTTLS fallback. Every command except LOGIN is proxied
// byte-for-byte to the upstream, except for identities configured read-only:
// they may issue only non-mutating commands and everything else is rejected
// locally. The LOGIN password is read from a systemd
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
	// ReadWriteIdentities is the exact SPIFFE-ID allowlist for clients that may
	// issue mutating IMAP commands. It is enforced during the TLS handshake.
	ReadWriteIdentities []string
	// ReadOnlyIdentities is the exact SPIFFE-ID allowlist for clients that may
	// issue only commands that do not change mailbox state (for example FETCH
	// and SEARCH, but not STORE or APPEND). It is enforced during the TLS
	// handshake. An ID must appear in exactly one of the two lists; Validate
	// rejects an overlap.
	ReadOnlyIdentities []string
	// Password is the single upstream IMAP account password. It is never read
	// from flags; main sets it from the systemd credential. It is never logged
	// and error messages never contain it.
	Password string
}

// Validate checks the configuration and fills in defaults. It canonicalizes the
// read-write and read-only identity lists. The password is validated without
// ever echoing its bytes.
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
	if len(c.ReadWriteIdentities) == 0 && len(c.ReadOnlyIdentities) == 0 {
		return errors.New("at least one read-write or read-only SPIFFE ID is required")
	}
	readWrite, readWriteSet, err := canonicalizeIdentities("read-write", c.ReadWriteIdentities)
	if err != nil {
		return err
	}
	c.ReadWriteIdentities = readWrite
	readOnly, _, err := canonicalizeIdentities("read-only", c.ReadOnlyIdentities)
	if err != nil {
		return err
	}
	c.ReadOnlyIdentities = readOnly
	for _, id := range readOnly {
		if _, ok := readWriteSet[id]; ok {
			return fmt.Errorf("SPIFFE ID %q is both read-write and read-only", id)
		}
	}
	return nil
}

// canonicalizeIdentities parses, de-duplicates and sorts one SPIFFE-ID list. It
// returns the canonical IDs and the set of canonical IDs.
func canonicalizeIdentities(kind string, raw []string) ([]string, map[string]struct{}, error) {
	seen := make(map[string]struct{}, len(raw))
	canonical := make([]string, 0, len(raw))
	for _, value := range raw {
		id, err := spiffeid.FromString(value)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid %s SPIFFE ID %q: %w", kind, value, err)
		}
		s := id.String()
		if _, dup := seen[s]; dup {
			return nil, nil, fmt.Errorf("duplicate %s SPIFFE ID %q", kind, s)
		}
		seen[s] = struct{}{}
		canonical = append(canonical, s)
	}
	sort.Strings(canonical)
	return canonical, seen, nil
}

// IsReadOnly reports whether id is restricted to non-mutating IMAP commands.
// Validate must have been called first; entries that do not parse are ignored
// so that a bug cannot silently widen the read-write set.
func (c Config) IsReadOnly(id spiffeid.ID) bool {
	want := id.String()
	for _, raw := range c.ReadOnlyIdentities {
		got, err := spiffeid.FromString(raw)
		if err != nil {
			continue
		}
		if got.String() == want {
			return true
		}
	}
	return false
}

// AllowedIDs returns the union of the read-write and read-only allowlists.
// Validate must have been called first; invalid entries are skipped here so
// that a bug cannot silently widen the allowlist.
func (c Config) AllowedIDs() []spiffeid.ID {
	ids := make([]spiffeid.ID, 0, len(c.ReadWriteIdentities)+len(c.ReadOnlyIdentities))
	for _, list := range [][]string{c.ReadWriteIdentities, c.ReadOnlyIdentities} {
		for _, raw := range list {
			if id, err := spiffeid.FromString(raw); err == nil {
				ids = append(ids, id)
			}
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
