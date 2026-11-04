package proxy

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	aliceID = "spiffe://example.org/client/alice"
	bobID   = "spiffe://example.org/client/bob"
	carolID = "spiffe://example.org/client/carol"
)

func validConfig() Config {
	return Config{
		ListenAddress:       "127.0.0.1:1430",
		UpstreamAddress:     "imap.example.com:993",
		Username:            "shared@example.com",
		ReadWriteIdentities: []string{aliceID},
		Password:            "app-password",
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.ReadWriteIdentities = []string{bobID, aliceID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.UpstreamTLSServerName != "imap.example.com" {
		t.Errorf("UpstreamTLSServerName = %q, want imap.example.com", cfg.UpstreamTLSServerName)
	}
	want := []string{aliceID, bobID}
	if got := strings.Join(cfg.ReadWriteIdentities, ","); got != strings.Join(want, ",") {
		t.Errorf("ReadWriteIdentities = %v, want %v", cfg.ReadWriteIdentities, want)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no listen", func(c *Config) { c.ListenAddress = "" }, "listen address"},
		{"no upstream", func(c *Config) { c.UpstreamAddress = "" }, "upstream address is required"},
		{"upstream without port", func(c *Config) { c.UpstreamAddress = "imap.example.com" }, "host:port"},
		{"upstream empty host", func(c *Config) { c.UpstreamAddress = ":993" }, "empty host"},
		{"no username", func(c *Config) { c.Username = "" }, "IMAP username"},
		{"no password", func(c *Config) { c.Password = "" }, "IMAP password"},
		{"non-printable username", func(c *Config) { c.Username = "shared\r\n" }, "non-printable"},
		{"non-printable server name", func(c *Config) { c.UpstreamTLSServerName = "imap\x00" }, "non-printable"},
		{"no identities", func(c *Config) {
			c.ReadWriteIdentities = nil
			c.ReadOnlyIdentities = nil
		}, "at least one read-write or read-only"},
		{"invalid read-write identity", func(c *Config) {
			c.ReadWriteIdentities = []string{"not-a-spiffe-id"}
		}, "invalid read-write"},
		{"duplicate read-write identity", func(c *Config) {
			c.ReadWriteIdentities = []string{aliceID, aliceID}
		}, "duplicate read-write"},
		{"invalid read-only identity", func(c *Config) {
			c.ReadOnlyIdentities = []string{"not-a-spiffe-id"}
		}, "invalid read-only"},
		{"duplicate read-only identity", func(c *Config) {
			c.ReadOnlyIdentities = []string{bobID, bobID}
		}, "duplicate read-only"},
		{"identity both read-write and read-only", func(c *Config) {
			c.ReadOnlyIdentities = []string{aliceID}
		}, "both read-write and read-only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestUpstreamTLSConfigVerifies(t *testing.T) {
	cfg := validConfig()
	cfg.UpstreamAddress = "127.0.0.1:993"
	cfg.UpstreamTLSServerName = "localhost"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	tlsCfg := cfg.UpstreamTLSConfig()
	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("RootCAs must be nil so the system trust store is used")
	}
	if tlsCfg.ServerName != "localhost" {
		t.Errorf("ServerName = %q, want localhost", tlsCfg.ServerName)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", tlsCfg.MinVersion)
	}
}

func TestValidateRejectsEmptyPasswordBeforeLogging(t *testing.T) {
	cfg := validConfig()
	cfg.Password = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want an error")
	}
	if strings.Contains(err.Error(), "app-password") {
		t.Fatalf("error leaks a password: %v", err)
	}
}

func TestValidateCanonicalizesIdentities(t *testing.T) {
	cfg := validConfig()
	cfg.ReadWriteIdentities = []string{bobID, aliceID}
	cfg.ReadOnlyIdentities = []string{carolID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got, want := strings.Join(cfg.ReadWriteIdentities, ","), strings.Join([]string{aliceID, bobID}, ","); got != want {
		t.Errorf("ReadWriteIdentities = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.ReadOnlyIdentities, ","), carolID; got != want {
		t.Errorf("ReadOnlyIdentities = %q, want %q", got, want)
	}
}

func TestIsReadOnly(t *testing.T) {
	parse := func(raw string) spiffeid.ID {
		t.Helper()
		id, err := spiffeid.FromString(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return id
	}

	cfg := validConfig()
	cfg.ReadWriteIdentities = []string{aliceID}
	cfg.ReadOnlyIdentities = []string{bobID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.IsReadOnly(parse(aliceID)) {
		t.Error("alice must be read-write")
	}
	if !cfg.IsReadOnly(parse(bobID)) {
		t.Error("bob must be read-only")
	}
	if cfg.IsReadOnly(parse(carolID)) {
		t.Error("carol is not listed at all")
	}
}

func TestAllowedIDsReturnsUnion(t *testing.T) {
	cfg := validConfig()
	cfg.ReadWriteIdentities = []string{aliceID}
	cfg.ReadOnlyIdentities = []string{bobID}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := make(map[string]bool, 2)
	for _, id := range cfg.AllowedIDs() {
		got[id.String()] = true
	}
	if len(got) != 2 || !got[aliceID] || !got[bobID] {
		t.Errorf("AllowedIDs = %v, want both %q and %q", got, aliceID, bobID)
	}
}
