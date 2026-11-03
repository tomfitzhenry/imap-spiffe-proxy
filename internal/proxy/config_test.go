package proxy

import (
	"crypto/tls"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		ListenAddress:     "127.0.0.1:1430",
		UpstreamAddress:   "imap.example.com:993",
		Username:          "shared@example.com",
		AllowedIdentities: []string{"spiffe://example.org/client/alice"},
		Password:          "app-password",
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.AllowedIdentities = []string{
		"spiffe://example.org/client/bob",
		"spiffe://example.org/client/alice",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.UpstreamTLSServerName != "imap.example.com" {
		t.Errorf("UpstreamTLSServerName = %q, want imap.example.com", cfg.UpstreamTLSServerName)
	}
	want := []string{"spiffe://example.org/client/alice", "spiffe://example.org/client/bob"}
	if strings.Join(cfg.AllowedIdentities, ",") != strings.Join(want, ",") {
		t.Errorf("AllowedIdentities = %v, want %v", cfg.AllowedIdentities, want)
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
		{"no identities", func(c *Config) { c.AllowedIdentities = nil }, "at least one allowed"},
		{"invalid identity", func(c *Config) { c.AllowedIdentities = []string{"not-a-spiffe-id"} }, "invalid allowed"},
		{"duplicate identity", func(c *Config) {
			c.AllowedIdentities = []string{"spiffe://example.org/client/alice", "spiffe://example.org/client/alice"}
		}, "duplicate"},
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
