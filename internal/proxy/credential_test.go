package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPasswordUnsetDirectory(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	_, err := LoadPassword()
	if err == nil || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("LoadPassword error = %v, want a CREDENTIALS_DIRECTORY error", err)
	}
}

func TestLoadPassword(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr string
	}{
		{"trailing newline", "app-password\n", "app-password", ""},
		{"trailing crlf", "app-password\r\n", "app-password", ""},
		{"no newline", "app-password", "app-password", ""},
		{"spaces", "app password with spaces\n", "app password with spaces", ""},
		{"empty", "", "", "is empty"},
		{"newline only", "\n", "", "is empty"},
		{"non printable", "pass\x00word\n", "", "non-printable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, passwordCredential), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CREDENTIALS_DIRECTORY", dir)
			got, err := LoadPassword()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadPassword error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadPassword: %v", err)
			}
			if got != tt.want {
				t.Errorf("LoadPassword = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadPasswordMissingFile(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	_, err := LoadPassword()
	if err == nil || !strings.Contains(err.Error(), "imap-password") {
		t.Fatalf("LoadPassword error = %v, want a missing credential error", err)
	}
}

func TestLoadPasswordRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, passwordCredential), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	_, err := LoadPassword()
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("LoadPassword error = %v, want a not-a-regular-file error", err)
	}
}
