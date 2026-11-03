package proxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const passwordCredential = "imap-password"

// LoadPassword reads the shared IMAP password from the systemd credentials
// directory: $CREDENTIALS_DIRECTORY/imap-password. The proxy is expected to run
// under systemd with LoadCredential=imap-password:/path/to/secret; there is
// deliberately no flag or config field that can carry the password.
//
// One trailing newline (and an optional preceding carriage return, so files
// written with echo work) is stripped. The result must be non-empty printable
// ASCII; spaces are allowed. The password is never logged, and errors only name
// the credential path.
func LoadPassword() (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", errors.New("CREDENTIALS_DIRECTORY is not set: run the proxy under systemd with LoadCredential=imap-password:/path/to/secret")
	}
	path := filepath.Join(dir, passwordCredential)
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat systemd credential %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("systemd credential %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read systemd credential %s: %w", path, err)
	}
	password := trimTrailingNewline(data)
	if err := validateCredentialPassword(password); err != nil {
		return "", fmt.Errorf("systemd credential %s: %w", path, err)
	}
	return string(password), nil
}

func trimTrailingNewline(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	return data
}

func validateCredentialPassword(password []byte) error {
	if len(password) == 0 {
		return errors.New("is empty")
	}
	for i, b := range password {
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("contains a non-printable-ASCII byte at offset %d", i)
		}
	}
	return nil
}
