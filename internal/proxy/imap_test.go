package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"crlf", "A1 NOOP\r\n", "A1 NOOP\r\n", nil},
		{"empty line", "\r\n", "\r\n", nil},
		{"bare lf", "A1 NOOP\n", "", errBareLF},
		{"bare cr", "A1 NO\rOP\r\n", "", errBareCR},
		{"truncated", "A1 NOOP", "", errTruncated},
		{"clean eof", "", "", io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReaderSize(strings.NewReader(tt.input), 16)
			got, err := readLine(r)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("readLine error = %v, want %v", err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Errorf("readLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadLineTooLong(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", int(maxLineBytes)+2)+"\r\n"), 64)
	if _, err := readLine(r); !errors.Is(err, errLineTooLong) {
		t.Fatalf("readLine error = %v, want errLineTooLong", err)
	}
}

func TestParseLiteralHeader(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    literalHeader
		ok      bool
		wantErr bool
	}{
		{"sync", "A1 APPEND INBOX {5}\r\n", literalHeader{Length: 5, Sync: true}, true, false},
		{"nonsync", "A1 APPEND INBOX {5+}\r\n", literalHeader{Length: 5, Sync: false}, true, false},
		{"zero", "A1 APPEND INBOX {0}\r\n", literalHeader{Length: 0, Sync: true}, true, false},
		{"no literal", "A1 NOOP\r\n", literalHeader{}, false, false},
		{"brace in atom", "A1 SEARCH TEXT foo}\r\n", literalHeader{}, false, false},
		{"empty length", "A1 APPEND INBOX {}\r\n", literalHeader{}, false, true},
		{"non numeric", "A1 APPEND INBOX {abc}\r\n", literalHeader{}, false, true},
		{"plus only", "A1 APPEND INBOX {+}\r\n", literalHeader{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := parseLiteralHeader([]byte(tt.line))
			if tt.wantErr {
				if !errors.Is(err, errInvalidLiteral) {
					t.Fatalf("parseLiteralHeader error = %v, want errInvalidLiteral", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLiteralHeader: %v", err)
			}
			if ok != tt.ok || got != tt.want {
				t.Errorf("parseLiteralHeader = %+v, ok=%v; want %+v, ok=%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParseCommand(t *testing.T) {
	cmd, err := parseCommand([]byte("a1 login \"user\" \"pass\"\r\n"))
	if err != nil {
		t.Fatalf("parseCommand: %v", err)
	}
	if cmd.Tag != "a1" || cmd.Name != "LOGIN" || cmd.Args != `"user" "pass"` {
		t.Errorf("parseCommand = %+v", cmd)
	}

	cmd, err = parseCommand([]byte("A1 NOOP\r\n"))
	if err != nil {
		t.Fatalf("parseCommand: %v", err)
	}
	if cmd.Name != "NOOP" || cmd.Args != "" {
		t.Errorf("parseCommand = %+v", cmd)
	}

	for _, bad := range []string{
		"A1\r\n",
		" A1 NOOP\r\n",
		"A1  NOOP\r\n",
		"A(1 NOOP\r\n",
		"* NOOP\r\n",
	} {
		if _, err := parseCommand([]byte(bad)); err == nil {
			t.Errorf("parseCommand(%q) succeeded, want an error", bad)
		}
	}
}

func TestParseLoginArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         string
		wantUsername string
		wantPassword string
		wantErr      bool
	}{
		{"quoted", `"shared" "secret"`, "shared", "secret", false},
		{"atoms", `shared secret`, "shared", "secret", false},
		{"escapes", `"sh\"ared" "sec\\ret"`, `sh"ared`, `sec\ret`, false},
		{"space in password", `"shared" "app password"`, "shared", "app password", false},
		{"too few", `"shared"`, "", "", true},
		{"too many", `"shared" "secret" extra`, "", "", true},
		{"unterminated", `"shared`, "", "", true},
		{"literal marker", `"shared" {5}`, "", "", true},
		{"empty", ``, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password, err := parseLoginArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseLoginArgs succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLoginArgs: %v", err)
			}
			if username != tt.wantUsername || password != tt.wantPassword {
				t.Errorf("parseLoginArgs = (%q, %q), want (%q, %q)", username, password, tt.wantUsername, tt.wantPassword)
			}
		})
	}
}

func TestQuoteString(t *testing.T) {
	tests := map[string]string{
		"simple":    `"simple"`,
		`has"quote`: `"has\"quote"`,
		`has\slash`: `"has\\slash"`,
		"spaces ok": `"spaces ok"`,
	}
	for in, want := range tests {
		if got := quoteString(in); got != want {
			t.Errorf("quoteString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidTag(t *testing.T) {
	for _, tag := range []string{"A1", "a1", "tag_1", "abc-def"} {
		if !validTag(tag) {
			t.Errorf("validTag(%q) = false, want true", tag)
		}
	}
	for _, tag := range []string{"", "*", "+", "a b", "a(", "a(b", "a{b", "a\"b", "a\\b", strings.Repeat("a", 65)} {
		if validTag(tag) {
			t.Errorf("validTag(%q) = true, want false", tag)
		}
	}
}

func TestWriteFullShortWrites(t *testing.T) {
	var b bytes.Buffer
	w := &limitedWriter{buf: &b, max: 2}
	if err := writeFull(w, []byte("hello")); err != nil {
		t.Fatalf("writeFull: %v", err)
	}
	if b.String() != "hello" {
		t.Errorf("writeFull wrote %q, want hello", b.String())
	}
}

type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}
