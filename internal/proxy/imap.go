package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Protocol limits. They are deliberately not configurable: the proxy enforces
// them fail-closed instead of truncating or retrying.
const (
	// maxLineBytes bounds one IMAP line (a command or response line, not the
	// literal payload that follows it).
	maxLineBytes int64 = 4 << 20
	// maxLiteralBytes bounds one IMAP literal payload.
	maxLiteralBytes int64 = 64 << 20
)

// goAhead is the continuation the proxy sends to the client for a
// synchronizing literal; the upstream's own continuation is swallowed.
const goAhead = "+ go ahead\r\n"

var (
	errLineTooLong     = errors.New("line exceeds the proxy limit")
	errBareLF          = errors.New("line ends with bare LF (IMAP requires CRLF)")
	errBareCR          = errors.New("bare CR in line (IMAP requires CRLF)")
	errTruncated       = errors.New("connection closed mid-line")
	errInvalidLiteral  = errors.New("invalid literal header")
	errInvalidCommand  = errors.New("invalid command")
	errLiteralTooLarge = errors.New("literal exceeds the proxy limit")
)

// readLine reads one strict-CRLF-terminated line, including its CRLF, from r.
// It fails when the line exceeds maxLineBytes, when the peer closes mid-line,
// or when the line contains a bare LF or CR.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		line = append(line, frag...)
		if int64(len(line)) > maxLineBytes {
			return nil, errLineTooLong
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return nil, io.EOF
			}
			return nil, errTruncated
		}
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errBareLF
	}
	if bytes.IndexByte(line[:len(line)-2], '\r') >= 0 {
		return nil, errBareCR
	}
	return line, nil
}

// literalHeader describes an IMAP literal marker ("{N}" or "{N+}") at the end
// of a line.
type literalHeader struct {
	// Length is the number of literal payload bytes.
	Length int64
	// Sync reports whether the literal is synchronizing ("{N}"): the server
	// must send a continuation request before the payload.
	Sync bool
}

// parseLiteralHeader reports whether line, which must include its trailing
// CRLF, ends with an IMAP literal marker. ok is false when the line does not
// end with a closing brace at all. A line that ends with "}" but has a
// malformed marker is an error.
func parseLiteralHeader(line []byte) (hdr literalHeader, ok bool, err error) {
	if len(line) < 2 {
		return literalHeader{}, false, nil
	}
	content := line[:len(line)-2]
	if len(content) == 0 || content[len(content)-1] != '}' {
		return literalHeader{}, false, nil
	}
	open := bytes.LastIndexByte(content, '{')
	if open < 0 {
		// A "}" that is not part of a literal marker.
		return literalHeader{}, false, nil
	}
	spec := content[open+1 : len(content)-1]
	sync := true
	if len(spec) > 0 && spec[len(spec)-1] == '+' {
		sync = false
		spec = spec[:len(spec)-1]
	}
	if len(spec) == 0 {
		return literalHeader{}, false, fmt.Errorf("%w: empty literal length", errInvalidLiteral)
	}
	for _, c := range spec {
		if c < '0' || c > '9' {
			return literalHeader{}, false, fmt.Errorf("%w: non-numeric literal length", errInvalidLiteral)
		}
	}
	n, err := strconv.ParseUint(string(spec), 10, 63)
	if err != nil {
		return literalHeader{}, false, fmt.Errorf("%w: literal length: %v", errInvalidLiteral, err)
	}
	return literalHeader{Length: int64(n), Sync: sync}, true, nil
}

// command is the parsed first line of an IMAP command.
type command struct {
	Tag  string
	Name string // upper case
	Args string // raw text after the command name, without CRLF
}

// parseCommand parses the tag and command name of one command line. Arguments
// are kept raw: only LOGIN arguments are ever inspected.
func parseCommand(line []byte) (*command, error) {
	if len(line) < 2 {
		return nil, errInvalidCommand
	}
	content := line[:len(line)-2]
	sp := bytes.IndexByte(content, ' ')
	if sp <= 0 {
		return nil, errInvalidCommand
	}
	tag := string(content[:sp])
	if !validTag(tag) {
		return nil, errInvalidCommand
	}
	rest := content[sp+1:]
	if len(rest) == 0 {
		return nil, errInvalidCommand
	}
	name := rest
	args := ""
	if sp := bytes.IndexByte(rest, ' '); sp >= 0 {
		name = rest[:sp]
		args = string(rest[sp+1:])
	}
	if !validAtom(string(name)) {
		return nil, errInvalidCommand
	}
	return &command{Tag: tag, Name: strings.ToUpper(string(name)), Args: args}, nil
}

// validTag reports whether tag is a safe IMAP command tag. The tag is echoed
// in tagged responses and in the rewritten LOGIN, so it is restricted to a
// conservative atom subset (fail closed).
func validTag(tag string) bool {
	if tag == "" || len(tag) > 64 {
		return false
	}
	for i := 0; i < len(tag); i++ {
		// '+' is excluded because a tagged response starting with it would be
		// indistinguishable from a continuation request.
		if !isAtomChar(tag[i]) || tag[i] == '+' {
			return false
		}
	}
	return true
}

// validAtom reports whether s is a non-empty IMAP atom.
func validAtom(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAtomChar(s[i]) {
			return false
		}
	}
	return true
}

func isAtomChar(c byte) bool {
	if c < 0x21 || c > 0x7e {
		return false
	}
	switch c {
	case '(', ')', '{', '%', '*', '"', '\\', ']':
		return false
	}
	return true
}

// parseLoginArgs parses exactly two astring arguments (atoms or quoted
// strings) from a LOGIN command's raw argument text. Literal arguments are not
// supported: LOGIN is rewritten by the proxy, so it requires the credentials on
// the command line.
func parseLoginArgs(args string) (username, password string, err error) {
	values, err := parseAStrings(args)
	if err != nil {
		return "", "", err
	}
	if len(values) != 2 {
		return "", "", fmt.Errorf("%w: LOGIN requires exactly two arguments", errInvalidCommand)
	}
	return values[0], values[1], nil
}

func parseAStrings(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ':
			i++
		case '"':
			value, n, err := parseQuoted(s[i:])
			if err != nil {
				return nil, err
			}
			out = append(out, value)
			i += n
		default:
			start := i
			for i < len(s) && s[i] != ' ' {
				i++
			}
			if !validAtom(s[start:i]) {
				return nil, fmt.Errorf("%w: invalid atom argument", errInvalidCommand)
			}
			out = append(out, s[start:i])
		}
	}
	return out, nil
}

// parseQuoted parses one IMAP quoted string starting at s[0] == '\"' and
// returns the unescaped value and the number of bytes consumed.
func parseQuoted(s string) (string, int, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			if i+1 >= len(s) {
				return "", 0, fmt.Errorf("%w: truncated quoted string escape", errInvalidCommand)
			}
			i++
			if s[i] != '"' && s[i] != '\\' {
				return "", 0, fmt.Errorf("%w: invalid quoted string escape", errInvalidCommand)
			}
			b.WriteByte(s[i])
		default:
			if c < 0x20 || c > 0x7e {
				return "", 0, fmt.Errorf("%w: non-printable byte in quoted string", errInvalidCommand)
			}
			b.WriteByte(c)
		}
	}
	return "", 0, fmt.Errorf("%w: unterminated quoted string", errInvalidCommand)
}

// quoteString encodes s as an IMAP quoted string. The caller must have ensured
// that s is non-empty printable ASCII, so the only characters needing escapes
// are the quote and the backslash.
func quoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// writeFull writes all of p to w.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
	}
	return nil
}
