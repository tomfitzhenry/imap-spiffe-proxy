// Command imap-spiffe-client is a minimal raw IMAP client for imap-spiffe-proxy.
// It gets its X509-SVID from the SPIFFE Workload API and verifies the proxy's
// SPIFFE ID in the TLS handshake. Login proves password injection (it sends a
// wrong password), a synchronizing-literal APPEND and a FETCH round trip; the
// read-only mode proves an identity may read but not mutate.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	dialTimeout = 15 * time.Second
	ioTimeout   = 15 * time.Second
	maxLiteral  = 16 << 20
	wrongPass   = "deliberately-wrong-client-password"
)

func main() {
	addr := flag.String("addr", "", "imap-spiffe-proxy address (host:port)")
	serverID := flag.String("server-id", "", "expected proxy SPIFFE ID (required)")
	username := flag.String("username", "", "IMAP username sent on LOGIN (required)")
	mode := flag.String("mode", "login", "mode: login, idle, wrong-username, auth, malformed, deny or read-only")
	message := flag.String("message", "hello from imap-spiffe-client", "APPEND body text")
	flag.Parse()
	if *addr == "" || *serverID == "" || *username == "" {
		fatal("-addr, -server-id and -username are required")
	}
	id, err := spiffeid.FromString(*serverID)
	if err != nil {
		fatal("-server-id is not a valid SPIFFE ID: %v", err)
	}
	// NewX509Source reads SPIFFE_ENDPOINT_SOCKET and blocks for its first update.
	srcCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	source, err := workloadapi.NewX509Source(srcCtx)
	cancel()
	if err != nil {
		fatal("cannot obtain an X509-SVID from the SPIFFE Workload API (is SPIFFE_ENDPOINT_SOCKET set?): %v", err)
	}
	defer source.Close()
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	if err := run(*mode, *addr, *username, *message, tlsCfg); err != nil {
		fatal("mode %s: %v", *mode, err)
	}
	fmt.Printf("mode %s: ok\n", *mode)
}

func run(mode, addr, username, message string, tlsCfg *tls.Config) error {
	if mode == "deny" {
		return runDeny(addr, tlsCfg)
	}
	switch mode {
	case "login", "idle", "wrong-username", "auth", "malformed", "read-only":
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	c, err := connect(addr, tlsCfg)
	if err != nil {
		return err
	}
	defer c.close()
	switch mode {
	case "login":
		return c.loginFlow(username, message)
	case "idle":
		return c.idleFlow(username)
	case "read-only":
		return c.readOnlyFlow(username)
	case "wrong-username":
		return c.cmdRejected("LOGIN %s %s", strconv.Quote("not-"+username), wrongPass)
	case "auth":
		return c.cmdRejected("AUTHENTICATE PLAIN")
	default:
		return c.malformed()
	}
}

type client struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	tag  int
}

func connect(addr string, tlsCfg *tls.Config) (*client, error) {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	tc := tls.Client(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(dialTimeout))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	c := &client{conn: tc, r: bufio.NewReaderSize(tc, 4096), w: bufio.NewWriterSize(tc, 4096)}
	greeting, err := c.readLine()
	if err != nil {
		c.close()
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		c.close()
		return nil, fmt.Errorf("unexpected greeting %q", strings.TrimRight(greeting, "\r\n"))
	}
	return c, nil
}

func (c *client) close() { _ = c.conn.Close() }

func (c *client) nextTag() string { c.tag++; return fmt.Sprintf("A%d", c.tag) }

func (c *client) readLine() (string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(ioTimeout))
	return c.r.ReadString('\n')
}

func (c *client) write(p []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	if _, err := c.w.Write(p); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *client) sendLine(line string) error { return c.write([]byte(line + "\r\n")) }

// reply is one complete server response, through the tagged response (or BYE).
type reply struct {
	literals [][]byte
	final    string
	seq      string
}

// literalLen reports the payload length of a literal ending a response line.
func literalLen(line string) (int, bool) {
	line = strings.TrimRight(line, "\r\n")
	open := strings.LastIndexByte(line, '{')
	if open < 0 || !strings.HasSuffix(line, "}") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(line[open+1:len(line)-1], "+"))
	return n, err == nil && n >= 0 && n <= maxLiteral
}

func (c *client) readReply(tag string) (*reply, error) {
	rep := &reply{}
	for {
		raw, err := c.readLine()
		if err != nil {
			return rep, err
		}
		line := strings.TrimRight(raw, "\r\n")
		if fields := strings.Fields(line); len(fields) >= 3 && fields[1] == "SEARCH" {
			rep.seq = fields[len(fields)-1]
		}
		if n, ok := literalLen(raw); ok {
			buf := make([]byte, n)
			if _, err := io.ReadFull(c.r, buf); err != nil {
				return rep, fmt.Errorf("read literal payload: %w", err)
			}
			rep.literals = append(rep.literals, buf)
		}
		if strings.HasPrefix(line, tag+" ") || strings.HasPrefix(line, "* BYE") {
			rep.final = line
			return rep, nil
		}
	}
}

// expectTagged requires a tagged OK when wantOK is set, else a rejection.
func (c *client) expectTagged(tag string, wantOK bool) (*reply, error) {
	rep, err := c.readReply(tag)
	if err != nil {
		if !wantOK && isConnEnd(err) {
			return rep, nil
		}
		return rep, fmt.Errorf("read response for %s: %w", tag, err)
	}
	fields := strings.Fields(rep.final)
	ok := len(fields) >= 2 && fields[0] == tag && strings.ToUpper(fields[1]) == "OK"
	if ok == wantOK {
		return rep, nil
	}
	if wantOK {
		return rep, fmt.Errorf("command %s failed: %q", tag, rep.final)
	}
	return rep, fmt.Errorf("proxy accepted the command (got %q)", rep.final)
}

func (c *client) cmd(wantOK bool, format string, args ...any) (*reply, error) {
	tag := c.nextTag()
	if err := c.sendLine(tag + " " + fmt.Sprintf(format, args...)); err != nil {
		return nil, err
	}
	return c.expectTagged(tag, wantOK)
}

func (c *client) cmdRejected(format string, args ...any) error {
	_, err := c.cmd(false, format, args...)
	return err
}

func (c *client) expectContinuation() error {
	for {
		line, err := c.readLine()
		if err != nil {
			return err
		}
		switch {
		case line[0] == '+':
			return nil
		case strings.HasPrefix(line, "* BYE"):
			return fmt.Errorf("server refused the literal: %s", strings.TrimSpace(line))
		case line[0] != '*':
			return fmt.Errorf("command completed without a continuation: %q", strings.TrimSpace(line))
		}
	}
}

func (c *client) loginFlow(username, message string) error {
	if _, err := c.cmd(true, "LOGIN %s %s", strconv.Quote(username), wrongPass); err != nil {
		return fmt.Errorf("LOGIN through proxy password injection: %w", err)
	}
	if _, err := c.cmd(true, "SELECT INBOX"); err != nil {
		return fmt.Errorf("SELECT INBOX: %w", err)
	}
	body := "Subject: imap-spiffe-client\r\n\r\n" + message + "\r\n"
	tag := c.nextTag()
	if err := c.sendLine(fmt.Sprintf("%s APPEND INBOX {%d}", tag, len(body))); err != nil {
		return err
	}
	if err := c.expectContinuation(); err != nil {
		return fmt.Errorf("APPEND synchronizing literal: %w", err)
	}
	// The literal payload is body; the CRLF after it terminates the command.
	if err := c.write([]byte(body + "\r\n")); err != nil {
		return err
	}
	if _, err := c.expectTagged(tag, true); err != nil {
		return fmt.Errorf("APPEND: %w", err)
	}
	rep, err := c.cmd(true, "SEARCH ALL")
	if err != nil {
		return fmt.Errorf("SEARCH ALL: %w", err)
	}
	if rep.seq == "" {
		return errors.New("SEARCH ALL returned no messages")
	}
	rep, err = c.cmd(true, "FETCH %s BODY[TEXT]", rep.seq)
	if err != nil {
		return fmt.Errorf("FETCH BODY[TEXT]: %w", err)
	}
	for _, literal := range rep.literals {
		if bytes.Contains(literal, []byte(message)) {
			return c.logout()
		}
	}
	return errors.New("FETCH BODY[TEXT] did not return the appended message body")
}

func (c *client) idleFlow(username string) error {
	if _, err := c.cmd(true, "LOGIN %s %s", strconv.Quote(username), wrongPass); err != nil {
		return fmt.Errorf("LOGIN: %w", err)
	}
	tag := c.nextTag()
	if err := c.sendLine(tag + " IDLE"); err != nil {
		return err
	}
	if err := c.expectContinuation(); err != nil {
		return fmt.Errorf("IDLE continuation: %w", err)
	}
	if err := c.sendLine("DONE"); err != nil {
		return err
	}
	if _, err := c.expectTagged(tag, true); err != nil {
		return fmt.Errorf("IDLE/DONE: %w", err)
	}
	return c.logout()
}

// readOnlyFlow proves a read-only identity may issue read commands but not
// mutating ones. The proxy answers the mutating command with a tagged NO and
// then closes the connection, so this mode deliberately never sends LOGOUT.
func (c *client) readOnlyFlow(username string) error {
	if _, err := c.cmd(true, "LOGIN %s %s", strconv.Quote(username), wrongPass); err != nil {
		return fmt.Errorf("LOGIN: %w", err)
	}
	if _, err := c.cmd(true, "SELECT INBOX"); err != nil {
		return fmt.Errorf("SELECT INBOX: %w", err)
	}
	rep, err := c.cmd(true, "SEARCH ALL")
	if err != nil {
		return fmt.Errorf("SEARCH ALL: %w", err)
	}
	if rep.seq != "" {
		if _, err := c.cmd(true, "FETCH %s BODY[TEXT]", rep.seq); err != nil {
			return fmt.Errorf("FETCH BODY[TEXT]: %w", err)
		}
	}
	// A mutating command must be rejected with a tagged NO, never OK; the proxy
	// then closes the connection, so there is no LOGOUT afterwards.
	rep, err = c.cmd(false, "STORE 1 +FLAGS (\\Deleted)")
	if err != nil {
		return fmt.Errorf("STORE was not rejected: %w", err)
	}
	fields := strings.Fields(rep.final)
	if len(fields) < 2 || strings.HasPrefix(fields[0], "*") || strings.ToUpper(fields[1]) != "NO" {
		return fmt.Errorf("STORE: expected a tagged NO, got %q", rep.final)
	}
	return nil
}

func (c *client) malformed() error {
	if err := c.write([]byte("A1 LOGIN \"unterminated\r\n")); err != nil {
		return err
	}
	rep, err := c.readReply("A1")
	if err != nil {
		if isConnEnd(err) {
			return nil
		}
		return err
	}
	if strings.HasPrefix(rep.final, "* BYE") {
		return nil
	}
	return fmt.Errorf("expected BYE/EOF for the malformed command, got %q", rep.final)
}

// runDeny expects a rejection in the TLS handshake or a BYE greeting.
func runDeny(addr string, tlsCfg *tls.Config) error {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer raw.Close()
	tc := tls.Client(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(ioTimeout))
	if err := tc.Handshake(); err != nil {
		return nil // rejected in the TLS handshake
	}
	line, err := bufio.NewReaderSize(tc, 4096).ReadString('\n')
	if err != nil || strings.HasPrefix(strings.TrimSpace(line), "* BYE") {
		return nil
	}
	return fmt.Errorf("expected rejection, but the proxy accepted the connection (greeting %q)", strings.TrimSpace(line))
}

func (c *client) logout() error {
	tag := c.nextTag()
	if err := c.sendLine(tag + " LOGOUT"); err != nil {
		return err
	}
	for {
		line, err := c.readLine()
		if err != nil {
			if isConnEnd(err) {
				return nil
			}
			return err
		}
		if strings.HasPrefix(line, tag+" ") {
			return nil
		}
	}
}

func isConnEnd(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "connection reset"))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "imap-spiffe-client: "+format+"\n", args...)
	os.Exit(1)
}
