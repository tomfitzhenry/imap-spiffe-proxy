package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// continuationTimeout bounds how long the client->upstream forwarder waits for
// the upstream's continuation request for a synchronizing literal.
const continuationTimeout = 10 * time.Second

// errUpstreamRejected means the upstream answered a synchronizing literal with
// something other than a continuation request (usually a tagged NO/BAD). The
// response has already been forwarded to the client.
var errUpstreamRejected = errors.New("upstream did not send a literal continuation")

// errContinuationTimeout means the upstream did not send a continuation
// request for a forwarded synchronizing literal in time.
var errContinuationTimeout = errors.New("timed out waiting for the upstream literal continuation")

// lockedWriter serializes writes to the client from the request loop and the
// response pump.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := writeFull(l.w, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (l *lockedWriter) write(p []byte) error {
	_, err := l.Write(p)
	return err
}

// continuation coordinates the one in-flight synchronizing literal between the
// client->upstream forwarder (which arms it and waits) and the upstream->client
// pump (which consumes the upstream continuation so the client does not see it
// twice). It is used serially: at most one literal is pending at a time.
type continuation struct {
	mu sync.Mutex
	ch chan error
}

// begin marks a continuation as pending and returns the channel that will carry
// the upstream's answer.
func (c *continuation) begin() (chan error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ch != nil {
		return nil, false
	}
	c.ch = make(chan error, 1)
	return c.ch, true
}

// pending reports whether a continuation is currently armed.
func (c *continuation) pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ch != nil
}

// deliver consumes a pending continuation. It reports whether one was pending.
func (c *continuation) deliver(err error) bool {
	c.mu.Lock()
	ch := c.ch
	c.ch = nil
	c.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- err
	return true
}

// clear forgets a pending continuation without answering it.
func (c *continuation) clear() {
	c.mu.Lock()
	c.ch = nil
	c.mu.Unlock()
}

// wait blocks until the continuation armed as ch is delivered or the timeout
// expires.
func (c *continuation) wait(ch chan error) error {
	timer := time.NewTimer(continuationTimeout)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-timer.C:
		c.clear()
		return errContinuationTimeout
	}
}

// session is one authenticated client connection and its upstream connection.
type session struct {
	cfg      Config
	client   net.Conn
	upstream net.Conn
	log      *slog.Logger

	// readOnly reports whether the peer identity may issue only commands that
	// do not change mailbox state.
	readOnly bool

	clientW *lockedWriter
	cont    continuation

	loginDone bool
	idle      bool
}

func newSession(cfg Config, client, upstream net.Conn, readOnly bool, logger *slog.Logger) *session {
	return &session{
		cfg:      cfg,
		client:   client,
		upstream: upstream,
		log:      logger,
		readOnly: readOnly,
		clientW:  &lockedWriter{w: client},
	}
}

// run proxies until either side closes. It always closes both connections
// before returning.
func (s *session) run() {
	pumpErr := make(chan error, 1)
	go func() {
		err := s.pump()
		// Closing both sides unblocks the request loop if the upstream is gone.
		_ = s.client.Close()
		_ = s.upstream.Close()
		pumpErr <- err
	}()

	loopErr := s.clientLoop()
	_ = s.client.Close()
	_ = s.upstream.Close()
	upErr := <-pumpErr

	if loopErr != nil && !isClosedError(loopErr) {
		s.log.Warn("client session ended with error", "error", loopErr)
	}
	if upErr != nil && !isClosedError(upErr) {
		s.log.Warn("upstream session ended with error", "error", upErr)
	}
}

// clientLoop reads one client command at a time, applies the proxy policy and
// forwards everything except the rewritten LOGIN to the upstream.
//
// IMAP allows literals inside a command: after the literal's payload the rest of
// the command line (normally just the terminating CRLF) follows. Only the first
// physical line of a command carries the tag and name, so only that line is
// policy-parsed; the remainder is forwarded verbatim upstream.
func (s *session) clientLoop() error {
	r := bufio.NewReaderSize(s.client, 4096)
	inCommand := false
	for {
		line, err := readLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedError(err) {
				return nil
			}
			s.log.Error("protocol error", "error", err)
			reason := "Protocol error"
			if errors.Is(err, errLineTooLong) {
				reason = "Command too large"
			}
			s.sendBYE(reason)
			return nil
		}

		// In IDLE state the next client line is normally DONE, which is
		// forwarded verbatim (it is not a command).
		if s.idle {
			s.idle = false
			if bytes.EqualFold(line, []byte("DONE\r\n")) {
				if err := writeFull(s.upstream, line); err != nil {
					return err
				}
				continue
			}
		}

		hdr, hasLiteral, err := parseLiteralHeader(line)
		if err != nil {
			s.log.Error("parse error", "error", err)
			s.sendBYE("Parse error")
			return nil
		}

		var cmd *command
		if !inCommand {
			cmd, err = parseCommand(line)
			if err != nil {
				s.log.Error("parse error", "error", err)
				s.sendBYE("Parse error")
				return nil
			}
		}

		forward := line
		if cmd != nil {
			switch cmd.Name {
			case "AUTHENTICATE":
				// SASL would bypass the configured password injection.
				s.log.Warn("policy: rejected AUTHENTICATE", "tag", cmd.Tag)
				s.sendTagged(cmd.Tag, "NO", "AUTHENTICATE not permitted")
				return nil
			case "STARTTLS":
				// The client leg is already mTLS.
				s.log.Warn("policy: rejected STARTTLS", "tag", cmd.Tag)
				s.sendTagged(cmd.Tag, "NO", "STARTTLS not permitted")
				return nil
			case "LOGIN":
				if hasLiteral {
					s.log.Warn("policy: rejected LOGIN with a literal argument", "tag", cmd.Tag)
					s.sendTagged(cmd.Tag, "NO", "LOGIN with literals is not supported")
					return nil
				}
				forward, err = s.rewriteLogin(cmd)
				if err != nil {
					if errors.Is(err, errCloseSession) {
						return nil
					}
					return err
				}
			}
			// Read-only identities may issue only commands that do not change
			// mailbox state; everything else is rejected locally, before
			// anything (including any literal payload) reaches the upstream.
			if s.readOnly {
				if !readOnlyAllowed(cmd) {
					s.log.Warn("policy: rejected command for a read-only identity", "tag", cmd.Tag, "command", cmd.Name)
					s.sendTagged(cmd.Tag, "NO", "Command not permitted for a read-only identity")
					return nil
				}
				// Open the mailbox read-only: the upstream then also refuses
				// mutations, and a plain FETCH BODY[...] cannot set \Seen.
				if cmd.Name == "SELECT" {
					forward = selectAsExamine(cmd)
				}
			}
		}

		if err := s.forward(forward, hdr, hasLiteral, r); err != nil {
			switch {
			case errors.Is(err, errCloseSession):
				return nil
			case errors.Is(err, errUpstreamRejected):
				// The pump already forwarded the upstream response.
				return nil
			case errors.Is(err, errContinuationTimeout):
				s.log.Error("upstream literal continuation timeout")
				s.sendBYE("Upstream continuation timeout")
				return nil
			default:
				return err
			}
		}
		// A literal means the command line continues after its payload (usually
		// with just CRLF); forward that remainder without policy parsing.
		inCommand = hasLiteral
		if !hasLiteral && cmd != nil && cmd.Name == "IDLE" {
			s.idle = true
		}
	}
}

var errCloseSession = errors.New("close session after responding")

// readOnlyCommands is the positive allowlist of commands a read-only identity
// may issue: commands that do not change mailbox state. It is a positive
// allowlist so that a command introduced by a future IMAP extension is
// rejected rather than accidentally forwarded (fail closed).
//
// Everything not listed here is a violation for a read-only identity,
// including APPEND, STORE, COPY, MOVE, EXPUNGE, CLOSE (which expunges),
// CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE, CHECK, SETACL, DELETEACL,
// SETQUOTA and SETMETADATA. UID is a command group, so the subcommand decides.
var readOnlyCommands = map[string]struct{}{
	// Session and capability commands. LOGIN is permitted: it is parsed,
	// rewritten with the shared account and injected password above, and
	// authenticating does not change mailbox state.
	"LOGIN":      {},
	"CAPABILITY": {},
	"ID":         {},
	"NOOP":       {},
	"LOGOUT":     {},
	"IDLE":       {},
	"ENABLE":     {},
	// Mailbox selection and metadata.
	"SELECT":    {},
	"EXAMINE":   {},
	"UNSELECT":  {},
	"STATUS":    {},
	"LIST":      {},
	"LSUB":      {},
	"XLIST":     {},
	"NAMESPACE": {},
	// Message access.
	"SEARCH":     {},
	"FETCH":      {},
	"SORT":       {},
	"THREAD":     {},
	"UID SEARCH": {},
	"UID FETCH":  {},
	"UID SORT":   {},
	"UID THREAD": {},
	// Quota and ACL reads.
	"GETQUOTA":     {},
	"GETQUOTAROOT": {},
	"GETMETADATA":  {},
	"MYRIGHTS":     {},
	"LISTRIGHTS":   {},
}

// readOnlyAllowed reports whether cmd is permitted for a read-only identity.
func readOnlyAllowed(cmd *command) bool {
	name := cmd.Name
	if name == "UID" {
		name = "UID " + firstArgumentUpper(cmd.Args)
	}
	_, ok := readOnlyCommands[name]
	return ok
}

// firstArgumentUpper returns the first space-delimited argument of args in
// upper case, or "" when there is none.
func firstArgumentUpper(args string) string {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}

// selectAsExamine rewrites a SELECT command's line to EXAMINE. The tag, the
// arguments and any trailing literal marker are preserved; the literal payload
// and the rest of the command line are relayed by forward like any other
// command.
func selectAsExamine(cmd *command) []byte {
	line := cmd.Tag + " EXAMINE"
	if cmd.Args != "" {
		line += " " + cmd.Args
	}
	return []byte(line + "\r\n")
}

// rewriteLogin enforces the LOGIN policy and returns the command line to send
// upstream: the configured username and password replace the client's
// credentials. The client's password is parsed only for syntax and discarded;
// it is never logged.
func (s *session) rewriteLogin(cmd *command) ([]byte, error) {
	if s.loginDone {
		s.log.Warn("policy: rejected second LOGIN", "tag", cmd.Tag)
		s.sendTagged(cmd.Tag, "NO", "LOGIN already attempted")
		return nil, errCloseSession
	}
	username, _, err := parseLoginArgs(cmd.Args)
	if err != nil {
		s.log.Error("parse error", "error", fmt.Errorf("LOGIN arguments: %w", err))
		s.sendBYE("Parse error")
		return nil, errCloseSession
	}
	if username != s.cfg.Username {
		s.log.Warn("policy: rejected LOGIN (username mismatch)")
		s.sendTagged(cmd.Tag, "NO", "Invalid credentials")
		return nil, errCloseSession
	}
	s.loginDone = true
	s.log.Info("LOGIN forwarded with the configured shared IMAP account")
	return []byte(cmd.Tag + " LOGIN " + quoteString(s.cfg.Username) + " " + quoteString(s.cfg.Password) + "\r\n"), nil
}

// forward writes one line upstream, relaying any literal payload that follows
// it. For a synchronizing literal the proxy sends its own continuation to the
// client and waits for (and the pump swallows) the upstream's continuation
// before writing the payload. The caller forwards the remainder of the command
// line (the command-terminating CRLF and any further arguments) on the next
// iteration.
func (s *session) forward(line []byte, hdr literalHeader, hasLiteral bool, client *bufio.Reader) error {
	if hasLiteral && hdr.Length > maxLiteralBytes {
		s.log.Error("protocol error", "error", errLiteralTooLarge)
		s.sendBYE("Command too large")
		return errCloseSession
	}
	if hasLiteral && hdr.Sync {
		ch, ok := s.cont.begin()
		if !ok {
			return errors.New("a literal continuation is already pending")
		}
		if err := writeFull(s.upstream, line); err != nil {
			s.cont.clear()
			return err
		}
		if err := s.clientW.write([]byte(goAhead)); err != nil {
			s.cont.clear()
			return err
		}
		if err := s.cont.wait(ch); err != nil {
			return err
		}
	} else if err := writeFull(s.upstream, line); err != nil {
		return err
	}
	if hasLiteral {
		if _, err := io.CopyN(s.upstream, client, hdr.Length); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: literal payload", errTruncated)
			}
			return err
		}
	}
	return nil
}

// pump forwards every upstream response to the client unchanged, while being
// literal-aware and consuming the continuation request that belongs to a
// synchronizing literal forwarded by the request loop.
func (s *session) pump() error {
	r := bufio.NewReaderSize(s.upstream, 4096)
	for {
		line, err := readLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.cont.deliver(io.EOF)
				return nil
			}
			s.cont.deliver(err)
			s.sendBYE("Upstream error")
			return err
		}
		if len(line) > 0 && line[0] == '+' {
			if s.cont.deliver(nil) {
				// Continuation for a literal the proxy forwarded: the client
				// already received the proxy's own continuation.
				continue
			}
			if err := s.clientW.write(line); err != nil {
				return err
			}
			continue
		}
		// Snapshot whether a literal continuation is armed before forwarding:
		// an upstream line that arrives while one is armed is that literal's
		// rejection, but a line read before a later command armed its own
		// continuation must not be mistaken for one. The request loop can arm
		// the next literal concurrently, so checking after the write would race.
		pending := s.cont.pending()
		// Forward the upstream response before waking a forwarder that is
		// waiting for a literal continuation, so the client sees the rejection
		// before the session closes.
		writeErr := s.clientW.write(line)
		if pending && s.cont.deliver(errUpstreamRejected) {
			// The upstream rejected the literal instead of accepting it.
			return errUpstreamRejected
		}
		if writeErr != nil {
			return writeErr
		}
		hdr, hasLiteral, err := parseLiteralHeader(line)
		if err != nil {
			s.sendBYE("Upstream protocol error")
			return err
		}
		if hasLiteral {
			if hdr.Length > maxLiteralBytes {
				return errLiteralTooLarge
			}
			if _, err := io.CopyN(s.clientW, r, hdr.Length); err != nil {
				return err
			}
		}
	}
}

func (s *session) sendTagged(tag, status, text string) {
	if err := s.clientW.write([]byte(tag + " " + status + " " + text + "\r\n")); err != nil {
		s.log.Debug("cannot send tagged response", "error", err)
	}
}

func (s *session) sendBYE(reason string) {
	if err := s.clientW.write([]byte("* BYE " + reason + "\r\n")); err != nil {
		s.log.Debug("cannot send BYE", "error", err)
	}
}

// isClosedError reports whether err means a connection we manage was closed
// (expected during session teardown).
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}
