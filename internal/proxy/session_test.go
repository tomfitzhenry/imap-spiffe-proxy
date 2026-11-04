package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// testPeer is one end of a net.Pipe connection driven by a test.
type testPeer struct {
	conn net.Conn
	r    *bufio.Reader
}

func newTestPeer(c net.Conn) *testPeer {
	return &testPeer{conn: c, r: bufio.NewReaderSize(c, 4096)}
}

func (p *testPeer) write(t *testing.T, s string) {
	t.Helper()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(p.conn, s); err != nil {
		t.Fatalf("test peer write %q: %v", s, err)
	}
}

func (p *testPeer) readLine(t *testing.T) string {
	t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := p.r.ReadString('\n')
	if err != nil {
		t.Fatalf("test peer read line: %v", err)
	}
	return line
}

func (p *testPeer) readN(t *testing.T, n int) string {
	t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		t.Fatalf("test peer read %d bytes: %v", n, err)
	}
	return string(buf)
}

func (p *testPeer) expectClosed(t *testing.T) {
	t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.r.ReadByte(); err == nil {
		t.Fatal("connection stayed open, want it closed")
	}
}

// startTestSession wires a session to two net.Pipe peers and returns the
// client-side and upstream-side peers. The peer identity is read-write.
func startTestSession(t *testing.T) (*testPeer, *testPeer) {
	t.Helper()
	return startTestSessionPolicy(t, false)
}

// startReadOnlyTestSession is startTestSession for a read-only peer identity.
func startReadOnlyTestSession(t *testing.T) (*testPeer, *testPeer) {
	t.Helper()
	return startTestSessionPolicy(t, true)
}

// startTestSessionPolicy wires a session whose peer identity is alice, either
// read-write or read-only, mirroring how Proxy.handle derives the policy from
// the peer's SPIFFE ID.
func startTestSessionPolicy(t *testing.T, readOnly bool) (*testPeer, *testPeer) {
	t.Helper()
	clientConn, proxyClient := net.Pipe()
	proxyUpstream, upstreamConn := net.Pipe()

	const peerID = "spiffe://example.org/client/alice"
	cfg := Config{
		ListenAddress:       "127.0.0.1:1430",
		UpstreamAddress:     "imap.example.com:993",
		Username:            "shared",
		Password:            "real-password",
		ReadWriteIdentities: []string{peerID},
	}
	if readOnly {
		cfg.ReadWriteIdentities = nil
		cfg.ReadOnlyIdentities = []string{peerID}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	id, err := spiffeid.FromString(peerID)
	if err != nil {
		t.Fatalf("parse peer ID: %v", err)
	}

	sess := newSession(cfg, proxyClient, proxyUpstream, cfg.IsReadOnly(id), slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		sess.run()
		close(done)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		<-done
	})
	return newTestPeer(clientConn), newTestPeer(upstreamConn)
}

func TestSessionLoginInjectsConfiguredPassword(t *testing.T) {
	client, upstream := startTestSession(t)
	client.write(t, "A1 LOGIN \"shared\" \"client-supplied-password\"\r\n")
	if got, want := upstream.readLine(t), "A1 LOGIN \"shared\" \"real-password\"\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK Logged in\r\n")
	if got, want := client.readLine(t), "A1 OK Logged in\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionRejectsWrongUsername(t *testing.T) {
	client, _ := startTestSession(t)
	client.write(t, "A1 LOGIN \"someone-else\" \"password\"\r\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "A1 NO ") {
		t.Fatalf("client got %q, want a tagged NO", got)
	}
	client.expectClosed(t)
}

func TestSessionRejectsSecondLogin(t *testing.T) {
	client, upstream := startTestSession(t)
	client.write(t, "A1 LOGIN \"shared\" \"x\"\r\n")
	upstream.readLine(t)
	upstream.write(t, "A1 OK\r\n")
	client.readLine(t)

	client.write(t, "A2 LOGIN \"shared\" \"y\"\r\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "A2 NO ") {
		t.Fatalf("client got %q, want a tagged NO", got)
	}
	client.expectClosed(t)
}

func TestSessionRejectsAuthenticateAndStartTLS(t *testing.T) {
	for _, command := range []string{"AUTHENTICATE PLAIN", "STARTTLS"} {
		t.Run(command, func(t *testing.T) {
			client, upstream := startTestSession(t)
			client.write(t, "A1 "+command+"\r\n")
			if got := client.readLine(t); !strings.HasPrefix(got, "A1 NO ") {
				t.Fatalf("client got %q, want a tagged NO", got)
			}
			client.expectClosed(t)
			// Nothing may be forwarded upstream.
			_ = upstream.conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := upstream.r.ReadByte(); err == nil {
				t.Fatal("rejected command was forwarded upstream")
			}
		})
	}
}

func TestSessionRejectsUnparseableCommand(t *testing.T) {
	client, _ := startTestSession(t)
	client.write(t, "A1\r\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "* BYE ") {
		t.Fatalf("client got %q, want a BYE", got)
	}
	client.expectClosed(t)
}

func TestSessionForwardsSynchronizingLiteral(t *testing.T) {
	client, upstream := startTestSession(t)

	client.write(t, "A2 APPEND INBOX {5}\r\n")
	if got, want := upstream.readLine(t), "A2 APPEND INBOX {5}\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	// The proxy sends its own continuation; the upstream's is swallowed.
	if got, want := client.readLine(t), goAhead; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	upstream.write(t, "+ go ahead\r\n")
	// The literal payload is followed by the command-terminating CRLF, which
	// the proxy must forward upstream as part of the same command.
	client.write(t, "hello\r\n")
	if got, want := upstream.readN(t, 5), "hello"; got != want {
		t.Fatalf("upstream literal = %q, want %q", got, want)
	}
	if got, want := upstream.readLine(t), "\r\n"; got != want {
		t.Fatalf("upstream command terminator = %q, want %q", got, want)
	}
	upstream.write(t, "A2 OK appended\r\n")
	if got, want := client.readLine(t), "A2 OK appended\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionForwardsNonSynchronizingLiteral(t *testing.T) {
	client, upstream := startTestSession(t)

	client.write(t, "A3 APPEND INBOX {5+}\r\n")
	if got, want := upstream.readLine(t), "A3 APPEND INBOX {5+}\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	client.write(t, "hello\r\n")
	if got, want := upstream.readN(t, 5), "hello"; got != want {
		t.Fatalf("upstream literal = %q, want %q", got, want)
	}
	if got, want := upstream.readLine(t), "\r\n"; got != want {
		t.Fatalf("upstream command terminator = %q, want %q", got, want)
	}
	upstream.write(t, "A3 OK appended\r\n")
	if got, want := client.readLine(t), "A3 OK appended\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionUpstreamRejectsLiteral(t *testing.T) {
	client, upstream := startTestSession(t)

	client.write(t, "A2 APPEND INBOX {5}\r\n")
	upstream.readLine(t)
	client.readLine(t) // the proxy's continuation

	upstream.write(t, "A2 NO rejected\r\n")
	if got, want := client.readLine(t), "A2 NO rejected\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	client.expectClosed(t)
}

func TestSessionForwardsLiteralResponse(t *testing.T) {
	client, upstream := startTestSession(t)

	upstream.write(t, "* 1 FETCH (BODY[TEXT] {5}\r\n")
	if got, want := client.readLine(t), "* 1 FETCH (BODY[TEXT] {5}\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	upstream.write(t, "hello")
	if got, want := client.readN(t, 5), "hello"; got != want {
		t.Fatalf("client literal = %q, want %q", got, want)
	}
	upstream.write(t, ")\r\n")
	if got, want := client.readLine(t), ")\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionIdleDone(t *testing.T) {
	client, upstream := startTestSession(t)

	client.write(t, "A1 IDLE\r\n")
	if got, want := upstream.readLine(t), "A1 IDLE\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "+ idling\r\n")
	if got, want := client.readLine(t), "+ idling\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	client.write(t, "DONE\r\n")
	if got, want := upstream.readLine(t), "DONE\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK done\r\n")
	if got, want := client.readLine(t), "A1 OK done\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionRejectsBareLF(t *testing.T) {
	client, _ := startTestSession(t)
	client.write(t, "A1 NOOP\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "* BYE ") {
		t.Fatalf("client got %q, want a BYE", got)
	}
	client.expectClosed(t)
}

func TestSessionForwardsLiteralRemainderVerbatim(t *testing.T) {
	client, upstream := startTestSession(t)

	// A literal argument with a command-terminating CRLF after it. The proxy
	// forwards the payload and the remainder as part of the same command.
	client.write(t, "A1 CREATE {4}\r\n")
	upstream.readLine(t)
	client.readLine(t) // the proxy's continuation
	upstream.write(t, "+ go ahead\r\n")
	client.write(t, "name\r\n")
	if got, want := upstream.readN(t, 4), "name"; got != want {
		t.Fatalf("upstream literal = %q, want %q", got, want)
	}
	if got, want := upstream.readLine(t), "\r\n"; got != want {
		t.Fatalf("upstream command terminator = %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK created\r\n")
	if got, want := client.readLine(t), "A1 OK created\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}

	// The next line is a new command again and is still policy-parsed.
	client.write(t, "A2 AUTHENTICATE PLAIN\r\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "A2 NO ") {
		t.Fatalf("client got %q, want a tagged NO", got)
	}
	client.expectClosed(t)
}

func TestSessionRejectsLoginWithLiteral(t *testing.T) {
	client, upstream := startTestSession(t)
	client.write(t, "A1 LOGIN {5}\r\n")
	if got := client.readLine(t); !strings.HasPrefix(got, "A1 NO ") {
		t.Fatalf("client got %q, want a tagged NO", got)
	}
	client.expectClosed(t)
	_ = upstream.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := upstream.r.ReadByte(); err == nil {
		t.Fatal("LOGIN with a literal was forwarded upstream")
	}
}

// assertNotForwarded checks that a rejected command never reached the upstream.
func assertNotForwarded(t *testing.T, upstream *testPeer) {
	t.Helper()
	_ = upstream.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := upstream.r.ReadByte(); err == nil {
		t.Fatal("rejected command was forwarded upstream")
	}
}

func TestSessionReadOnlyAllowsNonMutatingCommands(t *testing.T) {
	commands := []string{
		"CAPABILITY",
		"NOOP",
		"EXAMINE INBOX",
		"UNSELECT",
		"STATUS INBOX (MESSAGES UNSEEN)",
		`LIST "" *`,
		`LSUB "" *`,
		"NAMESPACE",
		"SEARCH ALL",
		"FETCH 1 BODY[TEXT]",
		"SORT (DATE) UTF-8 ALL",
		"THREAD REFERENCES UTF-8 ALL",
		"UID FETCH 1:* (FLAGS)",
		"UID SEARCH ALL",
		"UID SORT (SUBJECT) UTF-8 ALL",
		"UID THREAD ORDEREDSUBJECT UTF-8 ALL",
		`GETQUOTA ""`,
		"GETQUOTAROOT INBOX",
		"MYRIGHTS INBOX",
		"ID NIL",
		"ENABLE CONDSTORE",
		"IDLE",
	}
	for _, line := range commands {
		t.Run(line, func(t *testing.T) {
			client, upstream := startReadOnlyTestSession(t)
			client.write(t, "A1 "+line+"\r\n")
			if got, want := upstream.readLine(t), "A1 "+line+"\r\n"; got != want {
				t.Fatalf("upstream got %q, want %q", got, want)
			}
			if line != "IDLE" {
				upstream.write(t, "A1 OK\r\n")
				if got, want := client.readLine(t), "A1 OK\r\n"; got != want {
					t.Fatalf("client got %q, want %q", got, want)
				}
			}
		})
	}
}

func TestSessionReadOnlyRejectsMutatingCommands(t *testing.T) {
	commands := []string{
		"APPEND INBOX {5}",
		"STORE 1 +FLAGS (\\Deleted)",
		"COPY 1 Archive",
		"MOVE 1 Archive",
		"EXPUNGE",
		"CLOSE",
		"CREATE foo",
		"DELETE foo",
		"RENAME foo bar",
		"SUBSCRIBE foo",
		"UNSUBSCRIBE foo",
		"CHECK",
		"SETACL INBOX alice lr",
		"DELETEACL INBOX alice",
		`SETQUOTA "" (STORAGE 10 20)`,
		"SETMETADATA INBOX (/private/comment x)",
		"UID STORE 1 +FLAGS (\\Deleted)",
		"UID COPY 1 Archive",
		"UID MOVE 1 Archive",
		"UID EXPUNGE 1",
		"UID 1",
		"FROBNICATE",
	}
	for _, line := range commands {
		t.Run(line, func(t *testing.T) {
			client, upstream := startReadOnlyTestSession(t)
			client.write(t, "A1 "+line+"\r\n")
			if got := client.readLine(t); !strings.HasPrefix(got, "A1 NO ") {
				t.Fatalf("client got %q, want a tagged NO", got)
			}
			client.expectClosed(t)
			assertNotForwarded(t, upstream)
		})
	}
}

func TestSessionReadOnlyLoginIsRewrittenAndReadsWork(t *testing.T) {
	client, upstream := startReadOnlyTestSession(t)
	client.write(t, "A1 LOGIN \"shared\" \"client-password\"\r\n")
	if got, want := upstream.readLine(t), "A1 LOGIN \"shared\" \"real-password\"\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK Logged in\r\n")
	if got, want := client.readLine(t), "A1 OK Logged in\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}

	client.write(t, "A2 FETCH 1 BODY[TEXT]\r\n")
	if got, want := upstream.readLine(t), "A2 FETCH 1 BODY[TEXT]\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "* 1 FETCH (BODY[TEXT] {5}\r\n")
	if got, want := client.readLine(t), "* 1 FETCH (BODY[TEXT] {5}\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	upstream.write(t, "hello")
	if got, want := client.readN(t, 5), "hello"; got != want {
		t.Fatalf("client literal = %q, want %q", got, want)
	}
	upstream.write(t, ")\r\n")
	if got, want := client.readLine(t), ")\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionReadOnlyRewritesSelectAsExamine(t *testing.T) {
	client, upstream := startReadOnlyTestSession(t)

	client.write(t, "A1 SELECT INBOX\r\n")
	if got, want := upstream.readLine(t), "A1 EXAMINE INBOX\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK [READ-ONLY] selected\r\n")
	if got, want := client.readLine(t), "A1 OK [READ-ONLY] selected\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}

	// A literal mailbox name keeps its literal marker when rewritten.
	client.write(t, "A2 SELECT {5}\r\n")
	if got, want := upstream.readLine(t), "A2 EXAMINE {5}\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	if got, want := client.readLine(t), goAhead; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
	upstream.write(t, "+ go ahead\r\n")
	client.write(t, "INBOX\r\n")
	if got, want := upstream.readN(t, 5), "INBOX"; got != want {
		t.Fatalf("upstream literal = %q, want %q", got, want)
	}
	if got, want := upstream.readLine(t), "\r\n"; got != want {
		t.Fatalf("upstream command terminator = %q, want %q", got, want)
	}
	upstream.write(t, "A2 OK [READ-ONLY] selected\r\n")
	if got, want := client.readLine(t), "A2 OK [READ-ONLY] selected\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionReadWriteDoesNotRewriteSelect(t *testing.T) {
	client, upstream := startTestSession(t)
	client.write(t, "A1 SELECT INBOX\r\n")
	if got, want := upstream.readLine(t), "A1 SELECT INBOX\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK [READ-WRITE] selected\r\n")
	if got, want := client.readLine(t), "A1 OK [READ-WRITE] selected\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}

func TestSessionReadWriteStillForwardsMutatingCommands(t *testing.T) {
	client, upstream := startTestSession(t)
	client.write(t, "A1 STORE 1 +FLAGS (\\Deleted)\r\n")
	if got, want := upstream.readLine(t), "A1 STORE 1 +FLAGS (\\Deleted)\r\n"; got != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
	upstream.write(t, "A1 OK stored\r\n")
	if got, want := client.readLine(t), "A1 OK stored\r\n"; got != want {
		t.Fatalf("client got %q, want %q", got, want)
	}
}
