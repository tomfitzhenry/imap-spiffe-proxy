package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	handshakeTimeout     = 10 * time.Second
	dialTimeout          = 10 * time.Second
	upstreamTLSHandshake = 10 * time.Second
	byeTimeout           = 5 * time.Second
)

// Proxy terminates SPIFFE mTLS and proxies authenticated IMAP sessions to one
// upstream IMAP server over mandatory TLS.
type Proxy struct {
	cfg         Config
	serverTLS   *tls.Config
	upstreamTLS *tls.Config
	log         *slog.Logger
}

// New builds the mTLS server configuration and the upstream TLS configuration.
// The exact allowlist is enforced inside the TLS handshake with AuthorizeOneOf,
// so a non-allowlisted SPIFFE ID cannot complete the handshake at all.
func New(cfg Config, source *workloadapi.X509Source, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if source == nil {
		return nil, errors.New("SPIFFE workload API source is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ids := cfg.AllowedIDs()
	if len(ids) == 0 {
		return nil, errors.New("at least one allowed SPIFFE ID is required")
	}
	return &Proxy{
		cfg:         cfg,
		serverTLS:   tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeOneOf(ids...)),
		upstreamTLS: cfg.UpstreamTLSConfig(),
		log:         logger,
	}, nil
}

// Serve accepts connections until ctx is cancelled, then closes the listener
// and every active connection and waits for the handlers to finish.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	tracker := newConnTracker()
	var wg sync.WaitGroup

	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			tracker.closeAll()
		case <-stopWatcher:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			wg.Wait()
			return fmt.Errorf("accept: %w", err)
		}
		if !tracker.add(conn) {
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer tracker.remove(conn)
			p.handle(ctx, conn)
		}()
	}
}

func (p *Proxy) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr().String()

	tlsConn := tls.Server(raw, p.serverTLS)
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		// The handshake (including SVID verification and the exact allowlist)
		// failed; nothing is proxied and the TLS alert is the client-visible
		// failure.
		p.log.Warn("mTLS handshake rejected", "remote", remote, "error", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	peerID, err := spiffetls.PeerIDFromConnectionState(tlsConn.ConnectionState())
	if err != nil {
		// AuthorizeOneOf should make this impossible; fail closed if not.
		p.log.Warn("mTLS handshake produced no peer SPIFFE ID", "remote", remote, "error", err)
		return
	}
	logger := p.log.With("spiffe_id", peerID.String(), "remote", remote)
	logger.Info("accepted mTLS connection")

	upstream, err := p.dialUpstream(ctx)
	if err != nil {
		logger.Error("upstream unavailable", "upstream", p.cfg.UpstreamAddress, "error", err)
		_ = tlsConn.SetWriteDeadline(time.Now().Add(byeTimeout))
		_, _ = io.WriteString(tlsConn, "* BYE Upstream unavailable\r\n")
		return
	}
	defer upstream.Close()

	sess := newSession(p.cfg, tlsConn, upstream, logger)
	sess.run()
}

// dialUpstream opens an implicit-TLS connection to the upstream IMAP server and
// completes the TLS handshake (certificate chain and hostname verification).
// There is deliberately no plaintext or STARTTLS fallback.
func (p *Proxy) dialUpstream(ctx context.Context) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", p.cfg.UpstreamAddress)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", p.cfg.UpstreamAddress, err)
	}
	conn := tls.Client(raw, p.upstreamTLS)
	hsCtx, cancel := context.WithTimeout(ctx, upstreamTLSHandshake)
	defer cancel()
	if err := conn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("upstream TLS handshake with %s: %w", p.cfg.UpstreamAddress, err)
	}
	return conn, nil
}

// connTracker tracks accepted connections so shutdown can close them.
type connTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]struct{})}
}

func (t *connTracker) add(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.conns[c] = struct{}{}
	return true
}

func (t *connTracker) remove(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, c)
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for c := range t.conns {
		_ = c.Close()
	}
}
