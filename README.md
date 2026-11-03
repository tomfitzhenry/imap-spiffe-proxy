# imap-spiffe-proxy

> **Disclaimer:** This project is vibe-coded. It has not been independently
> security-reviewed, audited, fuzzed, or production-hardened. Treat it as a
> prototype and obtain an independent review before using it with real
> credentials.

A small IMAP front door that authenticates clients with [SPIFFE][spiffe] mTLS
and injects one shared upstream IMAP account's password on `LOGIN`, so the
password never has to be distributed to the clients.

```
 client (X509-SVID) ──mTLS──> imap-spiffe-proxy ──implicit TLS──> IMAP server
 spiffe://example.org/client/alice   │                    (e.g. imap.gmail.com:993)
                                    └─ injects the one shared account password,
                                       read from a systemd LoadCredential
```

It was extracted from the [`imap-spiffe-proxy` demo][demo] in `nixos-demos` and
simplified: no config file, no `go-imap` dependency, no command buffering, and a
much smaller test suite.

## Properties

- No public certificate: the proxy's TLS identity is its SPIFFE X509-SVID from
  the local SPIRE agent Workload API, and clients are authenticated by mTLS.
- The exact SPIFFE-ID allowlist is enforced inside the TLS handshake
  (`tlsconfig.AuthorizeOneOf`): a valid SVID that is not on the allowlist cannot
  even complete the handshake.
- All allowlisted identities share one upstream IMAP account. On the first
  `LOGIN` a client must name the configured account; its password is discarded
  and the configured password is injected.
- The IMAP password is never a flag or config field. It is read once at startup
  from the systemd credential `imap-password`
  (`$CREDENTIALS_DIRECTORY/imap-password`) and never logged.
- The upstream hop is always implicit TLS with certificate chain and hostname
  verification against the system trust store. There is no plaintext or
  STARTTLS fallback and no per-proxy CA override.
- `AUTHENTICATE`, `STARTTLS`, a second `LOGIN`, a mismatched username, and
  unparseable commands are rejected locally and close the connection. Nothing
  unparsed is ever forwarded.
- Byte-exact pass-through for every other command and for all responses,
  including IMAP literals.

## Status and known limitations

- **One shared account.** Every allowlisted SVID gets the same mailbox. There is
  no per-user isolation, per-client quota, or separate audit trail beyond the
  proxy log. Removing an identity from the allowlist is a restart.
- **The password is a bearer secret.** It is a systemd credential, so root and
  the service can read it. There is no secret-manager integration and no
  rotation without replacing the credential and restarting the service.
- **LOGIN must not use literals.** The proxy parses the `LOGIN` line to find the
  username and rewrites it; a literal argument is rejected. Normal clients send
  quoted strings, which is supported. Every other command may use
  synchronizing (`{N}`) and non-synchronizing (`{N+}`) literals; the payload and
  the remainder of the command line are relayed byte-for-byte, as are literals
  in responses.
- No management API, rate limiting, metrics, hot reload, or persistent audit
  log. Configuration is flags plus a restart; the flag and module option surface
  is not yet stable.

## How it works

The proxy is a single process. For every accepted TCP connection it:

1. Terminates TLS with its server X509-SVID and the SPIFFE trust bundle from
   the Workload API (`SPIFFE_ENDPOINT_SOCKET`), enforcing the allowlist in the
   handshake.
2. Opens a separate implicit-TLS connection to `-upstream` and verifies the
   certificate chain and hostname against the system trust store.
3. Reads one client command line at a time. `LOGIN` is parsed and rewritten with
   the configured username and password; `AUTHENTICATE`, `STARTTLS` and a second
   `LOGIN` are refused; everything else is forwarded byte-for-byte.
4. Relays literal payloads in both directions. For a synchronizing client
   literal the proxy sends its own continuation, waits for the upstream's
   continuation (which it swallows), then streams the payload and forwards the
   rest of the command line (normally the terminating CRLF) upstream.
5. Forwards upstream responses unchanged, being literal-aware so response
   literals are not corrupted.

## Build

```sh
go build -o bin/imap-spiffe-proxy ./cmd/imap-spiffe-proxy
go build -o bin/imap-spiffe-client ./cmd/imap-spiffe-client
go test ./...
```

The only Go dependency is [`github.com/spiffe/go-spiffe/v2`][go-spiffe].

## Configuration

There is no config file; everything is a flag. The IMAP password comes only
from the systemd credential.

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:1430` | TCP address for the SPIFFE mTLS listener |
| `-upstream` | required | upstream IMAP server `host:port`; always implicit TLS |
| `-upstream-server-name` | host of `-upstream` | TLS SNI/verification name |
| `-username` | required | the one shared upstream IMAP username |
| `-allow` | required (repeatable) | exact client SPIFFE ID to allow |
| `-version` | | print the version and exit |

The proxy and the test client find the SPIRE agent through the standard
`SPIFFE_ENDPOINT_SOCKET` environment variable:

```sh
export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/public/api.sock
```

The password is a systemd credential. Create the secret as a root-only file and
reference it from the unit:

```sh
sudo install -d -m 0755 /etc/imap-spiffe-proxy
printf '%s\n' 'gmail-app-password' | sudo install -m 0400 /dev/stdin /etc/imap-spiffe-proxy/imap-password
```

```ini
[Service]
User=imap-proxy
Group=imap-proxy
LoadCredential=imap-password:/etc/imap-spiffe-proxy/imap-password
ExecStart=/nix/store/.../bin/imap-spiffe-proxy \
  -listen :1430 \
  -upstream imap.gmail.com:993 \
  -username user@gmail.com \
  -allow spiffe://example.org/client/alice
```

`LoadCredential=` gives the service a private read-only copy at
`$CREDENTIALS_DIRECTORY/imap-password`; the service account does not need direct
access to the root-only file. For local development, point
`CREDENTIALS_DIRECTORY` at a `0700` directory containing `imap-password`
instead. The proxy refuses to start without the credential.

## Nix flake and NixOS module

```sh
nix build .#imap-spiffe-proxy
nix flake check
```

The module is exposed as `nixosModules.default`:

```nix
services.imap-spiffe-proxy = {
  enable = true;
  listenAddress = ":1430";
  upstreamAddress = "imap.gmail.com:993";
  username = "user@gmail.com";
  passwordFile = "/run/secrets/imap-password";
  allowedIdentities = [
    "spiffe://example.org/client/alice"
    "spiffe://example.org/client/bob"
  ];
};
```

The module creates a dedicated `imap-proxy` user and a hardened systemd unit,
gives it the `spire-agent` group so it can read the Workload API socket, sets
`SPIFFE_ENDPOINT_SOCKET`, and passes the password as a `LoadCredential` (it is
never on the command line). `spireEndpointSocket`, `spireGroup`, `user`, `group`,
`createUser`, `upstreamTLSServerName` and `extraArgs` are overridable.

## SPIRE registration

Run a SPIRE server and agent for your trust domain, then register the proxy and
each allowed client workload. The proxy's own SVID is its TLS server
certificate; clients pin it with the test client's `-server-id`.

```sh
# The proxy, selected by its service user.
spire-server entry create \
  -parentID spiffe://example.org/spire/agent/<agent-id> \
  -spiffeID spiffe://example.org/proxy/imap-spiffe-proxy \
  -selector unix:user:imap-proxy

# Each allowed client, selected by uid (or use unix:path / unix:sha256).
spire-server entry create \
  -parentID spiffe://example.org/spire/agent/<agent-id> \
  -spiffeID spiffe://example.org/client/alice \
  -selector unix:uid:$(id -u alice)
```

Registration and authorization are separate: `entry create` only decides which
workloads can obtain which SVID. Whether an SVID can use the proxy is decided
solely by `-allow` / `allowedIdentities`, inside the TLS handshake. The IDs must
match exactly.

## Gmail

Gmail no longer accepts a normal account password for IMAP. For an App Password:

1. Enable IMAP in the Gmail account settings.
2. Enable 2-Step Verification.
3. Create an [App Password][gmail-app-password] and put it in the credential
   file above.
4. Use the full Gmail address as `-username`, `imap.gmail.com:993` as
   `-upstream`, and `imap.gmail.com` as `-upstream-server-name`. No CA setting is
   needed: the proxy verifies with the system trust store.

OAuth2/XOAUTH2 is out of scope: the proxy only supports `LOGIN` and rejects
`AUTHENTICATE`. Revoking the App Password in the Google account immediately
disables the proxy's access.

## Test client

`imap-spiffe-client` obtains its own SVID from the Workload API, verifies the
proxy's SPIFFE ID, and exercises the proxy. It is used by the integration test
but is also useful for manual checks:

```sh
export SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/public/api.sock
./bin/imap-spiffe-client \
  -addr 127.0.0.1:1430 \
  -server-id spiffe://example.org/proxy/imap-spiffe-proxy \
  -username user@gmail.com \
  -mode login
```

Modes: `login` (LOGIN with a deliberately wrong password, SELECT, APPEND with a
synchronizing literal, SEARCH, FETCH and verify the body, LOGOUT), `idle`,
`wrong-username`, `auth`, `malformed`, and `deny` (must be rejected in the TLS
handshake). Every mode exits 0 only when the expected outcome is observed.

## Integration test

`checks.x86_64-linux.spire` is a NixOS VM test with a real SPIRE server and
agent (`x509pop` node attestation), a Dovecot 2.4 implicit-TLS IMAP server
whose test CA is added to the VM's system trust store, and the proxy from the
NixOS module. It asserts that:

- alice and bob log in through the proxy to the single shared Dovecot account
  (Dovecot's journal shows `user=<shared-imap>`, never alice or bob), proving
  that the proxy obtains its SVID from SPIRE, verifies the upstream TLS with the
  system trust store, loads the password from the systemd credential, and
  injects it;
- mallory, who has a valid SVID but is not allowlisted, is rejected and the
  proxy stays healthy;
- a mismatched username, `AUTHENTICATE`, and malformed commands are rejected;
- `IDLE`/`DONE` and a synchronizing-literal `APPEND` plus a literal `FETCH`
  round-trip.

Everything is local to the VM; it needs KVM but no host SPIRE, Gmail account, or
network.

## Security notes

- mTLS authenticates the client connection. The injected IMAP password remains
  a bearer credential: any allowlisted client can use the shared mailbox, and a
  malicious client with an allowlisted SVID is indistinguishable from a
  legitimate one until its SVID expires or its SPIRE entry is removed.
- The proxy log contains peer SPIFFE IDs and remote addresses, but never
  passwords, client-supplied password bytes, or SVID private keys.
- A private upstream CA must be installed in the host's system trust store;
  there is deliberately no per-proxy CA flag.
- The demo's motivating deployment is one shared Gmail account used by several
  short-lived workloads. Treat the account as shared and audit accordingly.

## License

MIT. Derived from the `imap-spiffe-proxy` demo in
[`nixos-demos`][demo], same author.

[spiffe]: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
[go-spiffe]: https://github.com/spiffe/go-spiffe
[demo]: https://github.com/tomfitzhenry/nixos-demos
[gmail-app-password]: https://support.google.com/accounts/answer/185833
