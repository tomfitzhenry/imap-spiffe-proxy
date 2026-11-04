# End-to-end test for the SPIFFE-mTLS IMAP proxy.
#
# One VM runs a real SPIRE server and agent (x509pop node attestation), Dovecot
# 2.4 serving IMAP over implicit TLS, and the proxy from ../module.nix. It
# proves the properties the proxy exists for: the client leg is mTLS with an
# exact SPIFFE-ID allowlist enforced in the TLS handshake; a valid SVID that is
# not allowlisted is denied; the upstream leg is implicit TLS verified against
# the system trust store (the test CA is added to it); every allowlisted
# identity maps to one shared IMAP account whose password comes only from a
# systemd LoadCredential; AUTHENTICATE, malformed commands and a mismatched
# LOGIN username are rejected without disturbing the service; and a read-only
# identity can read but cannot mutate, again without disturbing the service.
{ pkgs, lib, package }:

let
  trustDomain = "example.org";

  # Fixed numeric UIDs: the testScript's setpriv invocations and SPIRE's
  # `unix:uid:` workload selectors must agree. The proxy account (imap-proxy)
  # is created by the module and selected by name.
  aliceUid = 4500;
  bobUid = 4501;
  malloryUid = 4502;
  carolUid = 4503;
  sharedUid = 4600;

  proxyListen = "127.0.0.1:1430";
  dovecotTLSListen = "127.0.0.1:993";

  spireServerSocket = "/run/spire/server/private/api.sock";
  spireAgentSocket = "/run/spire/agent/public/api.sock";
  agentBundle = "/run/spire/agent/bundle.pem";

  sharedUsername = "shared-imap";
  sharedPassword = "shared-imap-password";

  nodeID = "spiffe://${trustDomain}/agent/spire-node";
  proxyID = "spiffe://${trustDomain}/proxy/imap-spiffe-proxy";
  aliceID = "spiffe://${trustDomain}/client/alice";
  bobID = "spiffe://${trustDomain}/client/bob";
  malloryID = "spiffe://${trustDomain}/client/mallory";
  carolID = "spiffe://${trustDomain}/client/carol";

  # The proxy only ever reads $CREDENTIALS_DIRECTORY/imap-password; tmpfiles
  # installs this test-only credential at /run with mode 0400.
  imapPasswordFile = pkgs.writeText "imap-spiffe-proxy-imap-password" sharedPassword;

  # One build-time CA signs both the SPIRE x509pop agent certificate and
  # Dovecot's TLS certificate. security.pki.certificateFiles adds it to the
  # VM's system trust store, the only trust store the proxy uses.
  testCerts = pkgs.runCommand "imap-spiffe-proxy-test-certs" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    mkdir -p $out
    cd $out

    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -key ca.key -sha256 -days 3650 \
      -subj "/CN=imap-spiffe-proxy-test-ca" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt

    printf '%s\n' 'keyUsage=digitalSignature' 'extendedKeyUsage=clientAuth' > agent.ext
    openssl ecparam -name prime256v1 -genkey -noout -out agent.key
    openssl req -new -key agent.key -subj "/CN=spire-test-agent" -out agent.csr
    openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -sha256 -extfile agent.ext -out agent.crt

    printf '%s\n' \
      'basicConstraints=critical,CA:FALSE' \
      'keyUsage=critical,digitalSignature' \
      'extendedKeyUsage=serverAuth' \
      'subjectAltName=DNS:localhost,IP:127.0.0.1' > server.ext
    openssl ecparam -name prime256v1 -genkey -noout -out server.key
    openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -sha256 -extfile server.ext -out server.crt

    rm -f *.csr *.ext ca.srl
    openssl verify -CAfile ca.crt agent.crt server.crt
  '';

  # Runs as root before the agent starts: publishes the trust bundle and
  # registers the x509pop node entry plus one workload entry per identity.
  bootstrap = pkgs.writeShellScript "spire-bootstrap" ''
    set -eu
    server=${pkgs.spire}/bin/spire-server
    socket=${spireServerSocket}

    for _ in $(${pkgs.coreutils}/bin/seq 1 300); do
      if "$server" healthcheck -socketPath "$socket" >/dev/null 2>&1; then
        break
      fi
      ${pkgs.coreutils}/bin/sleep 1
    done

    # 0755 so unprivileged workloads can traverse to the public API socket.
    ${pkgs.coreutils}/bin/install -d -m 0755 -o spire-agent -g spire-agent /run/spire/agent
    "$server" bundle show -socketPath "$socket" -format pem > ${agentBundle}
    ${pkgs.coreutils}/bin/chown spire-agent:spire-agent ${agentBundle}
    ${pkgs.coreutils}/bin/chmod 0444 ${agentBundle}

    have_entry() {
      "$server" entry show -socketPath "$socket" -output json | ${pkgs.gnugrep}/bin/grep -q "$1"
    }

    if ! have_entry "${nodeID}"; then
      "$server" entry create -socketPath "$socket" -node \
        -parentID "spiffe://${trustDomain}/spire/server" \
        -spiffeID "${nodeID}" \
        -selector "x509pop:subject:cn:spire-test-agent"
    fi

    create_workload() {
      if ! have_entry "$2"; then
        "$server" entry create -socketPath "$socket" -parentID "${nodeID}" \
          -spiffeID "$2" -selector "$1"
      fi
    }

    create_workload "unix:user:imap-proxy" "${proxyID}"
    create_workload "unix:uid:${toString aliceUid}" "${aliceID}"
    create_workload "unix:uid:${toString bobUid}" "${bobID}"
    create_workload "unix:uid:${toString malloryUid}" "${malloryID}"
    create_workload "unix:uid:${toString carolUid}" "${carolID}"
  '';
in
pkgs.testers.nixosTest {
  name = "imap-spiffe-proxy";

  nodes.machine =
    { config, ... }:
    {
      imports = [ ../module.nix ];

      virtualisation = {
        memorySize = 2048;
        cores = 2;
      };
      system.stateVersion = "26.05";

      # The proxy verifies the upstream against the system trust store only.
      security.pki.certificateFiles = [ "${testCerts}/ca.crt" ];

      # --- test identities ------------------------------------------------
      users.users = {
        alice = {
          isNormalUser = true;
          uid = aliceUid;
          group = "alice";
        };
        bob = {
          isNormalUser = true;
          uid = bobUid;
          group = "bob";
        };
        mallory = {
          isNormalUser = true;
          uid = malloryUid;
          group = "mallory";
        };
        carol = {
          isNormalUser = true;
          uid = carolUid;
          group = "carol";
        };
        # The one shared upstream IMAP account every allowlisted identity maps
        # to; it is the only account Dovecot ever authenticates.
        shared-imap = {
          isNormalUser = true;
          uid = sharedUid;
          group = "shared-imap";
          password = sharedPassword;
        };
      };
      users.groups = {
        alice.gid = aliceUid;
        bob.gid = bobUid;
        mallory.gid = malloryUid;
        carol.gid = carolUid;
        shared-imap.gid = sharedUid;
      };

      # --- upstream: Dovecot 2.4, IMAP over implicit TLS ------------------
      services.dovecot2 = {
        enable = true;
        enablePAM = true;
        settings = {
          dovecot_config_version = pkgs.dovecot.version;
          dovecot_storage_version = pkgs.dovecot.version;
          protocols.imap = true;
          mail_driver = "maildir";
          mail_home = "/home/%{user}";
          mail_path = "~/mail";
          listen = "127.0.0.1";
          ssl_server_cert_file = "${testCerts}/server.crt";
          ssl_server_key_file = "${testCerts}/server.key";
          ssl_server_ca_file = "${testCerts}/ca.crt";
          auth_allow_cleartext = true;
        };
      };

      # --- SPIRE server (x509pop node attestation) ------------------------
      services.spire.server = {
        enable = true;
        settings = {
          server = {
            trust_domain = trustDomain;
            bind_address = "127.0.0.1";
            bind_port = 8081;
          };
          plugins = {
            DataStore.sql.plugin_data = {
              database_type = "sqlite3";
              connection_string = "$STATE_DIRECTORY/datastore.sqlite3";
            };
            KeyManager.disk.plugin_data = {
              keys_path = "$STATE_DIRECTORY/keys.json";
            };
            NodeAttestor.x509pop.plugin_data = {
              ca_bundle_path = "${testCerts}/ca.crt";
            };
          };
        };
      };

      # --- SPIRE agent ----------------------------------------------------
      services.spire.agent = {
        enable = true;
        settings = {
          agent = {
            trust_domain = trustDomain;
            server_address = "127.0.0.1";
            server_port = 8081;
            socket_path = spireAgentSocket;
            trust_bundle_path = agentBundle;
          };
          plugins = {
            KeyManager.memory.plugin_data = { };
            NodeAttestor.x509pop.plugin_data = {
              private_key_path = "${testCerts}/agent.key";
              certificate_path = "${testCerts}/agent.crt";
            };
            WorkloadAttestor.unix.plugin_data = { };
          };
        };
      };

      systemd.services.spire-agent = {
        after = [ "spire-server.service" ];
        wants = [ "spire-server.service" ];
        serviceConfig.ExecStartPre = lib.mkBefore [ "+${bootstrap}" ];
      };

      # --- the proxy under test -------------------------------------------
      # 0400 credential, installed by tmpfiles from the store; the module maps
      # it to LoadCredential=imap-password:<path>.
      systemd.tmpfiles.rules = [
        "d /run/imap-spiffe-proxy 0750 root root -"
        "C+ /run/imap-spiffe-proxy/imap-password 0400 root root - ${imapPasswordFile}"
      ];

      services.imap-spiffe-proxy = {
        enable = true;
        package = package;
        listenAddress = proxyListen;
        upstreamAddress = dovecotTLSListen;
        upstreamTLSServerName = "localhost";
        username = sharedUsername;
        readWriteIdentities = [
          aliceID
          bobID
        ];
        # carol may read but must not mutate; the two lists are disjoint.
        readOnlyIdentities = [ carolID ];
        passwordFile = "/run/imap-spiffe-proxy/imap-password";
      };

      systemd.services.imap-spiffe-proxy = {
        after = [ "dovecot.service" ];
        wants = [ "dovecot.service" ];
      };

      environment.systemPackages = [ pkgs.util-linux ];
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("spire-server.service", timeout=120)
    machine.wait_until_succeeds(
        "spire-server healthcheck -socketPath ${spireServerSocket}", timeout=120
    )
    machine.wait_for_unit("spire-agent.service", timeout=180)
    machine.wait_until_succeeds(
        "spire-agent healthcheck -socketPath ${spireAgentSocket}", timeout=180
    )
    machine.wait_for_unit("dovecot.service", timeout=120)
    machine.wait_for_unit("imap-spiffe-proxy.service", timeout=180)
    machine.wait_for_open_port(1430, timeout=180)

    client = "${package}/bin/imap-spiffe-client"
    setpriv = "${pkgs.util-linux}/bin/setpriv"
    addr = "${proxyListen}"
    server_id = "${proxyID}"
    username = "${sharedUsername}"
    env = "SPIFFE_ENDPOINT_SOCKET=unix://${spireAgentSocket}"

    def imap_client(uid, mode):
        return (
            f"{env} {setpriv} --reuid={uid} --regid={uid} --init-groups -- "
            f"{client} -addr {addr} -server-id {server_id} "
            f"-username {username} -mode {mode}"
        )

    def count_shared_logins():
        output = machine.succeed(
            "journalctl -u dovecot.service --no-pager --output=cat | "
            "grep -c 'Logged in: user=<shared-imap>' || true"
        )
        return int(output.strip() or "0")

    def wait_for_shared_logins(at_least):
        machine.wait_until_succeeds(
            "n=$(journalctl -u dovecot.service --no-pager --output=cat | "
            "grep -c 'Logged in: user=<shared-imap>'); "
            f'[ "$n" -ge {at_least} ]',
            timeout=30,
        )

    with subtest("the proxy runs unprivileged with a systemd credential"):
        user = machine.succeed(
            "systemctl show -p User --value imap-spiffe-proxy.service"
        ).strip()
        assert user == "imap-proxy", user
        unit = machine.succeed("systemctl cat imap-spiffe-proxy.service")
        assert (
            "LoadCredential=imap-password:/run/imap-spiffe-proxy/imap-password" in unit
        ), unit

    with subtest("alice logs in to the shared IMAP account over a TLS upstream"):
        machine.wait_until_succeeds(
            imap_client(${toString aliceUid}, "login"), timeout=120
        )
        wait_for_shared_logins(1)

    with subtest("bob logs in to the same shared IMAP account"):
        before = count_shared_logins()
        machine.succeed(imap_client(${toString bobUid}, "login"), timeout=120)
        wait_for_shared_logins(before + 1)

    with subtest("IDLE/DONE round-trips through the proxy"):
        machine.succeed(imap_client(${toString aliceUid}, "idle"), timeout=60)

    with subtest("a LOGIN for a different username is rejected"):
        machine.succeed(imap_client(${toString aliceUid}, "wrong-username"), timeout=60)

    with subtest("AUTHENTICATE is rejected"):
        machine.succeed(imap_client(${toString aliceUid}, "auth"), timeout=60)

    with subtest("malformed commands are rejected"):
        machine.succeed(imap_client(${toString aliceUid}, "malformed"), timeout=60)

    with subtest("mallory has a valid SVID but is not allowlisted"):
        machine.succeed(imap_client(${toString malloryUid}, "deny"), timeout=60)
        machine.succeed("systemctl is-active imap-spiffe-proxy.service")
        machine.succeed(imap_client(${toString aliceUid}, "login"), timeout=120)

    with subtest("a read-only identity can read but cannot mutate"):
        # The client exits 0 only if its reads succeeded and the proxy answered
        # its STORE with a tagged NO and closed the connection.
        machine.succeed(imap_client(${toString carolUid}, "read-only"), timeout=120)
        machine.succeed("systemctl is-active imap-spiffe-proxy.service")
        machine.succeed(imap_client(${toString aliceUid}, "login"), timeout=120)
  '';

  meta.timeout = 900;
}
