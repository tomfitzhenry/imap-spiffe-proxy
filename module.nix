{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.imap-spiffe-proxy;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    concatStringsSep
    escapeShellArg
    ;

  execArgs =
    [
      "-listen"
      (escapeShellArg cfg.listenAddress)
      "-upstream"
      (escapeShellArg cfg.upstreamAddress)
      "-username"
      (escapeShellArg cfg.username)
    ]
    ++ lib.optionals (cfg.upstreamTLSServerName != null) [
      "-upstream-server-name"
      (escapeShellArg cfg.upstreamTLSServerName)
    ]
    ++ lib.concatMap (identity: [
      "-rw"
      (escapeShellArg identity)
    ]) cfg.readWriteIdentities
    ++ lib.concatMap (identity: [
      "-ro"
      (escapeShellArg identity)
    ]) cfg.readOnlyIdentities
    ++ cfg.extraArgs;
in
{
  options.services.imap-spiffe-proxy = {
    enable = mkEnableOption "the SPIFFE-mTLS IMAP proxy";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The imap-spiffe-proxy package.";
    };

    listenAddress = mkOption {
      type = types.str;
      default = ":1430";
      description = "TCP address for the mTLS IMAP listener.";
    };

    upstreamAddress = mkOption {
      type = types.str;
      description = "Upstream IMAP server as host:port. The upstream hop is always implicit TLS.";
    };

    upstreamTLSServerName = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "TLS SNI/verification name for the upstream. Defaults to the host of upstreamAddress.";
    };

    username = mkOption {
      type = types.str;
      description = "The one shared upstream IMAP username.";
    };

    readWriteIdentities = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Exact SPIFFE IDs allowed to connect with full (read-write) IMAP command access, enforced in the TLS handshake.";
    };

    readOnlyIdentities = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Exact SPIFFE IDs allowed to connect but restricted to IMAP commands
        that do not change mailbox state (for example FETCH and SEARCH, but not
        STORE or APPEND). The proxy rejects every other command locally, and
        rewrites SELECT to EXAMINE so the upstream also enforces read-only
        selection. An identity must appear in exactly one of
        `readWriteIdentities` and `readOnlyIdentities`.
      '';
    };

    passwordFile = mkOption {
      type = types.path;
      description = "File holding the shared IMAP account's password. Loaded as the `imap-password` systemd credential.";
    };

    spireEndpointSocket = mkOption {
      type = types.str;
      default = "unix:///run/spire/agent/public/api.sock";
      description = "SPIFFE Workload API endpoint.";
    };

    spireGroup = mkOption {
      type = types.str;
      default = "spire-agent";
      description = "Group that can read the SPIRE Workload API socket.";
    };

    user = mkOption {
      type = types.str;
      default = "imap-proxy";
      description = "Service user.";
    };

    group = mkOption {
      type = types.str;
      default = "imap-proxy";
      description = "Service group.";
    };

    createUser = mkOption {
      type = types.bool;
      default = true;
      description = "Create the service user and group.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments appended to the proxy command line.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.readWriteIdentities != [ ] || cfg.readOnlyIdentities != [ ];
        message = "services.imap-spiffe-proxy needs at least one entry in readWriteIdentities or readOnlyIdentities.";
      }
      {
        assertion = lib.all (id: !(lib.elem id cfg.readWriteIdentities)) cfg.readOnlyIdentities;
        message = "services.imap-spiffe-proxy.readWriteIdentities and readOnlyIdentities must be disjoint.";
      }
    ];

    users.groups = lib.mkIf cfg.createUser {
      ${cfg.group} = { };
    };
    users.users = lib.mkIf cfg.createUser {
      ${cfg.user} = {
        isSystemUser = true;
        group = cfg.group;
      };
    };

    systemd.services.imap-spiffe-proxy = {
      description = "SPIFFE-mTLS IMAP proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "spire-agent.service" ];
      wants = [ "spire-agent.service" ];
      startLimitIntervalSec = 0;

      environment.SPIFFE_ENDPOINT_SOCKET = cfg.spireEndpointSocket;

      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        SupplementaryGroups = [ cfg.spireGroup ];
        LoadCredential = "imap-password:${cfg.passwordFile}";
        ExecStart = "${lib.getExe cfg.package} ${concatStringsSep " " execArgs}";
        Restart = "on-failure";
        RestartSec = 2;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        LockPersonality = true;
        RestrictRealtime = true;
        CapabilityBoundingSet = "";
        SystemCallArchitectures = "native";
      };
    };
  };
}
