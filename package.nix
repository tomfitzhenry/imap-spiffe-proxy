{ lib, buildGoModule }:

buildGoModule {
  pname = "imap-spiffe-proxy";
  version = "0.1.0";
  src = ./.;

  # Updated with `nix build .#imap-spiffe-proxy`; regenerate after changing
  # go.mod/go.sum.
  vendorHash = "sha256-4VRcgnFF38mbVyQ25Kz7dbVbmLxCjhdyskq4PUV1w2o=";

  subPackages = [
    "cmd/imap-spiffe-proxy"
    "cmd/imap-spiffe-client"
  ];

  checkPhase = ''
    runHook preCheck
    go test ./...
    runHook postCheck
  '';

  meta = {
    description = "SPIFFE-mTLS IMAP proxy that injects one shared upstream account's password";
    homepage = "https://github.com/tomfitzhenry/imap-spiffe-proxy";
    license = lib.licenses.mit;
    mainProgram = "imap-spiffe-proxy";
    platforms = lib.platforms.linux;
  };
}
