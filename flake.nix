{
  description = "SPIFFE-mTLS IMAP proxy for one shared upstream account";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [ "x86_64-linux" ];
      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );
    in
    {
      packages = forAllSystems (
        { pkgs, ... }:
        let
          package = pkgs.callPackage ./package.nix { };
        in
        {
          default = package;
          imap-spiffe-proxy = package;
        }
      );

      nixosModules = {
        default = import ./module.nix;
        imap-spiffe-proxy = import ./module.nix;
      };

      checks = forAllSystems (
        { pkgs, system }:
        {
          imap-spiffe-proxy = self.packages.${system}.imap-spiffe-proxy;
          spire = import ./tests/spire.nix {
            inherit pkgs lib;
            package = self.packages.${system}.imap-spiffe-proxy;
          };
        }
      );
    };
}
