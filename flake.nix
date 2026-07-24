{
  description = "Common authentication service used by my custom applications.";

  inputs.haskellNix.url = "github:input-output-hk/haskell.nix";
  inputs.nixpkgs.follows = "haskellNix/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils, haskellNix }:
    let
      supportedSystems = [
        "x86_64-linux"
      ];
    in
      flake-utils.lib.eachSystem supportedSystems (system:
      let
        overlays = [ haskellNix.overlay
          (final: _prev: {
            hixProject = final.haskell-nix.project' {
              src = ./.;
              compiler-nix-name = "ghc9141";

              shell.tools.cabal = "latest";
              # hlint dropped for now - no GHC 9.14 / base 4.22
              # compatible release yet (same as parent project).
              shell.tools.haskell-language-server = {
                modules = [{
                  doCheck = false;
                }];
                cabalProjectLocal = ''
                  package haskell-language-server
                    flags: -ghcide-bench
                  allow-newer: *:base, *:containers, *:template-haskell, *:ghc, *:time
                '';
              };
              shell.nativeBuildInputs = with final; [];
            };
          })
          # Overlay exposing the service executable as pkgs.marmay-auth
          (final: _prev: {
            marmay-auth = import ./nix/auth.nix {
              inherit (final) hixProject;
            };
          })
        ];
        pkgs = import nixpkgs { inherit system overlays; inherit (haskellNix) config; };
        flake = pkgs.hixProject.flake {};

        # Get packages from pkgs (which now has our overlay applied)
        marmay-auth = pkgs.marmay-auth;
      in flake // {
        legacyPackages = pkgs;

        # Add explicit package outputs for deployment
        packages = flake.packages // {
          marmay-auth = marmay-auth;
        };
      }) // {
      # NixOS module (system-agnostic). The wrapper injects this
      # flake's own package as the default, so consumers just import
      # the module - no specialArgs, no manual package wiring.
      nixosModules.marmay-auth = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.marmay-auth.package = lib.mkDefault
          self.packages.${pkgs.stdenv.hostPlatform.system}.marmay-auth;
      };
    };
  # --- Flake Local Nix Configuration ----------------------------
  nixConfig = {
    # This sets the flake to use the IOG nix cache.
    # Nix should ask for permission before using it,
    # but remove it here if you do not want it to.
    extra-substituters = ["https://cache.iog.io"];
    extra-trusted-public-keys = ["hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="];
    allow-import-from-derivation = "true";
  };
}
