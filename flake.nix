{
  description = "logos-chat shared library";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [ "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachSystem [
      "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"
    ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        libchatDrv = pkgs.callPackage ./nix/libchat.nix {};
        librln     = pkgs.callPackage ./nix/librln.nix {};
      in {
        packages.default = pkgs.callPackage ./nix/default.nix {
          src = self;
          inherit libchatDrv librln;
        };
        devShells.default = pkgs.callPackage ./nix/shell.nix {
          inherit libchatDrv;
        };
      }
    );
}
