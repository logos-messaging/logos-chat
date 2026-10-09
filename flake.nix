{
  description = "libchat - Logos Chat cryptographic library";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [ "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU=" ];
  };

  inputs = {
    # nixos-unstable-small has both crates.io UA fixes (NixOS/nixpkgs#512735,
    # NixOS/nixpkgs#524985); nixos-unstable hasn't caught up yet as of 2026-05-28.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    logos-delivery = {
      url = "github:logos-messaging/logos-delivery/991d9dff74582b595ae3573aa50774e9db9a4249";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, logos-delivery }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      });
    in
    {
      packages = forAllSystems ({ system, ... }:
        {
          logos-delivery = logos-delivery.packages.${system}.liblogosdelivery.override {
            enablePostgres = false;
            enableNimDebugDlOpen = false;
            chroniclesLogLevel = "FATAL";
          };
        }
      );

      devShells = forAllSystems ({ pkgs, system, ... }:
        let
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust_toolchain.toml;
          logosDeliveryLib = self.packages.${system}.logos-delivery;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              rustToolchain
              pkgs.pkg-config
              pkgs.cmake
              pkgs.perl
              pkgs.protobuf
            ]
            # components/build.rs rewrites the dylib soname via patchelf on
            # Linux so consumers link without their own build.rs. macOS uses
            # install_name_tool, which ships with the toolchain.
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.patchelf ];
            buildInputs = [ logosDeliveryLib ];
            shellHook = ''
              export LOGOS_DELIVERY_LIB_DIR="${logosDeliveryLib}/lib"
            '';
          };
        }
      );
    };
}
