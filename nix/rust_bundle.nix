{ lib, stdenv, rust-bin, makeRustPlatform, perl, pkg-config, cmake, src }:

let
  rustToolchain = rust-bin.fromRustupToolchainFile (src + "/vendor/libchat/rust_toolchain.toml");
  rPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc  = rustToolchain;
  };
in rPlatform.buildRustPackage {
  pname = "logoschat_rust_bundle";
  version = "0.1.0";
  inherit src;
  cargoRoot = "rust-bundle";

  cargoLock = {
    lockFile = src + "/rust-bundle/Cargo.lock";
    outputHashes = {
      "chat-proto-0.1.0" = "sha256-aCl80VOIkd/GK3gnmRuFoSAvPBfeE/FKCaNlLt5AbUU=";
    };
  };

  nativeBuildInputs = [ perl pkg-config cmake ];
  doCheck = false;

  buildAndTestSubdir = "rust-bundle";

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib
    find "$CARGO_TARGET_DIR" -name "liblogoschat_rust_bundle.a" -path "*/release/*" -exec cp {} $out/lib/ \;
    test -f $out/lib/liblogoschat_rust_bundle.a
    runHook postInstall
  '';
}
