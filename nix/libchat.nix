{ lib, stdenv, rust-bin, makeRustPlatform, perl, pkg-config, cmake,
  darwin ? null }:

let
  rustToolchain = rust-bin.fromRustupToolchainFile ../vendor/libchat/rust_toolchain.toml;
  rPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };
in rPlatform.buildRustPackage {
  pname = "liblogos-chat";
  version = "0.1.0";
  src = ../vendor/libchat;

  cargoLock = {
    lockFile = ../vendor/libchat/Cargo.lock;
    outputHashes = {
      "chat-proto-0.1.0" = "sha256-aCl80VOIkd/GK3gnmRuFoSAvPBfeE/FKCaNlLt5AbUU=";
    };
  };

  nativeBuildInputs = [ perl pkg-config cmake ];
  buildInputs = lib.optionals stdenv.isDarwin (with darwin.apple_sdk.frameworks; [
    Security
    SystemConfiguration
  ]);
  doCheck = false;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib
    cp target/*/release/liblogos_chat.so   $out/lib/ 2>/dev/null || true
    cp target/*/release/liblogos_chat.dylib $out/lib/ 2>/dev/null || true
    cp target/*/release/liblogos_chat.a    $out/lib/ 2>/dev/null || true
    # fallback: non-cross build path
    cp target/release/liblogos_chat.so   $out/lib/ 2>/dev/null || true
    cp target/release/liblogos_chat.dylib $out/lib/ 2>/dev/null || true
    cp target/release/liblogos_chat.a    $out/lib/ 2>/dev/null || true
    runHook postInstall
  '';
}
