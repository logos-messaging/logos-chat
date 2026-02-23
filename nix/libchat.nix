{ rust-bin, makeRustPlatform, perl, pkg-config, cmake }:

let
  rustToolchain = rust-bin.fromRustupToolchainFile ../vendor/libchat/rust_toolchain.toml;
  rPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };
in rPlatform.buildRustPackage {
  pname = "libchat";
  version = "0.1.0";
  src = ../vendor/libchat;

  cargoLock = {
    lockFile = ../vendor/libchat/Cargo.lock;
    outputHashes = {
      "chat-proto-0.1.0" = "sha256-aCl80VOIkd/GK3gnmRuFoSAvPBfeE/FKCaNlLt5AbUU=";
    };
  };

  nativeBuildInputs = [ perl pkg-config cmake ];
  doCheck = false;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib
    cp target/*/release/liblibchat.so   $out/lib/ 2>/dev/null || true
    cp target/*/release/liblibchat.dylib $out/lib/ 2>/dev/null || true
    cp target/*/release/liblibchat.a    $out/lib/ 2>/dev/null || true
    # fallback: non-cross build path
    cp target/release/liblibchat.so   $out/lib/ 2>/dev/null || true
    cp target/release/liblibchat.dylib $out/lib/ 2>/dev/null || true
    cp target/release/liblibchat.a    $out/lib/ 2>/dev/null || true
    runHook postInstall
  '';
}
