{ pkgs, lib, stdenv, libchatDrv }:

let
  libExt = if stdenv.isDarwin then "dylib" else "so";
  darwinDeps = lib.optionals stdenv.isDarwin (with pkgs.darwin.apple_sdk.frameworks; [
    Security CoreFoundation SystemConfiguration
  ]);
in pkgs.mkShell {
  buildInputs = with pkgs; [
    nim cargo rustc clippy rustfmt
    git cmake gnumake which pkg-config
    openssl miniupnpc libnatpmp
  ] ++ darwinDeps;

  shellHook = ''
    export CONVERSATIONS_LIB="${libchatDrv}/lib/liblogos_chat.${libExt}"
    echo "logos-chat dev shell. CONVERSATIONS_LIB=$CONVERSATIONS_LIB"
    echo "Build: make liblogoschat"
    echo "Nix build: nix build '.?submodules=1#'"
  '';
}
