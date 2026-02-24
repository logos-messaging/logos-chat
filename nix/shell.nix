{ pkgs, lib, stdenv, libchatDrv }:

let
  libExt = if stdenv.isDarwin then "dylib" else "so";
in pkgs.mkShell {
  buildInputs = with pkgs; [
    nim cargo rustc clippy rustfmt
    git cmake gnumake which pkg-config
    openssl miniupnpc libnatpmp
  ];

  shellHook = ''
    export CONVERSATIONS_LIB="${libchatDrv}/lib/liblogos_chat.${libExt}"
    echo "logos-chat dev shell. CONVERSATIONS_LIB=$CONVERSATIONS_LIB"
    echo "Build: make liblogoschat"
    echo "Nix build: nix build '.?submodules=1#'"
  '';
}
