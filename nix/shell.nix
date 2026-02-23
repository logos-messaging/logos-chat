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
    echo "logos-chat dev shell."
    echo "Build: make liblogoschat"
    echo "Nix build: nix build '.?submodules=1#'"
  '';
}
