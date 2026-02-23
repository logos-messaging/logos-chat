{ lib, stdenv, nim, which, pkg-config, writeScriptBin,
  openssl, miniupnpc, libnatpmp, darwin ? null,
  src,         # logos-chat source (self from flake, with submodules=1)
  libchatDrv,  # result of libchat.nix
  librln }:    # result of librln.nix

# NOTE: this build requires git submodules to be present in src.
# When fetching from GitHub use '?submodules=1#', e.g.:
#   nix build "github:logos-messaging/logos-chat?submodules=1#"
# For local builds use: nix build ".?submodules=1#"

assert lib.assertMsg ((src.submodules or false) == true)
  "Unable to build without submodules. Append '?submodules=1#' to the URI.";

let
  revision = lib.substring 0 8 (src.rev or "dirty");
  libExt = if stdenv.isDarwin then "dylib" else "so";
  libchatPath = "${libchatDrv}/lib/liblogos_chat.${libExt}";
in stdenv.mkDerivation {
  pname = "liblogoschat";
  version = "0.1.0";
  inherit src;

  NIMFLAGS = lib.concatStringsSep " " [
    "--passL:vendor/nwaku/librln_v0.7.0.a"
    "--passL:-lm"
    "-d:miniupnpcUseSystemLibs"
    "-d:libnatpmpUseSystemLibs"
    "--passL:-lminiupnpc"
    "--passL:-lnatpmp"
    "-d:CONVERSATIONS_LIB:${libchatPath}"
    "-d:git_version=${revision}"
  ];

  nativeBuildInputs = let
    fakeGit = writeScriptBin "git" ''
      #!${stdenv.shell}
      echo "${revision}"
    '';
  in [ nim which pkg-config fakeGit ];

  # Nim defaults to $HOME/.cache/nim; the sandbox maps $HOME to /homeless-shelter
  # which doesn't exist. Point XDG_CACHE_HOME at /tmp so Nim writes its cache there.
  XDG_CACHE_HOME = "/tmp";

  buildInputs = [ openssl miniupnpc libnatpmp ]
    ++ lib.optionals stdenv.isDarwin (with darwin.apple_sdk.frameworks; [
      Security
      CoreFoundation
      SystemConfiguration
    ]);

  configurePhase = ''
    runHook preConfigure
    patchShebangs . vendor/nimbus-build-system > /dev/null 2>&1 || true
    # Create logos_chat.nims symlink (if not already a real file)
    if [ ! -e logos_chat.nims ]; then
      ln -sf logos_chat.nimble logos_chat.nims
    fi
    # Regenerate nimble-link files with sandbox-correct absolute paths.
    # vendor/.nimble/pkgs contains paths baked in at `nimble develop` time on a
    # developer's machine; they won't resolve inside the Nix sandbox. Running
    # the same generate_nimble_links.sh that logos-delivery uses re-creates them
    # from the current $PWD without requiring git.
    make nimbus-build-system-nimble-dir
    runHook postConfigure
  '';

  preBuild = ''
    # Place pre-built librln where the Nim linker expects it
    cp ${librln}/lib/librln_v0.7.0.a vendor/nwaku/librln_v0.7.0.a
    mkdir -p build
  '';

  makeFlags = [ "liblogoschat-nix" ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib $out/include
    cp build/liblogoschat.so    $out/lib/ 2>/dev/null || true
    cp build/liblogoschat.dylib $out/lib/ 2>/dev/null || true
    ls $out/lib/liblogoschat.* > /dev/null
    cp library/liblogoschat.h   $out/include/
    runHook postInstall
  '';

  meta = with lib; {
    description = "Logos-Chat shared library (C FFI)";
    homepage = "https://github.com/logos-messaging/logos-chat";
    license = licenses.mit;
    platforms = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
  };
}
