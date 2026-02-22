{ lib, stdenv, fetchurl }:

let
  version = "v0.7.0";
  triplets = {
    "x86_64-linux"   = "x86_64-unknown-linux-gnu";
    "aarch64-linux"  = "aarch64-unknown-linux-gnu";
    "x86_64-darwin"  = "x86_64-apple-darwin";
    "aarch64-darwin" = "aarch64-apple-darwin";
  };
  hashes = {
    "x86_64-linux"   = "sha256-FVXW7HHbmxxp6vy7Ji5iy0Y483P9JJXUnkyE84j3gZk=";
    "aarch64-linux"  = "sha256-E5dir4E/UT0XiaKJxnEXRz9pIGRwWHr5fHkRPYN6T80=";
    "x86_64-darwin"  = "sha256-FyuXn7hlecZMDhghE6CknVWNN9JMOADzVUVIUxknO78=";
    "aarch64-darwin" = "sha256-8buoDdGtPDtrVQh7oIpmd9OYqTkS5byGgjo7zhNLn84=";
  };
  triplet = triplets.${stdenv.hostPlatform.system};
  tarball = fetchurl {
    url = "https://github.com/vacp2p/zerokit/releases/download/${version}/${triplet}-arkzkey-rln.tar.gz";
    hash = hashes.${stdenv.hostPlatform.system};
  };
in stdenv.mkDerivation {
  pname = "librln";
  inherit version;
  src = tarball;
  unpackPhase = "tar -xzf $src";
  installPhase = ''
    mkdir -p $out/lib
    cp release/librln.a $out/lib/librln_${version}.a
  '';
}
