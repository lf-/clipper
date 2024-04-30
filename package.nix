# SPDX-FileCopyrightText: 2023 Jade Lovelace
#
# SPDX-License-Identifier: MPL-2.0

{ rustPlatform, slirp4netns, pkg-config, protobuf, frida, libclang, openssl, stdenv, lib, makeWrapper }:
let wrapperArgs =
  lib.optional stdenv.isLinux
    [ "--prefix PATH ':' '${slirp4netns}/bin'" ];
in
rustPlatform.buildRustPackage {
  pname = "clipper";
  version = "0.0.1";

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "chromiumoxide_cdp-0.5.0" = "sha256-qJYD7N+LNgOX2UnJ1VukbKnhpEZIZcaoMkIWiXQ/nU4=";
    };
  };

  postFixup = ''
    rm $out/bin/*-fixture
    wrapProgram $out/bin/clipper --inherit-argv0 ${builtins.toString wrapperArgs}
  '';

  # I don't know why this doesn't work, but it definitely does not work.
  # Possibly the function we're trying to hook is getting LTO'd out?
  checkType = "debug";

  src = ./.;

  buildInputs = [
    frida.frida-gum
    openssl
  ];

  nativeBuildInputs = [
    rustPlatform.bindgenHook
    pkg-config
    protobuf
    makeWrapper
  ] ++ lib.optional stdenv.isLinux slirp4netns;

  LIBCLANG_PATH = "${libclang.lib}/lib";
}
