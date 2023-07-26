# SPDX-FileCopyrightText: 2023 Jade Lovelace
#
# SPDX-License-Identifier: MPL-2.0

{ rustPlatform, slirp4netns, pkg-config, protobuf, frida, libclang, openssl }:
rustPlatform.buildRustPackage {
  pname = "clipper";
  version = "0.0.1";

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "chromiumoxide_cdp-0.5.0" = "sha256-qJYD7N+LNgOX2UnJ1VukbKnhpEZIZcaoMkIWiXQ/nU4=";
      "pcap-parser-0.14.0" = "sha256-Ur+gaNE7h6OEXaWrvPltMbBVkKJjm4paaPxSSGZHJ8g=";
    };
  };

  postFixup = ''
    rm $out/bin/*-fixture
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
    slirp4netns
    pkg-config
    protobuf
  ];

  LIBCLANG_PATH = "${libclang.lib}/lib";
}
