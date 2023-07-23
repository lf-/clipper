# SPDX-FileCopyrightText: 2023 Jade Lovelace
#
# SPDX-License-Identifier: MPL-2.0

{ rustPlatform, slirp4netns, pkg-config, protobuf, frida, libclang }:
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

  src = ./.;

  buildInputs = [
    frida.frida-gum
  ];

  nativeBuildInputs = [
    rustPlatform.bindgenHook
    slirp4netns
    pkg-config
    protobuf
  ];

  LIBCLANG_PATH = "${libclang.lib}/lib";
}
