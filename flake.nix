# SPDX-FileCopyrightText: 2023 Jade Lovelace
#
# SPDX-License-Identifier: MPL-2.0

{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    frida-nix = {
      url = "github:itstarsun/frida-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, flake-utils, frida-nix, rust-overlay }:
    let
      out = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default rust-overlay.overlays.default frida-nix.overlays.default ];
          };

          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          myRustPlatform = pkgs.makeRustPlatform {
            rustc = rust;
            cargo = rust;
          };

          inherit (pkgs) lib stdenv;
        in
        {
          packages.default = pkgs.callPackage ./package.nix { rustPlatform = myRustPlatform; };

          checks = {
            reuse = pkgs.runCommand "reuse-lint" { nativeBuildInputs = [ pkgs.reuse ]; } ''
              reuse --root ${./.} lint
              touch $out
            '';
          };

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              openssl
              frida.frida-gum
            ];

            nativeBuildInputs = with pkgs; [
              bashInteractive
              rustPlatform.bindgenHook
              pkg-config
              protobuf
              reuse
            ] ++ lib.optional stdenv.isLinux pkgs.slirp4netns;

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          };

        };

        supportedSystems = [
          "x86_64-linux"
          "aarch64-linux"
          "x86_64-darwin"
          "aarch64-darwin"
        ];
    in
    flake-utils.lib.eachSystem supportedSystems out // {
      overlays.default = final: prev: { };
    };

}
