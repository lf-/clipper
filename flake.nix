{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    frida-nix = {
      url = "github:itstarsun/frida-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, frida-nix }:
    let
      out = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ self.overlays.default ];
          };

          inherit (frida-nix.packages."${system}") frida-gum;
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              openssl
              frida-gum
            ];

            nativeBuildInputs = with pkgs; [
              bashInteractive
              rustPlatform.bindgenHook
              slirp4netns
              pkg-config
              protobuf
            ];

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          };

        };
    in
    flake-utils.lib.eachDefaultSystem out // {
      overlays.default = final: prev: { };
    };

}
