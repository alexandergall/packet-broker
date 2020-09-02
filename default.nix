let
  pkgs = import <nixpkgs>;
  bf-sde = import ./sde-version.nix pkgs;
in
bf-sde.buildP4Program rec {
  version = "0.1";
  name = "packet-broker-${version}";
  p4Name = "packet_broker";

  src = ./.;
}
