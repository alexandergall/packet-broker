{ sde_version, kernel_version }:

with import <nixpkgs>;
bf-sde.${sde_version}.${kernel_version}.buildP4Program rec {
  version = "0.1";
  name = "packet-broker-${version}";
  p4Name = "packet_broker";

  src = ./.;
}
