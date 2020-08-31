with import <nixpkgs>;

bf-sde-p4-builder rec {
  version = "0.1";
  name = "packet-broker-${version}";
  p4Name = "packet_broker";

  src = ./.;
}
