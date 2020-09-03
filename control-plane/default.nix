{ sde_version, kernel_version }:

let
  pkgs = import <nixpkgs>;
  bf-sde = pkgs.bf-sde.${sde_version}.${kernel_version};
in with pkgs; python2Packages.buildPythonApplication rec {
  pname = "packet-broker-configd";
  version = "0.1";

  src = ./.;

  propagatedBuildInputs = [
    bf-sde
    (python2.withPackages (ps: with ps; [ jsonschema ipaddress ]))
  ];
  buildInputs = [ makeWrapper ];

  postInstall = ''
    wrapProgram "$out/bin/configd.py" --set SDE "${bf-sde}" --set SDE_INSTALL "${bf-sde}/install"
  '';
}