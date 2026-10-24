{
  description = "context_signer_module: a logos.signer/1 signer for ed25519 identity keys derived per purpose and context. No network.";

  inputs = {
    # The Basecamp 0.3.2 generation (protocol 0.9.0), as the atlas's compatibility guide pins it.
    logos-module-builder.url = "github:logos-co/logos-module-builder/0.3.2";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross target the builder understands, never a host.
      targets = systems ++ [ "x86_64-windows" ];
      forAllTargets = f: nixpkgs.lib.genAttrs targets f;
    in
    {
      packages = forAllTargets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
