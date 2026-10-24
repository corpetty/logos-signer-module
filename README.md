# context_signer_module

A Logos signer, behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface),
for the families no other Logos signer holds: today an `ed25519` identity key. Each key is derived
from one recovery phrase by `(purpose, context)`, such as one key per room. Through
`signer_manager_module` it gives Muster's room identity the same approval path EVM and Bitcoin
signatures have.

- `docs/design.md`: where it sits and what it holds.
- `docs/proposal-logos-signer.md`: the draft upstream issue (not sent).

```sh
cd rust-lib && cargo test --no-default-features
```

It implements the interface with the `ed25519` family, pinned at
[corpetty/logos-signer-interface `feat/ed25519-family`](https://github.com/corpetty/logos-signer-interface/tree/feat/ed25519-family).

**Status: reference.** Ed25519 identity keys ship in `keystore_module` (branch
`feat/ed25519-identity`), because the keystore already holds the recovery phrase and a second signer
would need it imported again. This crate is where the derivation was proven, and the keystore's
tests are held to it. `nix build .#lgx` builds the module on
logos-module-builder `0.3.2`, the Basecamp 0.3.2 generation.

Licensed under MIT or Apache-2.0.
