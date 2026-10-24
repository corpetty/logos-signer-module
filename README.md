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

It needs `../logos-signer-interface` on branch `feat/ed25519-family` beside this checkout, and
`logos-rust-sdk-src`, a symlink to a logos-rust-sdk checkout, for the module build.

Licensed under MIT or Apache-2.0.
