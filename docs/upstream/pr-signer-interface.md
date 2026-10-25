# feat: an ed25519 family and scheme, for identity keys

**From:** corpetty/logos-signer-interface `feat/ed25519-family` (`3ebac51`), on `03eece5`.

Adds identity keys to `logos.signer/1`: an Ed25519 key for being someone somewhere, rather than for
holding coins, such as a member's authorship key in a chat room. It goes with
logos-co/logos-evm-keystore-module (identity groups) and logos-co/logos-signer-manager-module
(identity requests); see the issue for the design questions.

## What changes

- **`Family::Ed25519`.** An account carries its 32-byte public key, hex, as `address`, with no
  `path` and no `xpub`, and signs with its own key as an EVM account does.
- **`Scheme::Ed25519`.** Ed25519 (RFC 8032) with the item's 32 bytes as the message. The digest is
  the manager's, over a payload it parsed and rendered, so a screenless signer still signs nothing
  the person was not shown.
- **`verify::check`** holds the answer to the account's key with `verify_strict`. It refuses:
  - another key, including another key under the account's name;
  - another digest;
  - an item with a path;
  - another scheme.
- **Conformance:** the suite builds an item for the family and checks that its accounts carry a
  32-byte key and no xpub.
- **`docs/interface.md`** gains the rows.

Adding a `Family` variant breaks exhaustive matches downstream: the manager needs the same arms (its
branch has them). `#[non_exhaustive]` would spare the next family that.

## Tests

`cargo test --all-features`: every existing test passes unchanged. `verify` gains two:
- the RFC 8032 test-1 key and signature through the dalek API;
- an Ed25519 answer checked against the account, and each refusal above.

The mock signer has no Ed25519 account, since its keys are BIP-32 `XPrv`s. The keystore branch runs
the conformance suite on a real one.
