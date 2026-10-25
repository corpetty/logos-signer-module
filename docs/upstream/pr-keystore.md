# feat: identity keys (ed25519) from the phrase the keystore holds

**From:** corpetty/logos-evm-keystore-module `feat/ed25519-identity` (`b3dc6bc`), on `127d4ac`.

Identity keys come from the phrase the keystore already holds, so the phrase stays in one place. It
goes with the signer interface's `ed25519` family (pinned here at corpetty `3ebac51`) and the
manager's identity requests; see the issue for the design questions.

## What changes

- **An identity group** keeps one SLIP-0010 node, `m/7432'/0'`, and never the root, as every other
  group keeps its account level. It is made from a typed or kept phrase, as a Bitcoin wallet is, and
  there is one per phrase and passphrase.
  - **Vault:** `{ v: 1, family: "ed25519", node }` in the usual scrypt envelope.
  - **Record:** `family: "ed25519"`, `pathPrefix`, the phrase's `fingerprint`, `nodeKey` (the node's
    public key, which every opening checks the vault against), and `identities`.
- **Each identity key** is named by a purpose and a context: `m/7432'/0'/c0'…c7'`, hardened. The
  `c`s are the first 248 bits of SHA-256 over the dCBOR record `["logos.signer.context.v1",
  {context, purpose}]`.
  - The same phrase gives the same key on every device, and two contexts give keys nobody can link.
  - Adding one opens the node, never the phrase.
  - `7432'` is a placeholder: please choose the number.
- **Tier D:** `import_identity`, `derive_identity` (idempotent). Both announce.
- **`logos.signer/1`:** each identity key is an `ed25519` account.
  - `id` is `kr_` + 16 bytes of a hash over the node key, scheme, purpose and context: stable across
    a restore, and naming no path.
  - `address` is the public key, and `fingerprint` is the phrase's.
  - The label is the purpose. The context is not listed, since it may name a room.
  - It signs `ed25519` hash items with the password or inside an unlock, like every account.
- **What an identity opens** (Tier M, the keystore's own, outside `logos.signer/1`):
  - `identity_open` opens libsodium sealed boxes (`crypto_box_seal`) addressed to the identity's
    X25519 form;
  - `identity_secret` is HMAC-SHA256 keyed by the identity's seed over a record.
  - Both take the password or work inside the unlock, one request counting once. Neither returns a
    key. This is a proposal: see the issue's question on decryption.
- **Fix, exposed by the family:** every record naming a `family` was read as a Bitcoin wallet in six
  places (`bitcoin_groups`, custody proofs, seed matching, account origins, derivation and forget
  refusals). Now `Group::is_bitcoin` / `Group::is_identity`.
- **Docs:** `docs/specs.md` § Identity keys, and the tier tables.

## Tests

`cargo test --no-default-features`: 226 pass (213 before):
- **`identity`:**
  - SLIP-0010 vector 1;
  - keys equal to an independent derivation of the same path from the root;
  - unlinkable contexts;
  - node round trip;
  - dCBOR record bytes;
  - key refs;
  - vectors made by libsodium itself (`tools/gen_libsodium_vectors.py`): keys, signature, X25519
    conversion, sealed-box open, derived secret;
  - a box for someone else, or altered, does not open.
- **`keystore`:**
  - one node and never the root (the vault's fields are exactly `family`, `node`, `v`);
  - the phrase's fingerprint;
  - one group per phrase;
  - the group is not Bitcoin, not EVM-derivable, and its key not forgettable;
  - the same key and ref after a restore;
  - a wrong password records nothing;
  - a swapped vault signs nothing;
  - a kept phrase is named.
- **`signer`:**
  - the fixture now holds an identity key, so the conformance suite and the unlock test run on it;
  - opening and deriving with a password, inside an unlock (counted once), and their refusals.

`nix build .#lgx` and `.#lgx-portable` build. Under logoscore 0.3.1, `signer_info` lists `ed25519`,
and the CLI is refused `import_identity` / `derive_identity`.
