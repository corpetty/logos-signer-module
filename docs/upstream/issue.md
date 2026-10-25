# Identity keys (ed25519) behind logos.signer/1: five decisions

**For:** logos-co/logos-signer-interface, copying logos-co/logos-signer-manager-module and
logos-co/logos-evm-keystore-module. Three PRs carry a working answer to each question below, so
each one can be judged against code. Every one of them is open to change.

## Why

Muster (corpetty/muster) coordinates multi-party actions in encrypted rooms. Every member has a
room identity:
- an **Ed25519 key** that authors each event as Ed25519 over SHA-256 of a domain-separated dCBOR
  record;
- its **X25519 form**, to which the room seals its epoch keys;
- **a secret derived from it**, the key of the room's first epoch, so a founder who reinstalls can
  read their own room again.

Today Muster keeps that key in a file of its own. It should come from the person's wallet, from the
same recovery phrase, approved through the Signer app like every EVM and Bitcoin signature.

## What the three PRs do

| PR | |
|---|---|
| signer-interface `feat/ed25519-family` | an `ed25519` family and scheme; `verify::check` refuses another key, another digest, a path, another scheme |
| keystore `feat/ed25519-identity` | identity groups: one SLIP-0010 node per phrase, never the root; a key per purpose and context; `ed25519` accounts; `identity_open` / `identity_secret` (Tier M) |
| manager `feat/ed25519-record` | identity intents; `record` legs read strictly, shown field by field, hashed here, signatures checked; `open` / `secret` legs through the keystore |

`doctests/identity-e2e.sh` on the manager branch runs all three under logoscore 0.3.1, from the room
key made from a phrase to a libsodium-verified signature. It covers an approval and an unlock, a box
opened, and the founding secret derived.

## The decisions

1. **Does Ed25519 belong in the keystore?** We put it there because the keystore already holds the
   phrase and is the signer the manager unlocks. A separate signer would need the phrase imported a
   second time; the manager could join the wallets by fingerprint, but the phrase would sit in two
   places.
2. **A `record` request kind.** The manager signs only what it can show. Muster's routine signatures
   are over records, so the manager reads the record, shows its domain and fields, and hashes it
   itself. It accepts only the deterministic encoding. Is this the right shape for "an app's own
   signed data", or should the record format be something else?
3. **Keys per context, and who may ask for one.** The derivation is
   `m/7432'/0'/c0'…c7'`, hardened, the `c`s from a hash of purpose and context: one key per room,
   unlinkable, recoverable from the phrase.
   - Today only the custodian may make one (`derive_identity`, Tier D). An app needs to ask: should
     the manager take a request like `request_identity({ purpose, context, reason })` that the person
     approves, the way `request_open` works?
   - `7432'` is a placeholder. Which number?
4. **Where decryption lives.** Opening a sealed box addressed to the identity, and deriving a secret
   from it, are not signatures, and `logos.signer/1` answers with signatures only.
   - The PRs make them the keystore's own Tier M methods, and the manager's `open` / `secret` legs,
     under the same approvals and unlocks.
   - `data_key` (signer-manager#12) does not fit: its seed key is random rather than from the
     phrase, and it is scoped per module rather than per identity.
   - Keep it this way, a sibling interface (`logos.decrypt/1`?), or something else?
5. **Unlock terms for identities.** A member signs every message. So an identity key is used inside
   an unlock with `confirm: false` for the app that asked, exactly as the manager's "without asking"
   already works. Nothing new is needed, but it means a long-lived unlock on an identity. Is that
   acceptable, or should identities have their own terms?

## Also noticed

- A new `Family` variant breaks exhaustive matches in every consumer. `#[non_exhaustive]` on
  `Family` and `Scheme` would spare the next family that.
- The keystore had read every record naming a `family` as a Bitcoin wallet. It is fixed in the
  keystore PR, but it shows how a third family can be misread.
