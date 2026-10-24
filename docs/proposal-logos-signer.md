# Draft issue: logos.signer/1 for identity keys, records and keys by context

**For:** logos-co/logos-signer-interface, copying logos-co/logos-signer-manager-module. **Not sent.**
**Against:** interface `03eece5`, manager `d2548c6`, keystore `127d4ac` (2026-10-24).
**From:** Muster (corpetty/muster), which coordinates multi-party actions in encrypted rooms. Its
requirements are in `docs/design/wallet-signer-spec.md` there.

---

## Why

Muster makes signatures the platform's signers cannot make yet: Ed25519 for a room member's
authorship, X25519 to open the room's sealed grants, BIP-340 on LEZ, and FROST rounds. Today it makes
them in its own key file. We would rather they came from the person's wallet, approved through the
Signer app, like every EVM and Bitcoin signature. `logos.signer/1` and the manager are the right
shape for that.

This issue proposes one small change to the interface, which we have built and tested, and asks four
design questions that the manager would have to answer.

## 1. An `ed25519` family and scheme (built)

Branch `feat/ed25519-family`, one commit on `03eece5`:
- **`Family::Ed25519`.** An account carries its 32-byte public key, hex, as `address`, with no
  `path` and no `xpub`. It signs with its own key, as an EVM account does.
- **`Scheme::Ed25519`.** Ed25519 (RFC 8032) with the item's 32 bytes as the message.
  `verify::check` holds the answer to the account's key with `verify_strict`, and refuses:
  - another key;
  - another key under the account's name;
  - another digest;
  - an item with a path;
  - another scheme.
- **Conformance.** The suite builds items for the family and checks that its accounts carry a
  32-byte key and no xpub.
- **Docs.** `docs/interface.md` gains the rows.

All existing tests pass unchanged.

**One cost.** A new `Family` variant breaks exhaustive matches downstream. The manager needs the
same arms. `#[non_exhaustive]` would avoid that next time.

**A signer that passes the suite with it:** `context_signer_module`. It has the same signer half
as the keystore:
- hashes only, every item checked before the vault opens;
- a password per request, or `unlock {account, password, ttlMs?, count?}` / `lock` /
  `unlocked`;
- jobs settled inside `sign`.

Its accounts carry the phrase's BIP-32 master fingerprint, so a keystore holding the same phrase
names the same wallet.

## 2. Asks that need the manager

### 2a. A `record` request kind

**What it is.** A screenless signer signs the manager's digests. So for Ed25519 the manager needs
a payload it can parse, render and hash. Muster signs domain-separated records: the dCBOR
encoding of `[domain, {fields}]`, and the signature covers `SHA-256(record)`.

**The proposal:**

```json
{ "account": "<id>", "kind": "record", "record": "<dCBOR hex>" }
```

**What the manager does:**
1. Decodes the record strictly. It accepts only the canonical subset:
   - shortest integers, definite lengths;
   - map keys strictly increasing in bytewise order of their encoding;
   - no floats, no tags.
2. Refuses the record unless it re-encodes to the same bytes.
3. Renders the domain and each field.
4. Hashes the record.
5. Hands the signer one `hash` item.

**Reserved domains.** A domain under a prefix the platform reserves is refused.

**Why not a digest leg.** A requester can put any 32 bytes in a digest leg. That is why the
keystore shows a digest only as the requester's claim.

The decoder exists (`record.rs`, about 200 lines with tests), and we would contribute it.

### 2b. Keys by context

**Why.** Muster derives a fresh key for each room membership and each multisig, so that its
memberships cannot be linked. An app has to be able to ask for "a key for this purpose in this
context" and get the same key back after a restore from the phrase.

**How the signer derives it:**
1. `h = SHA-256(dCBOR(["logos.signer.context.v1", {purpose, context}]))`.
2. The path is `m / 7432' / scheme' / c0' … c7'`, all hardened, where `c0 … c7` are the first
   248 bits of `h` in 31-bit pieces.
3. secp256k1 takes BIP-32 along that path; Ed25519 takes SLIP-0010.

It is all hardened, so a Keycard could hold the secp256k1 keys. `7432'` is a placeholder for a
number you would choose.

**What the flow could be.** Something like `request_account({ family, purpose, context, reason })`
from an app. The person approves it in the Signer app, the signer derives the key, and the
account joins the roster. The path never reaches the app.

**Question:** Is this the manager's to offer, or the custodian's only, as the keystore's
`derive_account_at` is?

### 2c. Unattended signing beyond the keystore

A member signs every message they post in a room. So a room identity needs "without asking",
within terms the person chose. The manager's spec says "Only the keystore's copy of an account
is ever unlocked."

Our signer has the keystore's `unlock` / `lock` / `unlocked`, shape for shape. Could the manager
route an unlock to any signer that has them?

**The alternative** is that Ed25519 moves into `keystore_module` itself. It already keeps the
phrase and is the unattended signer. Our derivation and identity code would port as is (§3).

### 2d. Decryption is not a signature

Muster also needs two operations the interface's rule excludes ("no method returns … anything
derived from one except a signature"):
- **Opening a sealed box** (libsodium `crypto_box_seal`) addressed to the identity's X25519 key,
  derived from the Ed25519 key as libsodium derives it. This carries a room's epoch grants.
- **A derived secret.** HMAC-SHA256 under the identity's seed, over a record. Muster derives the
  key of a room's first epoch this way, so a founder who reinstalls can read their own room.

**Why `data_key` (signer-manager#12) does not fit.** Its seed key is random rather than derived
from the phrase, so it cannot survive a restore. It is also scoped per module, not per identity.

**Question:** Should these be a sibling interface (`logos.decrypt/1`?) under the same unlock
terms, or stay outside the platform?

## 3. Later families, flagged only

- **LEZ messages.** BIP-340 without the BIP-86 tweak, over a tagged digest. That means a `bip340`
  scheme and a `lez` family. We have drafted the matching ask for `lez_core`.
- **FROST** (ChillDKG, then BIP-445 signing). Its rounds keep state between steps, and a nonce
  must be used once. That does not fit stateless hash items.

## 4. Where should Ed25519 live?

| | A separate signer (`context_signer_module`) | `keystore_module` |
|---|---|---|
| Recovery phrase | imported twice; the manager joins the wallets by fingerprint | kept once |
| Unattended signing | needs 2c | already there |
| Change upstream | interface §1, manager arms, 2a | interface §1, manager arms, 2a, plus keystore |

We are happy to go either way. Our code is a crate with no runtime:
- `record` (the strict decoder);
- `derive` (hardened BIP-32 and SLIP-0010 by context; BIP-32 and SLIP-0010 vectors);
- `identity` (Ed25519, X25519 and sealed boxes, checked against libsodium's own output);
- `vault` (scrypt Web3 Secure Storage, as the keystore keeps keys).

So it can sit behind either.
