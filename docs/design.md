# signer_module: design

**Status:** draft, 2026-10-24. Slice S1 (see §9).
**Requirements:** Muster's `docs/design/wallet-signer-spec.md` (corpetty/muster, `c47cda4`), "the
spec" below. Its rules are cited as *rule n*, its sections as *spec §n*.
**Built on:** `keystore_module` = logos-co/logos-evm-keystore-module@`2318c679`, the version
Basecamp 0.3.2 ships. Its `docs/specs.md` is cited as *keystore §…*.

Words, as in the spec: **signer** holds keys and signs; **wallet** reads chains and sends; **app**
is the caller; **person** is the human who approves.

---

## 1. What it is

`signer_module` is a Rust cdylib Logos module (`type: core`). It holds the keys for the
schemes **no platform module holds today**, and it signs only what a person approved or granted.

It is a **leaf**, like `keystore_module`: it declares no dependencies, calls no module, and
has no network code. Reads, sends and proving belong to wallet modules (spec §3.8). They are
not part of the signer.

**What stays where it is.** Each existing holder keeps its chain. This module does not wrap
them or duplicate them:

| Need | Holder, unchanged |
|---|---|
| EVM transactions | `tx_sender_module` → `keystore_module` |
| EIP-712, EIP-191 | `keystore_module.request_approval` |
| LEZ private rails, receive by scan | `lez_core` |
| Monero request and send | `monero_wallet_backend` |

**What it adds,** over the slices in §9:
- the room identity: Ed25519 signing, X25519 sealed-box opening;
- context-derived keys;
- possession proofs;
- then BIP-340 (LEZ messages, Bitcoin taproot), PSBT signing and FROST rounds.

Today Muster's own `FileKeystore` makes every one of these (spec §1).

**Spec §7.1 (one module or a family?)** A family. This leaf signer joins the existing holders,
and they share **one approval contract**: this module's contract is `keystore_module`'s (§3).
The routing ("an EVM approval goes to keystore, an Ed25519 one comes here") stays in the
app's own seam. Muster's `Keystore` seam already routes. A separate composer module is
justified only when a second app needs the same routing, and it could hold no keys.

## 2. What is taken from keystore_module unchanged

These are proven, and an approver UI written for one module should serve both. Each one is
copied, not re-imagined:

- **Tiers by attested caller** (`logos_rust_sdk::current_caller()`, keystore §The three tiers):
  - A, the approver: `pending`, `acknowledge`, `approve`, `reject`, plus `list_grants` and
    `revoke_grant` here;
  - B, any named module: `request_approval`, `approval_status`, `fetch_result`, `ack_result`,
    `cancel_approval`, plus the grant uses (§5);
  - C, ungated reads;
  - D, the custodian: create, import, delete.

  The Tier D gate is a registry, and a method missing from it refuses everyone. Every refusal
  is the same string. `HostAnchor` is refused at A and B.
- **Request lifecycle:**
  - a `handle` is announced on the event plane; a `receipt` is returned once and authorizes
    collection;
  - at most one request is `Rendered`;
  - an unclaimed offer is collected after 60 s, and a claimed one has no timeout on the human;
  - settled records are kept for 120 s;
  - results are idempotent until `ack_result`;
  - limits: 4 pending per requester, 16 in all, 64 KiB per intent.
- **Display:** `acknowledge` returns two lists, which an approver must not merge.
  `claim_lines` is the requester's words. `render_lines` is authored by this module from the
  parsed payload, escaped, and shown verbatim.
- **Commitment:** `bundle_id` is SHA-256 over this module's own canonical re-encoding of the
  parsed intent. `approve(handle, bundle_id, password)` re-parses the intent, re-derives the
  commitment and refuses a mismatch (rule 3).
- **Secrets:**
  - the password is typed only into the approver;
  - the seed is decrypted inside `approve()` and zeroized before it returns;
  - the approver gets a count, never the signatures.
- **At rest:** the seed is kept as a Web3 Secure Storage (scrypt) vault, through
  `eth-keystore` as keystore_module uses it. Writes are atomic.
- **Roles:** `configure` behaves as keystore's does: total, in memory, and **ungated, with the
  same stated caveat** (keystore §configure). The default approver is `signer_ui`; the default
  custodian is `signer_ui` as well, until a custodian UI exists.
- **Events:** `approval_offered(handle)` and `approval_settled(handle, state)`, the handle
  only. Plus `keys_changed(count)` (`-1` = unknown, never `0`).

## 3. What changes, and why

| keystore_module | here | Spec |
|---|---|---|
| `digest` leg: 32 opaque bytes, shown as the requester's claim | **No such leg.** Every leg is a typed payload this module hashes itself | rule 2, spec §3.3 |
| `tx`, `message`, `typed_data` legs | not here: EVM stays in keystore_module | §1 |
| no account / environment / expiry on the intent | every leg names `keyRef`, `environment` and `expiry`, and the render shows them. A leg without them is refused | rule 4 |
| no on-demand signing at all | **standing grants** (§5), approved once, scoped by domain, held in memory | spec §3.2, rule 5 |
| accounts from a BIP-44 path | keys from `(scheme, purpose, context)` (§4) | rule 7, rule 8 |
| — | `refs`: opaque ids the app joins back on, stored and never shown | spec §4 |

### Leg kinds in S1

| `kind` | Payload | What is signed | Rendered as |
|---|---|---|---|
| `derive` | `{scheme, purpose, context}` | nothing. It mints (or re-finds) a key, and the result is `{keyRef, publicKey}` | "Create a key for *purpose* in *context*" |
| `record-sign` | `{keyRef, record}`: `record` is a canonical dCBOR `[domain, {fields}]` hash-input record | `SHA-256(record)`, with the key's scheme | the domain and every field, in diagnostic notation |
| `possession` | `{keyRef, context}` | the record `["logos.signer.possession.v1", {key, context}]`, which this module builds itself | "Prove *key* belongs to you, for *context*" |
| `grant` | `{keyRef, uses, domains, expiry}` | nothing. It opens a standing grant (§5) | "Let *requester* sign *domains* with *key* until *expiry*, without asking" |

`record-sign` is how Muster's signatures stay valid without change. Muster signs
`SHA-256(dCBOR([domain, {fields}]))` (`module/src/hashing/hash_input.nim`). This module:
1. decodes the record;
2. **refuses it unless re-encoding gives the same bytes** (invariant 5, held at the signer);
3. renders it;
4. hashes it itself.

Muster's verifiers see exactly the bytes they verify today.

**A digest that is a transaction hash** (spec §6) cannot be made to sign. Every leg's signed
bytes are the SHA-256 of a dCBOR array whose first element is a text domain. A transaction hash
is not such a value, and no leg accepts bare bytes.

## 4. Derivation (rule 7, rule 8, spec §3.1)

**Seed.** One BIP-39 phrase per *group*, as keystore_module has groups. The seed is held only
as a scrypt vault, under the person's password.

**Path.** A key is named by `(scheme, purpose, context)`:
1. `h = SHA-256(dCBOR(["logos.signer.context.v1", {purpose, context}]))`.
2. Its first 248 bits are split into eight 31-bit integers `c0 … c7`.
3. The path is `m / 7432' / scheme' / c0' / … / c7'`, all hardened.
4. The curve's standard derivation applies:
   - secp256k1 (ECDSA, BIP-340): BIP-32;
   - Ed25519: SLIP-0010.

Hardened BIP-32 is what a Keycard can do (spec §7.4), so a secp key here could later come from
a card. Purpose `7432'` is **provisional**, unregistered, and kept in one constant.

**Never disclosed.** The path never leaves the module (spec §3.1). The app learns `keyRef`
and the public key. `keyRef` = `kr_` + hex of the first 16 bytes of
`SHA-256(dCBOR(["logos.signer.keyref.v1", {group, scheme, purpose, context}]))`. `group` is
the group's own id, a fingerprint of its root public key. So `keyRef` is stable across a
restore from the same phrase, and it names no path.

**Minting needs the seed.** A `derive` is therefore an approval leg. Joining a room is the
person's act anyway, and `derive` plus `grant` are one prompt: "create Muster's identity for
room *X* and let it sign authorship there".

**After minting.** The module keeps a plain index (`keys.json`):
`keyRef → {scheme, purpose, context, publicKey, group}`. It holds no secret and no path, so
`list_keys` and `identity` answer without a password.

**Recovery** (spec §6). Restore the phrase, and the app re-requests `derive` for the same
`(purpose, context)`. It gets the same key and the same `keyRef`.

**What it is not.** These are not Muster's keys of today. A key labelled `lez-member/0` in
`FileKeystore` is derived from that file's own secret. Rooms keyed under `FileKeystore` stay
there; the new backend serves new identities (§8).

## 5. Standing grants (spec §3.2, §7.3)

This is the one deliberate departure from keystore_module, which signs nothing without a
password typed for that request.

A room identity signs **every message**, so a prompt per event is not usable.

**What a grant is:** `{grantId, requester, keyRef, uses, domains, expiry}`.
- `uses` ⊆ `{sign, open, secret}`.
- `domains` is a list of exact domain strings.
- Opened only by an approved `grant` leg.

**When the person approves:**
1. The module derives that one key from the seed.
2. It holds the key in memory as `Zeroizing`, bound to the grant.
3. It drops the seed.

**Using it (Tier B, the grant's requester only, with the grant's receipt):**
- `grant_sign(grantId, receipt, record)` signs a `record-sign` payload whose domain is in
  `domains`;
- `grant_open(grantId, receipt, sealed)` opens a sealed box addressed to the key's X25519
  identity.

- `grant_secret(grantId, receipt, record)` returns HMAC-SHA256, keyed by the Ed25519 seed,
  over a record whose domain is in `domains`. This is Muster's `derivedSecret`, which gives the
  key of a room's epoch 0, so a founder who relaunches reads its own room again (exo-6dc.1).
  It is a secret for one purpose that the app holds anyway, never the key.

All three answer at once, with no human. A domain outside the grant is refused (`domain-not-granted`).

**Ending a grant.** A grant ends at `expiry`, on `revoke_grant` (Tier A, or its own requester),
or when the module stops.
- A restart drops every held key. The grant record survives as `dormant`.
- Resuming it is one prompt: "resume Muster's use of *key*". So the cost is one prompt per
  launch per grant, and an unattended restart never revives a key.

**Scope is by domain, deliberately.** An Ed25519 signature counts as an approval in some of
Muster's rooms (a FROST contribution, a Monero multisig round). A grant for
`muster.event.author.v1` cannot make one of those. An approval-bearing domain stays a
per-request approval.

**Never under a grant.** No secp256k1 key, no transaction, nothing that moves funds.

## 6. The room identity (spec §3.2)

- **Ed25519:** SLIP-0010 under §4, purpose `room-identity`, context the room.
- **X25519:** derived from the Ed25519 key as libsodium's
  `crypto_sign_ed25519_{sk,pk}_to_curve25519` derive it. This is the identity Muster's rooms
  use (F-14).
- **Sealed boxes:** libsodium `crypto_box_seal` format (`crypto_box` crate, `seal` feature).
- **Held to Muster's bytes** (§7):
  - a box sealed by Muster's Nim code opens here;
  - a signature made here verifies in Muster;
  - every record re-encodes to Muster's bytes.

## 7. Contract (S1)

Written contract-first, as `signer_module.lidl`. JSON-in-`tstr` is used where keystore_module
uses it.

```
# Tier C, reads
list_keys() -> tstr                         # [{keyRef, scheme, purpose, context, publicKey, group}]
identity(key_ref: tstr) -> tstr             # {ed25519, x25519} for a room-identity key
caller_identity() -> tstr
configure(config_json: tstr) -> tstr        # roles; ungated, as keystore's (§2)

# Tier D, custodian
create_mnemonic(words: int) -> tstr
import_mnemonic(params_json: tstr) -> tstr  # {phrase, passphrase?, password, label?} -> {group}
list_groups() -> tstr
forget_group(params_json: tstr) -> tstr

# Tier B, requesters
request_approval(intent_json: tstr) -> tstr # {group?, purpose, refs?, legs:[…]} -> {handle, receipt}
approval_status(handle: tstr, receipt: tstr) -> tstr
fetch_result(handle: tstr, receipt: tstr) -> tstr
ack_result(handle: tstr, receipt: tstr) -> bool
cancel_approval(handle: tstr, receipt: tstr) -> bool
grant_sign(grant_id: tstr, receipt: tstr, record_hex: tstr) -> tstr
grant_open(grant_id: tstr, receipt: tstr, sealed_hex: tstr) -> tstr
grant_secret(grant_id: tstr, receipt: tstr, record_hex: tstr) -> tstr

# Tier A, approver
pending() -> tstr
acknowledge(handle: tstr) -> tstr
approve(handle: tstr, bundle_id: tstr, password: tstr) -> tstr
reject(handle: tstr) -> bool
list_grants() -> tstr
revoke_grant(grant_id: tstr) -> bool

events: approval_offered(handle), approval_settled(handle, state), keys_changed(count),
        grant_settled(grant_id, state)
```

**Refusal codes** (rule 10). Stable strings, under `{ok:false, error}`:
- `not authorized`: keystore's single string, for every tier refusal;
- `unknown-leg-kind`, `non-canonical-record`, `missing-environment`, `missing-expiry`;
- `domain-not-granted`, `grant-expired`, `grant-dormant`, `unknown-key`.

## 8. Muster's side

Muster reaches the module through a `SignerKeystore` backend behind its `Keystore` seam
(`module/src/crypto/keystore.nim`). That fits the seam's rule: operations, never a key getter.

**Mapping:**
- `edSign`/`edSignWith` → `grant_sign`;
- `sealOpen` → `grant_open`;
- `foundingKey` (via `derivedSecret`) → `grant_secret`;
- `encIdentity` → `identity`;
- a new room → one approval with `derive` and `grant` legs, raised to `signer_ui` through
  Muster's UI.

**What does not move in S1.** Muster's verifiers are unchanged (§3), and FileKeystore stays the
fallback where the module is absent, as it is for `keystore_module` today. Muster's work is an
epic of its own, `exo-833`.

## 9. Slices

| Slice | Holds | Test |
|---|---|---|
| **S1a** | The core crate, no Logos runtime: vault, derivation (§4), records, the approval state machine (§2–3), grants (§5), the room identity (§6) | `cargo test`: BIP-32/SLIP-0010 vectors, the spec §6 refusals, sealed-box and Ed25519 vectors from Muster's Nim, the lifecycle |
| **S1b** | The LIDL contract and glue, built by `logos-module-builder` 0.3.2 into `.lgx` and `.lgx-portable` | load it in `logoscore`; `caller_identity` from a probe module reads `module` |
| **S1c** | `signer_cli`: a headless approver relay, as `evm_signer_cli` is to keystore, so tests can approve without a UI | a probe requests; `signer_cli` approves; the probe fetches |
| **S1d** | Muster's `SignerKeystore` backend and the interop run | a room joined and messaged with the module as the identity holder; restore from the phrase, and the room is rejoined with the same key |
| S2 | `signer_ui`, the approval surface | on display |
| S3 | BIP-340 records (LEZ `sign_message`, possession on LEZ), PSBT signing | Muster's Bitcoin and lez-msig e2e with the module as backend |
| S4 | FROST: ChillDKG and signing rounds in the signer, constant time | Muster's FROST e2e |

## 10. Open

1. **Purpose number** `7432'` is a placeholder (§4).
2. **One phrase across modules.** keystore_module never exports a seed. So "one recovery
   phrase" (rule 7) means the person imports the same phrase into both custodians, and their
   paths do not collide. The long-term answer may be to merge these schemes into
   keystore_module upstream. This design keeps its contract identical so that stays cheap.
3. **Group secrets** (spec §7.2) and **remote proving** (§7.5) are out of S1.
4. **Hardware** (spec §7.4): Ed25519 on a Keycard is unknown. A scheme a backend lacks would be
   refused with `scheme-unavailable`, never emulated.
