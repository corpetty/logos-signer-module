# feat: identity keys (ed25519): record, open and secret requests

**From:** corpetty/logos-signer-manager-module `feat/ed25519-record` (`e25036f`), on `d2548c6`.

Lets any named module ask for an identity key's signature over a domain-separated record, shown
field by field, and, as a proposal, for what is sealed to that key. It goes with the signer
interface's `ed25519` family and the keystore's identity groups (both pinned at corpetty's
branches); see the issue for the design questions.

## What changes

- **The intent** may name `identity`, an Ed25519 public key, as an EVM intent names `address`.
  - Exactly one of `address`, `group`, `identity`.
  - An identity's roster key is `ed25519_<public key>`, so any signer holding the key may sign.
- **`record` legs.** A record is the dCBOR encoding of `[domain, {fields}]`, and SHA-256 of it is
  signed: the domain-separated records apps sign instead of bare digests. The manager:
  - decodes it strictly: the deterministic encoding only (shortest integers, definite lengths, map
    keys strictly increasing bytewise), re-encoding to the same bytes, no floats, no tags;
  - renders the identity key, the signer's name for it, the domain, every field in diagnostic
    notation with hidden characters escaped, and the digest;
  - commits to the key and every record's digest;
  - hands the signer `ed25519` hash items;
  - checks each signature against the key before anything can be collected.
- **`open` and `secret` legs** (a proposal). They are all of one kind per request:
  - **`open`:** sealed boxes addressed to the key's X25519 form; their contents go to the requester
    unshown;
  - **`secret`:** records, shown as above, each giving HMAC-SHA256 under the identity's seed.

  They reach the keystore through its `identity_open` / `identity_secret`: the `Registry` carries an
  `IdentityKeys` the glue binds to the keystore. Only the keystore takes them, with the password or
  inside its unlock. The render says the manager cannot check what the keystore opens as it checks a
  signature.
- **Unattended:** inside an unlock granted without confirmation, the keystore signs records and
  opens boxes as they arrive. The existing path is unchanged.
- **Refused:**
  - a `record`, `open` or `secret` leg for an address or a group;
  - any other leg for an identity;
  - mixed identity legs, two targets, and a device that shows requests.
- **`manager_probe`** gains `import_identity`, `derive_identity`, `unlock` and `lock`.
- **Docs:** `docs/specs.md` § An identity record.

## Tests

- **`cargo test --no-default-features`:** 101 pass (85 before):
  - the record decoder;
  - an in-test keystore holding one identity key that signs, refuses a wrong password, answers with
    another key (refused), and signs inside an unlock;
  - open and secret legs through an approval and inside an unlock, nothing opened unseen when
    locked, keystore only, and malformed or mixed legs refused.
- **`doctests/identity-e2e.sh`** runs this manager, the keystore branch and the probe under a
  logoscore 0.3.1 daemon:
  - the keystore makes the room key from the phrase, matching the reference derivation;
  - the CLI cannot ask;
  - the approver is shown a Muster authorship record's domain and fields, and a wrong password
    leaves it on screen;
  - libsodium verifies the signature over SHA-256 of the record;
  - non-canonical records, a digest for an identity, and signing past the manager are refused;
  - inside an unlock, the next record is signed unseen and a box libsodium sealed to the key opens;
  - after a lock, the room's founding secret is derived through an approval and matches the
    reference value.
