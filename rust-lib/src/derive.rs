//! Keys named by `(scheme, purpose, context)`, derived from one seed (design §4).
//!
//! The path is `m / PURPOSE' / scheme' / c0' / … / c7'`, all hardened. `c0 … c7` are the first
//! 248 bits of `SHA-256(["logos.signer.context.v1", {purpose, context}])` in 31-bit pieces.
//! The curve's standard derivation applies: BIP-32 for secp256k1, SLIP-0010 for Ed25519.
//! Only hardened steps are used, which is all SLIP-0010 defines for Ed25519 and what a
//! hardware signer can do for secp256k1.
//!
//! The path never leaves this module. Callers see a `keyRef` and a public key.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::record::{text, Record, Value};

/// The first path level. **Provisional and unregistered** (design §10.1).
pub const PURPOSE: u32 = 7432;

const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Ed25519,
    Secp256k1,
}

impl Scheme {
    pub fn parse(s: &str) -> Option<Scheme> {
        match s {
            "ed25519" => Some(Scheme::Ed25519),
            "secp256k1" => Some(Scheme::Secp256k1),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Ed25519 => "ed25519",
            Scheme::Secp256k1 => "secp256k1",
        }
    }

    fn index(self) -> u32 {
        match self {
            Scheme::Ed25519 => 0,
            Scheme::Secp256k1 => 1,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error("invalid-purpose")]
    Purpose,
    #[error("invalid-context")]
    Context,
    /// BIP-32's probability-2^-127 case: the step gives no valid key.
    #[error("derivation-invalid-child")]
    InvalidChild,
}

/// A derived secret: an Ed25519 seed or a secp256k1 scalar, wiped on drop.
pub type Secret = Zeroizing<[u8; 32]>;

/// The hardened path for a key. Private to the crate: it is never reported.
pub(crate) fn path(scheme: Scheme, purpose: &str, context: &str) -> Result<Vec<u32>, DeriveError> {
    check_name(purpose).map_err(|_| DeriveError::Purpose)?;
    if context.is_empty() || context.len() > 1024 {
        return Err(DeriveError::Context);
    }
    let h = context_digest(purpose, context);
    let mut p = vec![PURPOSE, scheme.index()];
    // 248 bits as eight big-endian 31-bit integers.
    let mut acc: u128 = 0;
    let mut bits = 0u32;
    let mut used = 0usize;
    for _ in 0..8 {
        while bits < 31 {
            acc = (acc << 8) | h[used] as u128;
            used += 1;
            bits += 8;
        }
        bits -= 31;
        p.push(((acc >> bits) & 0x7fff_ffff) as u32);
    }
    Ok(p.into_iter().map(|i| i | HARDENED).collect())
}

fn context_digest(purpose: &str, context: &str) -> [u8; 32] {
    Record::build(
        "logos.signer.context.v1",
        vec![("purpose", text(purpose)), ("context", text(context))],
    )
    .digest()
}

/// A purpose is a short lowercase name: `room-identity`, `lez-member`, …
pub fn check_name(s: &str) -> Result<(), ()> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if ok { Ok(()) } else { Err(()) }
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut m = Hmac::<Sha512>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

fn split(i: &[u8; 64]) -> (Secret, Zeroizing<[u8; 32]>) {
    let mut k = Zeroizing::new([0u8; 32]);
    let mut c = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&i[..32]);
    c.copy_from_slice(&i[32..]);
    (k, c)
}

/// SLIP-0010 for Ed25519: hardened steps only. Returns the 32-byte Ed25519 seed.
pub(crate) fn slip10_ed25519(seed: &[u8], path: &[u32]) -> Secret {
    let (mut k, mut c) = split(&hmac512(b"ed25519 seed", &[seed]));
    for &i in path {
        debug_assert!(i & HARDENED != 0);
        let next = hmac512(c.as_ref(), &[&[0u8], k.as_ref(), &i.to_be_bytes()]);
        (k, c) = split(&next);
    }
    k
}

/// BIP-32 for secp256k1: hardened steps only. Returns the 32-byte scalar.
pub(crate) fn bip32_secp256k1(seed: &[u8], path: &[u32]) -> Result<Secret, DeriveError> {
    let (mut k, mut c) = split(&hmac512(b"Bitcoin seed", &[seed]));
    k256::SecretKey::from_slice(k.as_ref()).map_err(|_| DeriveError::InvalidChild)?;
    for &i in path {
        debug_assert!(i & HARDENED != 0);
        let next = hmac512(c.as_ref(), &[&[0u8], k.as_ref(), &i.to_be_bytes()]);
        let (il, ci) = split(&next);
        let parent = scalar(&k)?;
        let tweak = scalar(&il)?;
        let child = parent + tweak;
        if bool::from(child.is_zero()) {
            return Err(DeriveError::InvalidChild);
        }
        let mut bytes: [u8; 32] = child.to_bytes().into();
        k.copy_from_slice(&bytes);
        bytes.zeroize();
        c = ci;
    }
    Ok(k)
}

/// A scalar below the group order, as BIP-32 requires of `IL` and of a key.
fn scalar(b: &[u8; 32]) -> Result<k256::Scalar, DeriveError> {
    use k256::elliptic_curve::PrimeField;
    Option::from(k256::Scalar::from_repr((*b).into())).ok_or(DeriveError::InvalidChild)
}

/// Derive the key `(scheme, purpose, context)` from a seed.
pub fn derive(seed: &[u8], scheme: Scheme, purpose: &str, context: &str) -> Result<Secret, DeriveError> {
    let p = path(scheme, purpose, context)?;
    match scheme {
        Scheme::Ed25519 => Ok(slip10_ed25519(seed, &p)),
        Scheme::Secp256k1 => bip32_secp256k1(seed, &p),
    }
}

/// The public key of a derived secret: 32 bytes for Ed25519, 33 (compressed) for secp256k1.
pub fn public_key(scheme: Scheme, secret: &Secret) -> Vec<u8> {
    match scheme {
        Scheme::Ed25519 => ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().to_bytes().to_vec(),
        Scheme::Secp256k1 => k256::SecretKey::from_slice(secret.as_ref())
            .expect("derived scalars are valid keys")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    }
}

/// A group's id: a fingerprint of its BIP-32 master public key. The same on every device
/// restored from the same phrase, and it reveals nothing a public key would not.
pub fn group_id(seed: &[u8]) -> Result<String, DeriveError> {
    let master = bip32_secp256k1(seed, &[])?;
    let pk = public_key(Scheme::Secp256k1, &master);
    let d = Record::build("logos.signer.group.v1", vec![("root", Value::Bytes(pk))]).digest();
    Ok(format!("g_{}", hex::encode(&d[..16])))
}

/// A key's opaque name. Stable across a restore, and it names no path.
pub fn key_ref(group: &str, scheme: Scheme, purpose: &str, context: &str) -> String {
    let d = Record::build(
        "logos.signer.keyref.v1",
        vec![
            ("group", text(group)),
            ("scheme", text(scheme.as_str())),
            ("purpose", text(purpose)),
            ("context", text(context)),
        ],
    )
    .digest();
    format!("kr_{}", hex::encode(&d[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(i: u32) -> u32 {
        i | HARDENED
    }

    // BIP-32 test vector 1 and SLIP-0010 test vector 1 share this seed.
    const SEED1: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn bip32_vector_1() {
        let seed = hex::decode(SEED1).unwrap();
        let m = bip32_secp256k1(&seed, &[]).unwrap();
        assert_eq!(hex::encode(m.as_ref()), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let k = bip32_secp256k1(&seed, &[h(0)]).unwrap();
        assert_eq!(hex::encode(k.as_ref()), "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
    }

    #[test]
    fn slip10_ed25519_vector_1() {
        let seed = hex::decode(SEED1).unwrap();
        let m = slip10_ed25519(&seed, &[]);
        assert_eq!(hex::encode(m.as_ref()), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
        let k = slip10_ed25519(&seed, &[h(0)]);
        assert_eq!(hex::encode(k.as_ref()), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3");
        assert_eq!(
            hex::encode(public_key(Scheme::Ed25519, &k)),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );
        let k = slip10_ed25519(&seed, &[h(0), h(1), h(2), h(2), h(1_000_000_000)]);
        assert_eq!(hex::encode(k.as_ref()), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793");
    }

    #[test]
    fn the_path_is_hardened_and_follows_the_context() {
        let a = path(Scheme::Ed25519, "room-identity", "room:a").unwrap();
        let b = path(Scheme::Ed25519, "room-identity", "room:b").unwrap();
        assert_eq!(a.len(), 10);
        assert!(a.iter().all(|i| i & HARDENED != 0));
        assert_eq!(a[0], h(PURPOSE));
        assert_ne!(a, b);
        // Same inputs, same path: a restore finds the same key.
        assert_eq!(a, path(Scheme::Ed25519, "room-identity", "room:a").unwrap());
        // Purpose and scheme each change the path.
        assert_ne!(a, path(Scheme::Ed25519, "lez-member", "room:a").unwrap());
        assert_ne!(a[1], path(Scheme::Secp256k1, "room-identity", "room:a").unwrap()[1]);
    }

    #[test]
    fn a_bad_purpose_or_context_is_refused() {
        assert_eq!(path(Scheme::Ed25519, "Room", "x"), Err(DeriveError::Purpose));
        assert_eq!(path(Scheme::Ed25519, "", "x"), Err(DeriveError::Purpose));
        assert_eq!(path(Scheme::Ed25519, "room-identity", ""), Err(DeriveError::Context));
    }

    #[test]
    fn key_refs_and_groups_are_stable_and_distinct() {
        let seed = hex::decode(SEED1).unwrap();
        let g = group_id(&seed).unwrap();
        assert_eq!(g, group_id(&seed).unwrap());
        assert_ne!(g, group_id(&[7u8; 64]).unwrap());
        let r1 = key_ref(&g, Scheme::Ed25519, "room-identity", "room:a");
        assert_eq!(r1, key_ref(&g, Scheme::Ed25519, "room-identity", "room:a"));
        assert_ne!(r1, key_ref(&g, Scheme::Secp256k1, "room-identity", "room:a"));
        assert!(r1.starts_with("kr_") && r1.len() == 35);
    }
}
