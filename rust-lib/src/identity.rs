//! The room identity (design §6): one Ed25519 key that authors, and the X25519 key derived
//! from it that opens sealed boxes. Byte for byte what libsodium does, because Muster's rooms
//! run on libsodium (`module/src/crypto/curve25519.nim`); `tests/vectors/libsodium.json`
//! holds the two to each other.

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::derive::Secret;

/// libsodium's `crypto_box_SEALBYTES`: an ephemeral public key and a MAC.
pub const SEAL_BYTES: usize = 48;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// Not addressed to this key, or altered. One answer for both, as libsodium gives.
    #[error("seal-open-failed")]
    SealOpen,
}

/// Public halves: the identity a room knows a member by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
}

/// An Ed25519 seed's keys. Holds the seed only; every other secret is recomputed and wiped.
pub struct RoomKey {
    seed: Secret,
}

impl RoomKey {
    pub fn from_seed(seed: Secret) -> RoomKey {
        RoomKey { seed }
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    pub fn identity(&self) -> Identity {
        let ed = self.signing().verifying_key();
        Identity { ed25519: ed.to_bytes(), x25519: ed.to_montgomery().to_bytes() }
    }

    /// Ed25519 over the message, as `crypto_sign_detached`.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing().sign(msg).to_bytes()
    }

    /// libsodium's `crypto_sign_ed25519_sk_to_curve25519`: SHA-512 of the seed, clamped.
    fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        let mut h = Zeroizing::new([0u8; 64]);
        h.copy_from_slice(&Sha512::digest(&self.seed[..]));
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        s
    }

    /// Open a `crypto_box_seal` box addressed to this identity's X25519 key.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, IdentityError> {
        if sealed.len() < SEAL_BYTES {
            return Err(IdentityError::SealOpen);
        }
        let sk = crypto_box::SecretKey::from(*self.x25519_secret());
        sk.unseal(sealed).map_err(|_| IdentityError::SealOpen)
    }

    /// HMAC-SHA256 keyed by the seed over `info`: Muster's `derivedSecret`, one secret for one
    /// purpose. `info` is a record the caller domain-separated; the seed never leaves.
    pub fn derived_secret(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.seed[..]).expect("any key length");
        m.update(info);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }
}

/// Seal to an X25519 key, as `crypto_box_seal`. Used by tests and by nothing on a signing path.
pub fn seal_to(x25519: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    crypto_box::PublicKey::from(*x25519)
        .seal(&mut rand::rngs::OsRng, plain)
        .expect("sealing to a public key cannot fail")
}

pub fn verify(ed25519: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier as _;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(ed25519) else { return false };
    vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct V {
        seed: String,
        ed_pk: String,
        msg: String,
        sig: String,
        x_pk: String,
        x_sk: String,
        plain: String,
        sealed: String,
        info: String,
        derived_secret: String,
    }

    fn b32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn agrees_with_libsodium() {
        let vs: Vec<V> = serde_json::from_str(include_str!("../tests/vectors/libsodium.json")).unwrap();
        assert!(!vs.is_empty());
        for v in vs {
            let k = RoomKey::from_seed(Zeroizing::new(b32(&v.seed)));
            let id = k.identity();
            assert_eq!(hex::encode(id.ed25519), v.ed_pk);
            assert_eq!(hex::encode(id.x25519), v.x_pk);
            assert_eq!(hex::encode(*k.x25519_secret()), v.x_sk);
            let msg = hex::decode(&v.msg).unwrap();
            assert_eq!(hex::encode(k.sign(&msg)), v.sig, "Ed25519 is deterministic");
            assert_eq!(k.open(&hex::decode(&v.sealed).unwrap()).unwrap(), hex::decode(&v.plain).unwrap());
            assert_eq!(hex::encode(*k.derived_secret(&hex::decode(&v.info).unwrap())), v.derived_secret);
        }
    }

    #[test]
    fn a_box_for_someone_else_or_altered_does_not_open() {
        let a = RoomKey::from_seed(Zeroizing::new([1u8; 32]));
        let b = RoomKey::from_seed(Zeroizing::new([2u8; 32]));
        let mut boxed = seal_to(&a.identity().x25519, b"grant");
        assert_eq!(a.open(&boxed).unwrap(), b"grant");
        assert_eq!(b.open(&boxed), Err(IdentityError::SealOpen));
        boxed[50] ^= 1;
        assert_eq!(a.open(&boxed), Err(IdentityError::SealOpen));
        assert_eq!(a.open(&[0u8; 10]), Err(IdentityError::SealOpen));
    }
}
