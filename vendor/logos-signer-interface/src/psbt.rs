//! For signers that hand a device the whole PSBT, over USB or QR codes: which inputs are the
//! account's, each taproot input's internal key named as devices want it, and the signatures a
//! device added, ready for the manager's checks.

use bitcoin::bip32::{Fingerprint, KeySource};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::Psbt;

use crate::wire::{ErrorCode, Family, Result, Signature, SignerError};

const HARDENED: u32 = 0x8000_0000;

fn invalid(m: String) -> SignerError {
    SignerError::new(ErrorCode::Invalid, m)
}

/// Every input must be this account's, at a path two unhardened steps below `base`, or the device
/// would be asked to sign with a key outside the account.
pub fn check_inputs(psbt: &Psbt, family: Family, fingerprint: [u8; 4], base: &[u32]) -> Result<()> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        let ours = |(fp, path): &KeySource| (fp.to_bytes() == fingerprint).then_some(path.clone());
        let origins: Vec<_> = if family == Family::Bitcoin {
            input.bip32_derivation.values().filter_map(ours).collect()
        } else {
            input
                .tap_key_origins
                .values()
                .filter_map(|(_, source)| ours(source))
                .collect()
        };
        if origins.is_empty() {
            return Err(invalid(format!("input {i}: no key of this wallet")));
        }
        for path in origins {
            let steps: Vec<u32> = path.into_iter().map(|c| u32::from(*c)).collect();
            let below = steps.len() == base.len() + 2
                && steps.starts_with(base)
                && steps[base.len()..].iter().all(|s| s & HARDENED == 0);
            if !below {
                return Err(invalid(format!("input {i}: a key outside the account")));
            }
        }
    }
    Ok(())
}

/// Devices sign a taproot input only once the PSBT names its internal key, which for this account's
/// key-path spend is the key at the input's own path: name it where a wallet left it out. An input
/// naming another key, or a script tree, is no key-path spend of this account.
pub fn name_internal_keys(psbt: &mut Psbt, fingerprint: [u8; 4]) -> Result<()> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(key) = input
            .tap_key_origins
            .iter()
            .find(|(_, (_, (fp, _)))| fp.to_bytes() == fingerprint)
            .map(|(k, _)| *k)
        else {
            continue;
        };
        if input.tap_merkle_root.is_some() || input.tap_internal_key.is_some_and(|k| k != key) {
            return Err(invalid(format!("input {i}: not a key-path spend of this account")));
        }
        input.tap_internal_key = Some(key);
    }
    Ok(())
}

/// The signature a device added to each input, by the key at that input's origin under
/// `fingerprint`; a taproot one names the tweaked output key. An input left unsigned has none, and
/// the manager then refuses the answer.
pub fn signatures(signed: &Psbt, fingerprint: [u8; 4]) -> Vec<Signature> {
    let secp = Secp256k1::verification_only();
    let ours = |fp: &Fingerprint| fp.to_bytes() == fingerprint;
    let mut out = Vec::new();
    for (i, input) in signed.inputs.iter().enumerate() {
        for (key, (fp, _)) in &input.bip32_derivation {
            if let (true, Some(sig)) = (ours(fp), input.partial_sigs.get(&bitcoin::PublicKey::new(*key))) {
                out.push(Signature {
                    item: i,
                    signature: hex::encode(sig.signature.serialize_compact()),
                    recovery_id: None,
                    pubkey: hex::encode(key.serialize()),
                });
            }
        }
        let internal: Option<XOnlyPublicKey> = input
            .tap_key_origins
            .iter()
            .find(|(_, (_, (fp, _)))| ours(fp))
            .map(|(k, _)| *k);
        if let (Some(internal), Some(sig)) = (internal, input.tap_key_sig) {
            let (output, _) = internal.tap_tweak(&secp, input.tap_merkle_root);
            out.push(Signature {
                item: i,
                signature: hex::encode(sig.signature.serialize()),
                recovery_id: None,
                pubkey: hex::encode(output.to_x_only_public_key().serialize()),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::bip32::DerivationPath;
    use bitcoin::secp256k1::{Keypair, Message, SecretKey};
    use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    use super::*;

    const FP: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

    fn psbt() -> Psbt {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn key(n: u8) -> (SecretKey, bitcoin::secp256k1::PublicKey) {
        let sk = SecretKey::from_slice(&[n; 32]).unwrap();
        (sk, sk.public_key(&Secp256k1::new()))
    }

    fn source(path: &str) -> KeySource {
        (Fingerprint::from(FP), DerivationPath::from_str(path).unwrap())
    }

    #[test]
    fn inputs_must_be_the_accounts() {
        let base = [84 | HARDENED, 1 | HARDENED, HARDENED];
        let mut p = psbt();
        p.inputs[0].bip32_derivation.insert(key(1).1, source("m/84'/1'/0'/0/3"));
        assert!(check_inputs(&p, Family::Bitcoin, FP, &base).is_ok());
        assert!(check_inputs(&p, Family::Bitcoin, [0; 4], &base).is_err());
        let mut outside = psbt();
        outside.inputs[0]
            .bip32_derivation
            .insert(key(1).1, source("m/84'/1'/1'/0/3"));
        assert!(check_inputs(&outside, Family::Bitcoin, FP, &base).is_err());
        let mut hardened = psbt();
        hardened.inputs[0]
            .bip32_derivation
            .insert(key(1).1, source("m/84'/1'/0'/0'/3"));
        assert!(check_inputs(&hardened, Family::Bitcoin, FP, &base).is_err());
    }

    #[test]
    fn taproot_inputs_name_their_internal_key() {
        let (x, _) = key(2).1.x_only_public_key();
        let mut p = psbt();
        p.inputs[0]
            .tap_key_origins
            .insert(x, (vec![], source("m/86'/1'/0'/0/0")));
        name_internal_keys(&mut p, FP).unwrap();
        assert_eq!(p.inputs[0].tap_internal_key, Some(x));

        let (other, _) = key(3).1.x_only_public_key();
        p.inputs[0].tap_internal_key = Some(other);
        assert!(name_internal_keys(&mut p, FP).is_err());
    }

    #[test]
    fn the_signatures_a_device_added() {
        let secp = Secp256k1::new();
        let msg = Message::from_digest([7; 32]);
        let (sk, pk) = key(1);
        let mut p = psbt();
        p.inputs[0].bip32_derivation.insert(pk, source("m/84'/1'/0'/0/0"));
        let ecdsa = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&msg, &sk));
        p.inputs[0].partial_sigs.insert(bitcoin::PublicKey::new(pk), ecdsa);
        let sigs = signatures(&p, FP);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].pubkey, hex::encode(pk.serialize()));

        let kp = Keypair::from_secret_key(&secp, &key(4).0);
        let (x, _) = kp.x_only_public_key();
        let mut t = psbt();
        t.inputs[0]
            .tap_key_origins
            .insert(x, (vec![], source("m/86'/1'/0'/0/0")));
        t.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&msg, &kp),
            sighash_type: bitcoin::TapSighashType::Default,
        });
        let sigs = signatures(&t, FP);
        let (tweaked, _) = x.tap_tweak(&secp, None);
        assert_eq!(sigs[0].pubkey, hex::encode(tweaked.to_x_only_public_key().serialize()));
        assert!(signatures(&t, [0; 4]).is_empty());
    }
}
