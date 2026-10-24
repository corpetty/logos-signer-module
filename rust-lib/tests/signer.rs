//! The signer behind `logos.signer/1`: the interface's own conformance suite, then what the suite
//! does not cover: unlocks, restores, and Muster's own record bytes.

use std::time::Duration;

use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::verify::check;
use logos_signer_interface::*;
use context_signer_module::identity;
use context_signer_module::record::{text, Record, Value};
use context_signer_module::signer::ContextSigner;
use context_signer_module::vault::Vault;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn signer_with(dir: &std::path::Path, contexts: &[&str]) -> ContextSigner {
    let v = Vault::new(dir);
    v.import(PHRASE, None, "pw").unwrap();
    let mut s = ContextSigner::new(v);
    for c in contexts {
        s.derive_account(None, "room-identity", c, "pw").unwrap();
    }
    s
}

fn hash_request(account: &Account, digest: [u8; 32], secret: Option<&str>) -> SignRequest {
    SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: vec![HashItem { path: None, scheme: Scheme::Ed25519, digest: hex::encode(digest) }],
        },
        secret: secret.map(Secret::new),
    }
}

#[test]
fn passes_the_interface_conformance_suite() {
    let d = tempfile::tempdir().unwrap();
    let mut s = signer_with(d.path(), &["room:a", "room:b"]);
    let fx = Fixture { secret: Some(Secret::new("pw")), wrong_secret: Some(Secret::new("nope")) };
    conformance::run(&mut s, &fx, &mut |_, _| {});
}

#[test]
fn a_restore_lists_the_same_accounts_and_signs_with_the_same_keys() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut first = signer_with(a.path(), &["room:a"]);
    let mut again = signer_with(b.path(), &["room:a"]);
    let (x, y) = (first.accounts().unwrap().remove(0), again.accounts().unwrap().remove(0));
    assert_eq!(x, y, "same id, key and fingerprint after a restore from the phrase");
    assert_eq!(x.fingerprint.as_deref(), Some("73c5da0a"), "the wallet the keystore names for this phrase");
    // A different context is a different, unlinkable key.
    let other = first.derive_account(None, "room-identity", "room:b", "pw").unwrap();
    assert_ne!(other.address, x.address);
}

#[test]
fn an_unlock_signs_without_a_password_until_its_count_or_time_runs_out() {
    let d = tempfile::tempdir().unwrap();
    let mut s = signer_with(d.path(), &["room:a"]);
    let acct = s.accounts().unwrap().remove(0);
    let ask = |s: &mut ContextSigner| {
        let job = s.sign(hash_request(&acct, [1; 32], None)).unwrap();
        s.status(&job).unwrap()
    };
    assert_eq!(ask(&mut s).error.unwrap().code, ErrorCode::Locked);
    assert_eq!(
        s.unlock(&acct.id, "nope", None, Some(2)).unwrap_err().code,
        ErrorCode::WrongSecret
    );
    s.unlock(&acct.id, "pw", None, Some(2)).unwrap();
    assert_eq!(ask(&mut s).state, JobState::Done);
    assert_eq!(ask(&mut s).state, JobState::Done);
    assert_eq!(ask(&mut s).error.unwrap().code, ErrorCode::Locked, "the count ran out");
    assert!(s.unlocked().is_empty());

    s.unlock(&acct.id, "pw", Some(Duration::from_millis(30)), None).unwrap();
    assert_eq!(ask(&mut s).state, JobState::Done);
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(ask(&mut s).error.unwrap().code, ErrorCode::Locked, "the time ran out");

    s.unlock(&acct.id, "pw", None, None).unwrap();
    assert_eq!(s.lock(Some(&acct.id)), 1);
    assert_eq!(ask(&mut s).error.unwrap().code, ErrorCode::Locked, "locked");
}

#[test]
fn items_are_checked_before_the_vault_opens() {
    let d = tempfile::tempdir().unwrap();
    let mut s = signer_with(d.path(), &["room:a"]);
    let acct = s.accounts().unwrap().remove(0);
    let mut r = hash_request(&acct, [1; 32], Some("wrong password, never tried"));
    let Payload::Hash { items } = &mut r.payload else { unreachable!() };
    items[0].path = Some("m/0".into());
    let job = s.sign(r).unwrap();
    assert_eq!(s.status(&job).unwrap().error.unwrap().code, ErrorCode::Invalid, "the path, not the password");
    let mut r = hash_request(&acct, [1; 32], Some("pw"));
    let Payload::Hash { items } = &mut r.payload else { unreachable!() };
    items[0].scheme = Scheme::Evm;
    let job = s.sign(r).unwrap();
    assert_eq!(s.status(&job).unwrap().error.unwrap().code, ErrorCode::Unsupported);
}

#[test]
fn signs_a_muster_authorship_record_as_muster_verifies_it() {
    // Muster signs SHA-256 of the dCBOR `[domain, {fields}]` record with its Ed25519 identity
    // (module/src/coordination/authorship.nim). The manager computes that digest; the signer
    // signs it; Muster's verifier, libsodium's crypto_sign_verify_detached, must accept it.
    let d = tempfile::tempdir().unwrap();
    let mut s = signer_with(d.path(), &["room:a"]);
    let acct = s.accounts().unwrap().remove(0);
    let rec = Record::build(
        "muster.event.author.v1",
        vec![("room", text("room:a")), ("author", text("m1")), ("seq", Value::Uint(3))],
    );
    let job = s.sign(hash_request(&acct, rec.digest(), Some("pw"))).unwrap();
    let sig = s.result(&job).unwrap().remove(0);
    let item = HashItem { path: None, scheme: Scheme::Ed25519, digest: hex::encode(rec.digest()) };
    check(&acct, &item, &sig).expect("the manager's check");
    let pk: [u8; 32] = hex::decode(acct.address.unwrap()).unwrap().try_into().unwrap();
    let sig: [u8; 64] = hex::decode(sig.signature).unwrap().try_into().unwrap();
    assert!(identity::verify(&pk, &rec.digest(), &sig));
}
