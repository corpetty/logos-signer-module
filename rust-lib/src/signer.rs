//! `logos.signer/1` over the vault: the signer `signer_manager_module` calls for the families no
//! other signer holds. It mirrors keystore_module's signer half (its `docs/specs.md`, *The
//! keystore as a signer*):
//! - **hashes only.** The manager reads, renders and commits to every request, computes each
//!   digest, and checks every signature before anything settles. This module parses no request;
//!   it signs the manager's digests;
//! - every item is checked against the account **before the vault opens**;
//! - with `secret`, the seed opens for this request only. Without it, the account's unlock
//!   answers, and one request counts once against it. A wrong password is `wrong_secret`; no
//!   secret and no unlock is `locked`;
//! - a job finishes inside `sign`.
//!
//! Families: `ed25519`. Accounts are the keys minted by `derive_account`, each named by
//! `(purpose, context)`; an account's id is its `keyRef`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use logos_signer_interface::jobs::JobTable;
use logos_signer_interface::{
    Account, Collects, ErrorCode, Family, JobState, JobStatus, Payload, RequestKind, Result, Scheme, SignRequest,
    Signature, Signer, SignerError, SignerInfo, INTERFACE,
};
use zeroize::Zeroizing;

use crate::derive::{self, Scheme as KeyScheme};
use crate::identity::RoomKey;
use crate::vault::{KeyEntry, Vault, VaultError};

pub const KIND: &str = "context";

fn err(code: ErrorCode, msg: impl Into<String>) -> SignerError {
    SignerError::new(code, msg)
}

fn from_vault(e: VaultError) -> SignerError {
    match e {
        // One answer for every way a vault fails to open, as keystore gives.
        VaultError::WrongPassword => err(ErrorCode::WrongSecret, "wrong password"),
        VaultError::UnknownKey => err(ErrorCode::UnknownAccount, "no such account"),
        VaultError::UnknownGroup => err(ErrorCode::UnknownAccount, "the account's phrase is not kept here"),
        VaultError::Mnemonic | VaultError::WordCount | VaultError::GroupExists => err(ErrorCode::Invalid, e.to_string()),
        other => err(ErrorCode::Internal, other.to_string()),
    }
}

/// An unlocked account: its key in memory, until the time or the count runs out, or a lock.
/// Nothing about an unlock is written to disk.
struct Unlock {
    key: RoomKey,
    until: Option<Instant>,
    count_left: Option<u64>,
}

impl Unlock {
    fn live(&self, now: Instant) -> bool {
        self.until.is_none_or(|u| now < u) && self.count_left != Some(0)
    }
}

pub struct ContextSigner {
    vault: Vault,
    jobs: JobTable,
    unlocks: BTreeMap<String, Unlock>,
}

impl ContextSigner {
    pub fn new(vault: Vault) -> Self {
        ContextSigner { vault, jobs: JobTable::new(), unlocks: BTreeMap::new() }
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    fn entry(&self, id: &str) -> Result<KeyEntry> {
        let e = self.vault.key(id).map_err(from_vault)?;
        if e.scheme != KeyScheme::Ed25519 {
            return Err(err(ErrorCode::UnknownAccount, "no such account"));
        }
        Ok(e)
    }

    fn account_of(&self, e: &KeyEntry) -> Account {
        Account {
            id: e.key_ref.clone(),
            family: Family::Ed25519,
            chain: None,
            path: None,
            fingerprint: self.vault.fingerprint(&e.group).ok().flatten(),
            address: Some(e.public_key.clone()),
            xpub: None,
            label: Some(e.purpose.clone()),
            available: true,
        }
    }

    // ── custodian ───────────────────────────────────────────────────────────

    /// Mint (or find again) the key for `(purpose, context)` in a group. The same inputs give the
    /// same key on any device restored from the phrase. Answers the new account.
    pub fn derive_account(&mut self, group: Option<&str>, purpose: &str, context: &str, password: &str) -> Result<Account> {
        let group = match group {
            Some(g) => g.to_string(),
            None => match self.vault.groups().map_err(from_vault)?.as_slice() {
                [g] => g.clone(),
                [] => return Err(err(ErrorCode::Invalid, "no phrase is kept here")),
                _ => return Err(err(ErrorCode::Invalid, "several phrases are kept here; name one")),
            },
        };
        derive::path(KeyScheme::Ed25519, purpose, context).map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        let key_ref = derive::key_ref(&group, KeyScheme::Ed25519, purpose, context);
        let pk = self
            .vault
            .with_seed(&group, password, |seed| {
                let secret = derive::derive(seed, KeyScheme::Ed25519, purpose, context)?;
                Ok(hex::encode(derive::public_key(KeyScheme::Ed25519, &secret)))
            })
            .map_err(from_vault)?;
        let entry = KeyEntry {
            key_ref,
            scheme: KeyScheme::Ed25519,
            purpose: purpose.into(),
            context: context.into(),
            public_key: pk,
            group,
        };
        self.vault.record_key(entry.clone()).map_err(from_vault)?;
        Ok(self.account_of(&entry))
    }

    // ── the manager ─────────────────────────────────────────────────────────

    /// Hold an account's key until `ttl` passes or `count` requests are signed, whichever comes
    /// first; neither means until it is locked. Answers `(expires_in, count_left)`.
    pub fn unlock(&mut self, id: &str, password: &str, ttl: Option<Duration>, count: Option<u64>) -> Result<()> {
        let e = self.entry(id)?;
        let key = self.key_from_seed(&e, password)?;
        let until = ttl.map(|t| Instant::now() + t);
        self.unlocks.insert(id.to_string(), Unlock { key, until, count_left: count });
        Ok(())
    }

    /// Lock one account, or every account. Answers how many were unlocked.
    pub fn lock(&mut self, id: Option<&str>) -> usize {
        match id {
            Some(id) => usize::from(self.unlocks.remove(id).is_some()),
            None => std::mem::take(&mut self.unlocks).len(),
        }
    }

    /// `(account, expires_in, count_left)` for every live unlock.
    pub fn unlocked(&mut self) -> Vec<(String, Option<Duration>, Option<u64>)> {
        let now = Instant::now();
        self.unlocks.retain(|_, u| u.live(now));
        self.unlocks
            .iter()
            .map(|(id, u)| (id.clone(), u.until.map(|t| t.saturating_duration_since(now)), u.count_left))
            .collect()
    }

    fn key_from_seed(&self, e: &KeyEntry, password: &str) -> Result<RoomKey> {
        self.vault
            .with_seed(&e.group, password, |seed| {
                Ok(RoomKey::from_seed(derive::derive(seed, KeyScheme::Ed25519, &e.purpose, &e.context)?))
            })
            .map_err(from_vault)
    }

    fn sign_items(&mut self, request: &SignRequest) -> Result<Vec<Signature>> {
        let Payload::Hash { items } = &request.payload else {
            return Err(err(ErrorCode::Unsupported, "this signer signs hashes only"));
        };
        let e = self.entry(&request.account)?;
        // Every item is checked before the vault opens.
        let mut digests = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            if item.scheme != Scheme::Ed25519 {
                return Err(err(ErrorCode::Unsupported, format!("item {i}: an ed25519 account signs ed25519 only")));
            }
            if item.path.is_some() {
                return Err(err(ErrorCode::Invalid, format!("item {i}: an ed25519 account signs at no path")));
            }
            let d: [u8; 32] = hex::decode(item.digest.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| err(ErrorCode::Invalid, format!("item {i}: a digest is 32 bytes hex")))?;
            digests.push(d);
        }
        if digests.is_empty() {
            return Err(err(ErrorCode::Invalid, "no items"));
        }
        let sign_all = |k: &RoomKey| -> Vec<Signature> {
            let pubkey = hex::encode(k.identity().ed25519);
            digests
                .iter()
                .enumerate()
                .map(|(i, d)| Signature {
                    item: i,
                    signature: hex::encode(k.sign(d)),
                    recovery_id: None,
                    pubkey: pubkey.clone(),
                })
                .collect()
        };
        match &request.secret {
            Some(secret) => {
                let key = self.key_from_seed(&e, secret.expose())?;
                Ok(sign_all(&key))
            }
            None => {
                let now = Instant::now();
                let u = match self.unlocks.get_mut(&request.account) {
                    Some(u) if u.live(now) => u,
                    _ => {
                        self.unlocks.remove(&request.account);
                        return Err(err(ErrorCode::Locked, "no password and no unlock"));
                    }
                };
                // One request counts once, however many items it carries.
                if let Some(c) = u.count_left.as_mut() {
                    *c -= 1;
                }
                Ok(sign_all(&u.key))
            }
        }
    }
}

impl Signer for ContextSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: INTERFACE.into(),
            kind: KIND.into(),
            model: "context-derived keys in scrypt key files".into(),
            families: vec![Family::Ed25519],
            request_kinds: vec![RequestKind::Hash],
            shows_request: false,
            collects: Collects::Password,
        }
    }

    fn accounts(&mut self) -> Result<Vec<Account>> {
        let keys = self.vault.keys().map_err(from_vault)?;
        Ok(keys.iter().filter(|e| e.scheme == KeyScheme::Ed25519).map(|e| self.account_of(e)).collect())
    }

    fn sign(&mut self, request: SignRequest) -> Result<String> {
        // Unknown accounts and kinds are refused at once, as the interface's own checks expect.
        if !matches!(request.payload, Payload::Hash { .. }) {
            return Err(err(ErrorCode::Unsupported, "this signer signs hashes only"));
        }
        self.entry(&request.account)?;
        let outcome = self.sign_items(&request);
        let job = self.jobs.start(JobState::Working);
        self.jobs.finish(&job, outcome)?;
        Ok(job)
    }

    fn status(&mut self, job: &str) -> Result<JobStatus> {
        self.jobs.status(job)
    }

    fn result(&mut self, job: &str) -> Result<Vec<Signature>> {
        self.jobs.result(job)
    }

    fn cancel(&mut self, job: &str) -> Result<()> {
        self.jobs.cancel(job)
    }
}

/// Wipe a password handed over as a plain `String`.
pub fn scrub(s: String) {
    drop(Zeroizing::new(s));
}
