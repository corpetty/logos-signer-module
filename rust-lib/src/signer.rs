//! The module's operations, gated by caller, with no Logos runtime in sight. The glue maps each
//! contract method onto one of these and turns the answer into the JSON the contract returns.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value as Json};

use crate::approval::{Approvals, ApprovalError};
use crate::derive::Scheme;
use crate::gate::{Caller, Roles, NOT_AUTHORIZED};
use crate::grant::Grants;
use crate::vault::{Vault, VaultError};

/// What a method answers: a JSON body, or a refusal with a stable code.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    /// Every tier's refusal, one string.
    NotAuthorized,
    Code { code: &'static str, detail: String },
}

impl Refusal {
    pub fn to_json(&self) -> Json {
        match self {
            Refusal::NotAuthorized => json!({ "ok": false, "error": NOT_AUTHORIZED }),
            Refusal::Code { code, detail } => json!({ "ok": false, "error": code, "detail": detail }),
        }
    }
}

impl From<ApprovalError> for Refusal {
    fn from(e: ApprovalError) -> Self {
        let ApprovalError::Refused { code, detail } = e;
        Refusal::Code { code, detail }
    }
}

impl From<VaultError> for Refusal {
    fn from(e: VaultError) -> Self {
        ApprovalError::from(e).into()
    }
}

pub type Answer = Result<Json, Refusal>;

/// An event for the glue to emit. Each carries a handle or a count, never content.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    ApprovalOffered(String),
    ApprovalSettled(String, &'static str),
    KeysChanged(i64),
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub struct Signer {
    vault: Vault,
    approvals: Approvals,
    grants: Grants,
    roles: Roles,
    events: Vec<Event>,
}

fn ok(mut v: Json) -> Answer {
    v["ok"] = json!(true);
    Ok(v)
}

fn bad(code: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal::Code { code, detail: detail.into() }
}

impl Signer {
    /// A signer keeping its state under `dir`. Grants found there are loaded dormant.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Signer> {
        let dir = dir.into();
        Ok(Signer {
            grants: Grants::load(dir.join("grants.json"))?,
            vault: Vault::new(dir),
            approvals: Approvals::new(),
            roles: Roles::default(),
            events: Vec::new(),
        })
    }

    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    pub fn approvals_mut(&mut self) -> &mut Approvals {
        &mut self.approvals
    }

    fn requester(c: &Caller) -> Result<&str, Refusal> {
        c.module_name().ok_or(Refusal::NotAuthorized)
    }

    fn approver(&self, c: &Caller) -> Result<(), Refusal> {
        if self.roles.is_approver(c) { Ok(()) } else { Err(Refusal::NotAuthorized) }
    }

    fn custodian(&self, c: &Caller) -> Result<(), Refusal> {
        if self.roles.is_custodian(c) { Ok(()) } else { Err(Refusal::NotAuthorized) }
    }

    fn keys_changed(&mut self) {
        let n = self.vault.keys().map(|k| k.len() as i64).unwrap_or(-1);
        self.events.push(Event::KeysChanged(n));
    }

    // ── Tier C ──────────────────────────────────────────────────────────────

    pub fn configure(&mut self, doc: &str) -> Answer {
        self.roles.configure(doc).map_err(|e| bad("invalid-params", e))?;
        ok(json!({ "approver": self.roles.approvers, "custodian": self.roles.custodians }))
    }

    pub fn caller_identity(&self, c: &Caller) -> Answer {
        ok(json!({
            "kind": c.kind(),
            "identity": c.identity(),
            "approvers": self.roles.approvers,
            "custodians": self.roles.custodians,
        }))
    }

    pub fn list_keys(&self) -> Answer {
        ok(json!({ "keys": self.vault.keys()? }))
    }

    pub fn list_groups(&self) -> Answer {
        ok(json!({ "groups": self.vault.groups()? }))
    }

    /// The public room identity of an Ed25519 key, from the index alone.
    pub fn identity(&self, key_ref: &str) -> Answer {
        let e = self.vault.key(key_ref)?;
        if e.scheme != Scheme::Ed25519 {
            return Err(bad("not-an-identity", "not an Ed25519 key"));
        }
        let pk: [u8; 32] = hex::decode(&e.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("storage", "keys.json holds a malformed key"))?;
        let x = ed25519_dalek::VerifyingKey::from_bytes(&pk)
            .map_err(|_| bad("storage", "keys.json holds a malformed key"))?
            .to_montgomery();
        ok(json!({ "keyRef": key_ref, "ed25519": e.public_key, "x25519": hex::encode(x.to_bytes()) }))
    }

    // ── Tier D ──────────────────────────────────────────────────────────────

    pub fn create_mnemonic(&mut self, c: &Caller, words: i64) -> Answer {
        self.custodian(c)?;
        let words = usize::try_from(words).map_err(|_| bad("invalid-word-count", "words"))?;
        let phrase = Vault::create_mnemonic(words)?;
        ok(json!({ "phrase": phrase.as_str() }))
    }

    pub fn import_mnemonic(&mut self, c: &Caller, params: &str) -> Answer {
        self.custodian(c)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct P {
            phrase: String,
            #[serde(default)]
            passphrase: Option<String>,
            password: String,
        }
        let p: P = serde_json::from_str(params).map_err(|_| bad("invalid-params", "{phrase, passphrase?, password}"))?;
        let g = self.vault.import(&p.phrase, p.passphrase.as_deref(), &p.password)?;
        ok(json!({ "group": g }))
    }

    pub fn forget_group(&mut self, c: &Caller, params: &str) -> Answer {
        self.custodian(c)?;
        let p: Json = serde_json::from_str(params).map_err(|_| bad("invalid-params", "{group}"))?;
        let g = p["group"].as_str().ok_or_else(|| bad("invalid-params", "{group}"))?;
        self.vault.forget(g)?;
        ok(json!({ "group": g }))
    }

    // ── Tier B ──────────────────────────────────────────────────────────────

    pub fn request_approval(&mut self, c: &Caller, intent: &str, now: u64) -> Answer {
        let who = Self::requester(c)?.to_string();
        let (handle, receipt) = self.approvals.request(&who, intent, &self.vault, now)?;
        self.events.push(Event::ApprovalOffered(handle.clone()));
        ok(json!({ "handle": handle, "receipt": receipt, "state": "offered" }))
    }

    pub fn approval_status(&mut self, c: &Caller, handle: &str, receipt: &str) -> Answer {
        Self::requester(c)?;
        let (state, reason) = self.approvals.status(handle, receipt)?;
        ok(json!({ "state": state, "reason": reason }))
    }

    pub fn fetch_result(&mut self, c: &Caller, handle: &str, receipt: &str) -> Answer {
        Self::requester(c)?;
        ok(json!({ "signed": self.approvals.fetch_result(handle, receipt)? }))
    }

    pub fn ack_result(&mut self, c: &Caller, handle: &str, receipt: &str) -> bool {
        Self::requester(c).is_ok() && self.approvals.ack_result(handle, receipt).is_ok()
    }

    pub fn cancel_approval(&mut self, c: &Caller, handle: &str, receipt: &str) -> bool {
        Self::requester(c).is_ok() && self.approvals.cancel(handle, receipt).is_ok()
    }

    pub fn grant_sign(&mut self, c: &Caller, id: &str, receipt: &str, record_hex: &str, now: u64) -> Answer {
        let who = Self::requester(c)?.to_string();
        let sig = self.grants.sign(&who, id, receipt, record_hex, now)?;
        ok(json!({ "signature": hex::encode(sig) }))
    }

    pub fn grant_open(&mut self, c: &Caller, id: &str, receipt: &str, sealed_hex: &str, now: u64) -> Answer {
        let who = Self::requester(c)?.to_string();
        let sealed = hex::decode(sealed_hex.trim_start_matches("0x")).map_err(|_| bad("invalid-params", "not hex"))?;
        let plain = self.grants.open_box(&who, id, receipt, &sealed, now)?;
        ok(json!({ "plaintext": hex::encode(plain) }))
    }

    pub fn grant_secret(&mut self, c: &Caller, id: &str, receipt: &str, record_hex: &str, now: u64) -> Answer {
        let who = Self::requester(c)?.to_string();
        let s = self.grants.secret(&who, id, receipt, record_hex, now)?;
        ok(json!({ "secret": hex::encode(*s) }))
    }

    /// The approver revokes any grant; a requester revokes its own, with its receipt.
    pub fn revoke_grant(&mut self, c: &Caller, id: &str, receipt: &str) -> bool {
        if self.roles.is_approver(c) {
            return self.grants.revoke(id).is_ok();
        }
        match c.module_name() {
            Some(who) => self.grants.revoke_own(who, id, receipt).is_ok(),
            None => false,
        }
    }

    // ── Tier A ──────────────────────────────────────────────────────────────

    pub fn pending(&mut self, c: &Caller) -> Answer {
        self.approver(c)?;
        let p: Vec<Json> = self
            .approvals
            .pending()
            .into_iter()
            .map(|s| {
                json!({ "handle": s.handle, "requester": s.requester, "state": s.state,
                        "purpose": s.purpose, "legCount": s.leg_count, "ageMs": s.age_ms as u64 })
            })
            .collect();
        ok(json!({ "pending": p }))
    }

    pub fn acknowledge(&mut self, c: &Caller, handle: &str) -> Answer {
        self.approver(c)?;
        let r = self.approvals.acknowledge(handle)?;
        ok(json!({ "handle": r.handle, "bundle_id": r.bundle_id, "requester": r.requester,
                   "claim_lines": r.claim_lines, "render_lines": r.render_lines }))
    }

    pub fn approve(&mut self, c: &Caller, handle: &str, bundle_id: &str, password: &str, now: u64) -> Answer {
        self.approver(c)?;
        let n = self.approvals.approve(&self.vault, &mut self.grants, handle, bundle_id, password, now)?;
        self.events.push(Event::ApprovalSettled(handle.into(), "approved"));
        self.keys_changed();
        ok(json!({ "signed_count": n }))
    }

    pub fn reject(&mut self, c: &Caller, handle: &str) -> bool {
        if self.approver(c).is_err() || self.approvals.reject(handle).is_err() {
            return false;
        }
        self.events.push(Event::ApprovalSettled(handle.into(), "rejected"));
        true
    }

    pub fn list_grants(&self, c: &Caller, now: u64) -> Answer {
        self.approver(c)?;
        ok(json!({ "grants": self.grants.list(now) }))
    }
}
