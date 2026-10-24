//! Between "a module asked" and "a person approved" (design §2–3).
//!
//! The lifecycle is `keystore_module`'s (its `docs/specs.md`, *Human-approved signing*):
//!
//! ```text
//! request ──▶ Offered ──acknowledge──▶ Rendered ──approve──▶ Settled(approved)
//!    │            │                       └─────reject────▶ Settled(rejected)
//!    │            └──(unclaimed for 60 s)─────────────────▶ Settled(expired_no_ack)
//!    └──cancel────────────────────────────────────────────▶ Settled(cancelled)
//! ```
//!
//! Two properties shape it, and the tests assert both:
//! 1. **One parse.** An intent is parsed once into typed legs. The render a person reads and
//!    the bytes that get signed both come from that value, and `approve` re-derives the
//!    commitment before it signs.
//! 2. **At most one record is `Rendered`.** Acknowledging one demotes any other, so what the
//!    person read is what their `approve` applies to.
//!
//! What differs from keystore_module: there is no `digest` leg, a signing leg must say which
//! record fields carry its environment and expiry, and a `grant` leg opens a standing grant.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use crate::derive::{self, Scheme};
use crate::grant::{Grants, Use};
use crate::identity::RoomKey;
use crate::record::{escape, text, Record, Value};
use crate::vault::{KeyEntry, Vault, VaultError};

/// Collects an offer nobody came for. Garbage collection, not flow control: once an approver
/// claims a request there is no timeout on the person (keystore §Lifecycle).
pub const ABANDONED_OFFER_TTL: Duration = Duration::from_secs(60);
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);
pub const MAX_PENDING_PER_REQUESTER: usize = 4;
pub const MAX_PENDING_TOTAL: usize = 16;
pub const MAX_INTENT_BYTES: usize = 64 * 1024;

/// Domains only this module authors. A requester can never have one signed.
pub const OWN_DOMAIN_PREFIX: &str = "logos.signer.";
pub const POSSESSION_DOMAIN: &str = "logos.signer.possession.v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    /// A stable code, and the detail for a person reading logs.
    #[error("{code}: {detail}")]
    Refused { code: &'static str, detail: String },
}

pub(crate) fn refuse(code: &'static str, detail: impl Into<String>) -> ApprovalError {
    ApprovalError::Refused { code, detail: detail.into() }
}

impl ApprovalError {
    pub fn code(&self) -> &'static str {
        match self {
            ApprovalError::Refused { code, .. } => code,
        }
    }
}

impl From<VaultError> for ApprovalError {
    fn from(e: VaultError) -> Self {
        let code = match &e {
            VaultError::UnknownKey => "unknown-key",
            VaultError::UnknownGroup => "unknown-group",
            VaultError::WrongPassword => "wrong-password",
            VaultError::Derive(_) => "derivation-failed",
            _ => "storage",
        };
        refuse(code, e.to_string())
    }
}

type Result<T> = std::result::Result<T, ApprovalError>;

// ── the intent, as a requester sends it ─────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum WireLeg {
    #[serde(rename_all = "camelCase")]
    Derive { scheme: String, purpose: String, context: String },
    #[serde(rename_all = "camelCase")]
    RecordSign { key_ref: String, record: String, environment_field: String, expiry_field: String },
    #[serde(rename_all = "camelCase")]
    Possession { key_ref: String, environment: String, expiry: u64, statement: String },
    #[serde(rename_all = "camelCase")]
    Grant {
        key_ref: String,
        uses: Vec<String>,
        domains: Vec<String>,
        expiry: u64,
        #[serde(default)]
        resume: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireIntent {
    #[serde(default)]
    group: Option<String>,
    purpose: String,
    #[serde(default)]
    refs: BTreeMap<String, String>,
    legs: Vec<WireLeg>,
}

// ── the parsed intent ───────────────────────────────────────────────────────

/// A key a leg names: either one already in the index, or one a `derive` earlier in the same
/// bundle mints.
#[derive(Debug, Clone)]
pub(crate) struct KeyName {
    pub key_ref: String,
    pub scheme: Scheme,
    pub purpose: String,
    pub context: String,
}

#[derive(Debug, Clone)]
pub(crate) enum Leg {
    Derive(KeyName),
    RecordSign { key: KeyName, record: Record, environment: String, expiry: u64 },
    Possession { key: KeyName, environment: String, expiry: u64, statement: String },
    Grant { key: KeyName, uses: Vec<Use>, domains: Vec<String>, expiry: u64, resume: Option<String> },
}

#[derive(Debug, Clone)]
pub(crate) struct Intent {
    pub group: String,
    pub purpose: String,
    pub refs: BTreeMap<String, String>,
    pub legs: Vec<Leg>,
}

/// The longest a grant may run before the person is asked again.
pub const MAX_GRANT: u64 = 90 * 24 * 3600;

fn check_display(s: &str, what: &str) -> Result<()> {
    if s.len() > 512 {
        return Err(refuse("too-long", format!("{what} is over 512 bytes")));
    }
    Ok(())
}

fn check_domain(d: &str) -> Result<()> {
    if derive::check_name(d).is_err() || !d.contains('.') {
        return Err(refuse("invalid-domain", format!("not a domain: {}", escape(d))));
    }
    if d.starts_with(OWN_DOMAIN_PREFIX) {
        return Err(refuse("reserved-domain", "only this module authors logos.signer.* records"));
    }
    Ok(())
}

fn field<'r>(r: &'r Record, name: &str) -> Option<&'r Value> {
    r.fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

pub(crate) fn parse(intent_json: &str, vault: &Vault, now: u64) -> Result<Intent> {
    if intent_json.len() > MAX_INTENT_BYTES {
        return Err(refuse("too-large", format!("intent is over {MAX_INTENT_BYTES} bytes")));
    }
    let w: WireIntent = serde_json::from_str(intent_json).map_err(|e| {
        if e.to_string().contains("unknown variant") {
            refuse("unknown-leg-kind", e.to_string())
        } else {
            refuse("invalid-intent", e.to_string())
        }
    })?;
    if w.legs.is_empty() {
        return Err(refuse("invalid-intent", "no legs"));
    }
    check_display(&w.purpose, "purpose")?;
    for (k, v) in &w.refs {
        check_display(k, "a ref")?;
        check_display(v, "a ref")?;
    }

    // One group per bundle: named, or the only one there is.
    let group = match w.group {
        Some(g) => {
            if !vault.groups()?.contains(&g) {
                return Err(refuse("unknown-group", g));
            }
            g
        }
        None => {
            let gs = vault.groups()?;
            match gs.as_slice() {
                [g] => g.clone(),
                [] => return Err(refuse("no-group", "no recovery phrase has been imported")),
                _ => return Err(refuse("ambiguous-group", "several groups; name one")),
            }
        }
    };

    let mut minted: Vec<KeyName> = Vec::new();
    let resolve = |key_ref: &str, minted: &[KeyName]| -> Result<KeyName> {
        if let Some(k) = minted.iter().find(|k| k.key_ref == key_ref) {
            return Ok(k.clone());
        }
        let e: KeyEntry = vault.key(key_ref)?;
        if e.group != group {
            return Err(refuse("wrong-group", "a key of another group"));
        }
        Ok(KeyName { key_ref: e.key_ref, scheme: e.scheme, purpose: e.purpose, context: e.context })
    };

    let mut legs = Vec::with_capacity(w.legs.len());
    for leg in w.legs {
        legs.push(match leg {
            WireLeg::Derive { scheme, purpose, context } => {
                let s = Scheme::parse(&scheme).ok_or_else(|| refuse("unknown-scheme", scheme.clone()))?;
                derive::path(s, &purpose, &context).map_err(|e| refuse("invalid-derivation", e.to_string()))?;
                check_display(&context, "context")?;
                let k = KeyName {
                    key_ref: derive::key_ref(&group, s, &purpose, &context),
                    scheme: s,
                    purpose,
                    context,
                };
                minted.push(k.clone());
                Leg::Derive(k)
            }
            WireLeg::RecordSign { key_ref, record, environment_field, expiry_field } => {
                let key = resolve(&key_ref, &minted)?;
                if key.scheme != Scheme::Ed25519 {
                    return Err(refuse("scheme-unavailable", "S1 signs records with Ed25519 keys only"));
                }
                let bytes = hex::decode(record.trim_start_matches("0x"))
                    .map_err(|_| refuse("invalid-intent", "record is not hex"))?;
                let r = Record::parse(&bytes).map_err(|e| match e {
                    crate::record::RecordError::NonCanonical(_) => refuse("non-canonical-record", e.to_string()),
                    crate::record::RecordError::NotARecord(_) => refuse("not-a-record", e.to_string()),
                })?;
                check_domain(&r.domain)?;
                // Rule 4: the signature must commit to where and until when it is valid, so
                // those must be IN the signed record. The requester names the fields; this
                // module reads them and shows them as its own words.
                let environment = match field(&r, &environment_field) {
                    Some(Value::Text(t)) if !t.is_empty() => t.clone(),
                    _ => return Err(refuse("missing-environment", format!("no text field {}", escape(&environment_field)))),
                };
                let expiry = match field(&r, &expiry_field) {
                    Some(Value::Uint(u)) => *u,
                    _ => return Err(refuse("missing-expiry", format!("no uint field {}", escape(&expiry_field)))),
                };
                if expiry <= now {
                    return Err(refuse("expired", "the record's expiry has passed"));
                }
                Leg::RecordSign { key, record: r, environment, expiry }
            }
            WireLeg::Possession { key_ref, environment, expiry, statement } => {
                let key = resolve(&key_ref, &minted)?;
                if key.scheme != Scheme::Ed25519 {
                    return Err(refuse("scheme-unavailable", "S1 proves possession of Ed25519 keys only"));
                }
                if environment.is_empty() {
                    return Err(refuse("missing-environment", "possession needs an environment"));
                }
                if expiry <= now {
                    return Err(refuse("expired", "the expiry has passed"));
                }
                check_display(&environment, "environment")?;
                check_display(&statement, "statement")?;
                Leg::Possession { key, environment, expiry, statement }
            }
            WireLeg::Grant { key_ref, uses, domains, expiry, resume } => {
                let key = resolve(&key_ref, &minted)?;
                if key.scheme != Scheme::Ed25519 {
                    return Err(refuse("not-grantable", "only Ed25519 identity keys can be granted"));
                }
                if uses.is_empty() || domains.is_empty() {
                    return Err(refuse("invalid-grant", "a grant names its uses and its domains"));
                }
                let uses = uses
                    .iter()
                    .map(|u| Use::parse(u).ok_or_else(|| refuse("invalid-grant", format!("unknown use {}", escape(u)))))
                    .collect::<Result<Vec<_>>>()?;
                for d in &domains {
                    check_domain(d)?;
                }
                if expiry <= now || expiry > now + MAX_GRANT {
                    return Err(refuse("invalid-grant", "a grant's expiry must be in the next 90 days"));
                }
                Leg::Grant { key, uses, domains, expiry, resume }
            }
        });
    }
    Ok(Intent { group, purpose: w.purpose, refs: w.refs, legs })
}

// ── commitment and render ───────────────────────────────────────────────────

fn key_value(k: &KeyName) -> Value {
    Value::Map(vec![
        (text("keyRef"), text(&k.key_ref)),
        (text("scheme"), text(k.scheme.as_str())),
        (text("purpose"), text(&k.purpose)),
        (text("context"), text(&k.context)),
    ])
}

/// SHA-256 over this module's own deterministic encoding of the parsed intent, never over the
/// requester's bytes. SHA-256 of a `logos.signer.bundle.v1` record: it cannot be mistaken for
/// any digest this module signs, which are all of requester-domain records.
pub(crate) fn commitment(requester: &str, i: &Intent) -> [u8; 32] {
    let legs = i
        .legs
        .iter()
        .map(|l| match l {
            Leg::Derive(k) => Value::Map(vec![(text("kind"), text("derive")), (text("key"), key_value(k))]),
            Leg::RecordSign { key, record, environment, expiry } => Value::Map(vec![
                (text("kind"), text("record-sign")),
                (text("key"), key_value(key)),
                (text("record"), Value::Bytes(record.bytes().to_vec())),
                (text("environment"), text(environment)),
                (text("expiry"), Value::Uint(*expiry)),
            ]),
            Leg::Possession { key, environment, expiry, statement } => Value::Map(vec![
                (text("kind"), text("possession")),
                (text("key"), key_value(key)),
                (text("environment"), text(environment)),
                (text("expiry"), Value::Uint(*expiry)),
                (text("statement"), text(statement)),
            ]),
            Leg::Grant { key, uses, domains, expiry, resume } => Value::Map(vec![
                (text("kind"), text("grant")),
                (text("key"), key_value(key)),
                (text("uses"), Value::Array(uses.iter().map(|u| text(u.as_str())).collect())),
                (text("domains"), Value::Array(domains.iter().map(|d| text(d)).collect())),
                (text("expiry"), Value::Uint(*expiry)),
                (text("resume"), resume.as_deref().map(text).unwrap_or(Value::Null)),
            ]),
        })
        .collect();
    let refs = i.refs.iter().map(|(k, v)| (text(k), text(v))).collect();
    Record::build(
        "logos.signer.bundle.v1",
        vec![
            ("requester", text(requester)),
            ("group", text(&i.group)),
            ("purpose", text(&i.purpose)),
            ("refs", Value::Map(refs)),
            ("legs", Value::Array(legs)),
        ],
    )
    .digest()
}

fn key_line(k: &KeyName) -> String {
    format!("Key {} ({}, {} for {})", k.key_ref, k.scheme.as_str(), escape(&k.purpose), escape(&k.context))
}

/// `(claim_lines, render_lines)`. Claims are the requester's words. The render is this
/// module's, escaped, and must be shown verbatim. `refs` are never shown: they are the app's
/// own join keys, and showing them would invite reading them as meaning.
pub(crate) fn render(i: &Intent, bundle_id: &[u8; 32]) -> (Vec<String>, Vec<String>) {
    let claim = vec![format!("The requester says this is for: {}", escape(&i.purpose))];
    let mut r = vec![format!("Recovery phrase group: {}", i.group)];
    for (n, l) in i.legs.iter().enumerate() {
        r.push(format!("Leg {} of {}:", n + 1, i.legs.len()));
        match l {
            Leg::Derive(k) => {
                r.push(format!("  Create (or find again) a {} key for {}", k.scheme.as_str(), escape(&k.purpose)));
                r.push(format!("  Context: {}", escape(&k.context)));
                r.push(format!("  It will be named {}", k.key_ref));
            }
            Leg::RecordSign { key, record, environment, expiry } => {
                r.push(format!("  Sign this record with {}", key_line(key)));
                r.push(format!("  Valid in: {}", escape(environment)));
                r.push(format!("  Valid until: {expiry} (unix seconds)"));
                r.extend(record.render().into_iter().map(|l| format!("  {l}")));
            }
            Leg::Possession { key, environment, expiry, statement } => {
                r.push(format!("  Prove that {} is yours", key_line(key)));
                r.push(format!("  For: {}", escape(environment)));
                r.push(format!("  Until: {expiry} (unix seconds)"));
                r.push(format!("  Statement: {}", escape(statement)));
            }
            Leg::Grant { key, uses, domains, expiry, resume } => {
                let what = if resume.is_some() { "Resume letting" } else { "Let" };
                r.push(format!("  {what} the requester use {} WITHOUT ASKING", key_line(key)));
                r.push(format!(
                    "  For: {}",
                    uses.iter().map(|u| u.describe()).collect::<Vec<_>>().join("; ")
                ));
                r.push("  Only records of these domains:".into());
                r.extend(domains.iter().map(|d| format!("    {}", escape(d))));
                r.push(format!("  Until: {expiry} (unix seconds), revocation, or the signer stopping"));
            }
        }
    }
    r.push(format!("Commitment: {}", hex::encode(bundle_id)));
    (claim, r)
}

// ── the store ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Offered,
    Rendered,
    Settled(Outcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Rejected,
    ExpiredNoAck,
    Cancelled,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Rejected => "rejected",
            Outcome::ExpiredNoAck => "expired_no_ack",
            Outcome::Cancelled => "cancelled",
        }
    }
}

struct Entry {
    handle: String,
    receipt_hash: [u8; 32],
    requester: String,
    intent: Intent,
    bundle_id: [u8; 32],
    claim_lines: Vec<String>,
    render_lines: Vec<String>,
    state: State,
    offered_at: Instant,
    settled_at: Option<Instant>,
    claimed: bool,
    results: Option<Vec<Json>>,
}

pub struct Rendered {
    pub handle: String,
    pub bundle_id: String,
    /// The caller's attested identity, never a field it filled in.
    pub requester: String,
    pub claim_lines: Vec<String>,
    pub render_lines: Vec<String>,
}

pub struct Summary {
    pub handle: String,
    pub requester: String,
    pub state: &'static str,
    pub purpose: String,
    pub leg_count: usize,
    pub age_ms: u128,
}

pub struct Approvals {
    entries: Vec<Entry>,
    seq: u64,
    abandoned_offer_ttl: Duration,
}

impl Default for Approvals {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// 128 random bits and a sequence number, so two mints in one instant cannot collide.
pub(crate) fn token(prefix: &str, seq: u64) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}{}{seq:x}", hex::encode(b))
}

impl Approvals {
    pub fn new() -> Self {
        Approvals { entries: Vec::new(), seq: 0, abandoned_offer_ttl: ABANDONED_OFFER_TTL }
    }

    /// Shortening it only fails closed sooner, which is what the expiry test relies on.
    pub fn set_abandoned_offer_ttl(&mut self, d: Duration) {
        self.abandoned_offer_ttl = d;
    }

    /// Lazy collection, at the head of every entry point.
    fn sweep(&mut self) {
        let now = Instant::now();
        for e in &mut self.entries {
            if e.state == State::Offered && !e.claimed && now.duration_since(e.offered_at) > self.abandoned_offer_ttl {
                e.state = State::Settled(Outcome::ExpiredNoAck);
            }
            if matches!(e.state, State::Settled(_)) && e.settled_at.is_none() {
                e.settled_at = Some(now);
            }
        }
        self.entries.retain(|e| match e.settled_at {
            None => true,
            Some(at) => e.results.is_some() || now.duration_since(at) < SETTLED_RETENTION,
        });
    }

    fn live(e: &&Entry) -> bool {
        !matches!(e.state, State::Settled(_))
    }

    /// Returns `(handle, receipt)`. The receipt is returned once and kept only as a hash.
    pub fn request(&mut self, requester: &str, intent_json: &str, vault: &Vault, now: u64) -> Result<(String, String)> {
        self.sweep();
        if self.entries.iter().filter(Self::live).count() >= MAX_PENDING_TOTAL {
            return Err(refuse("too-many-pending", "16 requests are waiting"));
        }
        if self.entries.iter().filter(Self::live).filter(|e| e.requester == requester).count() >= MAX_PENDING_PER_REQUESTER {
            return Err(refuse("too-many-pending", "4 requests from this module are waiting"));
        }
        let intent = parse(intent_json, vault, now)?;
        let bundle_id = commitment(requester, &intent);
        let (claim_lines, render_lines) = render(&intent, &bundle_id);
        self.seq += 1;
        let handle = token("sgh_", self.seq);
        let receipt = token("sgc_", self.seq);
        self.entries.push(Entry {
            handle: handle.clone(),
            receipt_hash: sha256(receipt.as_bytes()),
            requester: requester.to_string(),
            intent,
            bundle_id,
            claim_lines,
            render_lines,
            state: State::Offered,
            offered_at: Instant::now(),
            settled_at: None,
            claimed: false,
            results: None,
        });
        Ok((handle, receipt))
    }

    pub fn pending(&mut self) -> Vec<Summary> {
        self.sweep();
        let now = Instant::now();
        self.entries
            .iter()
            .filter(Self::live)
            .map(|e| Summary {
                handle: e.handle.clone(),
                requester: e.requester.clone(),
                state: if e.state == State::Rendered { "rendered" } else { "offered" },
                purpose: e.intent.purpose.clone(),
                leg_count: e.intent.legs.len(),
                age_ms: now.duration_since(e.offered_at).as_millis(),
            })
            .collect()
    }

    /// Claim a request for display, demoting any other on screen.
    pub fn acknowledge(&mut self, handle: &str) -> Result<Rendered> {
        self.sweep();
        let Some(idx) = self.entries.iter().position(|e| e.handle == handle) else {
            return Err(refuse("not-found", "no such request"));
        };
        if let State::Settled(o) = self.entries[idx].state {
            return Err(refuse("already-settled", o.as_str()));
        }
        for (i, e) in self.entries.iter_mut().enumerate() {
            if i != idx && e.state == State::Rendered {
                e.state = State::Offered;
            }
        }
        let e = &mut self.entries[idx];
        e.state = State::Rendered;
        e.claimed = true;
        Ok(Rendered {
            handle: e.handle.clone(),
            bundle_id: hex::encode(e.bundle_id),
            requester: e.requester.clone(),
            claim_lines: e.claim_lines.clone(),
            render_lines: e.render_lines.clone(),
        })
    }

    /// The person said yes. Re-derives the commitment, checks the approver echoed the one it
    /// showed, opens the seed once, does every leg, and wipes. Answers a count: the approver
    /// never receives what it authorized.
    pub fn approve(
        &mut self,
        vault: &Vault,
        grants: &mut Grants,
        handle: &str,
        bundle_id_echo: &str,
        password: &str,
        now: u64,
    ) -> Result<usize> {
        self.sweep();
        let Some(e) = self.entries.iter_mut().find(|e| e.handle == handle) else {
            return Err(refuse("not-found", "no such request"));
        };
        if e.state != State::Rendered {
            return Err(refuse("not-rendered", "this request is not the one on screen"));
        }
        let fresh = commitment(&e.requester, &e.intent);
        if !ct_eq(&fresh, &e.bundle_id) {
            return Err(refuse("commitment-drift", "the request changed after it was shown"));
        }
        if bundle_id_echo.trim().trim_start_matches("0x") != hex::encode(fresh) {
            return Err(refuse("bundle-mismatch", "bundle_id is not the one shown"));
        }
        // Time passes while a person reads: an expiry is checked again here.
        for l in &e.intent.legs {
            let exp = match l {
                Leg::RecordSign { expiry, .. } | Leg::Possession { expiry, .. } | Leg::Grant { expiry, .. } => *expiry,
                Leg::Derive(_) => u64::MAX,
            };
            if exp <= now {
                return Err(refuse("expired", "an expiry passed while the request was on screen"));
            }
        }
        let requester = e.requester.clone();
        let intent = e.intent.clone();
        let mut minted: Vec<KeyEntry> = Vec::new();
        let mut held: Vec<(KeyName, Vec<Use>, Vec<String>, u64, Option<String>, RoomKey)> = Vec::new();
        let results = vault.with_seed(&intent.group, password, |seed| {
            let key_of = |k: &KeyName| -> std::result::Result<RoomKey, VaultError> {
                Ok(RoomKey::from_seed(derive::derive(seed, k.scheme, &k.purpose, &k.context)?))
            };
            let mut out = Vec::with_capacity(intent.legs.len());
            for l in &intent.legs {
                out.push(match l {
                    Leg::Derive(k) => {
                        let secret = derive::derive(seed, k.scheme, &k.purpose, &k.context)?;
                        let pk = hex::encode(derive::public_key(k.scheme, &secret));
                        minted.push(KeyEntry {
                            key_ref: k.key_ref.clone(),
                            scheme: k.scheme,
                            purpose: k.purpose.clone(),
                            context: k.context.clone(),
                            public_key: pk.clone(),
                            group: intent.group.clone(),
                        });
                        let mut v = json!({ "kind": "derive", "keyRef": k.key_ref, "publicKey": pk });
                        if k.scheme == Scheme::Ed25519 {
                            let id = RoomKey::from_seed(secret).identity();
                            v["x25519"] = json!(hex::encode(id.x25519));
                        }
                        v
                    }
                    Leg::RecordSign { key, record, .. } => {
                        let sig = key_of(key)?.sign(&record.digest());
                        json!({ "kind": "record-sign", "keyRef": key.key_ref, "signature": hex::encode(sig) })
                    }
                    Leg::Possession { key, environment, expiry, statement } => {
                        let rk = key_of(key)?;
                        let rec = possession_record(&rk.identity().ed25519, environment, *expiry, statement);
                        json!({
                            "kind": "possession",
                            "keyRef": key.key_ref,
                            "record": hex::encode(rec.bytes()),
                            "signature": hex::encode(rk.sign(&rec.digest())),
                        })
                    }
                    Leg::Grant { key, uses, domains, expiry, resume } => {
                        held.push((key.clone(), uses.clone(), domains.clone(), *expiry, resume.clone(), key_of(key)?));
                        json!({ "kind": "grant", "keyRef": key.key_ref })
                    }
                });
            }
            Ok(out)
        })?;
        // The seed is wiped. Only now does anything persist or a grant open.
        for m in minted {
            vault.record_key(m)?;
        }
        let mut results = results;
        let mut held = held.into_iter();
        for r in results.iter_mut().filter(|r| r["kind"] == "grant") {
            let (key, uses, domains, expiry, resume, rk) = held.next().expect("one held key per grant leg");
            let (id, receipt) = grants.open(&requester, &key.key_ref, uses, domains, expiry, resume.as_deref(), rk, now)?;
            r["grantId"] = json!(id);
            r["grantReceipt"] = json!(receipt);
        }
        let n = results.len();
        let e = self.entries.iter_mut().find(|e| e.handle == handle).expect("found above");
        e.results = Some(results);
        e.state = State::Settled(Outcome::Approved);
        Ok(n)
    }

    pub fn reject(&mut self, handle: &str) -> Result<()> {
        self.sweep();
        let Some(e) = self.entries.iter_mut().find(|e| e.handle == handle) else {
            return Err(refuse("not-found", "no such request"));
        };
        if let State::Settled(o) = e.state {
            return Err(refuse("already-settled", o.as_str()));
        }
        e.state = State::Settled(Outcome::Rejected);
        Ok(())
    }

    fn by_receipt(&mut self, handle: &str, receipt: &str) -> Option<&mut Entry> {
        let want = sha256(receipt.as_bytes());
        self.entries.iter_mut().find(|e| e.handle == handle && ct_eq(&e.receipt_hash, &want))
    }

    /// `(state, outcome)`. Never the intent, never the results.
    pub fn status(&mut self, handle: &str, receipt: &str) -> Result<(&'static str, Option<&'static str>)> {
        self.sweep();
        let e = self.by_receipt(handle, receipt).ok_or_else(|| refuse("not-found", "no such request"))?;
        Ok(match e.state {
            State::Offered => ("offered", None),
            State::Rendered => ("rendered", None),
            State::Settled(o) => ("settled", Some(o.as_str())),
        })
    }

    /// Idempotent until `ack_result`, so a dropped reply never costs the person a second
    /// password entry.
    pub fn fetch_result(&mut self, handle: &str, receipt: &str) -> Result<Vec<Json>> {
        self.sweep();
        let e = self.by_receipt(handle, receipt).ok_or_else(|| refuse("not-found", "no such request"))?;
        e.results.clone().ok_or_else(|| refuse("no-result", "nothing to collect"))
    }

    pub fn ack_result(&mut self, handle: &str, receipt: &str) -> Result<()> {
        let e = self.by_receipt(handle, receipt).ok_or_else(|| refuse("not-found", "no such request"))?;
        e.results = None;
        self.sweep();
        Ok(())
    }

    pub fn cancel(&mut self, handle: &str, receipt: &str) -> Result<()> {
        let e = self.by_receipt(handle, receipt).ok_or_else(|| refuse("not-found", "no such request"))?;
        if !matches!(e.state, State::Settled(_)) {
            e.state = State::Settled(Outcome::Cancelled);
        }
        e.results = None;
        self.sweep();
        Ok(())
    }
}

/// The record a possession proof signs. This module writes it whole; no requester can.
pub fn possession_record(ed25519: &[u8; 32], environment: &str, expiry: u64, statement: &str) -> Record {
    Record::build(
        POSSESSION_DOMAIN,
        vec![
            ("key", Value::Bytes(ed25519.to_vec())),
            ("scheme", text("ed25519")),
            ("environment", text(environment)),
            ("expiry", Value::Uint(expiry)),
            ("statement", text(statement)),
        ],
    )
}
