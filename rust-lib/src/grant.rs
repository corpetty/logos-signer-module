//! Standing grants (design §5): a person lets one module use one identity key for named record
//! domains, without a prompt per use.
//!
//! This is the one place the module departs from keystore_module, which signs nothing without
//! a password typed for that request. The departure is bounded:
//! - only an Ed25519 identity key, never a key that moves funds;
//! - only exact domains the person read;
//! - only the requester that asked, holding the grant's receipt;
//! - until the expiry, a revocation, or the module stopping. A stopped module drops every held
//!   key; the grant record survives as `dormant`, and resuming it is a new approval.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::approval::{ct_eq, refuse, sha256, token, ApprovalError, OWN_DOMAIN_PREFIX};
use crate::identity::RoomKey;
use crate::record::Record;

type Result<T> = std::result::Result<T, ApprovalError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Use {
    /// Ed25519 over `SHA-256(record)`.
    Sign,
    /// Open a sealed box addressed to the key's X25519 identity.
    Open,
    /// HMAC-SHA256 under the key's seed over a record: one secret for one purpose.
    Secret,
}

impl Use {
    pub fn parse(s: &str) -> Option<Use> {
        match s {
            "sign" => Some(Use::Sign),
            "open" => Some(Use::Open),
            "secret" => Some(Use::Secret),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Use::Sign => "sign",
            Use::Open => "open",
            Use::Secret => "secret",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Use::Sign => "sign records",
            Use::Open => "open sealed messages addressed to this key",
            Use::Secret => "derive secrets for records",
        }
    }
}

/// What survives a restart. No key, and the receipt only as a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRecord {
    pub grant_id: String,
    pub requester: String,
    pub key_ref: String,
    pub uses: Vec<Use>,
    pub domains: Vec<String>,
    pub expiry: u64,
    receipt_hash: String,
}

struct Grant {
    rec: GrantRecord,
    receipt_hash: [u8; 32],
    key: Option<RoomKey>,
}

/// A grant as an approver lists it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    pub grant_id: String,
    pub requester: String,
    pub key_ref: String,
    pub uses: Vec<Use>,
    pub domains: Vec<String>,
    pub expiry: u64,
    /// `active`, `dormant` (no key held: the module restarted) or `expired`.
    pub state: &'static str,
}

pub struct Grants {
    grants: BTreeMap<String, Grant>,
    seq: u64,
    path: Option<PathBuf>,
}

impl Grants {
    /// Grants kept only in memory.
    pub fn in_memory() -> Grants {
        Grants { grants: BTreeMap::new(), seq: 0, path: None }
    }

    /// Grants recorded at `path`. Every loaded grant is dormant: no key survives a restart.
    pub fn load(path: PathBuf) -> std::io::Result<Grants> {
        let mut g = Grants { grants: BTreeMap::new(), seq: 0, path: Some(path.clone()) };
        match std::fs::read(&path) {
            Ok(b) => {
                let recs: Vec<GrantRecord> = serde_json::from_slice(&b)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                for rec in recs {
                    let mut h = [0u8; 32];
                    if hex::decode_to_slice(&rec.receipt_hash, &mut h).is_err() {
                        continue;
                    }
                    g.grants.insert(rec.grant_id.clone(), Grant { rec, receipt_hash: h, key: None });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(g)
    }

    fn save(&self) -> Result<()> {
        let Some(p) = &self.path else { return Ok(()) };
        let recs: Vec<&GrantRecord> = self.grants.values().map(|g| &g.rec).collect();
        let bytes = serde_json::to_vec_pretty(&recs).expect("serializable");
        let dir = p.parent().expect("a file in a directory");
        std::fs::create_dir_all(dir).map_err(|e| refuse("storage", e.to_string()))?;
        let mut f = tempfile::NamedTempFile::new_in(dir).map_err(|e| refuse("storage", e.to_string()))?;
        std::io::Write::write_all(&mut f, &bytes).map_err(|e| refuse("storage", e.to_string()))?;
        f.persist(p).map_err(|e| refuse("storage", e.to_string()))?;
        Ok(())
    }

    /// Open a grant, or resume a dormant one, holding `key`. Only an approval calls this.
    /// Returns `(grantId, receipt)`; the receipt goes to the requester through `fetch_result`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        &mut self,
        requester: &str,
        key_ref: &str,
        uses: Vec<Use>,
        domains: Vec<String>,
        expiry: u64,
        resume: Option<&str>,
        key: RoomKey,
        now: u64,
    ) -> Result<(String, String)> {
        self.seq += 1;
        let receipt = token("sgr_", self.seq);
        let rh = sha256(receipt.as_bytes());
        let id = match resume {
            Some(id) => {
                let g = self.grants.get(id).ok_or_else(|| refuse("unknown-grant", "nothing to resume"))?;
                if g.rec.requester != requester || g.rec.key_ref != key_ref {
                    return Err(refuse("unknown-grant", "not this requester's grant for this key"));
                }
                id.to_string()
            }
            None => token("sgg_", self.seq),
        };
        debug_assert!(expiry > now);
        let rec = GrantRecord {
            grant_id: id.clone(),
            requester: requester.into(),
            key_ref: key_ref.into(),
            uses,
            domains,
            expiry,
            receipt_hash: hex::encode(rh),
        };
        self.grants.insert(id.clone(), Grant { rec, receipt_hash: rh, key: Some(key) });
        self.save()?;
        Ok((id, receipt))
    }

    /// The key behind a grant, for `requester` holding `receipt`, if the grant allows `using`.
    fn held(&mut self, requester: &str, id: &str, receipt: &str, using: Use, now: u64) -> Result<&RoomKey> {
        let want = sha256(receipt.as_bytes());
        let g = match self.grants.get_mut(id) {
            Some(g) if g.rec.requester == requester && ct_eq(&g.receipt_hash, &want) => g,
            // One answer whether the grant is absent or not this caller's.
            _ => return Err(refuse("unknown-grant", "no such grant for this caller")),
        };
        if now >= g.rec.expiry {
            g.key = None;
            return Err(refuse("grant-expired", "ask the person again"));
        }
        if !g.rec.uses.contains(&using) {
            return Err(refuse("use-not-granted", using.as_str()));
        }
        g.key.as_ref().ok_or_else(|| refuse("grant-dormant", "the signer restarted; resume the grant"))
    }

    fn domain_ok(&self, id: &str, r: &Record) -> Result<()> {
        let g = &self.grants[id];
        // A grant can never name one (approval.rs refuses it), and is checked again here.
        if r.domain.starts_with(OWN_DOMAIN_PREFIX) || !g.rec.domains.iter().any(|d| *d == r.domain) {
            return Err(refuse("domain-not-granted", r.domain.clone()));
        }
        Ok(())
    }

    fn record(record_hex: &str) -> Result<Record> {
        let b = hex::decode(record_hex.trim_start_matches("0x")).map_err(|_| refuse("invalid-params", "not hex"))?;
        Record::parse(&b).map_err(|e| match e {
            crate::record::RecordError::NonCanonical(_) => refuse("non-canonical-record", e.to_string()),
            crate::record::RecordError::NotARecord(_) => refuse("not-a-record", e.to_string()),
        })
    }

    pub fn sign(&mut self, requester: &str, id: &str, receipt: &str, record_hex: &str, now: u64) -> Result<[u8; 64]> {
        let r = Self::record(record_hex)?;
        self.held(requester, id, receipt, Use::Sign, now)?;
        self.domain_ok(id, &r)?;
        Ok(self.held(requester, id, receipt, Use::Sign, now)?.sign(&r.digest()))
    }

    pub fn secret(&mut self, requester: &str, id: &str, receipt: &str, record_hex: &str, now: u64) -> Result<Zeroizing<[u8; 32]>> {
        let r = Self::record(record_hex)?;
        self.held(requester, id, receipt, Use::Secret, now)?;
        self.domain_ok(id, &r)?;
        Ok(self.held(requester, id, receipt, Use::Secret, now)?.derived_secret(r.bytes()))
    }

    pub fn open_box(&mut self, requester: &str, id: &str, receipt: &str, sealed: &[u8], now: u64) -> Result<Vec<u8>> {
        self.held(requester, id, receipt, Use::Open, now)?
            .open(sealed)
            .map_err(|e| refuse("seal-open-failed", e.to_string()))
    }

    pub fn list(&self, now: u64) -> Vec<GrantView> {
        self.grants
            .values()
            .map(|g| GrantView {
                grant_id: g.rec.grant_id.clone(),
                requester: g.rec.requester.clone(),
                key_ref: g.rec.key_ref.clone(),
                uses: g.rec.uses.clone(),
                domains: g.rec.domains.clone(),
                expiry: g.rec.expiry,
                state: if now >= g.rec.expiry {
                    "expired"
                } else if g.key.is_some() {
                    "active"
                } else {
                    "dormant"
                },
            })
            .collect()
    }

    /// Revoked by the approver: the key is dropped and the record goes.
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        self.grants.remove(id).ok_or_else(|| refuse("unknown-grant", "no such grant"))?;
        self.save()
    }

    /// Revoked by its own requester, which proves it with the receipt.
    pub fn revoke_own(&mut self, requester: &str, id: &str, receipt: &str) -> Result<()> {
        let want = sha256(receipt.as_bytes());
        match self.grants.get(id) {
            Some(g) if g.rec.requester == requester && ct_eq(&g.receipt_hash, &want) => self.revoke(id),
            _ => Err(refuse("unknown-grant", "no such grant for this caller")),
        }
    }

    /// The requester a grant id belongs to, for gating.
    pub fn requester_of(&self, id: &str) -> Option<&str> {
        self.grants.get(id).map(|g| g.rec.requester.as_str())
    }
}
