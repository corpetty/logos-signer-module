//! Logos module glue for `context_signer_module` (rust-first authoring, as keystore_module's).
//!
//! This file is the contract: the builder derives the `.lidl` from the `ContextSignerModule`
//! trait (`codegen.rust = { trait, source: "src/glue.rs" }`) and injects the generated scaffold
//! at the `include!` point. It is compiled only with the default `logos_module` feature, so
//! `cargo test --no-default-features` tests the core without the runtime.
//!
//! Every structured value crosses as a JSON string. The `logos.signer/1` methods answer in that
//! interface's shape (`{ ok, code, error }` on refusal); the rest answer `{ ok, error }`. A tier
//! refusal is always `{ ok: false, error: "not authorized" }`.

use std::time::Duration;

use logos_signer_interface::json as signer_json;
use logos_signer_interface::wire;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::gate::{self, Caller};
use crate::signer::ContextSigner;
use crate::vault::Vault;

/// The module's IPC contract. No secret appears in any answer: public keys, signatures and
/// job states only.
pub trait ContextSignerModule: Send + 'static {
    /// Name who holds the roles: `{ manager?, custodian? }` → `{ ok, managers, custodians }`.
    /// TOTAL: a role the document does not name is held by nobody. UNGATED, as keystore's is:
    /// it keeps an honest deployer's policy, not one enforced against a hostile module.
    fn configure(&mut self, config_json: String) -> String;
    /// What this module sees as its caller: `{ ok, kind, identity, managers, custodians }`.
    fn caller_identity(&mut self) -> String;

    // ── logos.signer/1 ───────────────────────────────────────────────────
    /// `{ ok, interface, kind, model, families, requestKinds, showsRequest, collects }`. Ungated.
    fn signer_info(&mut self) -> String;
    /// `{ ok, accounts }`, public keys only. The manager and the custodian.
    fn signer_accounts(&mut self) -> String;
    /// `{ account, kind: "hash", items: [{ scheme: "ed25519", digest }], secret? }` → `{ ok, job }`.
    /// Tier M.
    fn sign(&mut self, request_json: String) -> String;
    /// `{ ok, job, state, code?, error? }`. Tier M.
    fn sign_status(&mut self, job: String) -> String;
    /// `{ ok, job, signatures }`, repeatable until the job is swept. Tier M.
    fn sign_result(&mut self, job: String) -> String;
    /// `{ ok, job }`. Tier M.
    fn cancel_sign(&mut self, job: String) -> String;
    /// Hold an account's key in memory until `ttlMs` passes or `count` requests are signed:
    /// `{ account, password, ttlMs?, count? }` → `{ ok, account, expiresInMs, countLeft }`. Tier M.
    fn unlock(&mut self, params_json: String) -> String;
    /// `{ account? }` locks one account, `{}` every one → `{ ok, locked }`. Tier M.
    fn lock(&mut self, params_json: String) -> String;
    /// `{ ok, unlocked: [{ account, expiresInMs, countLeft }] }`. The manager and the custodian.
    fn unlocked(&mut self) -> String;

    // ── the custodian ────────────────────────────────────────────────────
    /// A fresh phrase, `{ ok, phrase }`; nothing is stored. Tier D.
    fn create_mnemonic(&mut self, words: i64) -> String;
    /// `{ phrase, passphrase?, password }` → `{ ok, group, fingerprint }`. Tier D.
    fn import_mnemonic(&mut self, params_json: String) -> String;
    /// Mint (or find again) the key for a purpose and a context:
    /// `{ group?, purpose, context, password }` → `{ ok, account }`. Tier D.
    fn derive_account(&mut self, params_json: String) -> String;
    /// Stop keeping a phrase's seed: `{ group }` → `{ ok, group }`. Tier D.
    fn forget_group(&mut self, params_json: String) -> String;
    /// `{ ok, groups: [{ group, fingerprint }] }`. Ungated: ids and fingerprints, never words.
    fn list_groups(&mut self) -> String;

    /// Framework hook, defaulted, so not part of the IPC contract.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

/// Typed events: `logos.signer/1`'s three.
pub trait ContextSignerModuleEvents {
    /// The accounts it offers changed. `count` is advisory; re-read.
    fn signer_accounts_changed(&self, count: i64);
    /// Device state. This signer has no device and never sends it.
    fn signer_changed(&self, state: String);
    /// A job moved. Jobs here finish inside `sign` and never send it.
    fn sign_progress(&self, job: String, state: String);
}

// The builder injects the generated module-impl scaffold here: `install`, `context()`,
// `RustModuleContext`, the event emitters and the C-ABI dispatch.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct ContextSignerModuleImpl {
    signer: Option<ContextSigner>,
    roles: gate::Roles,
}

fn not_authorized() -> String {
    json!({ "ok": false, "error": gate::NOT_AUTHORIZED }).to_string()
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

const NOT_READY: &str = "signer not initialized (context not ready)";

impl ContextSignerModuleImpl {
    fn caller() -> Caller {
        match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Unknown => Caller::Unknown,
            logos_rust_sdk::LogosCaller::HostAnchor => Caller::HostAnchor,
            logos_rust_sdk::LogosCaller::Module { name, .. } => Caller::Module(name),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => Caller::Derived { parent, leaf },
            logos_rust_sdk::LogosCaller::Operator { name } => Caller::Operator(name),
        }
    }

    fn manager(&self, method: &str) -> bool {
        self.roles.manager_may(method, &Self::caller())
    }

    fn custodian(&self, method: &str) -> bool {
        self.roles.custodian_may(method, &Self::caller())
    }

    fn announce(&mut self) {
        let count = self
            .signer
            .as_mut()
            .and_then(|s| logos_signer_interface::Signer::accounts(s).ok())
            .map(|a| a.len() as i64)
            .unwrap_or(-1);
        emit_signer_accounts_changed(count);
    }
}

/// A parameter document that carries a secret: wiped whether or not it parses.
fn secret_params<T: for<'de> Deserialize<'de>>(raw: String) -> Result<T, String> {
    let raw = Zeroizing::new(raw);
    serde_json::from_str(&raw).map_err(|_| err("malformed parameters"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockParams {
    account: String,
    password: String,
    #[serde(default)]
    ttl_ms: Option<u64>,
    #[serde(default)]
    count: Option<u64>,
}

#[derive(Deserialize, Default)]
struct LockParams {
    #[serde(default)]
    account: Option<String>,
}

#[derive(Deserialize)]
struct ImportParams {
    phrase: String,
    #[serde(default)]
    passphrase: Option<String>,
    password: String,
}

#[derive(Deserialize)]
struct DeriveParams {
    #[serde(default)]
    group: Option<String>,
    purpose: String,
    context: String,
    password: String,
}

impl ContextSignerModule for ContextSignerModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        let base = std::path::Path::new(&ctx.instance_persistence_path);
        self.signer = Some(ContextSigner::new(Vault::new(base.join("context_signer"))));
    }

    fn configure(&mut self, config_json: String) -> String {
        match self.roles.configure(&config_json) {
            Ok(()) => json!({ "ok": true, "managers": self.roles.managers, "custodians": self.roles.custodians })
                .to_string(),
            Err(e) => err(e),
        }
    }

    fn caller_identity(&mut self) -> String {
        let c = Self::caller();
        json!({ "ok": true, "kind": c.kind(), "identity": c.identity(),
                "managers": self.roles.managers, "custodians": self.roles.custodians })
        .to_string()
    }

    fn signer_info(&mut self) -> String {
        match self.signer.as_ref() {
            Some(s) => signer_json::signer_info(s),
            None => err(NOT_READY),
        }
    }

    fn signer_accounts(&mut self) -> String {
        if !self.roles.reads_signer_state(&Self::caller()) {
            return not_authorized();
        }
        match self.signer.as_mut() {
            Some(s) => signer_json::signer_accounts(s),
            None => err(NOT_READY),
        }
    }

    fn sign(&mut self, request_json: String) -> String {
        let request_json = Zeroizing::new(request_json);
        if !self.manager("sign") {
            return not_authorized();
        }
        match self.signer.as_mut() {
            Some(s) => signer_json::sign(s, &request_json),
            None => err(NOT_READY),
        }
    }

    fn sign_status(&mut self, job: String) -> String {
        if !self.manager("sign_status") {
            return not_authorized();
        }
        match self.signer.as_mut() {
            Some(s) => signer_json::sign_status(s, &job),
            None => err(NOT_READY),
        }
    }

    fn sign_result(&mut self, job: String) -> String {
        if !self.manager("sign_result") {
            return not_authorized();
        }
        match self.signer.as_mut() {
            Some(s) => signer_json::sign_result(s, &job),
            None => err(NOT_READY),
        }
    }

    fn cancel_sign(&mut self, job: String) -> String {
        if !self.manager("cancel_sign") {
            return not_authorized();
        }
        match self.signer.as_mut() {
            Some(s) => signer_json::cancel_sign(s, &job),
            None => err(NOT_READY),
        }
    }

    fn unlock(&mut self, params_json: String) -> String {
        if !self.manager("unlock") {
            drop(Zeroizing::new(params_json));
            return not_authorized();
        }
        let p: UnlockParams = match secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = Zeroizing::new(p.password);
        let Some(s) = self.signer.as_mut() else { return err(NOT_READY) };
        match s.unlock(&p.account, &password, p.ttl_ms.map(Duration::from_millis), p.count) {
            Ok(()) => {
                let live = s.unlocked().into_iter().find(|(a, _, _)| *a == p.account);
                let (expires, left) = live.map(|(_, e, c)| (e, c)).unwrap_or((None, None));
                json!({ "ok": true, "account": p.account,
                        "expiresInMs": expires.map(|d| d.as_millis() as u64), "countLeft": left })
                .to_string()
            }
            Err(e) => wire::err(&e),
        }
    }

    fn lock(&mut self, params_json: String) -> String {
        if !self.manager("lock") {
            return not_authorized();
        }
        let p: LockParams = if params_json.trim().is_empty() {
            LockParams::default()
        } else {
            match serde_json::from_str(&params_json) {
                Ok(p) => p,
                Err(e) => return err(e),
            }
        };
        let Some(s) = self.signer.as_mut() else { return err(NOT_READY) };
        json!({ "ok": true, "locked": s.lock(p.account.as_deref()) }).to_string()
    }

    fn unlocked(&mut self) -> String {
        if !self.roles.reads_signer_state(&Self::caller()) {
            return not_authorized();
        }
        let Some(s) = self.signer.as_mut() else { return err(NOT_READY) };
        let list: Vec<_> = s
            .unlocked()
            .into_iter()
            .map(|(a, e, c)| json!({ "account": a, "expiresInMs": e.map(|d| d.as_millis() as u64), "countLeft": c }))
            .collect();
        json!({ "ok": true, "unlocked": list }).to_string()
    }

    fn create_mnemonic(&mut self, words: i64) -> String {
        if !self.custodian("create_mnemonic") {
            return not_authorized();
        }
        let Ok(words) = usize::try_from(words) else { return err("invalid-word-count") };
        match Vault::create_mnemonic(words) {
            Ok(phrase) => json!({ "ok": true, "phrase": phrase.as_str() }).to_string(),
            Err(e) => err(e),
        }
    }

    fn import_mnemonic(&mut self, params_json: String) -> String {
        if !self.custodian("import_mnemonic") {
            drop(Zeroizing::new(params_json));
            return not_authorized();
        }
        let p: ImportParams = match secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let (phrase, password) = (Zeroizing::new(p.phrase), Zeroizing::new(p.password));
        let passphrase = p.passphrase.map(Zeroizing::new);
        let Some(s) = self.signer.as_ref() else { return err(NOT_READY) };
        match s.vault().import(&phrase, passphrase.as_deref().map(|x| x.as_str()), &password) {
            Ok(group) => {
                let fp = s.vault().fingerprint(&group).ok().flatten();
                json!({ "ok": true, "group": group, "fingerprint": fp }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn derive_account(&mut self, params_json: String) -> String {
        if !self.custodian("derive_account") {
            drop(Zeroizing::new(params_json));
            return not_authorized();
        }
        let p: DeriveParams = match secret_params(params_json) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let password = Zeroizing::new(p.password);
        let Some(s) = self.signer.as_mut() else { return err(NOT_READY) };
        match s.derive_account(p.group.as_deref(), &p.purpose, &p.context, &password) {
            Ok(account) => {
                self.announce();
                json!({ "ok": true, "account": account }).to_string()
            }
            Err(e) => wire::err(&e),
        }
    }

    fn forget_group(&mut self, params_json: String) -> String {
        if !self.custodian("forget_group") {
            return not_authorized();
        }
        #[derive(Deserialize)]
        struct P {
            group: String,
        }
        let p: P = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let Some(s) = self.signer.as_mut() else { return err(NOT_READY) };
        match s.vault().forget(&p.group) {
            Ok(()) => {
                s.lock(None);
                self.announce();
                json!({ "ok": true, "group": p.group }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn list_groups(&mut self) -> String {
        let Some(s) = self.signer.as_ref() else { return err(NOT_READY) };
        match s.vault().groups() {
            Ok(gs) => {
                let rows: Vec<_> = gs
                    .into_iter()
                    .map(|g| json!({ "group": g, "fingerprint": s.vault().fingerprint(&g).ok().flatten() }))
                    .collect();
                json!({ "ok": true, "groups": rows }).to_string()
            }
            Err(e) => err(e),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<ContextSignerModuleImpl>();
}
