//! Who may call what, by the identity the platform attests (`current_caller()`), as
//! keystore_module's tiers have it (its `docs/specs.md`, *Who may call*):
//!
//! | Methods | Admits |
//! |---|---|
//! | `signer_info`, `caller_identity`, `list_groups`, and for now `configure` | anyone |
//! | `signer_accounts`, `unlocked` | a manager or a custodian |
//! | [`TIER_M_METHODS`] | a configured **manager** (default `signer_manager_module`) |
//! | [`TIER_D_METHODS`] | a configured **custodian** (default: nobody) |
//!
//! Only a plain named module holds a role. The host anchor is refused: its token is shared by
//! more than one party, so admitting it admits an unbounded set.
//!
//! The custodian defaults to nobody because no custodian app knows these methods yet. As the
//! keystore has it, a role whose surface does not exist leaves that capability unavailable, not
//! open to everyone.

pub const DEFAULT_MANAGER: &str = "signer_manager_module";

/// The refusal every tier gives, identical so it reveals nothing about which tier failed.
pub const NOT_AUTHORIZED: &str = "not authorized";

pub const TIER_M_METHODS: &[&str] = &["sign", "sign_status", "sign_result", "cancel_sign", "unlock", "lock"];
pub const TIER_D_METHODS: &[&str] = &["create_mnemonic", "import_mnemonic", "derive_account", "forget_group"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    HostAnchor,
    Module(String),
    Derived { parent: String, leaf: String },
    Operator(String),
}

impl Caller {
    pub fn named(&self) -> Option<&str> {
        match self {
            Caller::Module(n) if !n.is_empty() => Some(n),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Caller::Unknown => "unknown",
            Caller::HostAnchor => "host",
            Caller::Module(_) => "module",
            Caller::Derived { .. } => "derived",
            Caller::Operator(_) => "operator",
        }
    }

    pub fn identity(&self) -> String {
        match self {
            Caller::Unknown | Caller::HostAnchor => String::new(),
            Caller::Module(n) | Caller::Operator(n) => n.clone(),
            Caller::Derived { parent, leaf } => format!("{parent}.{leaf}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Roles {
    pub managers: Vec<String>,
    pub custodians: Vec<String>,
}

impl Default for Roles {
    fn default() -> Self {
        Roles { managers: vec![DEFAULT_MANAGER.into()], custodians: Vec::new() }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesDoc {
    #[serde(default)]
    manager: Option<OneOrMany>,
    #[serde(default)]
    custodian: Option<OneOrMany>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn names(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect()
    }
}

fn holds(holders: &[String], c: &Caller) -> bool {
    c.named().is_some_and(|n| holders.iter().any(|h| h == n))
}

impl Roles {
    /// TOTAL: a role the document does not name is held by nobody. A malformed document changes
    /// nothing. Ungated, as keystore's `configure` is: it keeps an honest deployer's policy
    /// rather than enforcing one against a hostile co-resident module.
    pub fn configure(&mut self, doc: &str) -> Result<(), String> {
        let d: RolesDoc = serde_json::from_str(doc).map_err(|e| e.to_string())?;
        self.managers = d.manager.map(OneOrMany::names).unwrap_or_default();
        self.custodians = d.custodian.map(OneOrMany::names).unwrap_or_default();
        Ok(())
    }

    /// Tier M, for a method the registry names. A method missing from it refuses everyone.
    pub fn manager_may(&self, method: &str, c: &Caller) -> bool {
        TIER_M_METHODS.contains(&method) && holds(&self.managers, c)
    }

    /// Tier D, likewise.
    pub fn custodian_may(&self, method: &str, c: &Caller) -> bool {
        TIER_D_METHODS.contains(&method) && holds(&self.custodians, c)
    }

    pub fn reads_signer_state(&self, c: &Caller) -> bool {
        holds(&self.managers, c) || holds(&self.custodians, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(n: &str) -> Caller {
        Caller::Module(n.into())
    }

    #[test]
    fn only_the_named_manager_reaches_tier_m() {
        let r = Roles::default();
        for method in TIER_M_METHODS {
            assert!(r.manager_may(method, &m(DEFAULT_MANAGER)), "{method}");
            for other in [
                m("muster_module"),
                Caller::HostAnchor,
                Caller::Unknown,
                Caller::Operator(DEFAULT_MANAGER.into()),
                Caller::Derived { parent: DEFAULT_MANAGER.into(), leaf: "x".into() },
            ] {
                assert!(!r.manager_may(method, &other), "{method} {other:?}");
            }
        }
        assert!(!r.manager_may("not_a_registered_method", &m(DEFAULT_MANAGER)));
    }

    #[test]
    fn nobody_is_custodian_until_configured_and_configure_is_total() {
        let mut r = Roles::default();
        for method in TIER_D_METHODS {
            assert!(!r.custodian_may(method, &m("evm_keystore_ui")), "{method}");
        }
        r.configure(r#"{"custodian":"signer_probe"}"#).unwrap();
        assert!(r.custodian_may("derive_account", &m("signer_probe")));
        assert!(r.managers.is_empty(), "an unnamed role is held by nobody");
        assert!(r.configure("{nope").is_err());
        assert_eq!(r.custodians, vec!["signer_probe"]);
    }
}
