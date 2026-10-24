//! Who may call what, by the caller identity the platform attests (`current_caller()`), as
//! keystore_module's tiers have it:
//!
//! | Tier | Admits | Methods |
//! |---|---|---|
//! | A | a configured approver | `pending`, `acknowledge`, `approve`, `reject`, `list_grants` |
//! | B | any named module | `request_approval` and the rest of a request's life; the grant uses |
//! | C | anyone | reads, `caller_identity`, and for now `configure` |
//! | D | a configured custodian | `create_mnemonic`, `import_mnemonic`, `forget_group` |
//!
//! Only a plain named module can hold a role or ask. The host anchor is refused at A, B and D:
//! the token it presents is shared by more than one party, so admitting it admits an unbounded
//! set (keystore §Caller identity).

pub const DEFAULT_APPROVER: &str = "signer_ui";
pub const DEFAULT_CUSTODIAN: &str = "signer_ui";

/// The refusal every tier gives, identical so it reveals nothing about which tier failed.
pub const NOT_AUTHORIZED: &str = "not authorized";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    Host,
    Module(String),
    Derived { parent: String, leaf: String },
    Operator(String),
}

impl Caller {
    pub fn module_name(&self) -> Option<&str> {
        match self {
            Caller::Module(n) if !n.is_empty() => Some(n),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Caller::Unknown => "unknown",
            Caller::Host => "host",
            Caller::Module(_) => "module",
            Caller::Derived { .. } => "derived",
            Caller::Operator(_) => "operator",
        }
    }

    pub fn identity(&self) -> String {
        match self {
            Caller::Unknown | Caller::Host => String::new(),
            Caller::Module(n) | Caller::Operator(n) => n.clone(),
            Caller::Derived { parent, leaf } => format!("{parent}/{leaf}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Roles {
    pub approvers: Vec<String>,
    pub custodians: Vec<String>,
}

impl Default for Roles {
    fn default() -> Self {
        Roles { approvers: vec![DEFAULT_APPROVER.into()], custodians: vec![DEFAULT_CUSTODIAN.into()] }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesDoc {
    #[serde(default)]
    approver: Option<OneOrMany>,
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

impl Roles {
    /// TOTAL: a role the document does not name is held by nobody. A malformed document
    /// changes nothing.
    pub fn configure(&mut self, doc: &str) -> Result<(), String> {
        let d: RolesDoc = serde_json::from_str(doc).map_err(|e| e.to_string())?;
        self.approvers = d.approver.map(OneOrMany::names).unwrap_or_default();
        self.custodians = d.custodian.map(OneOrMany::names).unwrap_or_default();
        Ok(())
    }

    pub fn is_approver(&self, c: &Caller) -> bool {
        c.module_name().is_some_and(|n| self.approvers.iter().any(|a| a == n))
    }

    pub fn is_custodian(&self, c: &Caller) -> bool {
        c.module_name().is_some_and(|n| self.custodians.iter().any(|a| a == n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_named_module_holds_a_role() {
        let r = Roles::default();
        assert!(r.is_approver(&Caller::Module("signer_ui".into())));
        for c in [
            Caller::Host,
            Caller::Unknown,
            Caller::Operator("signer_ui".into()),
            Caller::Derived { parent: "signer_ui".into(), leaf: "x".into() },
            Caller::Module("muster_module".into()),
        ] {
            assert!(!r.is_approver(&c), "{c:?}");
        }
    }

    #[test]
    fn configure_is_total_and_a_bad_document_changes_nothing() {
        let mut r = Roles::default();
        r.configure(r#"{"approver":"signer_cli"}"#).unwrap();
        assert_eq!(r.approvers, vec!["signer_cli"]);
        assert!(r.custodians.is_empty(), "an unnamed role is held by nobody");
        assert!(r.configure("{nope").is_err());
        assert_eq!(r.approvers, vec!["signer_cli"]);
    }
}
