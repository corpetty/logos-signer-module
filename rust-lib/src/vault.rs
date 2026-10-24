//! Where seeds and the key index live (design §4).
//!
//! ```text
//! <dir>/groups/<group>.json   a Web3 Secure Storage (scrypt) vault holding the 64-byte BIP-39 seed
//! <dir>/keys.json             keyRef → {scheme, purpose, context, publicKey, group}: no secret, no path
//! <dir>/groups.json           group → BIP-32 master fingerprint: public
//! ```
//!
//! The seed is decrypted only inside `with_seed`, and wiped when it returns. Every write goes
//! to a temporary file in the same directory and is renamed into place.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use coins_bip39::{English, Mnemonic};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::derive::{self, Scheme};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid-mnemonic")]
    Mnemonic,
    #[error("invalid-word-count")]
    WordCount,
    #[error("unknown-group")]
    UnknownGroup,
    #[error("group-exists")]
    GroupExists,
    #[error("wrong-password")]
    WrongPassword,
    #[error("unknown-key")]
    UnknownKey,
    #[error("storage: {0}")]
    Io(String),
    #[error("{0}")]
    Derive(#[from] derive::DeriveError),
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

type Result<T> = std::result::Result<T, VaultError>;

/// One entry of the key index. Public facts only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyEntry {
    pub key_ref: String,
    pub scheme: Scheme,
    pub purpose: String,
    pub context: String,
    /// Hex.
    pub public_key: String,
    pub group: String,
}

#[derive(Default, Serialize, Deserialize)]
struct GroupIndex {
    fingerprints: BTreeMap<String, String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Index {
    keys: BTreeMap<String, KeyEntry>,
}

pub struct Vault {
    dir: PathBuf,
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>) -> Vault {
        Vault { dir: dir.into() }
    }

    fn groups_dir(&self) -> PathBuf {
        self.dir.join("groups")
    }

    fn group_path(&self, group: &str) -> PathBuf {
        self.groups_dir().join(format!("{group}.json"))
    }

    /// A fresh phrase of 12, 15, 18, 21 or 24 words. Nothing is stored.
    pub fn create_mnemonic(words: usize) -> Result<Zeroizing<String>> {
        if ![12, 15, 18, 21, 24].contains(&words) {
            return Err(VaultError::WordCount);
        }
        let m = Mnemonic::<English>::new_with_count(&mut rand::rngs::OsRng, words)
            .map_err(|_| VaultError::WordCount)?;
        Ok(Zeroizing::new(m.to_phrase()))
    }

    /// Keep a phrase's seed under `password`. Returns the group id, which is the same for the
    /// same phrase and passphrase on any device.
    pub fn import(&self, phrase: &str, passphrase: Option<&str>, password: &str) -> Result<String> {
        let m = Mnemonic::<English>::new_from_phrase(phrase.trim()).map_err(|_| VaultError::Mnemonic)?;
        let seed = Zeroizing::new(m.to_seed(passphrase).map_err(|_| VaultError::Mnemonic)?);
        let group = derive::group_id(&seed[..])?;
        let fingerprint = derive::master_fingerprint(&seed[..])?;
        if self.group_path(&group).exists() {
            return Err(VaultError::GroupExists);
        }
        fs::create_dir_all(self.groups_dir())?;
        // eth-keystore writes in place, so it writes into a fresh directory beside the target
        // and the file is renamed in: the group either exists whole or not at all.
        let stage = tempfile::tempdir_in(self.groups_dir())?;
        eth_keystore::encrypt_key(stage.path(), &mut rand::rngs::OsRng, &seed[..], password, Some("v"))
            .map_err(|e| VaultError::Io(e.to_string()))?;
        fs::rename(stage.path().join("v"), self.group_path(&group))?;
        let mut gi = self.read_groups()?;
        gi.fingerprints.insert(group.clone(), fingerprint);
        write_atomic(&self.dir.join("groups.json"), &serde_json::to_vec_pretty(&gi).expect("serializable"))?;
        Ok(group)
    }

    fn read_groups(&self) -> Result<GroupIndex> {
        match fs::read(self.dir.join("groups.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| VaultError::Io(format!("groups.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GroupIndex::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// A group's BIP-32 master fingerprint, recorded at import.
    pub fn fingerprint(&self, group: &str) -> Result<Option<String>> {
        Ok(self.read_groups()?.fingerprints.get(group).cloned())
    }

    pub fn groups(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(self.groups_dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for e in rd {
            let name = e?.file_name().to_string_lossy().into_owned();
            if let Some(g) = name.strip_suffix(".json") {
                if g.starts_with("g_") {
                    out.push(g.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Run `f` with a group's seed, wiped as soon as `f` returns.
    pub fn with_seed<T>(&self, group: &str, password: &str, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let p = self.group_path(group);
        if !p.exists() {
            return Err(VaultError::UnknownGroup);
        }
        let seed = Zeroizing::new(eth_keystore::decrypt_key(&p, password).map_err(|e| match e {
            eth_keystore::KeystoreError::MacMismatch => VaultError::WrongPassword,
            other => VaultError::Io(other.to_string()),
        })?);
        f(&seed)
    }

    /// Stop keeping a group's seed. The phrase is the only way back.
    pub fn forget(&self, group: &str) -> Result<()> {
        match fs::remove_file(self.group_path(group)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(VaultError::UnknownGroup),
            Err(e) => Err(e.into()),
        }
    }

    // ── the key index ───────────────────────────────────────────────────────

    fn index_path(&self) -> PathBuf {
        self.dir.join("keys.json")
    }

    fn read_index(&self) -> Result<Index> {
        match fs::read(self.index_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| VaultError::Io(format!("keys.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn keys(&self) -> Result<Vec<KeyEntry>> {
        Ok(self.read_index()?.keys.into_values().collect())
    }

    pub fn key(&self, key_ref: &str) -> Result<KeyEntry> {
        self.read_index()?.keys.remove(key_ref).ok_or(VaultError::UnknownKey)
    }

    /// Record a minted key. Idempotent: the same key minted again changes nothing.
    pub fn record_key(&self, entry: KeyEntry) -> Result<bool> {
        let mut idx = self.read_index()?;
        if idx.keys.get(&entry.key_ref) == Some(&entry) {
            return Ok(false);
        }
        idx.keys.insert(entry.key_ref.clone(), entry);
        fs::create_dir_all(&self.dir)?;
        write_atomic(&self.index_path(), &serde_json::to_vec_pretty(&idx).expect("serializable"))?;
        Ok(true)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("a file in a directory");
    let mut f = tempfile::NamedTempFile::new_in(dir)?;
    f.write_all(bytes)?;
    f.as_file().sync_all()?;
    f.persist(path).map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn a_phrase_imports_once_and_its_seed_opens_with_the_password() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::new(d.path());
        let g = v.import(PHRASE, None, "pw").unwrap();
        assert_eq!(v.groups().unwrap(), vec![g.clone()]);
        // The "abandon … about" phrase's master fingerprint, as BIP-32 wallets report it.
        assert_eq!(v.fingerprint(&g).unwrap().as_deref(), Some("73c5da0a"));
        assert!(matches!(v.import(PHRASE, None, "other"), Err(VaultError::GroupExists)));
        // BIP-39's own vector for this phrase, empty passphrase.
        let seed = v.with_seed(&g, "pw", |s| Ok(hex::encode(s))).unwrap();
        assert!(seed.starts_with("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"));
        assert!(matches!(v.with_seed(&g, "nope", |_| Ok(())), Err(VaultError::WrongPassword)));
        // A passphrase is a different group.
        assert_ne!(v.import(PHRASE, Some("x"), "pw").unwrap(), g);
    }

    #[test]
    fn a_restore_elsewhere_gives_the_same_group() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        assert_eq!(
            Vault::new(a.path()).import(PHRASE, None, "1").unwrap(),
            Vault::new(b.path()).import(PHRASE, None, "2").unwrap()
        );
    }

    #[test]
    fn bad_phrases_and_counts_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::new(d.path());
        assert!(matches!(v.import("abandon abandon", None, "pw"), Err(VaultError::Mnemonic)));
        assert!(matches!(Vault::create_mnemonic(13), Err(VaultError::WordCount)));
        assert_eq!(Vault::create_mnemonic(24).unwrap().split(' ').count(), 24);
    }

    #[test]
    fn the_index_holds_no_secret_and_records_idempotently() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::new(d.path());
        let e = KeyEntry {
            key_ref: "kr_1".into(),
            scheme: Scheme::Ed25519,
            purpose: "room-identity".into(),
            context: "room:a".into(),
            public_key: "00".into(),
            group: "g_1".into(),
        };
        assert!(v.record_key(e.clone()).unwrap());
        assert!(!v.record_key(e.clone()).unwrap());
        assert_eq!(v.key("kr_1").unwrap(), e);
        assert!(matches!(v.key("kr_2"), Err(VaultError::UnknownKey)));
        let raw = fs::read_to_string(d.path().join("keys.json")).unwrap();
        assert!(!raw.contains("path") && !raw.contains("secret"));
    }
}
