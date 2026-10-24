//! signer_module: keys for the schemes no other Logos module holds, signing only what a person
//! approved or granted. No network. A secret never crosses the module boundary.
//!
//! The core below is plain Rust, tested with `cargo test --no-default-features`. The Logos glue
//! is behind the default `logos_module` feature, as keystore_module arranges it.

pub mod record;
pub mod derive;
pub mod identity;
pub mod vault;
pub mod approval;
pub mod grant;
pub mod gate;
pub mod signer;
