//! The crypto core Muster's missing signer families need: the record codec (Muster's CDE
//! subset, strict), keys derived by (scheme, purpose, context) from one phrase (BIP-32,
//! SLIP-0010, hardened only), and the room identity, byte for byte as libsodium does it.
//! No Logos runtime: tested with `cargo test --no-default-features`.

pub mod record;
pub mod derive;
pub mod identity;
pub mod vault;
pub mod signer;
