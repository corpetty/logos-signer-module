//! A mock standing in for another signer, as a manager's tests need to hold one phrase in two.

use logos_signer_interface::mock::{MockOptions, MockSigner};
use logos_signer_interface::Signer;

#[test]
fn a_mock_stands_in_for_another_signer_and_starts_unplugged() {
    let mut s = MockSigner::new(MockOptions {
        kind: "keycard_shell".into(),
        available: false,
        ..Default::default()
    });
    assert_eq!(s.info().kind, "keycard_shell");
    let accounts = s.accounts().unwrap();
    assert!(!accounts.is_empty() && accounts.iter().all(|a| !a.available));
    assert!(
        accounts
            .iter()
            .all(|a| a.fingerprint.as_deref().map(str::len) == Some(8)),
        "every account names its wallet, EVM ones too"
    );
    s.set_available(true);
    assert!(s.accounts().unwrap().iter().all(|a| a.available));
}
