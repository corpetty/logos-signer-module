use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::json;
use logos_signer_interface::mock::{MockOptions, MockSigner};
use logos_signer_interface::*;

fn no_device(_: &mut MockSigner, _: &str) {}

#[test]
fn a_signer_without_a_secret_passes() {
    let mut s = MockSigner::new(MockOptions::default());
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut no_device,
    );
}

#[test]
fn a_signer_with_a_password_passes() {
    let mut s = MockSigner::new(MockOptions {
        collects: Collects::Password,
        secret: "pw".into(),
        ..Default::default()
    });
    let fx = Fixture {
        secret: Some(Secret::new("pw")),
        wrong_secret: Some(Secret::new("nope")),
    };
    conformance::run(&mut s, &fx, &mut no_device);
}

#[test]
fn a_signer_that_waits_for_its_device_passes() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        request_kinds: vec![RequestKind::Hash, RequestKind::EvmMessage],
        ..Default::default()
    });
    conformance::run(
        &mut s,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut |s, job| s.confirm(job).unwrap(),
    );
}

#[test]
fn a_device_that_signs_whole_requests_passes() {
    for kinds in [
        vec![RequestKind::EvmTransaction, RequestKind::BtcPsbt],
        vec![RequestKind::EvmMessage, RequestKind::BtcPsbt],
    ] {
        let mut s = MockSigner::new(MockOptions {
            needs_confirmation: true,
            request_kinds: kinds,
            ..Default::default()
        });
        conformance::run(
            &mut s,
            &Fixture {
                secret: None,
                wrong_secret: None,
            },
            &mut |s, job| s.confirm(job).unwrap(),
        );
    }
}

#[test]
fn the_suites_transaction_is_canonical_rlp() {
    // Worked by hand in EIP-1559's field order: a 47-byte list after the type byte.
    let want = [
        "02ef",                                       // type 2, list of 47 bytes
        "01",                                         // chain id 1
        "07",                                         // nonce 7
        "843b9aca00",                                 // priority fee, 1 gwei
        "8506fc23ac00",                               // max fee, 30 gwei
        "825208",                                     // gas 21000
        "94dddddddddddddddddddddddddddddddddddddddd", // to
        "87038d7ea4c68000",                           // 0.001 ether
        "80",                                         // no data
        "c0",                                         // no access list
    ]
    .concat();
    assert_eq!(hex::encode(conformance::eip1559(7)), want);
}

#[test]
fn a_refusal_on_the_device_is_a_refused_job_with_no_signatures() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        ..Default::default()
    });
    let account = s.accounts().unwrap().remove(0);
    let req = SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&account),
        },
        secret: None,
    };
    let job = s.sign(req).unwrap();
    assert_eq!(s.status(&job).unwrap().state, JobState::ConfirmOnDevice);
    s.refuse(&job).unwrap();
    assert_eq!(s.status(&job).unwrap().state, JobState::Refused);
    assert_eq!(s.result(&job).unwrap_err().code, ErrorCode::Refused);
}

#[test]
fn a_cancelled_job_never_signs() {
    let mut s = MockSigner::new(MockOptions {
        needs_confirmation: true,
        ..Default::default()
    });
    let account = s.accounts().unwrap().remove(0);
    let req = SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&account),
        },
        secret: None,
    };
    let job = s.sign(req).unwrap();
    s.cancel(&job).unwrap();
    assert!(s.confirm(&job).is_err());
    assert_eq!(s.status(&job).unwrap().state, JobState::Cancelled);
}

#[test]
fn the_json_replies_read_back_as_they_were_written() {
    let mut s = MockSigner::new(MockOptions {
        collects: Collects::Pin,
        secret: "123456".into(),
        ..Default::default()
    });
    let info = json::read_info(&json::signer_info(&s)).unwrap();
    assert_eq!(info, s.info());
    let accounts = json::read_accounts(&json::signer_accounts(&mut s)).unwrap();
    assert_eq!(accounts.len(), 3);

    let bad = json::sign(
        &mut s,
        &serde_json::json!({ "account": accounts[0].id, "kind": "hash", "items": [] }).to_string(),
    );
    assert_eq!(json::read_job(&bad).unwrap_err().code, ErrorCode::Locked);

    let req = SignRequest {
        account: accounts[1].id.clone(),
        payload: Payload::Hash {
            items: conformance::items_for(&accounts[1]),
        },
        secret: Some(Secret::new("123456")),
    };
    let job = json::read_job(&json::sign(&mut s, &serde_json::to_string(&req).unwrap())).unwrap();
    let status = json::read_status(&json::sign_status(&mut s, &job)).unwrap();
    assert_eq!(status.state, JobState::Done);
    let sigs = json::read_signatures(&json::sign_result(&mut s, &job)).unwrap();
    assert_eq!(sigs.len(), 2);

    let unknown = json::read_status(&json::sign_status(&mut s, "job_0"));
    assert_eq!(unknown.unwrap_err().code, ErrorCode::UnknownJob);
}

#[test]
fn a_failed_job_reports_its_code_beside_its_state() {
    let st = JobStatus {
        job: "job_1".into(),
        state: JobState::Failed,
        error: Some(SignerError::new(ErrorCode::WrongSecret, "wrong password")),
    };
    let v = serde_json::to_value(&st).unwrap();
    assert_eq!(v["code"], "wrong_secret");
    assert_eq!(v["state"], "failed");
    let back: JobStatus = serde_json::from_value(v).unwrap();
    assert_eq!(back, st);
}

#[test]
fn a_secret_never_prints() {
    let s = Secret::new("hunter2");
    assert_eq!(format!("{s:?}"), "Secret(..)");
    let req = SignRequest {
        account: "a".into(),
        payload: Payload::Hash { items: vec![] },
        secret: Some(s),
    };
    assert!(!format!("{req:?}").contains("hunter2"));
}

#[test]
fn the_mock_evm_account_is_the_well_known_first_test_account() {
    let mut s = MockSigner::new(MockOptions::default());
    let evm = s.accounts().unwrap().remove(0);
    assert_eq!(
        evm.address.as_deref(),
        Some("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
    );
}

#[test]
fn check_refuses_a_signature_over_another_digest_or_by_another_account() {
    let mut s = MockSigner::new(MockOptions::default());
    let accounts = s.accounts().unwrap();
    for account in &accounts {
        let items = conformance::items_for(account);
        let req = SignRequest {
            account: account.id.clone(),
            payload: Payload::Hash { items: items.clone() },
            secret: None,
        };
        let job = s.sign(req).unwrap();
        let sig = s.result(&job).unwrap().remove(0);
        verify::check(account, &items[0], &sig).unwrap();

        let mut other_digest = items[0].clone();
        other_digest.digest = conformance::items_for(account)[0].digest.clone();
        assert!(
            verify::check(account, &other_digest, &sig).is_err(),
            "{}: another digest",
            account.id
        );

        let stranger = accounts
            .iter()
            .find(|a| a.family == account.family && a.id != account.id);
        if let Some(stranger) = stranger {
            assert!(verify::check(stranger, &items[0], &sig).is_err());
        }
        if account.family.is_bitcoin() {
            let mut other_key = items[0].clone();
            other_key.path = items.get(1).and_then(|i| i.path.clone());
            assert!(
                verify::check(account, &other_key, &sig).is_err(),
                "{}: another key",
                account.id
            );
        }
    }
}
