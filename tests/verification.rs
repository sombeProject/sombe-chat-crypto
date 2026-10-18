//! Point 2 (an old identity cannot come back), point 4 (a wallet cannot claim someone
//! else's keys) and the safety number two people compare.

mod common;

use common::{device, TestWallet};
use sombe_chat_crypto::*;

const CREATED: &str = "2026-10-14T18:30:01.183Z";
const LATER: &str = "2026-10-15T09:00:00Z";

fn identity(seed: u8, created: &str) -> VerifiedIdentity {
    let wallet = TestWallet::from_seed([seed; 32]);
    let statement = device().identity_statement(wallet.address(), created.into()).unwrap();
    verify_identity(statement.clone(), wallet.address(), wallet.sign(&statement)).unwrap()
}

#[test]
fn a_wallet_cannot_claim_another_identity() {
    let bob_wallet = TestWallet::from_seed([1; 32]);
    let mallory_wallet = TestWallet::from_seed([2; 32]);
    let statement = device().identity_statement(bob_wallet.address(), CREATED.into()).unwrap();

    // Mallory copies Bob's statement, puts her own wallet in it and signs it with that wallet:
    // her signature is valid, but Bob's identity never vouched for her wallet.
    let claimed = statement.replace(&bob_wallet.address(), &mallory_wallet.address());
    assert_eq!(
        verify_identity(claimed.clone(), mallory_wallet.address(), mallory_wallet.sign(&claimed)),
        Err(ChatCryptoError::InvalidSignature)
    );

    // Dropping the identity's signature does not help either.
    let (body, _) = claimed.rsplit_once('\n').unwrap();
    assert!(matches!(
        verify_identity(body.into(), mallory_wallet.address(), mallory_wallet.sign(body)),
        Err(ChatCryptoError::InvalidStatement { .. })
    ));
}

#[test]
fn version_1_statements_are_refused() {
    let wallet = TestWallet::from_seed([3; 32]);
    let keys = device().identity_keys();
    let v1 = format!(
        "SOMBE chat identity v1\nprotocol:olm-v1\nwallet:{}\ncurve25519:{}\ned25519:{}\ncreated:{CREATED}",
        wallet.address(),
        keys.curve25519_key,
        keys.ed25519_key
    );
    assert!(matches!(
        verify_identity(v1.clone(), wallet.address(), wallet.sign(&v1)),
        Err(ChatCryptoError::InvalidStatement { .. })
    ));
}

#[test]
fn pinned_identity_only_moves_forward() {
    let first = identity(4, CREATED);
    assert_eq!(check_identity_update(None, first.clone()), Ok(IdentityUpdate::New));
    assert_eq!(check_identity_update(Some(first.clone()), first.clone()), Ok(IdentityUpdate::Unchanged));

    // The contact moves to a new phone: a newer identity of the same wallet.
    let wallet = TestWallet::from_seed([4; 32]);
    let statement = device().identity_statement(wallet.address(), LATER.into()).unwrap();
    let newer = verify_identity(statement.clone(), wallet.address(), wallet.sign(&statement)).unwrap();
    assert_eq!(check_identity_update(Some(first.clone()), newer.clone()), Ok(IdentityUpdate::Changed));

    // A server serving the old phone's identity again is refused, as is one with the same date.
    assert_eq!(
        check_identity_update(Some(newer.clone()), first.clone()),
        Err(ChatCryptoError::StaleIdentity)
    );
    let same_date = VerifiedIdentity { created_at: LATER.into(), ..first.clone() };
    assert_eq!(check_identity_update(Some(newer), same_date), Err(ChatCryptoError::StaleIdentity));

    // Another wallet is never an update of this contact.
    assert_eq!(check_identity_update(Some(first), identity(5, LATER)), Err(ChatCryptoError::WalletChanged));
}

#[test]
fn milliseconds_count_when_comparing_dates() {
    let old = VerifiedIdentity { created_at: "2026-10-14T18:30:01Z".into(), ..identity(6, CREATED) };
    let newer = VerifiedIdentity { created_at: "2026-10-14T18:30:01.001Z".into(), ..identity(6, CREATED) };
    let newer = VerifiedIdentity { curve25519_key: device().identity_keys().curve25519_key, ..newer };
    assert_eq!(check_identity_update(Some(old.clone()), newer.clone()), Ok(IdentityUpdate::Changed));
    assert_eq!(check_identity_update(Some(newer), old), Err(ChatCryptoError::StaleIdentity));
}

#[test]
fn both_phones_get_the_same_safety_number() {
    let awa = identity(7, CREATED);
    let malik = identity(8, CREATED);
    let on_awa = safety_number(awa.clone(), malik.clone()).unwrap();
    let on_malik = safety_number(malik.clone(), awa.clone()).unwrap();
    assert_eq!(on_awa, on_malik);

    assert_eq!(on_awa.digits.len(), 60);
    assert!(on_awa.digits.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(on_awa.groups.len(), 12);
    assert!(on_awa.groups.iter().all(|g| g.len() == 5));
    assert_eq!(on_awa.groups.concat(), on_awa.digits);
    assert_eq!(on_awa.qr_payload, format!("SOMBE-SN1:{}", on_awa.digits));
}

#[test]
fn a_changed_key_changes_the_safety_number() {
    let awa = identity(9, CREATED);
    let malik = identity(10, CREATED);
    let before = safety_number(awa.clone(), malik.clone()).unwrap();

    // Someone between the phones swaps Malik's keys: Awa's phone now shows other digits.
    let swapped =
        VerifiedIdentity { curve25519_key: device().identity_keys().curve25519_key, ..malik.clone() };
    assert_ne!(safety_number(awa.clone(), swapped).unwrap().digits, before.digits);
    let swapped = VerifiedIdentity { ed25519_key: device().identity_keys().ed25519_key, ..malik };
    assert_ne!(safety_number(awa, swapped).unwrap().digits, before.digits);
}

#[test]
fn no_safety_number_with_oneself() {
    let awa = identity(11, CREATED);
    assert!(matches!(safety_number(awa.clone(), awa), Err(ChatCryptoError::InvalidKey { .. })));
}

#[test]
fn scanning_a_qr_code() {
    let awa = identity(12, CREATED);
    let malik = identity(13, CREATED);
    let code = safety_number(malik.clone(), awa.clone()).unwrap();
    assert_eq!(
        compare_scanned_safety_code(awa.clone(), malik.clone(), code.qr_payload),
        Ok(ScanResult::Match)
    );

    let elsewhere = safety_number(awa.clone(), identity(14, CREATED)).unwrap();
    assert_eq!(
        compare_scanned_safety_code(awa.clone(), malik.clone(), elsewhere.qr_payload),
        Ok(ScanResult::Mismatch)
    );
    for scanned in ["https://example.com", "SOMBE-SN1:123", &format!("SOMBE-SN1:{}x", "1".repeat(59)), ""] {
        assert_eq!(
            compare_scanned_safety_code(awa.clone(), malik.clone(), scanned.into()),
            Ok(ScanResult::NotASafetyCode),
            "{scanned}"
        );
    }
}
