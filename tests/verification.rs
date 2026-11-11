//! How a contact's identity is judged against the one pinned for them (an old identity
//! cannot come back, another account key needs a rotation proof), and the safety number v2
//! two people compare.

mod common;

use std::sync::Arc;

use common::device;
use sombe_chat_crypto::*;

const CREATED: &str = "2026-10-14T18:30:01.183Z";
const LATER: &str = "2026-10-15T09:00:00Z";
const LATEST: &str = "2026-10-16T09:00:00Z";

/// The verified identity v3 of `olm` under `account`, as `verify_identity` returns it.
fn identity_of(account: &ChatAccountKey, olm: &Arc<ChatCrypto>, created: &str) -> VerifiedIdentity {
    let signed = account.sign_identity_statement(olm.clone(), created.into()).unwrap();
    let keys = olm.identity_keys();
    verify_identity(StatementFields {
        account_public_key: account.public_key(),
        curve25519_key: keys.curve25519_key,
        ed25519_key: keys.ed25519_key,
        created_at: created.into(),
        identity_signature: signed.identity_signature,
        account_signature: signed.account_signature,
    })
    .unwrap()
}

fn identity(seed: u8, created: &str) -> VerifiedIdentity {
    identity_of(&derive_account_key(vec![seed; 32], 1).unwrap().key, &device(), created)
}

fn pinned(identity: &VerifiedIdentity, wallet: Option<&str>, generation: Option<u16>) -> PinnedIdentity {
    PinnedIdentity {
        account_public_key: identity.account_public_key.clone(),
        account_generation: generation,
        wallet_address: wallet.map(str::to_owned),
        olm: Some(PinnedOlm {
            curve25519_key: identity.curve25519_key.clone(),
            ed25519_key: identity.ed25519_key.clone(),
            created_at: identity.created_at.clone(),
        }),
    }
}

fn content_of(proof: &RotationProof, card: &WalletCard) -> AccountRotationContent {
    AccountRotationContent {
        old_account_public_key: proof.old_account_public_key.clone(),
        new_account_public_key: proof.new_account_public_key.clone(),
        generation: proof.generation,
        old_signature: proof.old_signature.clone(),
        new_signature: proof.new_signature.clone(),
        wallet_address: card.wallet_address.clone(),
        wallet_signature: card.wallet_signature.clone(),
    }
}

#[test]
fn same_account_key_old_identity_cannot_come_back() {
    let account = derive_account_key(vec![4; 32], 1).unwrap().key;
    let first = identity_of(&account, &device(), CREATED);
    assert_eq!(check_identity_update(None, first.clone(), None), Ok(IdentityUpdate::New));
    let pin = pinned(&first, None, None);
    assert_eq!(check_identity_update(Some(pin.clone()), first.clone(), None), Ok(IdentityUpdate::Unchanged));

    // A new phone under the same account key: newer, so accepted.
    let newer = identity_of(&account, &device(), LATER);
    assert_eq!(check_identity_update(Some(pin), newer.clone(), None), Ok(IdentityUpdate::Changed));

    // The server cannot bring the old identity back, nor one of the same date.
    assert_eq!(
        check_identity_update(Some(pinned(&newer, None, None)), first.clone(), None),
        Err(ChatCryptoError::StaleIdentity)
    );
    let same_date = VerifiedIdentity { created_at: LATER.into(), ..first.clone() };
    assert_eq!(
        check_identity_update(Some(pinned(&newer, None, None)), same_date, None),
        Err(ChatCryptoError::StaleIdentity)
    );

    // The account key pinned but no Olm keys yet: the first identity of this account.
    let key_only = PinnedIdentity { olm: None, ..pinned(&first, None, None) };
    assert_eq!(check_identity_update(Some(key_only), first, None), Ok(IdentityUpdate::New));
}

#[test]
fn milliseconds_count_when_comparing_dates() {
    let old = VerifiedIdentity { created_at: "2026-10-14T18:30:01Z".into(), ..identity(6, CREATED) };
    let newer = VerifiedIdentity {
        created_at: "2026-10-14T18:30:01.001Z".into(),
        curve25519_key: device().identity_keys().curve25519_key,
        ..old.clone()
    };
    assert_eq!(
        check_identity_update(Some(pinned(&old, None, None)), newer.clone(), None),
        Ok(IdentityUpdate::Changed)
    );
    assert_eq!(
        check_identity_update(Some(pinned(&newer, None, None)), old, None),
        Err(ChatCryptoError::StaleIdentity)
    );
}

/// A contact who rotated their account key from generation 1 to 2, same phone.
struct Rotated {
    before: VerifiedIdentity,
    after: VerifiedIdentity,
    wallet: String,
    content: AccountRotationContent,
}

fn rotated(seed: u8) -> Rotated {
    let derived = derive_account_key(vec![seed; 32], 1).unwrap();
    let olm = device();
    let before = identity_of(&derived.key, &olm, CREATED);
    let rotation = derived.key.rotate(vec![seed; 32]).unwrap();
    let after = identity_of(&rotation.new_key, &olm, LATER);
    Rotated {
        before,
        after,
        wallet: derived.card.wallet_address,
        content: content_of(&rotation.proof, &rotation.card),
    }
}

#[test]
fn a_proven_rotation_is_accepted() {
    let r = rotated(20);
    let pin = pinned(&r.before, Some(&r.wallet), None);
    assert_eq!(
        check_identity_update(Some(pin.clone()), r.after.clone(), Some(r.content.clone())),
        Ok(IdentityUpdate::AccountRotated)
    );
    // Known generation 1: generation 2 is strictly greater.
    let known = PinnedIdentity { account_generation: Some(1), ..pin.clone() };
    assert_eq!(
        check_identity_update(Some(known), r.after.clone(), Some(r.content.clone())),
        Ok(IdentityUpdate::AccountRotated)
    );
    // The same rotation with new Olm keys: the identity is replaced too.
    let derived = derive_account_key(vec![20; 32], 2).unwrap();
    let new_phone = identity_of(&derived.key, &device(), LATEST);
    assert_eq!(
        check_identity_update(Some(pin.clone()), new_phone.clone(), Some(r.content.clone())),
        Ok(IdentityUpdate::AccountRotatedAndChanged)
    );
    // An account key pinned without Olm keys yet: a proven rotation replaces it too.
    let key_only = PinnedIdentity { olm: None, ..pin };
    assert_eq!(
        check_identity_update(Some(key_only), r.after, Some(r.content)),
        Ok(IdentityUpdate::AccountRotatedAndChanged)
    );
}

#[test]
fn each_missing_condition_is_account_changed() {
    let r = rotated(21);
    let pin = pinned(&r.before, Some(&r.wallet), None);
    let refused =
        |pin: PinnedIdentity, candidate: VerifiedIdentity, rotation: Option<AccountRotationContent>| {
            assert_eq!(
                check_identity_update(Some(pin), candidate, rotation),
                Err(ChatCryptoError::AccountChanged)
            );
        };
    let other = rotated(22);

    // No proof at all, even when no Olm keys are pinned (never `New`).
    refused(pin.clone(), r.after.clone(), None);
    refused(PinnedIdentity { olm: None, ..pin.clone() }, r.after.clone(), None);
    // The old signature, or the new one, made by someone else.
    refused(
        pin.clone(),
        r.after.clone(),
        Some(AccountRotationContent {
            old_signature: other.content.old_signature.clone(),
            ..r.content.clone()
        }),
    );
    refused(
        pin.clone(),
        r.after.clone(),
        Some(AccountRotationContent {
            new_signature: other.content.new_signature.clone(),
            ..r.content.clone()
        }),
    );
    // A proof from another key than the pinned one, or to another key than the one served.
    refused(pinned(&other.before, Some(&r.wallet), None), r.after.clone(), Some(r.content.clone()));
    refused(pin.clone(), other.after.clone(), Some(r.content.clone()));
    // A card from another wallet, or no wallet pinned.
    refused(
        pin.clone(),
        r.after.clone(),
        Some(AccountRotationContent {
            wallet_address: other.wallet.clone(),
            wallet_signature: other.content.wallet_signature.clone(),
            ..r.content.clone()
        }),
    );
    refused(pinned(&r.before, Some(&other.wallet), None), r.after.clone(), Some(r.content.clone()));
    refused(pinned(&r.before, None, None), r.after.clone(), Some(r.content.clone()));
    // A generation not above the one pinned: no way back to a key already left.
    refused(pinned(&r.before, Some(&r.wallet), Some(2)), r.after.clone(), Some(r.content.clone()));
    refused(pinned(&r.before, Some(&r.wallet), Some(5)), r.after.clone(), Some(r.content.clone()));
    // A statement not newer than the pinned identity.
    let same_date = VerifiedIdentity { created_at: CREATED.into(), ..r.after.clone() };
    refused(pin.clone(), same_date, Some(r.content.clone()));
    // A signature of another generation than the one claimed.
    refused(pin, r.after, Some(AccountRotationContent { generation: 3, ..r.content }));
}

#[test]
fn a_proof_from_any_earlier_generation_is_accepted() {
    let seed = vec![23; 32];
    let first = derive_account_key(seed.clone(), 1).unwrap();
    let olm = device();
    let before = identity_of(&first.key, &olm, CREATED);
    let third = derive_account_key(seed.clone(), 3).unwrap().key;
    let after = identity_of(&third, &olm, LATER);
    let proven = prove_rotation(seed, 1, 3).unwrap();
    assert_eq!(proven.proof.generation, 3);
    assert_eq!(
        check_identity_update(
            Some(pinned(&before, Some(&first.card.wallet_address), Some(1))),
            after,
            Some(content_of(&proven.proof, &proven.card)),
        ),
        Ok(IdentityUpdate::AccountRotated)
    );
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
    assert_eq!(on_awa.qr_payload, format!("SOMBE-SN2:{}", on_awa.digits));
}

#[test]
fn a_changed_key_changes_the_safety_number() {
    let awa = identity(9, CREATED);
    let malik = identity(10, CREATED);
    let before = safety_number(awa.clone(), malik.clone()).unwrap();
    let swapped =
        VerifiedIdentity { curve25519_key: device().identity_keys().curve25519_key, ..malik.clone() };
    assert_ne!(safety_number(awa.clone(), swapped).unwrap().digits, before.digits);
    let swapped = VerifiedIdentity { ed25519_key: device().identity_keys().ed25519_key, ..malik.clone() };
    assert_ne!(safety_number(awa.clone(), swapped).unwrap().digits, before.digits);
    // Since 0.7.0 the account key is in the number, so a rotation changes it.
    let rotated = VerifiedIdentity { account_public_key: identity(15, CREATED).account_public_key, ..malik };
    assert_ne!(safety_number(awa, rotated).unwrap().digits, before.digits);
}

#[test]
fn no_safety_number_with_oneself() {
    let awa = identity(11, CREATED);
    let same_account =
        VerifiedIdentity { curve25519_key: device().identity_keys().curve25519_key, ..awa.clone() };
    assert!(matches!(safety_number(awa, same_account), Err(ChatCryptoError::InvalidKey { .. })));
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
    // A version 1 code of 60 digits comes from a phone not yet on 0.7.0.
    assert_eq!(
        compare_scanned_safety_code(awa.clone(), malik.clone(), format!("SOMBE-SN1:{}", "1".repeat(60))),
        Ok(ScanResult::OutdatedCode)
    );
    for scanned in [
        "https://example.com",
        "SOMBE-SN1:123",
        &format!("SOMBE-SN1:{}x", "1".repeat(59)),
        "SOMBE-SN2:123",
        &format!("SOMBE-SN2:{}x", "1".repeat(59)),
        "",
    ] {
        assert_eq!(
            compare_scanned_safety_code(awa.clone(), malik.clone(), scanned.into()),
            Ok(ScanResult::NotASafetyCode),
            "{scanned}"
        );
    }
}
