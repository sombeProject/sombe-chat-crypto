//! The checks added in 0.7.1: a `created` that exists and is not far ahead of this phone's
//! clock, one spelling per base64 key, sessions bound to their contact, and base58 fields
//! refused by their length before they are decoded.

mod common;

use std::sync::Arc;
use std::time::Instant;

use common::{device, key};
use sombe_chat_crypto::*;
use vodozemac::Ed25519SecretKey;

const CREATED: &str = "2026-10-14T18:30:01.183Z";

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// A statement v3 signed with raw keys, so the test controls every string of it.
fn raw_statement(
    account: &Ed25519SecretKey,
    identity: &Ed25519SecretKey,
    curve25519_key: &str,
    ed25519_key: &str,
    created_at: &str,
) -> StatementFields {
    let account_public_key = b58(account.public_key().as_bytes());
    let body = format!(
        "SOMBE chat identity v3\nprotocol:olm-v1\naccount:{account_public_key}\ncurve25519:{curve25519_key}\ned25519:{ed25519_key}\ncreated:{created_at}"
    );
    let identity_signature = identity.sign(body.as_bytes()).to_base64();
    let statement = format!("{body}\nidentity_signature:{identity_signature}");
    StatementFields {
        account_public_key,
        curve25519_key: curve25519_key.to_owned(),
        ed25519_key: ed25519_key.to_owned(),
        created_at: created_at.to_owned(),
        identity_signature,
        account_signature: b58(&account.sign(statement.as_bytes()).to_bytes()),
    }
}

fn raw_identity(account: &Ed25519SecretKey, created_at: &str) -> Result<VerifiedIdentity, ChatCryptoError> {
    let identity = Ed25519SecretKey::new();
    let curve = device().identity_keys().curve25519_key;
    verify_identity(raw_statement(account, &identity, &curve, &identity.public_key().to_base64(), created_at))
}

fn pinned(identity: &VerifiedIdentity) -> PinnedIdentity {
    PinnedIdentity {
        account_public_key: identity.account_public_key.clone(),
        account_generation: None,
        wallet_address: None,
        olm: Some(PinnedOlm {
            curve25519_key: identity.curve25519_key.clone(),
            ed25519_key: identity.ed25519_key.clone(),
            created_at: identity.created_at.clone(),
        }),
    }
}

fn keys(device: &Arc<ChatCrypto>) -> IdentityKeys {
    device.identity_keys()
}

#[test]
fn a_date_that_does_not_exist_is_not_a_statement() {
    let account = Ed25519SecretKey::new();
    for created in
        ["9999-99-99T99:99:99.999Z", "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-11-12T24:00:00Z"]
    {
        assert!(
            matches!(raw_identity(&account, created), Err(ChatCryptoError::InvalidStatement { .. })),
            "{created}"
        );
    }
}

#[test]
fn an_identity_dated_far_ahead_is_never_pinned() {
    let account = Ed25519SecretKey::new();
    let first = raw_identity(&account, CREATED).unwrap();
    // Validly signed, and a real date: but centuries after this phone's clock.
    let ahead = raw_identity(&account, "9999-12-31T23:59:59.999Z").unwrap();
    for pin in [None, Some(pinned(&first)), Some(PinnedIdentity { olm: None, ..pinned(&first) })] {
        assert!(matches!(
            check_identity_update(pin, ahead.clone(), None),
            Err(ChatCryptoError::InvalidStatement { .. })
        ));
    }
    // An identity that is both older and far ahead cannot be: older stays stale.
    assert_eq!(
        check_identity_update(Some(pinned(&ahead)), first.clone(), None),
        Err(ChatCryptoError::StaleIdentity)
    );
    // The pinned identity itself is still recognized.
    assert_eq!(check_identity_update(Some(pinned(&first)), first, None).unwrap(), IdentityUpdate::Unchanged);
}

#[test]
fn a_rotation_to_an_identity_dated_far_ahead_does_not_hold() {
    let wallet = vec![21u8; 32];
    let old = derive_account_key(wallet.clone(), 1).unwrap();
    let rotated = old.key.rotate(wallet).unwrap();
    let olm = device();
    let identity_of = |account: &ChatAccountKey, created: &str| {
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
    };
    let before = identity_of(&old.key, CREATED);
    let pin = PinnedIdentity { wallet_address: Some(old.card.wallet_address.clone()), ..pinned(&before) };
    let proof = AccountRotationContent {
        old_account_public_key: rotated.proof.old_account_public_key.clone(),
        new_account_public_key: rotated.proof.new_account_public_key.clone(),
        generation: rotated.proof.generation,
        old_signature: rotated.proof.old_signature.clone(),
        new_signature: rotated.proof.new_signature.clone(),
        wallet_address: rotated.card.wallet_address.clone(),
        wallet_signature: rotated.card.wallet_signature.clone(),
    };
    assert_eq!(
        check_identity_update(
            Some(pin.clone()),
            identity_of(&rotated.new_key, "2026-10-15T09:00:00Z"),
            Some(proof.clone())
        )
        .unwrap(),
        IdentityUpdate::AccountRotated
    );
    assert_eq!(
        check_identity_update(Some(pin), identity_of(&rotated.new_key, "9999-12-31T23:59:59Z"), Some(proof)),
        Err(ChatCryptoError::AccountChanged)
    );
}

#[test]
fn keys_and_signatures_have_one_base64_spelling() {
    let account = Ed25519SecretKey::new();
    let identity = Ed25519SecretKey::new();
    let curve = device().identity_keys().curve25519_key;
    let ed = identity.public_key().to_base64();
    assert!(verify_identity(raw_statement(&account, &identity, &curve, &ed, CREATED)).is_ok());

    // The same keys with padding, validly signed as written: refused.
    let padded = raw_statement(&account, &identity, &format!("{curve}="), &ed, CREATED);
    assert!(matches!(verify_identity(padded), Err(ChatCryptoError::InvalidKey { .. })));
    let padded = raw_statement(&account, &identity, &curve, &format!("{ed}="), CREATED);
    assert!(matches!(verify_identity(padded), Err(ChatCryptoError::InvalidKey { .. })));
    let mut padded = raw_statement(&account, &identity, &curve, &ed, CREATED);
    padded.identity_signature.push_str("==");
    assert_eq!(verify_identity(padded), Err(ChatCryptoError::InvalidSignature));

    // One time keys too.
    let bob = device();
    let one_time_key = bob.generate_one_time_keys(1).remove(0);
    assert!(verify_one_time_key(keys(&bob), one_time_key.clone()));
    let mut padded = one_time_key.clone();
    padded.signature.push_str("==");
    assert!(!verify_one_time_key(keys(&bob), padded));
    let mut padded_identity = keys(&bob);
    padded_identity.ed25519_key.push('=');
    assert!(!verify_one_time_key(padded_identity, one_time_key));
}

#[test]
fn a_session_opens_only_for_its_contact() {
    let (alice, bob, carol) = (device(), device(), device());
    let one_time_key = bob.generate_one_time_keys(1).remove(0);
    let first = alice.encrypt_for(keys(&bob), None, Some(one_time_key), "one".into(), key()).unwrap();
    assert!(first.session.pickle.starts_with("v2:"));

    // Bob's session passed while naming Carol: nothing is encrypted.
    assert_eq!(
        alice.encrypt_for(keys(&carol), Some(first.session.clone()), None, "for Carol".into(), key()).err(),
        Some(ChatCryptoError::InvalidPickle)
    );

    let read = bob.decrypt_from(keys(&alice), vec![], first.envelope, key()).unwrap();
    assert_eq!(read.plaintext, "one");
    // Bob answers, so the session is confirmed and Alice's next message is of type 1.
    let answer = bob.encrypt_for(keys(&alice), Some(read.session), None, "two".into(), key()).unwrap();
    let heard = alice.decrypt_from(keys(&bob), vec![first.session], answer.envelope, key()).unwrap();
    let third = alice.encrypt_for(keys(&bob), Some(heard.session), None, "three".into(), key()).unwrap();
    assert_eq!(third.envelope.olm_type, 1);
    // Alice's session offered as Carol's decrypts nothing; as Alice's it does.
    assert_eq!(
        bob.decrypt_from(keys(&carol), vec![answer.session.clone()], third.envelope.clone(), key()).err(),
        Some(ChatCryptoError::NoMatchingSession)
    );
    assert_eq!(
        bob.decrypt_from(keys(&alice), vec![answer.session], third.envelope, key()).unwrap().plaintext,
        "three"
    );
}

#[test]
fn a_session_stored_by_0_7_0_still_opens_and_is_bound_when_stored_again() {
    // 0.7.0 wrote the vodozemac pickle under the pickle key itself, with no prefix.
    use vodozemac::olm::{Account, SessionConfig};
    use vodozemac::Curve25519PublicKey;
    let bob = device();
    let one_time_key = bob.generate_one_time_keys(1).remove(0);
    let old_alice = Account::new();
    let pickle_key: [u8; 32] = key().try_into().unwrap();
    let mut session = old_alice
        .create_outbound_session(
            SessionConfig::version_1(),
            Curve25519PublicKey::from_base64(&keys(&bob).curve25519_key).unwrap(),
            Curve25519PublicKey::from_base64(&one_time_key.public_key).unwrap(),
        )
        .unwrap();
    let (olm_type, bytes) = session.encrypt("one").unwrap().to_parts();
    let legacy =
        StoredSession { session_id: session.session_id(), pickle: session.pickle().encrypt(&pickle_key) };
    let alice = ChatCrypto::restore_account(old_alice.pickle().encrypt(&pickle_key), key()).unwrap();

    let first = Envelope {
        protocol: "olm-v1".into(),
        olm_type: olm_type as u8,
        ciphertext: vodozemac::base64_encode(bytes),
    };
    let read = bob.decrypt_from(keys(&alice), vec![], first, key()).unwrap();
    assert_eq!(read.plaintext, "one");

    let second = alice.encrypt_for(keys(&bob), Some(legacy), None, "two".into(), key()).unwrap();
    assert!(second.session.pickle.starts_with("v2:"));
    assert_eq!(
        bob.decrypt_from(keys(&alice), vec![read.session], second.envelope, key()).unwrap().plaintext,
        "two"
    );
}

#[test]
fn a_base58_field_too_long_is_refused_without_being_decoded() {
    let json = format!(
        "{{\"v\":3,\"kind\":\"wallet_card\",\"sender_account_id\":\"a1a1a1a1-0000-4000-8000-0000000000a1\",\"recipient_account_id\":\"b2b2b2b2-0000-4000-8000-0000000000b2\",\"envelope_id\":\"22222222-2222-2222-2222-222222222222\",\"wallet_address\":\"{}\",\"account_public_key\":\"x\",\"wallet_signature\":\"x\"}}",
        "z".repeat(200_000)
    );
    let started = Instant::now();
    assert!(matches!(
        decode_content(json, common::mailbox("22222222-2222-2222-2222-222222222222")),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
    // Decoding 200 000 characters takes many seconds; refusing them by length does not.
    assert!(started.elapsed().as_millis() < 500);
    let long_key = "1".repeat(45);
    let card = WalletCard {
        wallet_address: long_key.clone(),
        account_public_key: long_key,
        wallet_signature: "1".repeat(89),
    };
    assert!(matches!(verify_wallet_card(card), Err(ChatCryptoError::InvalidKey { .. })));
}
