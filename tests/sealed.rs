//! The sealed sender from end to end (since 0.10.0): Alice seals a real Olm message for Bob's
//! identity, Bob opens it, checks the sender against what he pinned for Alice, decrypts it
//! and binds the content to the sealed sender.

mod common;

use std::sync::Arc;

use common::{device, key};
use sombe_chat_crypto::*;

const ALICE: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
const ALICE_IDENTITY: &str = "a1a1a1a1-1111-4111-8111-1111111111a1";
const BOB: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const BOB_IDENTITY: &str = "b2b2b2b2-1111-4111-8111-1111111111b2";
const ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
const CREATED: &str = "2026-11-18T09:00:00.183Z";

struct Person {
    account: Arc<ChatAccountKey>,
    olm: Arc<ChatCrypto>,
    sealing: Arc<ChatSealingKey>,
    statement: StatementFields,
}

fn person(wallet: u8) -> Person {
    let account = derive_account_key(vec![wallet; 32], 1).unwrap().key;
    let olm = device();
    let sealing = ChatSealingKey::generate().unwrap();
    let signed = account.sign_identity_statement(olm.clone(), sealing.clone(), CREATED.into()).unwrap();
    let keys = olm.identity_keys();
    let statement = StatementFields {
        account_public_key: account.public_key(),
        curve25519_key: keys.curve25519_key,
        ed25519_key: keys.ed25519_key,
        sealing_key: Some(sealing.public_key()),
        created_at: CREATED.into(),
        identity_signature: signed.identity_signature,
        account_signature: signed.account_signature,
    };
    Person { account, olm, sealing, statement }
}

#[test]
fn alice_seals_a_message_and_bob_opens_checks_and_reads_it() {
    let alice = person(1);
    let bob = person(2);
    // Alice verified Bob's statement v4: his Olm keys and his sealing key.
    let bob_verified = verify_identity(bob.statement.clone()).unwrap();
    let otk = bob.olm.generate_one_time_keys(1).remove(0);
    bob.olm.mark_keys_published();
    let bob_keys = IdentityKeys {
        curve25519_key: bob_verified.curve25519_key.clone(),
        ed25519_key: bob_verified.ed25519_key.clone(),
    };
    let content = encode_content(OutgoingContent {
        sender_account_id: ALICE.into(),
        sender_ed25519_key: alice.statement.ed25519_key.clone(),
        recipient_account_id: BOB.into(),
        recipient_ed25519_key: bob_keys.ed25519_key.clone(),
        envelope_id: Some(ENVELOPE.into()),
        body: ContentBody::Text {
            client_message_id: "c1c1c1c1-0000-4000-8000-0000000000c1".into(),
            body: "hello".into(),
            reply_to_message_id: None,
            reply_excerpt: None,
        },
    })
    .unwrap();
    let encrypted = alice.olm.encrypt_for(bob_keys, None, Some(otk), content, key()).unwrap();
    let sealed = seal(
        SealedRecipient {
            account_id: BOB.into(),
            identity_id: BOB_IDENTITY.into(),
            sealing_key: bob_verified.sealing_key.clone().unwrap(),
        },
        ENVELOPE.into(),
        SealedSender {
            account_id: ALICE.into(),
            identity_id: ALICE_IDENTITY.into(),
            statement: alice.statement.clone(),
        },
        encrypted.envelope.clone(),
    )
    .unwrap();
    assert!(!sealed.contains(ALICE));

    // Bob opens it with his own ids and the element's id.
    let opened =
        bob.sealing.open_sealed(sealed.clone(), BOB.into(), BOB_IDENTITY.into(), ENVELOPE.into()).unwrap();
    assert_eq!(opened.sender.account_id, ALICE);
    assert_eq!(opened.envelope, encrypted.envelope);
    // The certificate: the statement holds for the account key Bob pinned for Alice, and
    // names the identity he pinned.
    let sender = verify_identity(opened.sender.statement.clone()).unwrap();
    assert_eq!(sender.account_public_key, alice.account.public_key());
    assert_eq!(sender.ed25519_key, alice.olm.identity_keys().ed25519_key);
    let alice_keys =
        IdentityKeys { curve25519_key: sender.curve25519_key, ed25519_key: sender.ed25519_key.clone() };
    let decrypted = bob.olm.decrypt_from(alice_keys, vec![], opened.envelope, key()).unwrap();
    let read = decode_content(
        decrypted.plaintext,
        ContentBinding {
            channel: ContentChannel::Mailbox,
            envelope_id: Some(ENVELOPE.into()),
            sender_account_id: opened.sender.account_id,
            sender_ed25519_key: sender.ed25519_key,
            my_account_id: BOB.into(),
            my_ed25519_key: bob.statement.ed25519_key.clone(),
            legacy_conversation_id: None,
        },
    )
    .unwrap();
    assert!(matches!(read.body, ContentBody::Text { body, .. } if body == "hello"));

    // Copied under another id, or to Alice's own sealing key, it does not open.
    assert_eq!(
        bob.sealing.open_sealed(sealed.clone(), BOB.into(), BOB_IDENTITY.into(), ALICE_IDENTITY.into()),
        Err(ChatCryptoError::InvalidSealed)
    );
    assert_eq!(
        alice.sealing.open_sealed(sealed, BOB.into(), BOB_IDENTITY.into(), ENVELOPE.into()),
        Err(ChatCryptoError::InvalidSealed)
    );
}

#[test]
fn a_forged_sender_does_not_pass_the_certificate() {
    // Mallory, who holds the server, writes a statement naming Alice's account id but signed
    // by Mallory's own account key: it seals and opens, but its account key is not the one
    // Bob pinned for Alice.
    let alice = person(1);
    let mallory = person(3);
    let bob = person(2);
    let sealed = seal(
        SealedRecipient {
            account_id: BOB.into(),
            identity_id: BOB_IDENTITY.into(),
            sealing_key: bob.sealing.public_key(),
        },
        ENVELOPE.into(),
        SealedSender {
            account_id: ALICE.into(),
            identity_id: ALICE_IDENTITY.into(),
            statement: mallory.statement,
        },
        Envelope { protocol: protocol_id(), olm_type: 1, ciphertext: "AAAA".into() },
    )
    .unwrap();
    let opened = bob.sealing.open_sealed(sealed, BOB.into(), BOB_IDENTITY.into(), ENVELOPE.into()).unwrap();
    let claimed = verify_identity(opened.sender.statement).unwrap();
    assert_ne!(claimed.account_public_key, alice.account.public_key());
}
