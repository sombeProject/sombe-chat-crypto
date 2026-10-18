mod common;

use common::{device, key, TestWallet};
use sombe_chat_crypto::*;

const CREATED: &str = "2026-10-14T18:30:01.183Z";

/// The content JSON without its `pad` field, after checking the padding itself.
fn unpadded(json: &str) -> String {
    assert!(json.len() >= 256 && json.len().is_power_of_two(), "padded to a bucket: {}", json.len());
    let start = json.rfind(r#","pad":""#).expect("a pad field");
    assert!(json[start + 8..json.len() - 2].bytes().all(|b| b == b' '), "pad holds only spaces");
    format!("{}}}", &json[..start])
}

#[test]
fn first_message_reply_and_follow_up() {
    let alice = device();
    let bob = device();
    let bob_keys = bob.generate_one_time_keys(5);
    bob.mark_keys_published();
    assert_eq!(bob_keys.len(), 5);

    // Alice claims one of Bob's keys and opens a session with her first message.
    let first = alice
        .encrypt_for(bob.identity_keys(), None, Some(bob_keys[0].clone()), "Salut Bob".into(), key())
        .unwrap();
    assert_eq!(first.envelope.olm_type, 0);
    assert_eq!(first.envelope.protocol, "olm-v1");
    assert!(!first.envelope.ciphertext.contains("Salut"));

    let received = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap();
    assert_eq!(received.plaintext, "Salut Bob");
    assert!(received.new_session && received.account_changed);

    // Bob answers on the session he just opened.
    let reply = bob
        .encrypt_for(alice.identity_keys(), Some(received.session.clone()), None, "Salut Alice".into(), key())
        .unwrap();
    assert_eq!(reply.envelope.olm_type, 1);
    let read = alice.decrypt_from(bob.identity_keys(), vec![first.session], reply.envelope, key()).unwrap();
    assert_eq!(read.plaintext, "Salut Alice");
    assert!(!read.new_session && !read.account_changed);

    // Once Alice has read a reply, her messages are no longer first messages.
    let next =
        alice.encrypt_for(bob.identity_keys(), Some(read.session), None, "Ça va ?".into(), key()).unwrap();
    assert_eq!(next.envelope.olm_type, 1);
    let got = bob.decrypt_from(alice.identity_keys(), vec![reply.session], next.envelope, key()).unwrap();
    assert_eq!(got.plaintext, "Ça va ?");
}

#[test]
fn second_first_message_reuses_the_inbound_session() {
    let alice = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let one = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "un".into(), key()).unwrap();
    let two = alice.encrypt_for(bob.identity_keys(), Some(one.session), None, "deux".into(), key()).unwrap();
    assert_eq!(two.envelope.olm_type, 0, "still a first message until Bob replies");

    let r1 = bob.decrypt_from(alice.identity_keys(), vec![], one.envelope, key()).unwrap();
    let r2 = bob.decrypt_from(alice.identity_keys(), vec![r1.session], two.envelope, key()).unwrap();
    assert_eq!(r2.plaintext, "deux");
    assert!(!r2.new_session);
}

#[test]
fn replayed_first_message_is_unreadable_once_the_key_is_used() {
    let alice = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "une fois".into(), key()).unwrap();
    bob.decrypt_from(alice.identity_keys(), vec![], first.envelope.clone(), key()).unwrap();

    // The session was lost (or never stored): the one time key is gone, nothing opens.
    let err = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap_err();
    assert!(matches!(err, ChatCryptoError::SessionCreation { .. }));
}

#[test]
fn following_message_without_session_never_opens_one() {
    let alice = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "a".into(), key()).unwrap();
    let r = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap();
    let reply = bob.encrypt_for(alice.identity_keys(), Some(r.session), None, "b".into(), key()).unwrap();

    let err = alice.decrypt_from(bob.identity_keys(), vec![], reply.envelope, key()).unwrap_err();
    assert_eq!(err, ChatCryptoError::NoMatchingSession);
}

#[test]
fn first_message_from_another_identity_is_refused() {
    let alice = device();
    let mallory = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "a".into(), key()).unwrap();
    let err = bob.decrypt_from(mallory.identity_keys(), vec![], first.envelope, key()).unwrap_err();
    assert!(matches!(err, ChatCryptoError::InvalidMessage { .. }));
}

#[test]
fn forged_one_time_key_is_refused() {
    let alice = device();
    let bob = device();
    let mallory = device();
    let mut forged = mallory.generate_one_time_keys(1).remove(0);
    assert!(!verify_one_time_key(bob.identity_keys(), forged.clone()));
    let err =
        alice.encrypt_for(bob.identity_keys(), None, Some(forged.clone()), "x".into(), key()).unwrap_err();
    assert_eq!(err, ChatCryptoError::InvalidSignature);

    // A genuine key whose fallback flag was flipped no longer verifies either.
    forged = bob.generate_one_time_keys(1).remove(0);
    assert!(verify_one_time_key(bob.identity_keys(), forged.clone()));
    forged.is_fallback = true;
    assert!(!verify_one_time_key(bob.identity_keys(), forged));
}

#[test]
fn fallback_key_opens_a_session() {
    let alice = device();
    let bob = device();
    let fallback = bob.generate_fallback_key();
    assert!(fallback.is_fallback);
    assert!(verify_one_time_key(bob.identity_keys(), fallback.clone()));
    let first =
        alice.encrypt_for(bob.identity_keys(), None, Some(fallback), "secours".into(), key()).unwrap();
    let r = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap();
    assert_eq!(r.plaintext, "secours");
}

#[test]
fn neither_session_nor_key_is_an_error() {
    let alice = device();
    let bob = device();
    let err = alice.encrypt_for(bob.identity_keys(), None, None, "x".into(), key()).unwrap_err();
    assert!(matches!(err, ChatCryptoError::SessionCreation { .. }));
}

#[test]
fn account_pickle_round_trip() {
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let pickle = bob.pickle(key()).unwrap();
    assert!(!pickle.contains(&otk.public_key));

    let restored = ChatCrypto::restore_account(pickle.clone(), key()).unwrap();
    assert_eq!(restored.identity_keys(), bob.identity_keys());

    // The restored account still holds the private one time key.
    let alice = device();
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "après".into(), key()).unwrap();
    assert_eq!(
        restored.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap().plaintext,
        "après"
    );

    assert!(matches!(
        ChatCrypto::restore_account(pickle.clone(), vec![8; 32]),
        Err(ChatCryptoError::InvalidPickle)
    ));
    assert!(matches!(
        ChatCrypto::restore_account(pickle, vec![7; 31]),
        Err(ChatCryptoError::InvalidKey { .. })
    ));
}

#[test]
fn unknown_protocol_and_broken_ciphertext() {
    let bob = device();
    let alice = device();
    let bad = Envelope { protocol: "signal-v1".into(), olm_type: 0, ciphertext: "AAAA".into() };
    assert!(matches!(
        bob.decrypt_from(alice.identity_keys(), vec![], bad, key()),
        Err(ChatCryptoError::UnsupportedProtocol { .. })
    ));
    let broken = Envelope { protocol: "olm-v1".into(), olm_type: 0, ciphertext: "AAAA".into() };
    assert!(matches!(
        bob.decrypt_from(alice.identity_keys(), vec![], broken, key()),
        Err(ChatCryptoError::InvalidMessage { .. })
    ));
}

#[test]
fn identity_statement_signed_by_the_wallet() {
    let wallet = TestWallet::from_seed([1; 32]);
    let bob = device();
    let statement = bob.identity_statement(wallet.address(), CREATED.into()).unwrap();
    let keys = bob.identity_keys();
    let body = format!(
        "SOMBE chat identity v2\nprotocol:olm-v1\nwallet:{}\ncurve25519:{}\ned25519:{}\ncreated:{CREATED}",
        wallet.address(),
        keys.curve25519_key,
        keys.ed25519_key
    );
    let (signed, identity_signature) = statement.rsplit_once('\n').unwrap();
    assert_eq!(signed, body);
    assert!(identity_signature.starts_with("identity_signature:"));
    let signature = wallet.sign(&statement);

    let verified = verify_identity(statement.clone(), wallet.address(), signature.clone()).unwrap();
    assert_eq!(verified.curve25519_key, keys.curve25519_key);
    assert_eq!(verified.ed25519_key, keys.ed25519_key);
    assert_eq!(verified.created_at, CREATED);

    // Another wallet, a changed key, or a forged signature all fail.
    let other = TestWallet::from_seed([2; 32]);
    assert_eq!(
        verify_identity(statement.clone(), other.address(), signature.clone()),
        Err(ChatCryptoError::InvalidSignature)
    );
    let mallory = device();
    let swapped = statement.replace(&keys.curve25519_key, &mallory.identity_keys().curve25519_key);
    assert_eq!(verify_identity(swapped, wallet.address(), signature), Err(ChatCryptoError::InvalidSignature));
    assert_eq!(
        verify_identity(statement.clone(), wallet.address(), other.sign(&statement)),
        Err(ChatCryptoError::InvalidSignature)
    );
    assert_eq!(
        verify_identity(statement, wallet.address(), "not-base58-0OIl".into()),
        Err(ChatCryptoError::InvalidSignature)
    );
}

#[test]
fn identity_statement_rejects_bad_inputs() {
    let bob = device();
    let wallet = TestWallet::from_seed([3; 32]);
    assert!(bob.identity_statement("abc".into(), CREATED.into()).is_err());
    for created in ["2026-10-14 18:30:01Z", "2026-10-14T18:30:01", "2026-10-14T18:30:01+01:00", ""] {
        assert!(bob.identity_statement(wallet.address(), created.into()).is_err(), "{created}");
    }
    assert!(bob.identity_statement(wallet.address(), "2026-10-14T18:30:01Z".into()).is_ok());

    // A well signed text that is not our format is still refused.
    let text = "hello";
    assert!(matches!(
        verify_identity(text.into(), wallet.address(), wallet.sign(text)),
        Err(ChatCryptoError::InvalidStatement { .. })
    ));
}

#[test]
fn content_round_trip_and_rules() {
    let content = MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000002".into(),
        kind: ContentKind::Text,
        body: Some("Bonjour".into()),
        reply_excerpt: Some("Dimanche à midi".into()),
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: None,
    };
    let json = encode_content(content.clone()).unwrap();
    assert_eq!(
        unpadded(&json),
        r#"{"v":1,"conversation_id":"6f1c2a8e-0000-4000-8000-000000000001","client_message_id":"6f1c2a8e-0000-4000-8000-000000000002","kind":"text","body":"Bonjour","reply_excerpt":"Dimanche à midi"}"#
    );
    assert_eq!(decode_content(json).unwrap(), content);

    let payment = MessageContent {
        kind: ContentKind::Payment,
        body: None,
        reply_excerpt: None,
        comment: Some("Pour le marché".into()),
        ..content.clone()
    };
    assert_eq!(decode_content(encode_content(payment.clone()).unwrap()).unwrap(), payment);

    let empty = MessageContent { body: Some("  ".into()), reply_excerpt: None, ..content.clone() };
    assert!(encode_content(empty).is_err());
    let long_excerpt = MessageContent { reply_excerpt: Some("é".repeat(201)), ..content.clone() };
    assert!(encode_content(long_excerpt).is_err());
    let exact_excerpt = MessageContent { reply_excerpt: Some("é".repeat(200)), ..content };
    assert!(encode_content(exact_excerpt).is_ok());
    assert!(decode_content(
        r#"{"v":2,"conversation_id":"a","client_message_id":"b","kind":"text","body":"x"}"#.into()
    )
    .is_err());
    assert!(decode_content("not json".into()).is_err());
}

#[test]
fn edit_content_rules() {
    let edit = MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000003".into(),
        kind: ContentKind::Edit,
        body: Some("Je t’envoie pour le marché".into()),
        reply_excerpt: None,
        comment: None,
        edits_message_id: Some("6f1c2a8e-0000-4000-8000-000000000002".into()),
        reacts_to_message_id: None,
    };
    let json = encode_content(edit.clone()).unwrap();
    assert_eq!(
        unpadded(&json),
        r#"{"v":1,"conversation_id":"6f1c2a8e-0000-4000-8000-000000000001","client_message_id":"6f1c2a8e-0000-4000-8000-000000000003","kind":"edit","body":"Je t’envoie pour le marché","edits_message_id":"6f1c2a8e-0000-4000-8000-000000000002"}"#
    );
    assert_eq!(decode_content(json).unwrap(), edit);

    let no_target = MessageContent { edits_message_id: None, ..edit.clone() };
    assert!(encode_content(no_target).is_err());
    let empty_target = MessageContent { edits_message_id: Some(String::new()), ..edit.clone() };
    assert!(encode_content(empty_target).is_err());
    let blank = MessageContent { body: Some(" ".into()), ..edit.clone() };
    assert!(encode_content(blank).is_err());
    let too_long = MessageContent { body: Some("é".repeat(4001)), ..edit.clone() };
    assert!(encode_content(too_long).is_err());
    let longest = MessageContent { body: Some("é".repeat(4000)), ..edit.clone() };
    assert!(encode_content(longest).is_ok());
    let quoted = MessageContent { reply_excerpt: Some("Dimanche".into()), ..edit.clone() };
    assert!(encode_content(quoted).is_err());
    let commented = MessageContent { comment: Some("x".into()), ..edit.clone() };
    assert!(encode_content(commented).is_err());

    let text_with_target = MessageContent { kind: ContentKind::Text, ..edit.clone() };
    assert!(encode_content(text_with_target).is_err());
    let payment_with_target =
        MessageContent { kind: ContentKind::Payment, body: None, comment: Some("x".into()), ..edit };
    assert!(encode_content(payment_with_target).is_err());
    assert!(decode_content(
        r#"{"v":1,"conversation_id":"a","client_message_id":"b","kind":"text","body":"x","edits_message_id":"c"}"#
            .into()
    )
    .is_err());
    assert!(decode_content(
        r#"{"v":1,"conversation_id":"a","client_message_id":"b","kind":"edit","body":"x"}"#.into()
    )
    .is_err());
}

#[test]
fn reaction_content_rules() {
    let reaction = MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000004".into(),
        kind: ContentKind::Reaction,
        body: Some("❤️".into()),
        reply_excerpt: None,
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: Some("6f1c2a8e-0000-4000-8000-000000000002".into()),
    };
    let json = encode_content(reaction.clone()).unwrap();
    assert_eq!(
        unpadded(&json),
        r#"{"v":1,"conversation_id":"6f1c2a8e-0000-4000-8000-000000000001","client_message_id":"6f1c2a8e-0000-4000-8000-000000000004","kind":"reaction","body":"❤️","reacts_to_message_id":"6f1c2a8e-0000-4000-8000-000000000002"}"#
    );
    assert_eq!(decode_content(json).unwrap(), reaction);

    // A family emoji is several code points joined, still one reaction.
    let family = MessageContent { body: Some("👨‍👩‍👧‍👦".into()), ..reaction.clone() };
    assert!(encode_content(family).is_ok());
    let longest = MessageContent { body: Some("x".repeat(16)), ..reaction.clone() };
    assert!(encode_content(longest).is_ok());
    let too_long = MessageContent { body: Some("x".repeat(17)), ..reaction.clone() };
    assert!(encode_content(too_long).is_err());
    let empty = MessageContent { body: Some(String::new()), ..reaction.clone() };
    assert!(encode_content(empty).is_err());
    let missing = MessageContent { body: None, ..reaction.clone() };
    assert!(encode_content(missing).is_err());
    let spaced = MessageContent { body: Some("👍 ".into()), ..reaction.clone() };
    assert!(encode_content(spaced).is_err());
    let no_target = MessageContent { reacts_to_message_id: None, ..reaction.clone() };
    assert!(encode_content(no_target).is_err());
    let empty_target = MessageContent { reacts_to_message_id: Some(String::new()), ..reaction.clone() };
    assert!(encode_content(empty_target).is_err());
    let quoted = MessageContent { reply_excerpt: Some("Dimanche".into()), ..reaction.clone() };
    assert!(encode_content(quoted).is_err());
    let commented = MessageContent { comment: Some("x".into()), ..reaction.clone() };
    assert!(encode_content(commented).is_err());
    let editing = MessageContent { edits_message_id: Some("c".into()), ..reaction.clone() };
    assert!(encode_content(editing).is_err());

    let text_with_target = MessageContent { kind: ContentKind::Text, ..reaction.clone() };
    assert!(encode_content(text_with_target).is_err());
    let edit_with_target =
        MessageContent { kind: ContentKind::Edit, edits_message_id: Some("c".into()), ..reaction.clone() };
    assert!(encode_content(edit_with_target).is_err());
    let payment_with_target =
        MessageContent { kind: ContentKind::Payment, body: None, comment: Some("x".into()), ..reaction };
    assert!(encode_content(payment_with_target).is_err());
    assert!(decode_content(
        r#"{"v":1,"conversation_id":"a","client_message_id":"b","kind":"text","body":"x","reacts_to_message_id":"c"}"#
            .into()
    )
    .is_err());
    assert!(decode_content(
        r#"{"v":1,"conversation_id":"a","client_message_id":"b","kind":"reaction","body":"👍"}"#.into()
    )
    .is_err());
}

#[test]
fn message_after_several_skipped_ones_still_decrypts() {
    // A phone that ignored some messages (a kind it did not know yet) must still read the next.
    let alice = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "un".into(), key()).unwrap();
    let opened = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap();
    let reply = bob
        .encrypt_for(alice.identity_keys(), Some(opened.session.clone()), None, "oui".into(), key())
        .unwrap();
    let read = alice.decrypt_from(bob.identity_keys(), vec![first.session], reply.envelope, key()).unwrap();

    let mut session = read.session;
    for i in 0..5 {
        session = alice
            .encrypt_for(bob.identity_keys(), Some(session), None, format!("sauté {i}"), key())
            .unwrap()
            .session;
    }
    let next = alice.encrypt_for(bob.identity_keys(), Some(session), None, "lu".into(), key()).unwrap();
    let got = bob.decrypt_from(alice.identity_keys(), vec![reply.session], next.envelope, key()).unwrap();
    assert_eq!(got.plaintext, "lu");
}

#[test]
fn content_is_padded_to_a_size_bucket() {
    let text = |body: &str| MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000002".into(),
        kind: ContentKind::Text,
        body: Some(body.into()),
        reply_excerpt: None,
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: None,
    };
    // "Oui" and a longer sentence look the same size to the server.
    let short = encode_content(text("Oui")).unwrap();
    let longer = encode_content(text("Je serai là vers midi, garde-moi une place")).unwrap();
    assert_eq!(short.len(), 256);
    assert_eq!(longer.len(), 256);

    // Larger contents go to the next power of two, up to the longest text allowed.
    assert_eq!(encode_content(text(&"a".repeat(300))).unwrap().len(), 512);
    assert_eq!(encode_content(text(&"é".repeat(4000))).unwrap().len(), 8192);
    let longest = encode_content(text(&"😀".repeat(4000))).unwrap();
    assert_eq!(longest.len(), 16384);
    assert_eq!(decode_content(longest).unwrap(), text(&"😀".repeat(4000)));

    // Content from a phone built before padding (0.2.0) is still read.
    let unpadded = r#"{"v":1,"conversation_id":"a","client_message_id":"b","kind":"text","body":"x"}"#;
    assert_eq!(decode_content(unpadded.into()).unwrap().body.as_deref(), Some("x"));
}

#[test]
fn reaction_removal_is_encrypted_content() {
    let removal = MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000005".into(),
        kind: ContentKind::ReactionRemove,
        body: None,
        reply_excerpt: None,
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: Some("6f1c2a8e-0000-4000-8000-000000000002".into()),
    };
    let json = encode_content(removal.clone()).unwrap();
    assert_eq!(
        unpadded(&json),
        r#"{"v":1,"conversation_id":"6f1c2a8e-0000-4000-8000-000000000001","client_message_id":"6f1c2a8e-0000-4000-8000-000000000005","kind":"reaction_remove","reacts_to_message_id":"6f1c2a8e-0000-4000-8000-000000000002"}"#
    );
    assert_eq!(decode_content(json).unwrap(), removal);

    // It names its text and nothing else.
    for wrong in [
        MessageContent { reacts_to_message_id: None, ..removal.clone() },
        MessageContent { reacts_to_message_id: Some(String::new()), ..removal.clone() },
        MessageContent { body: Some("❤️".into()), ..removal.clone() },
        MessageContent { reply_excerpt: Some("x".into()), ..removal.clone() },
        MessageContent { comment: Some("x".into()), ..removal.clone() },
        MessageContent { edits_message_id: Some("c".into()), ..removal },
    ] {
        assert!(encode_content(wrong.clone()).is_err(), "{wrong:?}");
    }
}
