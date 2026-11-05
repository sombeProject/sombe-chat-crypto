//! Content version 2 (since 0.5.0): one variant per kind, version 1 still read, and the
//! sizes and session limits the SOMBE app relies on.

mod common;

use common::{device, key};
use sombe_chat_crypto::*;

const CONVERSATION: &str = "6f1c2a8e-0000-4000-8000-000000000001";
const ENVELOPE: &str = "6f1c2a8e-0000-4000-8000-0000000000e1";
const CLIENT: &str = "6f1c2a8e-0000-4000-8000-000000000002";
const TARGET: &str = "6f1c2a8e-0000-4000-8000-000000000003";

fn v2(body: ContentBody) -> Content {
    let envelope_id = match body {
        ContentBody::Typing { .. } => None,
        _ => Some(ENVELOPE.to_owned()),
    };
    Content { version: 2, conversation_id: CONVERSATION.into(), envelope_id, body }
}

fn text(body: &str) -> ContentBody {
    ContentBody::Text {
        client_message_id: CLIENT.into(),
        body: body.into(),
        reply_to_message_id: None,
        reply_excerpt: None,
    }
}

fn receipt(status: ReceiptStatus, at: &str) -> ContentBody {
    ContentBody::Receipt { status, up_to_envelope_id: TARGET.into(), up_to_created_at: at.into() }
}

/// The content JSON without its `pad` field, after checking the padding itself.
fn unpadded(json: &str) -> String {
    assert!(json.len() >= 256 && json.len().is_power_of_two(), "padded to a bucket: {}", json.len());
    let start = json.rfind(r#","pad":""#).expect("a pad field");
    assert!(json[start + 8..json.len() - 2].bytes().all(|b| b == b' '), "pad holds only spaces");
    format!("{}}}", &json[..start])
}

fn is_invalid(result: Result<impl std::fmt::Debug, ChatCryptoError>) -> bool {
    matches!(result, Err(ChatCryptoError::InvalidContent { .. }))
}

fn is_unsupported(result: Result<Content, ChatCryptoError>) -> bool {
    matches!(result, Err(ChatCryptoError::UnsupportedContent { .. }))
}

#[test]
fn every_kind_round_trips_with_its_fields_in_order() {
    let cases = [
        (
            ContentBody::Text {
                client_message_id: CLIENT.into(),
                body: "Bonjour".into(),
                reply_to_message_id: Some(TARGET.into()),
                reply_excerpt: Some("Dimanche à midi".into()),
            },
            r#""kind":"text","conversation_id":"C","envelope_id":"E","client_message_id":"M","body":"Bonjour","reply_to_message_id":"T","reply_excerpt":"Dimanche à midi""#,
        ),
        (
            text("Bonjour"),
            r#""kind":"text","conversation_id":"C","envelope_id":"E","client_message_id":"M","body":"Bonjour""#,
        ),
        (
            ContentBody::Edit {
                client_message_id: CLIENT.into(),
                edits_message_id: TARGET.into(),
                body: "Bonsoir".into(),
            },
            r#""kind":"edit","conversation_id":"C","envelope_id":"E","client_message_id":"M","edits_message_id":"T","body":"Bonsoir""#,
        ),
        (
            ContentBody::Reaction {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: TARGET.into(),
                body: "❤️".into(),
            },
            r#""kind":"reaction","conversation_id":"C","envelope_id":"E","client_message_id":"M","reacts_to_message_id":"T","body":"❤️""#,
        ),
        (
            ContentBody::ReactionRemove {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: TARGET.into(),
            },
            r#""kind":"reaction_remove","conversation_id":"C","envelope_id":"E","client_message_id":"M","reacts_to_message_id":"T""#,
        ),
        (
            ContentBody::Delete { client_message_id: CLIENT.into(), deletes_message_id: TARGET.into() },
            r#""kind":"delete","conversation_id":"C","envelope_id":"E","client_message_id":"M","deletes_message_id":"T""#,
        ),
        (
            ContentBody::Payment { client_message_id: CLIENT.into(), body: "Pour le marché".into() },
            r#""kind":"payment","conversation_id":"C","envelope_id":"E","client_message_id":"M","body":"Pour le marché""#,
        ),
        (
            receipt(ReceiptStatus::Delivered, "2026-11-04T12:34:56.789Z"),
            r#""kind":"receipt","conversation_id":"C","envelope_id":"E","status":"delivered","up_to_envelope_id":"T","up_to_created_at":"2026-11-04T12:34:56.789Z""#,
        ),
        (
            receipt(ReceiptStatus::Read, "2026-11-04T13:34:56+01:00"),
            r#""kind":"receipt","conversation_id":"C","envelope_id":"E","status":"read","up_to_envelope_id":"T","up_to_created_at":"2026-11-04T13:34:56+01:00""#,
        ),
        (
            ContentBody::Typing { state: TypingState::Start },
            r#""kind":"typing","conversation_id":"C","state":"start""#,
        ),
        (
            ContentBody::Typing { state: TypingState::Stop },
            r#""kind":"typing","conversation_id":"C","state":"stop""#,
        ),
    ];
    for (body, fields) in cases {
        let content = v2(body);
        let json = encode_content(content.clone()).unwrap();
        let expected = format!(r#"{{"v":2,{fields}}}"#)
            .replace(r#""C""#, &format!(r#""{CONVERSATION}""#))
            .replace(r#""E""#, &format!(r#""{ENVELOPE}""#))
            .replace(r#""M""#, &format!(r#""{CLIENT}""#))
            .replace(r#""T""#, &format!(r#""{TARGET}""#));
        assert_eq!(unpadded(&json), expected);
        assert_eq!(decode_content(json).unwrap(), content);
    }
}

#[test]
fn only_version_2_is_written() {
    for version in [0, 1, 3] {
        assert!(is_invalid(encode_content(Content { version, ..v2(text("x")) })), "version {version}");
    }
}

#[test]
fn envelope_id_is_required_except_on_typing_where_it_is_forbidden() {
    assert!(is_invalid(encode_content(Content { envelope_id: None, ..v2(text("x")) })));
    let no_id = Content { envelope_id: None, ..v2(receipt(ReceiptStatus::Read, "2026-11-04T12:34:56Z")) };
    assert!(is_invalid(encode_content(no_id)));
    let typing_with_id = Content {
        envelope_id: Some(ENVELOPE.into()),
        ..v2(ContentBody::Typing { state: TypingState::Start })
    };
    assert!(is_invalid(encode_content(typing_with_id)));

    // The same rules when read.
    let read =
        |fields: &str| decode_content(format!(r#"{{"v":2,"conversation_id":"{CONVERSATION}",{fields}}}"#));
    assert!(is_invalid(read(&format!(r#""kind":"typing","envelope_id":"{ENVELOPE}","state":"start""#))));
    assert!(is_invalid(read(&format!(r#""kind":"text","client_message_id":"{CLIENT}","body":"x""#))));
    assert!(read(r#""kind":"typing","state":"stop""#).is_ok());
    assert!(read(r#""kind":"typing","envelope_id":null,"state":"stop""#).is_ok());
}

#[test]
fn every_id_is_a_uuid_and_comes_out_in_lower_case() {
    let upper = "6F1C2A8E-0000-4000-8000-00000000ABCD";
    let lower = "6f1c2a8e-0000-4000-8000-00000000abcd";
    let content = Content {
        version: 2,
        conversation_id: upper.into(),
        envelope_id: Some(upper.into()),
        body: ContentBody::Text {
            client_message_id: upper.into(),
            body: "x".into(),
            reply_to_message_id: Some(upper.into()),
            reply_excerpt: None,
        },
    };
    let json = encode_content(content).unwrap();
    assert!(!json.contains("ABCD"));
    let read = decode_content(json).unwrap();
    assert_eq!(read.conversation_id, lower);
    assert_eq!(read.envelope_id.as_deref(), Some(lower));
    assert_eq!(
        read.body,
        ContentBody::Text {
            client_message_id: lower.into(),
            body: "x".into(),
            reply_to_message_id: Some(lower.into()),
            reply_excerpt: None
        }
    );
    // Read with upper case ids too.
    let typed = format!(r#"{{"v":2,"kind":"typing","conversation_id":"{upper}","state":"start"}}"#);
    assert_eq!(decode_content(typed).unwrap().conversation_id, lower);

    for bad in [
        "",
        "not-a-uuid",
        "6f1c2a8e00004000800000000000abcd",
        "6f1c2a8e-0000-4000-8000-00000000abc",
        "6f1c2a8e-0000-4000-8000-00000000abcg",
        "{6f1c2a8e-0000-4000-8000-00000000abcd}",
        "6f1c2a8e-0000-4000-8000-00000000abcd ",
    ] {
        assert!(
            is_invalid(encode_content(Content { conversation_id: bad.into(), ..v2(text("x")) })),
            "{bad:?}"
        );
        assert!(
            is_invalid(encode_content(Content { envelope_id: Some(bad.into()), ..v2(text("x")) })),
            "{bad:?}"
        );
        let targets = [
            ContentBody::Text {
                client_message_id: bad.into(),
                body: "x".into(),
                reply_to_message_id: None,
                reply_excerpt: None,
            },
            ContentBody::Text {
                client_message_id: CLIENT.into(),
                body: "x".into(),
                reply_to_message_id: Some(bad.into()),
                reply_excerpt: None,
            },
            ContentBody::Edit {
                client_message_id: CLIENT.into(),
                edits_message_id: bad.into(),
                body: "x".into(),
            },
            ContentBody::Reaction {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: bad.into(),
                body: "👍".into(),
            },
            ContentBody::ReactionRemove {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: bad.into(),
            },
            ContentBody::Delete { client_message_id: CLIENT.into(), deletes_message_id: bad.into() },
            ContentBody::Payment { client_message_id: bad.into(), body: "x".into() },
            ContentBody::Receipt {
                status: ReceiptStatus::Read,
                up_to_envelope_id: bad.into(),
                up_to_created_at: "2026-11-04T12:34:56Z".into(),
            },
        ];
        for body in targets {
            assert!(is_invalid(encode_content(v2(body.clone()))), "{bad:?} in {body:?}");
        }
    }
}

#[test]
fn receipt_date_is_rfc_3339_with_an_offset() {
    for good in [
        "2026-11-04T12:34:56Z",
        "2026-11-04T12:34:56.789Z",
        "2026-11-04T12:34:56.123456Z",
        "2026-11-04T13:34:56+01:00",
        "2026-11-04T07:34:56-05:00",
    ] {
        let json = encode_content(v2(receipt(ReceiptStatus::Delivered, good))).unwrap();
        assert!(json.contains(good), "{good}");
    }
    for bad in [
        "",
        "2026-11-04T12:34:56",
        "2026-11-04 12:34:56Z",
        "2026-11-04t12:34:56z",
        "2026-11-04T12:34:56.Z",
        "2026-13-04T12:34:56Z",
        "2026-11-00T12:34:56Z",
        "2026-11-04T24:34:56Z",
        "2026-11-04T12:34:56+0100",
        "2026-11-04T12:34:56+01:00Z",
        "26-11-04T12:34:56Z",
        "1730723696",
    ] {
        assert!(is_invalid(encode_content(v2(receipt(ReceiptStatus::Read, bad)))), "{bad:?}");
    }
}

#[test]
fn text_limits_are_those_of_0_4_0() {
    // Body of a text or an edit: 1 to 4000 characters, not blank.
    assert!(encode_content(v2(text(&"é".repeat(4000)))).is_ok());
    assert!(is_invalid(encode_content(v2(text(&"é".repeat(4001))))));
    assert!(is_invalid(encode_content(v2(text("  ")))));
    assert!(is_invalid(encode_content(v2(text("")))));
    let edit = |body: &str| ContentBody::Edit {
        client_message_id: CLIENT.into(),
        edits_message_id: TARGET.into(),
        body: body.into(),
    };
    assert!(encode_content(v2(edit(&"é".repeat(4000)))).is_ok());
    assert!(is_invalid(encode_content(v2(edit(&"é".repeat(4001))))));
    assert!(is_invalid(encode_content(v2(edit(" ")))));

    // Reply excerpt: at most 200 characters.
    let quoted = |excerpt: &str| ContentBody::Text {
        client_message_id: CLIENT.into(),
        body: "x".into(),
        reply_to_message_id: Some(TARGET.into()),
        reply_excerpt: Some(excerpt.into()),
    };
    assert!(encode_content(v2(quoted(&"é".repeat(200)))).is_ok());
    assert!(is_invalid(encode_content(v2(quoted(&"é".repeat(201))))));

    // Reaction: one emoji of 1 to 16 code points, without white space.
    let reaction = |body: &str| ContentBody::Reaction {
        client_message_id: CLIENT.into(),
        reacts_to_message_id: TARGET.into(),
        body: body.into(),
    };
    assert!(encode_content(v2(reaction("👨‍👩‍👧‍👦"))).is_ok());
    assert!(encode_content(v2(reaction(&"x".repeat(16)))).is_ok());
    assert!(is_invalid(encode_content(v2(reaction(&"x".repeat(17))))));
    assert!(is_invalid(encode_content(v2(reaction("")))));
    assert!(is_invalid(encode_content(v2(reaction("👍 ")))));

    // Payment comment: 1 to 500 characters in version 2.
    let payment = |body: &str| ContentBody::Payment { client_message_id: CLIENT.into(), body: body.into() };
    assert!(encode_content(v2(payment(&"é".repeat(500)))).is_ok());
    assert!(is_invalid(encode_content(v2(payment(&"é".repeat(501))))));
    assert!(is_invalid(encode_content(v2(payment(" ")))));
}

#[test]
fn unknown_kind_or_newer_version_is_unsupported_never_another_kind() {
    assert!(is_unsupported(decode_content(format!(
        r#"{{"v":2,"kind":"poll","conversation_id":"{CONVERSATION}","envelope_id":"{ENVELOPE}","question":"?"}}"#
    ))));
    assert!(is_unsupported(decode_content(format!(
        r#"{{"v":3,"kind":"text","conversation_id":"{CONVERSATION}","envelope_id":"{ENVELOPE}","client_message_id":"{CLIENT}","body":"x"}}"#
    ))));
    assert!(is_unsupported(decode_content(r#"{"v":42}"#.into())));
    // A version 1 kind unknown to 0.4.0 used to fall back on nothing either; now it is said so.
    assert!(is_unsupported(decode_content(format!(
        r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}","kind":"receipt"}}"#
    ))));
    assert!(is_unsupported(decode_content(format!(
        r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}","kind":"typing"}}"#
    ))));
}

#[test]
fn malformed_content_is_invalid() {
    let read = |fields: &str| {
        decode_content(format!(
            r#"{{"v":2,"conversation_id":"{CONVERSATION}","envelope_id":"{ENVELOPE}",{fields}}}"#
        ))
    };
    // An unknown field in version 2: a later addition goes through a version 3.
    assert!(is_invalid(read(&format!(
        r#""kind":"text","client_message_id":"{CLIENT}","body":"x","comment":"y""#
    ))));
    assert!(is_invalid(read(&format!(
        r#""kind":"delete","client_message_id":"{CLIENT}","deletes_message_id":"{TARGET}","body":"x""#
    ))));
    assert!(is_invalid(read(&format!(
        r#""kind":"receipt","status":"read","up_to_envelope_id":"{TARGET}","up_to_created_at":"2026-11-04T12:34:56Z","client_message_id":"{CLIENT}""#
    ))));
    // A field the kind needs is missing, or has the wrong type or value.
    assert!(is_invalid(read(&format!(r#""kind":"edit","client_message_id":"{CLIENT}","body":"x""#))));
    assert!(is_invalid(read(&format!(
        r#""kind":"receipt","status":"seen","up_to_envelope_id":"{TARGET}","up_to_created_at":"2026-11-04T12:34:56Z""#
    ))));
    assert!(is_invalid(read(r#""kind":"receipt","status":"read""#)));
    assert!(is_invalid(read(&format!(r#""kind":"text","client_message_id":"{CLIENT}","body":7"#))));
    assert!(is_invalid(read(r#""client_message_id":"x","body":"x""#)));
    assert!(is_invalid(decode_content(format!(
        r#"{{"v":2,"kind":"typing","conversation_id":"{CONVERSATION}","state":"paused"}}"#
    ))));
    assert!(is_invalid(decode_content(r#"{"kind":"text"}"#.into())));
    assert!(is_invalid(decode_content(r#"{"v":0,"kind":"text"}"#.into())));
    assert!(is_invalid(decode_content(r#"{"v":"2","kind":"text"}"#.into())));
    assert!(is_invalid(decode_content(r#"[2]"#.into())));
    assert!(is_invalid(decode_content("not json".into())));
    // The padding is ignored when read.
    let padded = format!(
        r#"{{"v":2,"kind":"typing","conversation_id":"{CONVERSATION}","state":"start","pad":"   "}}"#
    );
    assert!(decode_content(padded).is_ok());
}

#[test]
fn version_1_is_read_with_the_rules_of_0_4_0() {
    let read = |fields: &str| {
        decode_content(format!(
            r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}",{fields}}}"#
        ))
    };
    // A text keeps its excerpt but has no link to the quoted message.
    let quoted = read(r#""kind":"text","body":"Oui","reply_excerpt":"Dimanche ?""#).unwrap();
    assert_eq!((quoted.version, quoted.envelope_id.clone()), (1, None));
    assert_eq!(
        quoted.body,
        ContentBody::Text {
            client_message_id: CLIENT.into(),
            body: "Oui".into(),
            reply_to_message_id: None,
            reply_excerpt: Some("Dimanche ?".into())
        }
    );
    // A payment's comment becomes the body; a card without comment reads as empty.
    assert_eq!(
        read(r#""kind":"payment","comment":"Pour le marché""#).unwrap().body,
        ContentBody::Payment { client_message_id: CLIENT.into(), body: "Pour le marché".into() }
    );
    assert_eq!(
        read(r#""kind":"payment""#).unwrap().body,
        ContentBody::Payment { client_message_id: CLIENT.into(), body: String::new() }
    );
    // Unknown fields are ignored in version 1, as 0.4.0 did; ids were not required to be UUIDs.
    assert!(read(r#""kind":"text","body":"x","later":true"#).is_ok());
    assert_eq!(
        decode_content(
            r#"{"v":1,"conversation_id":"A","client_message_id":"B","kind":"text","body":"x"}"#.into()
        )
        .unwrap()
        .conversation_id,
        "a"
    );
    // The rules of each kind still hold.
    assert!(is_invalid(read(r#""kind":"text","body":"x","edits_message_id":"c""#)));
    assert!(is_invalid(read(r#""kind":"edit","body":"x""#)));
    assert!(is_invalid(read(r#""kind":"reaction","body":"👍""#)));
    assert!(is_invalid(read(r#""kind":"reaction","body":"👍 👍","reacts_to_message_id":"c""#)));
    assert!(is_invalid(read(r#""kind":"reaction_remove","body":"👍","reacts_to_message_id":"c""#)));
    assert!(is_invalid(read(r#""kind":"delete""#)));
    assert!(is_invalid(read(r#""kind":"text","body":"x","deletes_message_id":"d""#)));
    assert!(is_invalid(read(r#""kind":"payment","body":"x""#)));
    assert!(is_invalid(read(&format!(r#""kind":"payment","comment":"{}""#, "é".repeat(501)))));
    assert!(is_invalid(read(r#""kind":"text","body":" ""#)));
    assert!(is_invalid(decode_content(
        r#"{"v":1,"conversation_id":"","client_message_id":"b","kind":"text","body":"x"}"#.into()
    )));
}

#[test]
fn contents_are_padded_to_their_bucket() {
    // A typing signal, start or stop, is in the smallest bucket.
    for state in [TypingState::Start, TypingState::Stop] {
        assert_eq!(encode_content(v2(ContentBody::Typing { state })).unwrap().len(), 256);
    }
    // A receipt is in the next one (512 bytes), even the shortest one possible.
    let shortest = encode_content(v2(receipt(ReceiptStatus::Read, "2026-11-04T12:34:56Z"))).unwrap();
    assert_eq!(shortest.len(), 512);
    let longest =
        encode_content(v2(receipt(ReceiptStatus::Delivered, "2026-11-04T12:34:56.123456789+01:00"))).unwrap();
    assert_eq!(longest.len(), 512);
    // "Oui" and a short sentence look the same; a medium text shares the receipt's bucket.
    assert_eq!(encode_content(v2(text("Oui"))).unwrap().len(), 256);
    assert_eq!(encode_content(v2(text("Je serai là vers midi"))).unwrap().len(), 256);
    assert_eq!(encode_content(v2(text(&"a".repeat(100)))).unwrap().len(), 512);
    // The longest text allowed.
    let largest = encode_content(v2(text(&"😀".repeat(4000)))).unwrap();
    assert_eq!(largest.len(), 16384);
    assert_eq!(decode_content(largest).unwrap(), v2(text(&"😀".repeat(4000))));
}

/// Opens a session from Alice to Bob, and Bob's answer, so both have a confirmed session.
fn confirmed_sessions(
) -> (std::sync::Arc<ChatCrypto>, std::sync::Arc<ChatCrypto>, StoredSession, StoredSession) {
    let alice = device();
    let bob = device();
    let otk = bob.generate_one_time_keys(1).remove(0);
    bob.mark_keys_published();
    let first = alice.encrypt_for(bob.identity_keys(), None, Some(otk), "un".into(), key()).unwrap();
    let opened = bob.decrypt_from(alice.identity_keys(), vec![], first.envelope, key()).unwrap();
    let reply = bob
        .encrypt_for(alice.identity_keys(), Some(opened.session.clone()), None, "oui".into(), key())
        .unwrap();
    let read = alice.decrypt_from(bob.identity_keys(), vec![first.session], reply.envelope, key()).unwrap();
    (alice, bob, read.session, reply.session)
}

#[test]
fn a_typing_signal_on_a_confirmed_session_is_type_1_and_under_2048_characters() {
    let (alice, bob, alice_session, bob_session) = confirmed_sessions();
    let typing = encode_content(v2(ContentBody::Typing { state: TypingState::Start })).unwrap();
    let sealed =
        alice.encrypt_for(bob.identity_keys(), Some(alice_session), None, typing.clone(), key()).unwrap();
    assert_eq!(sealed.envelope.olm_type, 1);
    assert!(sealed.envelope.ciphertext.len() < 2048, "{}", sealed.envelope.ciphertext.len());
    let got = bob.decrypt_from(alice.identity_keys(), vec![bob_session], sealed.envelope, key()).unwrap();
    assert_eq!(
        decode_content(got.plaintext).unwrap().body,
        ContentBody::Typing { state: TypingState::Start }
    );
}

/// vodozemac 0.11.1 reads a message after at most 2000 skipped ones (typing signals the
/// contact never received). A message overtaken by a later one (a mailbox message read
/// after a typing signal sent after it) can still be read late only when the later one was
/// at most 40 messages ahead of it.
#[test]
fn vodozemac_message_gap_limits() {
    // 2000 skipped messages: the next still opens.
    let (alice, bob, mut session, bob_session) = confirmed_sessions();
    for i in 0..2000 {
        session = alice
            .encrypt_for(bob.identity_keys(), Some(session), None, format!("{i}"), key())
            .unwrap()
            .session;
    }
    let next = alice.encrypt_for(bob.identity_keys(), Some(session), None, "lu".into(), key()).unwrap();
    let got = bob.decrypt_from(alice.identity_keys(), vec![bob_session], next.envelope, key()).unwrap();
    assert_eq!(got.plaintext, "lu");

    // 2001 skipped messages: the next no longer opens on that session.
    let (alice, bob, mut session, bob_session) = confirmed_sessions();
    for i in 0..2001 {
        session = alice
            .encrypt_for(bob.identity_keys(), Some(session), None, format!("{i}"), key())
            .unwrap()
            .session;
    }
    let next = alice.encrypt_for(bob.identity_keys(), Some(session), None, "perdu".into(), key()).unwrap();
    assert!(matches!(
        bob.decrypt_from(alice.identity_keys(), vec![bob_session], next.envelope, key()),
        Err(ChatCryptoError::NoMatchingSession)
    ));

    // A message overtaken by a later one: its key is kept only when the later one is at
    // most 40 messages ahead of it (the receiver jumps once, storing at most 40 keys).
    for (unsent, readable) in [(39, true), (40, false)] {
        let (alice, bob, session, bob_session) = confirmed_sessions();
        let early = alice.encrypt_for(bob.identity_keys(), Some(session), None, "tôt".into(), key()).unwrap();
        let mut session = early.session;
        for i in 0..unsent {
            session = alice
                .encrypt_for(bob.identity_keys(), Some(session), None, format!("{i}"), key())
                .unwrap()
                .session;
        }
        let ahead =
            alice.encrypt_for(bob.identity_keys(), Some(session), None, "devant".into(), key()).unwrap();
        let read = bob.decrypt_from(alice.identity_keys(), vec![bob_session], ahead.envelope, key()).unwrap();
        let late = bob.decrypt_from(alice.identity_keys(), vec![read.session], early.envelope, key());
        assert_eq!(late.is_ok(), readable, "overtaken by a message {} ahead", unsent + 1);
    }
}
