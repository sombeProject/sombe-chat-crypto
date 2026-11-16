//! Content version 4 (since 0.8.1): one variant per kind, bound to its element by the
//! sender's and the recipient's account ids and identity keys, the channel and the envelope id; versions 1
//! and 2 still read for an element vouched for with its old conversation id; and the sizes
//! and session limits the SOMBE app relies on.

mod common;

use common::{
    device, key, legacy, mailbox, out, websocket, RECIPIENT, RECIPIENT_KEY, SENDER, SENDER_KEY, STRANGER_KEY,
};
use sombe_chat_crypto::*;

const CONVERSATION: &str = "6f1c2a8e-0000-4000-8000-000000000001";
const ENVELOPE: &str = "6f1c2a8e-0000-4000-8000-0000000000e1";
const CLIENT: &str = "6f1c2a8e-0000-4000-8000-000000000002";
const TARGET: &str = "6f1c2a8e-0000-4000-8000-000000000003";
const OTHER: &str = "c3c3c3c3-0000-4000-8000-0000000000c3";

fn v4(body: ContentBody) -> OutgoingContent {
    let envelope_id = match body {
        ContentBody::Typing { .. } => None,
        _ => Some(ENVELOPE),
    };
    out(envelope_id, body)
}

/// Reads a content as `RECIPIENT` would: a typing from the websocket, anything else from
/// the mailbox element `ENVELOPE`.
fn read(json: String) -> Result<Content, ChatCryptoError> {
    let typing = json.contains(r#""kind":"typing""#);
    decode_content(json, if typing { websocket() } else { mailbox(ENVELOPE) })
}

fn read_back(content: &OutgoingContent) -> Content {
    Content { version: 4, envelope_id: content.envelope_id.clone(), body: content.body.clone() }
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

/// A version 4 JSON from `SENDER` to `RECIPIENT` with these fields after the ids.
fn v4_json(fields: &str) -> String {
    format!(
        r#"{{"v":4,"sender_account_id":"{SENDER}","sender_ed25519":"{SENDER_KEY}","recipient_account_id":"{RECIPIENT}","recipient_ed25519":"{RECIPIENT_KEY}",{fields}}}"#
    )
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

fn is_unbound(result: Result<Content, ChatCryptoError>) -> bool {
    matches!(result, Err(ChatCryptoError::UnboundContent))
}

/// A test attestation and signature: their form only, the module never reads them here.
const ATTESTATION: &str = "SOMBE alias attestation v1\nkid:t1\nalias:alice_01\naccount_id:a1a1a1a1-0000-4000-8000-0000000000a1\naccount:F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4\nexpires:1794916800";
const SIGNATURE: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

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
            r#""kind":"text",IDS,"envelope_id":"E","client_message_id":"M","body":"Bonjour","reply_to_message_id":"T","reply_excerpt":"Dimanche à midi""#,
        ),
        (text("Bonjour"), r#""kind":"text",IDS,"envelope_id":"E","client_message_id":"M","body":"Bonjour""#),
        (
            ContentBody::Edit {
                client_message_id: CLIENT.into(),
                edits_message_id: TARGET.into(),
                body: "Bonsoir".into(),
            },
            r#""kind":"edit",IDS,"envelope_id":"E","client_message_id":"M","edits_message_id":"T","body":"Bonsoir""#,
        ),
        (
            ContentBody::Reaction {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: TARGET.into(),
                body: "❤️".into(),
            },
            r#""kind":"reaction",IDS,"envelope_id":"E","client_message_id":"M","reacts_to_message_id":"T","body":"❤️""#,
        ),
        (
            ContentBody::ReactionRemove {
                client_message_id: CLIENT.into(),
                reacts_to_message_id: TARGET.into(),
            },
            r#""kind":"reaction_remove",IDS,"envelope_id":"E","client_message_id":"M","reacts_to_message_id":"T""#,
        ),
        (
            ContentBody::Delete { client_message_id: CLIENT.into(), deletes_message_id: TARGET.into() },
            r#""kind":"delete",IDS,"envelope_id":"E","client_message_id":"M","deletes_message_id":"T""#,
        ),
        (
            ContentBody::Payment { client_message_id: CLIENT.into(), body: "Pour le marché".into() },
            r#""kind":"payment",IDS,"envelope_id":"E","client_message_id":"M","body":"Pour le marché""#,
        ),
        (
            receipt(ReceiptStatus::Delivered, "2026-11-04T12:34:56.789Z"),
            r#""kind":"receipt",IDS,"envelope_id":"E","status":"delivered","up_to_envelope_id":"T","up_to_created_at":"2026-11-04T12:34:56.789Z""#,
        ),
        (
            receipt(ReceiptStatus::Read, "2026-11-04T13:34:56+01:00"),
            r#""kind":"receipt",IDS,"envelope_id":"E","status":"read","up_to_envelope_id":"T","up_to_created_at":"2026-11-04T13:34:56+01:00""#,
        ),
        (ContentBody::Typing { state: TypingState::Start }, r#""kind":"typing",IDS,"state":"start""#),
        (ContentBody::Typing { state: TypingState::Stop }, r#""kind":"typing",IDS,"state":"stop""#),
        (
            ContentBody::ContactRequest {
                attestation: ATTESTATION.into(),
                attestation_signature: SIGNATURE.into(),
            },
            r#""kind":"contact_request",IDS,"envelope_id":"E","attestation":"A","attestation_signature":"G""#,
        ),
        (
            ContentBody::ContactAccept {
                request_id: TARGET.into(),
                attestation: ATTESTATION.into(),
                attestation_signature: SIGNATURE.into(),
            },
            r#""kind":"contact_accept",IDS,"envelope_id":"E","request_id":"T","attestation":"A","attestation_signature":"G""#,
        ),
        (
            ContentBody::ContactCancel { request_id: TARGET.into() },
            r#""kind":"contact_cancel",IDS,"envelope_id":"E","request_id":"T""#,
        ),
    ];
    for (body, fields) in cases {
        let content = v4(body);
        let json = encode_content(content.clone()).unwrap();
        let expected = format!(r#"{{"v":4,{fields}}}"#)
            .replace(
                "IDS",
                &format!(
                    r#""sender_account_id":"{SENDER}","sender_ed25519":"{SENDER_KEY}","recipient_account_id":"{RECIPIENT}","recipient_ed25519":"{RECIPIENT_KEY}""#
                ),
            )
            .replace(r#""E""#, &format!(r#""{ENVELOPE}""#))
            .replace(r#""M""#, &format!(r#""{CLIENT}""#))
            .replace(r#""T""#, &format!(r#""{TARGET}""#))
            .replace(r#""A""#, &serde_json::to_string(ATTESTATION).unwrap())
            .replace(r#""G""#, &format!(r#""{SIGNATURE}""#));
        assert_eq!(unpadded(&json), expected);
        assert_eq!(read(json).unwrap(), read_back(&content));
    }
}

#[test]
fn envelope_id_is_required_except_on_typing_where_it_is_forbidden() {
    assert!(is_invalid(encode_content(OutgoingContent { envelope_id: None, ..v4(text("x")) })));
    let no_id =
        OutgoingContent { envelope_id: None, ..v4(receipt(ReceiptStatus::Read, "2026-11-04T12:34:56Z")) };
    assert!(is_invalid(encode_content(no_id)));
    let typing_with_id = OutgoingContent {
        envelope_id: Some(ENVELOPE.into()),
        ..v4(ContentBody::Typing { state: TypingState::Start })
    };
    assert!(is_invalid(encode_content(typing_with_id)));

    // The same rules when read.
    assert!(is_invalid(read(v4_json(&format!(
        r#""kind":"typing","envelope_id":"{ENVELOPE}","state":"start""#
    )))));
    assert!(is_invalid(read(v4_json(&format!(
        r#""kind":"text","client_message_id":"{CLIENT}","body":"x""#
    )))));
    assert!(read(v4_json(r#""kind":"typing","state":"stop""#)).is_ok());
    assert!(read(v4_json(r#""kind":"typing","envelope_id":null,"state":"stop""#)).is_ok());
}

#[test]
fn ids_are_written_in_lower_case_and_read_only_in_lower_case() {
    let upper = "6F1C2A8E-0000-4000-8000-00000000ABCD";
    let lower = "6f1c2a8e-0000-4000-8000-00000000abcd";
    let content = OutgoingContent {
        sender_account_id: SENDER.to_uppercase(),
        sender_ed25519_key: SENDER_KEY.into(),
        recipient_account_id: RECIPIENT.to_uppercase(),
        recipient_ed25519_key: RECIPIENT_KEY.into(),
        envelope_id: Some(upper.into()),
        body: ContentBody::Text {
            client_message_id: upper.into(),
            body: "x".into(),
            reply_to_message_id: Some(upper.into()),
            reply_excerpt: None,
        },
    };
    let json = encode_content(content).unwrap();
    assert!(!json.contains("ABCD") && !json.contains("A1A1"));
    let got = decode_content(json.clone(), mailbox(lower)).unwrap();
    assert_eq!(got.envelope_id.as_deref(), Some(lower));
    assert_eq!(
        got.body,
        ContentBody::Text {
            client_message_id: lower.into(),
            body: "x".into(),
            reply_to_message_id: Some(lower.into()),
            reply_excerpt: None
        }
    );
    // Version 3 has one spelling: an id in upper case is refused when read.
    assert!(is_invalid(decode_content(json.replace(lower, upper), mailbox(lower))));
    assert!(is_invalid(decode_content(json.replacen(SENDER, &SENDER.to_uppercase(), 1), mailbox(lower))));

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
            is_invalid(encode_content(OutgoingContent { sender_account_id: bad.into(), ..v4(text("x")) })),
            "{bad:?}"
        );
        assert!(
            is_invalid(encode_content(OutgoingContent { recipient_account_id: bad.into(), ..v4(text("x")) })),
            "{bad:?}"
        );
        assert!(
            is_invalid(encode_content(OutgoingContent { envelope_id: Some(bad.into()), ..v4(text("x")) })),
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
            ContentBody::ContactCancel { request_id: bad.into() },
        ];
        for body in targets {
            assert!(is_invalid(encode_content(v4(body.clone()))), "{bad:?} in {body:?}");
        }
    }
}

#[test]
fn the_content_is_bound_to_its_element() {
    let json = encode_content(v4(text("Bonjour"))).unwrap();
    assert!(decode_content(json.clone(), mailbox(ENVELOPE)).is_ok());
    // Sent again by the server to someone else, or presented as coming from someone else.
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { my_account_id: OTHER.into(), ..mailbox(ENVELOPE) }
    )));
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { sender_account_id: OTHER.into(), ..mailbox(ENVELOPE) }
    )));
    // Under another envelope id.
    assert!(is_unbound(decode_content(json.clone(), mailbox(TARGET))));
    // Through the wrong channel, or a binding that does not fit its channel.
    assert!(is_unbound(decode_content(json.clone(), websocket())));
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { envelope_id: None, ..mailbox(ENVELOPE) }
    )));
    let typing = encode_content(v4(ContentBody::Typing { state: TypingState::Start })).unwrap();
    assert!(decode_content(typing.clone(), websocket()).is_ok());
    assert!(is_unbound(decode_content(typing.clone(), mailbox(ENVELOPE))));
    assert!(is_unbound(decode_content(
        typing.clone(),
        ContentBinding { envelope_id: Some(ENVELOPE.into()), ..websocket() }
    )));
    assert!(is_unbound(decode_content(
        typing,
        ContentBinding { my_account_id: OTHER.into(), ..websocket() }
    )));
    // A binding id in any other spelling than lower case binds nothing.
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { sender_account_id: SENDER.to_uppercase(), ..mailbox(ENVELOPE) }
    )));
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { my_account_id: "me".into(), ..mailbox(ENVELOPE) }
    )));
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { envelope_id: Some(ENVELOPE.to_uppercase()), ..mailbox(ENVELOPE) }
    )));
    // A legacy id given with a version 4 content changes nothing.
    assert!(decode_content(json, legacy(ENVELOPE, CONVERSATION)).is_ok());
}

#[test]
fn a_content_is_bound_to_both_identity_keys() {
    let json = encode_content(v4(text("Salut"))).unwrap();
    assert!(decode_content(json.clone(), mailbox(ENVELOPE)).is_ok());
    // The right account ids, but the element's sender has another identity key: the
    // account ids come from the server, the keys from identities the phone verified.
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { sender_ed25519_key: STRANGER_KEY.into(), ..mailbox(ENVELOPE) }
    )));
    // Written for another identity than mine.
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding { my_ed25519_key: STRANGER_KEY.into(), ..mailbox(ENVELOPE) }
    )));
    // The two keys swapped.
    assert!(is_unbound(decode_content(
        json.clone(),
        ContentBinding {
            sender_ed25519_key: RECIPIENT_KEY.into(),
            my_ed25519_key: SENDER_KEY.into(),
            ..mailbox(ENVELOPE)
        }
    )));
    // A binding key in any other spelling binds nothing: padded, too short, not base64.
    for bad in [format!("{SENDER_KEY}="), SENDER_KEY[..42].to_owned(), "!".repeat(43), String::new()] {
        assert!(is_unbound(decode_content(
            json.clone(),
            ContentBinding { sender_ed25519_key: bad.clone(), ..mailbox(ENVELOPE) }
        )));
        assert!(is_unbound(decode_content(
            json.clone(),
            ContentBinding { my_ed25519_key: bad, ..mailbox(ENVELOPE) }
        )));
    }
    // A typing signal is bound the same way.
    let typing = encode_content(v4(ContentBody::Typing { state: TypingState::Start })).unwrap();
    assert!(is_unbound(decode_content(
        typing,
        ContentBinding { sender_ed25519_key: STRANGER_KEY.into(), ..websocket() }
    )));
}

#[test]
fn a_content_is_written_only_with_two_well_formed_identity_keys() {
    for bad in [format!("{SENDER_KEY}="), SENDER_KEY[..42].to_owned(), "!".repeat(43), String::new()] {
        assert!(is_invalid(encode_content(OutgoingContent {
            sender_ed25519_key: bad.clone(),
            ..v4(text("Salut"))
        })));
        assert!(is_invalid(encode_content(OutgoingContent {
            recipient_ed25519_key: bad,
            ..v4(text("Salut"))
        })));
    }
}

#[test]
fn version_3_of_0_8_0_is_no_longer_read() {
    // What 0.8.0 wrote: the account ids, no identity key. Authentic, but not bound.
    let v3 = format!(
        r#"{{"v":3,"kind":"text","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}","envelope_id":"{ENVELOPE}","client_message_id":"{CLIENT}","body":"Salut"}}"#
    );
    assert!(is_unsupported(decode_content(v3, mailbox(ENVELOPE))));
}

#[test]
fn a_form_error_comes_before_a_binding_error() {
    let malformed = v4_json(r#""kind":"text","envelope_id":"x","client_message_id":"y","body":"z""#);
    assert!(is_invalid(decode_content(
        malformed,
        ContentBinding { my_account_id: OTHER.into(), ..mailbox(ENVELOPE) }
    )));
}

#[test]
fn version_2_is_read_only_with_the_old_conversation_id_of_this_contact() {
    let v2 = format!(
        r#"{{"v":2,"kind":"text","conversation_id":"{CONVERSATION}","envelope_id":"{ENVELOPE}","client_message_id":"{CLIENT}","body":"x"}}"#
    );
    let got = decode_content(v2.clone(), legacy(ENVELOPE, CONVERSATION)).unwrap();
    assert_eq!((got.version, got.envelope_id.as_deref()), (2, Some(ENVELOPE)));
    assert!(is_unbound(decode_content(v2.clone(), mailbox(ENVELOPE))));
    assert!(is_unbound(decode_content(v2.clone(), legacy(ENVELOPE, OTHER))));
    assert!(is_unbound(decode_content(v2.clone(), legacy(TARGET, CONVERSATION))));
    // An upper case conversation id in version 2 still matches, as version 2 always read it.
    let upper = v2.replace(CONVERSATION, &CONVERSATION.to_uppercase());
    assert!(decode_content(upper, legacy(ENVELOPE, CONVERSATION)).is_ok());
    // A legacy typing signal is refused on either channel.
    let typing = format!(r#"{{"v":2,"kind":"typing","conversation_id":"{CONVERSATION}","state":"start"}}"#);
    assert!(is_unbound(decode_content(
        typing.clone(),
        ContentBinding { legacy_conversation_id: Some(CONVERSATION.into()), ..websocket() }
    )));
    assert!(is_unbound(decode_content(typing, legacy(ENVELOPE, CONVERSATION))));
    // The contact kinds do not exist in version 2.
    assert!(is_unsupported(decode_content(
        format!(
            r#"{{"v":2,"kind":"contact_cancel","conversation_id":"{CONVERSATION}","envelope_id":"{ENVELOPE}","request_id":"{TARGET}"}}"#
        ),
        legacy(ENVELOPE, CONVERSATION)
    )));
}

#[test]
fn contact_kinds_check_their_form_only() {
    let request = |attestation: &str, signature: &str| {
        encode_content(v4(ContentBody::ContactRequest {
            attestation: attestation.into(),
            attestation_signature: signature.into(),
        }))
    };
    assert!(request(ATTESTATION, SIGNATURE).is_ok());
    // The module does not read the attestation: any text of 1 to 512 bytes passes here.
    assert!(request("x", SIGNATURE).is_ok());
    assert!(request(&"x".repeat(512), SIGNATURE).is_ok());
    assert!(is_invalid(request("", SIGNATURE)));
    assert!(is_invalid(request(&"x".repeat(513), SIGNATURE)));
    assert!(is_invalid(request(ATTESTATION, "")));
    // 32 bytes, a key, not a signature.
    assert!(is_invalid(request(ATTESTATION, "F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4")));
    assert!(is_invalid(request(ATTESTATION, &format!("1{SIGNATURE}"))));
    // Read: exactly their fields, and no alias anywhere.
    assert!(is_invalid(read(v4_json(&format!(
        r#""kind":"contact_request","envelope_id":"{ENVELOPE}","attestation":"x","attestation_signature":"{SIGNATURE}","alias":"alice""#
    )))));
    assert!(is_invalid(read(v4_json(&format!(
        r#""kind":"contact_accept","envelope_id":"{ENVELOPE}","attestation":"x","attestation_signature":"{SIGNATURE}""#
    )))));
    assert!(is_invalid(read(v4_json(&format!(r#""kind":"contact_cancel","envelope_id":"{ENVELOPE}""#)))));
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
        let json = encode_content(v4(receipt(ReceiptStatus::Delivered, good))).unwrap();
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
        assert!(is_invalid(encode_content(v4(receipt(ReceiptStatus::Read, bad)))), "{bad:?}");
    }
}

#[test]
fn text_limits_are_those_of_0_4_0() {
    // Body of a text or an edit: 1 to 4000 characters, not blank.
    assert!(encode_content(v4(text(&"é".repeat(4000)))).is_ok());
    assert!(is_invalid(encode_content(v4(text(&"é".repeat(4001))))));
    assert!(is_invalid(encode_content(v4(text("  ")))));
    assert!(is_invalid(encode_content(v4(text("")))));
    let edit = |body: &str| ContentBody::Edit {
        client_message_id: CLIENT.into(),
        edits_message_id: TARGET.into(),
        body: body.into(),
    };
    assert!(encode_content(v4(edit(&"é".repeat(4000)))).is_ok());
    assert!(is_invalid(encode_content(v4(edit(&"é".repeat(4001))))));
    assert!(is_invalid(encode_content(v4(edit(" ")))));

    // Reply excerpt: at most 200 characters.
    let quoted = |excerpt: &str| ContentBody::Text {
        client_message_id: CLIENT.into(),
        body: "x".into(),
        reply_to_message_id: Some(TARGET.into()),
        reply_excerpt: Some(excerpt.into()),
    };
    assert!(encode_content(v4(quoted(&"é".repeat(200)))).is_ok());
    assert!(is_invalid(encode_content(v4(quoted(&"é".repeat(201))))));

    // Reaction: one emoji of 1 to 16 code points, without white space.
    let reaction = |body: &str| ContentBody::Reaction {
        client_message_id: CLIENT.into(),
        reacts_to_message_id: TARGET.into(),
        body: body.into(),
    };
    assert!(encode_content(v4(reaction("👨‍👩‍👧‍👦"))).is_ok());
    assert!(encode_content(v4(reaction(&"x".repeat(16)))).is_ok());
    assert!(is_invalid(encode_content(v4(reaction(&"x".repeat(17))))));
    assert!(is_invalid(encode_content(v4(reaction("")))));
    assert!(is_invalid(encode_content(v4(reaction("👍 ")))));

    // Payment comment: 1 to 500 characters.
    let payment = |body: &str| ContentBody::Payment { client_message_id: CLIENT.into(), body: body.into() };
    assert!(encode_content(v4(payment(&"é".repeat(500)))).is_ok());
    assert!(is_invalid(encode_content(v4(payment(&"é".repeat(501))))));
    assert!(is_invalid(encode_content(v4(payment(" ")))));
}

#[test]
fn unknown_kind_or_newer_version_is_unsupported_never_another_kind() {
    assert!(is_unsupported(read(v4_json(&format!(
        r#""kind":"poll","envelope_id":"{ENVELOPE}","question":"?""#
    )))));
    assert!(is_unsupported(read(format!(
        r#"{{"v":5,"kind":"text","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}","envelope_id":"{ENVELOPE}","client_message_id":"{CLIENT}","body":"x"}}"#
    ))));
    assert!(is_unsupported(read(r#"{"v":42}"#.into())));
    // A version 1 kind unknown to 0.4.0 used to fall back on nothing either; now it is said so.
    let v1 = |kind: &str| {
        decode_content(
            format!(
                r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}","kind":"{kind}"}}"#
            ),
            legacy(ENVELOPE, CONVERSATION),
        )
    };
    assert!(is_unsupported(v1("receipt")));
    assert!(is_unsupported(v1("typing")));
}

#[test]
fn malformed_content_is_invalid() {
    let fields = |rest: &str| read(v4_json(&format!(r#""envelope_id":"{ENVELOPE}",{rest}"#)));
    // An unknown field: a later addition goes through a new version.
    assert!(is_invalid(fields(&format!(
        r#""kind":"text","client_message_id":"{CLIENT}","body":"x","comment":"y""#
    ))));
    assert!(is_invalid(fields(&format!(
        r#""kind":"delete","client_message_id":"{CLIENT}","deletes_message_id":"{TARGET}","body":"x""#
    ))));
    assert!(is_invalid(fields(&format!(
        r#""kind":"receipt","status":"read","up_to_envelope_id":"{TARGET}","up_to_created_at":"2026-11-04T12:34:56Z","client_message_id":"{CLIENT}""#
    ))));
    // The version 2 field has no place in version 4.
    assert!(is_invalid(fields(&format!(
        r#""kind":"text","conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}","body":"x""#
    ))));
    // A field the kind needs is missing, or has the wrong type or value.
    assert!(is_invalid(fields(&format!(r#""kind":"edit","client_message_id":"{CLIENT}","body":"x""#))));
    assert!(is_invalid(fields(&format!(
        r#""kind":"receipt","status":"seen","up_to_envelope_id":"{TARGET}","up_to_created_at":"2026-11-04T12:34:56Z""#
    ))));
    assert!(is_invalid(fields(r#""kind":"receipt","status":"read""#)));
    assert!(is_invalid(fields(&format!(r#""kind":"text","client_message_id":"{CLIENT}","body":7"#))));
    assert!(is_invalid(fields(r#""client_message_id":"x","body":"x""#)));
    assert!(is_invalid(read(v4_json(r#""kind":"typing","state":"paused""#))));
    // Without the sender or the recipient, or without one of their identity keys.
    assert!(is_invalid(read(format!(
        r#"{{"v":4,"kind":"typing","sender_account_id":"{SENDER}","sender_ed25519":"{SENDER_KEY}","state":"start"}}"#
    ))));
    assert!(is_invalid(read(format!(
        r#"{{"v":4,"kind":"typing","recipient_account_id":"{RECIPIENT}","recipient_ed25519":"{RECIPIENT_KEY}","state":"start"}}"#
    ))));
    assert!(is_invalid(read(format!(
        r#"{{"v":4,"kind":"typing","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}","recipient_ed25519":"{RECIPIENT_KEY}","state":"start"}}"#
    ))));
    assert!(is_invalid(read(format!(
        r#"{{"v":4,"kind":"typing","sender_account_id":"{SENDER}","sender_ed25519":"{SENDER_KEY}","recipient_account_id":"{RECIPIENT}","state":"start"}}"#
    ))));
    // An identity key written with padding is not the one spelling.
    assert!(is_invalid(read(format!(
        r#"{{"v":4,"kind":"typing","sender_account_id":"{SENDER}","sender_ed25519":"{SENDER_KEY}=","recipient_account_id":"{RECIPIENT}","recipient_ed25519":"{RECIPIENT_KEY}","state":"start"}}"#
    ))));
    assert!(is_invalid(read(r#"{"kind":"text"}"#.into())));
    assert!(is_invalid(read(r#"{"v":0,"kind":"text"}"#.into())));
    assert!(is_invalid(read(r#"{"v":"3","kind":"text"}"#.into())));
    assert!(is_invalid(read(r#"[3]"#.into())));
    assert!(is_invalid(read("not json".into())));
    // The padding is ignored when read.
    assert!(read(v4_json(r#""kind":"typing","state":"start","pad":"   ""#)).is_ok());
}

#[test]
fn version_1_is_read_with_the_rules_of_0_4_0() {
    let v1 = |fields: &str| {
        decode_content(
            format!(
                r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}",{fields}}}"#
            ),
            legacy(ENVELOPE, CONVERSATION),
        )
    };
    // A text keeps its excerpt but has no link to the quoted message.
    let quoted = v1(r#""kind":"text","body":"Oui","reply_excerpt":"Dimanche ?""#).unwrap();
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
        v1(r#""kind":"payment","comment":"Pour le marché""#).unwrap().body,
        ContentBody::Payment { client_message_id: CLIENT.into(), body: "Pour le marché".into() }
    );
    assert_eq!(
        v1(r#""kind":"payment""#).unwrap().body,
        ContentBody::Payment { client_message_id: CLIENT.into(), body: String::new() }
    );
    // Unknown fields are ignored in version 1, as 0.4.0 did; ids come out in lower case.
    assert!(v1(r#""kind":"text","body":"x","later":true"#).is_ok());
    let upper = format!(
        r#"{{"v":1,"conversation_id":"{}","client_message_id":"B","kind":"text","body":"x"}}"#,
        CONVERSATION.to_uppercase()
    );
    assert!(decode_content(upper, legacy(ENVELOPE, CONVERSATION)).is_ok());
    // Without the old conversation id of this contact, nothing is read.
    let plain = format!(
        r#"{{"v":1,"conversation_id":"{CONVERSATION}","client_message_id":"{CLIENT}","kind":"text","body":"x"}}"#
    );
    assert!(is_unbound(decode_content(plain.clone(), mailbox(ENVELOPE))));
    assert!(is_unbound(decode_content(plain, legacy(ENVELOPE, OTHER))));
    // The rules of each kind still hold.
    assert!(is_invalid(v1(r#""kind":"text","body":"x","edits_message_id":"c""#)));
    assert!(is_invalid(v1(r#""kind":"edit","body":"x""#)));
    assert!(is_invalid(v1(r#""kind":"reaction","body":"👍""#)));
    assert!(is_invalid(v1(r#""kind":"reaction","body":"👍 👍","reacts_to_message_id":"c""#)));
    assert!(is_invalid(v1(r#""kind":"reaction_remove","body":"👍","reacts_to_message_id":"c""#)));
    assert!(is_invalid(v1(r#""kind":"delete""#)));
    assert!(is_invalid(v1(r#""kind":"text","body":"x","deletes_message_id":"d""#)));
    assert!(is_invalid(v1(r#""kind":"payment","body":"x""#)));
    assert!(is_invalid(v1(&format!(r#""kind":"payment","comment":"{}""#, "é".repeat(501)))));
    assert!(is_invalid(v1(r#""kind":"text","body":" ""#)));
    assert!(is_invalid(decode_content(
        r#"{"v":1,"conversation_id":"","client_message_id":"b","kind":"text","body":"x"}"#.into(),
        legacy(ENVELOPE, CONVERSATION)
    )));
}

#[test]
fn contents_are_padded_to_their_bucket() {
    let size = |body: ContentBody| encode_content(v4(body)).unwrap().len();
    // Since version 4 nothing fits 256 bytes any more: the two identity keys add about 130.
    // A typing signal, start or stop, is at 512 bytes.
    for state in [TypingState::Start, TypingState::Stop] {
        assert_eq!(size(ContentBody::Typing { state }), 512);
    }
    // So is a receipt, from the shortest to the longest.
    assert_eq!(size(receipt(ReceiptStatus::Read, "2026-11-04T12:34:56Z")), 512);
    assert_eq!(size(receipt(ReceiptStatus::Delivered, "2026-11-04T12:34:56.123456789+01:00")), 512);
    // "Oui", a short sentence, a text of 100 bytes, a receipt and a typing signal all look
    // the same; a text of more than about 110 bytes moves to 1024.
    assert_eq!(size(text("Oui")), 512);
    assert_eq!(size(text("Je serai là vers midi")), 512);
    assert_eq!(size(text(&"a".repeat(100))), 512);
    assert_eq!(size(text(&"a".repeat(110))), 512);
    assert_eq!(size(text(&"a".repeat(111))), 1024);
    // The contact kinds, with a real attestation.
    let request = ContentBody::ContactRequest {
        attestation: ATTESTATION.into(),
        attestation_signature: SIGNATURE.into(),
    };
    assert_eq!(size(request), 1024);
    let accept = ContentBody::ContactAccept {
        request_id: TARGET.into(),
        attestation: ATTESTATION.into(),
        attestation_signature: SIGNATURE.into(),
    };
    assert_eq!(size(accept), 1024);
    assert_eq!(size(ContentBody::ContactCancel { request_id: TARGET.into() }), 512);
    // The longest text allowed: 4000 characters of 4 bytes are 16000 bytes, 18 too many for
    // 16384 with the rest of a version 4 content. 3995 of them still fit.
    assert_eq!(size(text(&"😀".repeat(3995))), 16384);
    assert_eq!(size(text(&"a".repeat(4000))), 8192);
    let largest = encode_content(v4(text(&"😀".repeat(4000)))).unwrap();
    assert_eq!(largest.len(), 32768);
    assert_eq!(read(largest).unwrap().body, text(&"😀".repeat(4000)));
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
    let typing = encode_content(v4(ContentBody::Typing { state: TypingState::Start })).unwrap();
    let sealed =
        alice.encrypt_for(bob.identity_keys(), Some(alice_session), None, typing.clone(), key()).unwrap();
    assert_eq!(sealed.envelope.olm_type, 1);
    assert!(sealed.envelope.ciphertext.len() < 2048, "{}", sealed.envelope.ciphertext.len());
    let got = bob.decrypt_from(alice.identity_keys(), vec![bob_session], sealed.envelope, key()).unwrap();
    assert_eq!(
        decode_content(got.plaintext, websocket()).unwrap().body,
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
