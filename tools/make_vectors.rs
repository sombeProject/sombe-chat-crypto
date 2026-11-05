//! Writes vectors/v2.json (since 0.5.0): the padded version 2 content of every kind, how
//! each version 1 kind is read, and contents that must be refused. Contents carry no
//! randomness, so running it again gives the same file; tests/vectors.rs checks it.
//! vectors/v1.json (identity, keys, a first message, safety number, version 1 contents)
//! was written by 0.4.0 and stays as it is: version 1 content is no longer written, so it
//! cannot be generated again. Never use these ids for anything real.

use serde_json::{json, Value};
use sombe_chat_crypto::{decode_content, encode_content, Content, ContentBody, ReceiptStatus, TypingState};

const CONVERSATION: &str = "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01";
const TARGET: &str = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34";
const TEXT_ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";

fn v2(envelope_id: Option<&str>, body: ContentBody) -> Content {
    Content {
        version: 2,
        conversation_id: CONVERSATION.into(),
        envelope_id: envelope_id.map(str::to_owned),
        body,
    }
}

fn main() {
    let contents: Vec<(&str, Content)> = vec![
        (
            "text",
            v2(
                Some(TEXT_ENVELOPE),
                ContentBody::Text {
                    client_message_id: "1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12".into(),
                    body: "Salut ! Tu es rentré ?".into(),
                    reply_to_message_id: None,
                    reply_excerpt: None,
                },
            ),
        ),
        (
            "text_reply",
            v2(
                Some("8d5a2f4c-1e9b-4a6c-8f0d-3b4c5d6e7f89"),
                ContentBody::Text {
                    client_message_id: "9e6b3a5d-2f0c-4b7d-9a1e-4c5d6e7f8a90".into(),
                    body: "Oui, à l’instant".into(),
                    reply_to_message_id: Some(TARGET.into()),
                    reply_excerpt: Some("Salut ! Tu es rentré ?".into()),
                },
            ),
        ),
        (
            "edit",
            v2(
                Some("af7c4b6e-3a1d-4c8e-8b2f-5d6e7f8a9b01"),
                ContentBody::Edit {
                    client_message_id: "2d9a6f8c-5e3b-4a0c-9f4d-7b8c9e0f1a23".into(),
                    edits_message_id: TARGET.into(),
                    body: "Salut ! Tu es rentrée ?".into(),
                },
            ),
        ),
        (
            "reaction",
            v2(
                Some("b08d5c7f-4b2e-4d9f-9c3a-6e7f8a9b0c12"),
                ContentBody::Reaction {
                    client_message_id: "4f1c8b0e-7a5d-4c2e-9b6f-9d0e1f2a3c45".into(),
                    reacts_to_message_id: TARGET.into(),
                    body: "❤️".into(),
                },
            ),
        ),
        (
            "reaction_remove",
            v2(
                Some("c19e6d8a-5c3f-4e0a-8d4b-7f8a9b0c1d23"),
                ContentBody::ReactionRemove {
                    client_message_id: "5a2d9c1f-8b6e-4d3f-8c7a-0e1f2a3b4d56".into(),
                    reacts_to_message_id: TARGET.into(),
                },
            ),
        ),
        (
            "delete",
            v2(
                Some("d2af7e9b-6d4a-4f1b-9e5c-8a9b0c1d2e34"),
                ContentBody::Delete {
                    client_message_id: "6b3e0d2a-9c7f-4e4a-8d8b-1f2a3b4c5e67".into(),
                    deletes_message_id: TARGET.into(),
                },
            ),
        ),
        (
            "payment",
            v2(
                Some("e3b08fac-7e5b-4a2c-8f6d-9b0c1d2e3f45"),
                ContentBody::Payment {
                    client_message_id: "f4c19abd-8f6c-4b3d-9a7e-0c1d2e3f4a56".into(),
                    body: "Pour le marché".into(),
                },
            ),
        ),
        (
            "receipt_delivered",
            v2(
                Some("05d2abce-9a7d-4c4e-8b8f-1d2e3f4a5b67"),
                ContentBody::Receipt {
                    status: ReceiptStatus::Delivered,
                    up_to_envelope_id: TEXT_ENVELOPE.into(),
                    up_to_created_at: "2026-11-04T12:34:56.789Z".into(),
                },
            ),
        ),
        (
            "receipt_read",
            v2(
                Some("16e3bcdf-ab8e-4d5f-9c9a-2e3f4a5b6c78"),
                ContentBody::Receipt {
                    status: ReceiptStatus::Read,
                    up_to_envelope_id: TEXT_ENVELOPE.into(),
                    up_to_created_at: "2026-11-04T12:34:56Z".into(),
                },
            ),
        ),
        ("typing_start", v2(None, ContentBody::Typing { state: TypingState::Start })),
        ("typing_stop", v2(None, ContentBody::Typing { state: TypingState::Stop })),
    ];
    let mut v2_vectors = serde_json::Map::new();
    for (name, content) in contents {
        let plaintext = encode_content(content.clone()).unwrap();
        assert_eq!(decode_content(plaintext.clone()).unwrap(), content);
        v2_vectors.insert(name.into(), json!({ "bytes": plaintext.len(), "plaintext": plaintext }));
    }

    // Version 1 as phones up to 0.4.0 wrote it: some ids in upper case come out in lower
    // case, and an unknown field is ignored, as 0.4.0 did.
    let v1_inputs = [
        (
            "text",
            r#"{"v":1,"conversation_id":"0B7E4D6A-3C1F-4E8A-9D2B-5F6A7C8E9D01","client_message_id":"1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12","kind":"text","body":"Salut ! Tu es rentré ?","reply_excerpt":"Dimanche à midi","pad":"  "}"#,
        ),
        (
            "payment",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"f4c19abd-8f6c-4b3d-9a7e-0c1d2e3f4a56","kind":"payment","comment":"Pour le marché"}"#,
        ),
        (
            "payment_without_comment",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"f4c19abd-8f6c-4b3d-9a7e-0c1d2e3f4a56","kind":"payment"}"#,
        ),
        (
            "edit",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"2d9a6f8c-5e3b-4a0c-9f4d-7b8c9e0f1a23","kind":"edit","body":"Salut ! Tu es rentrée ?","edits_message_id":"3E0B7A9D-6F4C-4B1D-8A5E-8C9D0E1F2B34"}"#,
        ),
        (
            "reaction",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"4f1c8b0e-7a5d-4c2e-9b6f-9d0e1f2a3c45","kind":"reaction","body":"❤️","reacts_to_message_id":"3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34","later_field":1}"#,
        ),
        (
            "reaction_remove",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"5a2d9c1f-8b6e-4d3f-8c7a-0e1f2a3b4d56","kind":"reaction_remove","reacts_to_message_id":"3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34"}"#,
        ),
        (
            "delete",
            r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"6b3e0d2a-9c7f-4e4a-8d8b-1f2a3b4c5e67","kind":"delete","deletes_message_id":"3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34"}"#,
        ),
    ];
    let mut v1_vectors = serde_json::Map::new();
    for (name, input) in v1_inputs {
        let read = decode_content(input.into()).unwrap();
        v1_vectors.insert(name.into(), json!({ "plaintext": input, "read": describe(&read) }));
    }

    // A kind or a version this module does not know: UnsupportedContent, never another kind.
    let unsupported = [
        r#"{"v":3,"kind":"text","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01"}"#,
        r#"{"v":2,"kind":"poll","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78"}"#,
        r#"{"v":1,"conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","client_message_id":"1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12","kind":"poll"}"#,
    ];
    // A known kind with a wrong shape: InvalidContent.
    let invalid = [
        r#"{"v":2,"kind":"typing","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78","state":"start"}"#,
        r#"{"v":2,"kind":"receipt","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","status":"read","up_to_envelope_id":"7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78","up_to_created_at":"2026-11-04T12:34:56Z"}"#,
        r#"{"v":2,"kind":"delete","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"d2af7e9b-6d4a-4f1b-9e5c-8a9b0c1d2e34","client_message_id":"6b3e0d2a-9c7f-4e4a-8d8b-1f2a3b4c5e67","deletes_message_id":"3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34","later_field":1}"#,
        r#"{"v":2,"kind":"receipt","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"05d2abce-9a7d-4c4e-8b8f-1d2e3f4a5b67","status":"read","up_to_envelope_id":"7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78","up_to_created_at":"2026-11-04T12:34:56"}"#,
        r#"{"v":2,"kind":"text","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"not-a-uuid","client_message_id":"1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12","body":"x"}"#,
    ];

    let vectors = json!({
        "description": "SOMBE chat content test vectors, content version 2 (sombe-chat-crypto 0.5.0). Test ids only.",
        "v2": v2_vectors,
        "v1_read": v1_vectors,
        "unsupported_content": unsupported,
        "invalid_content": invalid,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v2.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

/// The decoded content as JSON, so another implementation can compare it field by field.
pub fn describe(content: &Content) -> Value {
    let body = match &content.body {
        ContentBody::Text { client_message_id, body, reply_to_message_id, reply_excerpt } => json!({
            "variant": "Text", "client_message_id": client_message_id, "body": body,
            "reply_to_message_id": reply_to_message_id, "reply_excerpt": reply_excerpt,
        }),
        ContentBody::Edit { client_message_id, edits_message_id, body } => json!({
            "variant": "Edit", "client_message_id": client_message_id,
            "edits_message_id": edits_message_id, "body": body,
        }),
        ContentBody::Reaction { client_message_id, reacts_to_message_id, body } => json!({
            "variant": "Reaction", "client_message_id": client_message_id,
            "reacts_to_message_id": reacts_to_message_id, "body": body,
        }),
        ContentBody::ReactionRemove { client_message_id, reacts_to_message_id } => json!({
            "variant": "ReactionRemove", "client_message_id": client_message_id,
            "reacts_to_message_id": reacts_to_message_id,
        }),
        ContentBody::Delete { client_message_id, deletes_message_id } => json!({
            "variant": "Delete", "client_message_id": client_message_id,
            "deletes_message_id": deletes_message_id,
        }),
        ContentBody::Payment { client_message_id, body } => json!({
            "variant": "Payment", "client_message_id": client_message_id, "body": body,
        }),
        ContentBody::Receipt { .. } | ContentBody::Typing { .. } => unreachable!("never in version 1"),
    };
    json!({
        "version": content.version,
        "conversation_id": content.conversation_id,
        "envelope_id": content.envelope_id,
        "body": body,
    })
}
