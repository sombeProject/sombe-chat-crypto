//! Writes vectors/v2.json (since 0.5.0; wallet card and payment kinds since 0.6.0): the
//! padded version 2 content of every kind, how
//! each version 1 kind is read, and contents that must be refused. Contents carry no
//! randomness, so running it again gives the same file; tests/vectors.rs checks it.
//! vectors/v1.json (identity, keys, a first message, safety number, version 1 contents)
//! was written by 0.4.0 and stays as it is: version 1 content is no longer written, so it
//! cannot be generated again. Never use these ids for anything real.

use serde_json::{json, Value};
use sombe_chat_crypto::{decode_content, encode_content, Content, ContentBody, ReceiptStatus, TypingState};
use vodozemac::Ed25519SecretKey;

const CONVERSATION: &str = "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01";
const TARGET: &str = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34";
const TEXT_ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
/// The test wallet of vectors/v1.json, and a test account key: never use them for anything real.
const WALLET_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31,
];
const ACCOUNT_SEED: [u8; 32] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, 62, 63,
];
const REQUEST: &str = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89";
/// Native SOL, as an envelope always names it.
const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
/// USDC on mainnet.
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TX_SIGNATURE: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

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
        ("wallet_card", v2(Some("38a5def1-cdaf-4f7b-9ebc-4a5b6c7d8e90"), wallet_card())),
        (
            "wallet_card_request",
            v2(Some("49b6ef02-debf-4a8c-8fcd-5b6c7d8e9fa1"), ContentBody::WalletCardRequest),
        ),
        (
            "payment_request",
            v2(
                Some("5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2"),
                ContentBody::PaymentRequest {
                    request_id: REQUEST.into(),
                    amount_base_units: 1_500_000_000,
                    mint: SOL_MINT.into(),
                    decimals: 9,
                    note: Some("Pour le marché".into()),
                },
            ),
        ),
        (
            "payment_request_without_note",
            v2(
                Some("6bd80124-f0d1-4cae-8bef-7d8e9fa0b1c3"),
                ContentBody::PaymentRequest {
                    request_id: REQUEST.into(),
                    amount_base_units: 9_223_372_036_854_775_807,
                    mint: USDC_MINT.into(),
                    decimals: 6,
                    note: None,
                },
            ),
        ),
        (
            "payment_sent",
            v2(
                Some("7ce91235-01e2-4dbf-9cf0-8e9fa0b1c2d4"),
                ContentBody::PaymentSent {
                    request_id: Some(REQUEST.into()),
                    signature: TX_SIGNATURE.into(),
                    amount_base_units: 1_500_000_000,
                    mint: SOL_MINT.into(),
                    decimals: 9,
                    note: Some("Pour le marché".into()),
                },
            ),
        ),
        (
            "payment_sent_direct",
            v2(
                Some("8dfa2346-12f3-4ec0-8d01-9fa0b1c2d3e5"),
                ContentBody::PaymentSent {
                    request_id: None,
                    signature: TX_SIGNATURE.into(),
                    amount_base_units: 25_000_000,
                    mint: USDC_MINT.into(),
                    decimals: 6,
                    note: None,
                },
            ),
        ),
        (
            "payment_request_declined",
            v2(
                Some("9e0b3457-2304-4fd1-9e12-a0b1c2d3e4f6"),
                ContentBody::PaymentRequestDeclined { request_id: REQUEST.into() },
            ),
        ),
        (
            "payment_request_cancelled",
            v2(
                Some("af1c4568-3415-4ae2-8f23-b1c2d3e4f5a7"),
                ContentBody::PaymentRequestCancelled { request_id: REQUEST.into() },
            ),
        ),
    ];
    let mut v2_vectors = serde_json::Map::new();
    for (name, content) in contents {
        let plaintext = encode_content(content.clone()).unwrap();
        assert_eq!(decode_content(plaintext.clone()).unwrap(), content);
        v2_vectors.insert(name.into(), json!({ "bytes": plaintext.len(), "plaintext": plaintext }));
    }
    // The card text the wallet signed, so another implementation can check the signature.
    let ContentBody::WalletCard { wallet_address, account_public_key, .. } = wallet_card() else {
        unreachable!("a wallet card")
    };
    let card_text = format!("SOMBE wallet card v1\nwallet:{wallet_address}\naccount:{account_public_key}");
    v2_vectors["wallet_card"]["signed_text"] = Value::from(card_text);

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
        // Since 0.6.0: an amount as a JSON number, with a leading zero, zero, or above i64::MAX.
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":1500000000,"mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"01500000000","mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"0","mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"9223372036854775808","mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        // A mint that is not 32 bytes, decimals above 255, a blank note, a request without its id.
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"1500000000","mint":"So1111111111111111111111111111111111111111","decimals":9}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"1500000000","mint":"So11111111111111111111111111111111111111112","decimals":256}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89","amount_base_units":"1500000000","mint":"So11111111111111111111111111111111111111112","decimals":9,"note":"   "}"#,
        r#"{"v":2,"kind":"payment_request","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"5ac7f013-efc0-4b9d-9ade-6c7d8e9fa0b2","amount_base_units":"1500000000","mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        // A payment sent whose signature is not 64 bytes, a refusal with a client_message_id.
        r#"{"v":2,"kind":"payment_sent","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"7ce91235-01e2-4dbf-9cf0-8e9fa0b1c2d4","request_id":null,"signature":"So11111111111111111111111111111111111111112","amount_base_units":"1500000000","mint":"So11111111111111111111111111111111111111112","decimals":9}"#,
        r#"{"v":2,"kind":"payment_request_declined","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"9e0b3457-2304-4fd1-9e12-a0b1c2d3e4f6","client_message_id":"1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12","request_id":"27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89"}"#,
        // A wallet card whose address is not base58 (0 is not in the alphabet).
        r#"{"v":2,"kind":"wallet_card","conversation_id":"0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01","envelope_id":"38a5def1-cdaf-4f7b-9ebc-4a5b6c7d8e90","wallet_address":"0Ae4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF","account_public_key":"FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF","wallet_signature":"5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"}"#,
    ];

    let vectors = json!({
        "description": "SOMBE chat content test vectors, content version 2 (sombe-chat-crypto 0.6.0). Test ids and test keys only.",
        "v2": v2_vectors,
        "v1_read": v1_vectors,
        "unsupported_content": unsupported,
        "invalid_content": invalid,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v2.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

/// The test wallet's card for the test account key, signed by the wallet.
fn wallet_card() -> ContentBody {
    let wallet = Ed25519SecretKey::from_slice(&WALLET_SEED);
    let account = Ed25519SecretKey::from_slice(&ACCOUNT_SEED);
    let wallet_address = bs58::encode(wallet.public_key().as_bytes()).into_string();
    let account_public_key = bs58::encode(account.public_key().as_bytes()).into_string();
    let text = format!("SOMBE wallet card v1\nwallet:{wallet_address}\naccount:{account_public_key}");
    let wallet_signature = bs58::encode(wallet.sign(text.as_bytes()).to_bytes()).into_string();
    ContentBody::WalletCard { wallet_address, account_public_key, wallet_signature }
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
        _ => unreachable!("never in version 1"),
    };
    json!({
        "version": content.version,
        "conversation_id": content.conversation_id,
        "envelope_id": content.envelope_id,
        "body": body,
    })
}
