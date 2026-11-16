//! Writes vectors/v5.json (since 0.8.1): the version 4 content of the kinds the app sends
//! most, how each is bound to its element (channel, envelope id, account ids and identity
//! keys), the contents and bindings that must be refused as `UnboundContent`, a version 2
//! content read with its old conversation id, and a version 3 content of 0.8.0, which is no
//! longer read. Running it again gives the same file; tests/content_vectors.rs checks it.
//!
//! vectors/v1.json (0.4.0), vectors/v2.json (content version 2, 0.5.0 and 0.6.0),
//! vectors/v3.json (the account key, 0.7.0) and vectors/v4.json (the alias attestation and
//! content version 3, 0.8.0) stay as they are: the module writes only content version 4,
//! so their contents cannot be written again, and the attestations of v4.json are still
//! checked as they are by tests/attestation.rs. Their generators are in the history of
//! this file. Never use these ids, seeds or keys for anything real.

use serde_json::{json, Value};
use sombe_chat_crypto::{
    decode_content, encode_content, prove_rotation, AccountRotationContent, ChatCryptoError, ContentBinding,
    ContentBody, ContentChannel, OutgoingContent, ReceiptStatus, TypingState,
};
use vodozemac::Ed25519SecretKey;

/// The test wallet seed, whose rotation proof an `account_rotation` carries.
const WALLET_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31,
];
/// The seeds of the test identities' ed25519 keys: the sender, the recipient, a stranger.
const SENDER_KEY_SEED: [u8; 32] = [0xa1; 32];
const RECIPIENT_KEY_SEED: [u8; 32] = [0xb2; 32];
const STRANGER_KEY_SEED: [u8; 32] = [0xc3; 32];

fn main() {
    let v4: Value = serde_json::from_str(include_str!("../vectors/v4.json")).unwrap();
    let attestation = s_of(&v4["server_signs"]["text"]);
    let attestation_signature = s_of(&v4["server_signs"]["signature"]);
    let version_3 = s_of(&v4["content_v3"]["bound"]["text"]["plaintext"]);

    let vectors = json!({
        "description": "SOMBE test vectors of sombe-chat-crypto 0.8.1: content version 4 with its binding (content_v4: bound, unbound, legacy_read, version_3_refused). A content names the account ids and the ed25519 identity keys of its sender and its recipient; decode_content refuses any that differs from the binding. Test seeds and test keys only: never use them for anything real. Identity keys are Ed25519 public keys, base64 without padding.",
        "identity_keys": {
            "sender": {"seed_hex": hex(&SENDER_KEY_SEED), "ed25519": identity_key(&SENDER_KEY_SEED)},
            "recipient": {"seed_hex": hex(&RECIPIENT_KEY_SEED), "ed25519": identity_key(&RECIPIENT_KEY_SEED)},
            "stranger": {"seed_hex": hex(&STRANGER_KEY_SEED), "ed25519": identity_key(&STRANGER_KEY_SEED)},
        },
        "content_v4": content_vectors(&attestation, &attestation_signature, &version_3),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v5.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The ed25519 public key of a seed, as an identity writes it: base64 without padding.
fn identity_key(seed: &[u8; 32]) -> String {
    Ed25519SecretKey::from_slice(seed).public_key().to_base64()
}

const SENDER: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
const RECIPIENT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const STRANGER: &str = "c3c3c3c3-0000-4000-8000-0000000000c3";
const CONTENT_ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
const CONTENT_TARGET: &str = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34";
const CONTENT_CLIENT: &str = "1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12";
const CONTENT_REQUEST: &str = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89";
const OLD_CONVERSATION: &str = "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01";

fn binding_json(b: &ContentBinding) -> Value {
    json!({
        "channel": match b.channel { ContentChannel::Mailbox => "mailbox", ContentChannel::Websocket => "websocket" },
        "envelope_id": b.envelope_id,
        "sender_account_id": b.sender_account_id,
        "sender_ed25519_key": b.sender_ed25519_key,
        "my_account_id": b.my_account_id,
        "my_ed25519_key": b.my_ed25519_key,
        "legacy_conversation_id": b.legacy_conversation_id,
    })
}

/// Every version 4 kind the app sends most, bound to its element; then contents that
/// must be refused as `UnboundContent`, a version 2 content of vectors/v2.json read with
/// and without the old conversation id, and a version 3 content of vectors/v4.json refused.
fn content_vectors(attestation: &str, attestation_signature: &str, version_3: &str) -> Value {
    let (sender_key, recipient_key, stranger_key) =
        (identity_key(&SENDER_KEY_SEED), identity_key(&RECIPIENT_KEY_SEED), identity_key(&STRANGER_KEY_SEED));
    let mailbox = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(CONTENT_ENVELOPE.into()),
        sender_account_id: SENDER.into(),
        sender_ed25519_key: sender_key.clone(),
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: recipient_key.clone(),
        legacy_conversation_id: None,
    };
    let websocket =
        ContentBinding { channel: ContentChannel::Websocket, envelope_id: None, ..mailbox.clone() };
    let proven = prove_rotation(WALLET_SEED.to_vec(), 1, 2).unwrap();
    let kinds: Vec<(&str, ContentBody)> = vec![
        (
            "text",
            ContentBody::Text {
                client_message_id: CONTENT_CLIENT.into(),
                body: "Salut ! Tu es rentré ?".into(),
                reply_to_message_id: Some(CONTENT_TARGET.into()),
                reply_excerpt: Some("Dimanche à midi".into()),
            },
        ),
        ("typing_start", ContentBody::Typing { state: TypingState::Start }),
        (
            "receipt_read",
            ContentBody::Receipt {
                status: ReceiptStatus::Read,
                up_to_envelope_id: CONTENT_TARGET.into(),
                up_to_created_at: "2026-11-16T12:34:56.789Z".into(),
            },
        ),
        (
            "payment_request",
            ContentBody::PaymentRequest {
                request_id: CONTENT_REQUEST.into(),
                amount_base_units: 1_500_000_000,
                mint: "So11111111111111111111111111111111111111112".into(),
                decimals: 9,
                note: Some("Pour le marché".into()),
            },
        ),
        (
            "account_rotation",
            ContentBody::AccountRotation {
                rotation: AccountRotationContent {
                    old_account_public_key: proven.proof.old_account_public_key.clone(),
                    new_account_public_key: proven.proof.new_account_public_key.clone(),
                    generation: proven.proof.generation,
                    old_signature: proven.proof.old_signature.clone(),
                    new_signature: proven.proof.new_signature.clone(),
                    wallet_address: proven.card.wallet_address.clone(),
                    wallet_signature: proven.card.wallet_signature.clone(),
                },
            },
        ),
        (
            "contact_request",
            ContentBody::ContactRequest {
                attestation: attestation.into(),
                attestation_signature: attestation_signature.into(),
            },
        ),
        (
            "contact_accept",
            ContentBody::ContactAccept {
                request_id: CONTENT_REQUEST.into(),
                attestation: attestation.into(),
                attestation_signature: attestation_signature.into(),
            },
        ),
        ("contact_cancel", ContentBody::ContactCancel { request_id: CONTENT_REQUEST.into() }),
    ];
    let mut bound = serde_json::Map::new();
    let mut text_plaintext = String::new();
    for (name, body) in kinds {
        let typing = matches!(body, ContentBody::Typing { .. });
        let binding = if typing { websocket.clone() } else { mailbox.clone() };
        let content = OutgoingContent {
            sender_account_id: SENDER.into(),
            sender_ed25519_key: sender_key.clone(),
            recipient_account_id: RECIPIENT.into(),
            recipient_ed25519_key: recipient_key.clone(),
            envelope_id: binding.envelope_id.clone(),
            body: body.clone(),
        };
        let plaintext = encode_content(content).unwrap();
        let read = decode_content(plaintext.clone(), binding.clone()).unwrap();
        assert_eq!((read.version, read.body), (4, body), "{name}");
        if name == "text" {
            text_plaintext = plaintext.clone();
        }
        bound.insert(
            name.into(),
            json!({ "bytes": plaintext.len(), "plaintext": plaintext, "binding": binding_json(&binding) }),
        );
    }

    let unbound_cases = vec![
        (
            "sent again by the server to another recipient",
            ContentBinding { my_account_id: STRANGER.into(), ..mailbox.clone() },
        ),
        (
            "presented as coming from another sender",
            ContentBinding { sender_account_id: STRANGER.into(), ..mailbox.clone() },
        ),
        (
            "the same account ids, but the sender's verified identity has another key",
            ContentBinding { sender_ed25519_key: stranger_key.clone(), ..mailbox.clone() },
        ),
        (
            "the same account ids, but written for another identity key than mine",
            ContentBinding { my_ed25519_key: stranger_key.clone(), ..mailbox.clone() },
        ),
        (
            "a binding key written with base64 padding",
            ContentBinding { sender_ed25519_key: format!("{sender_key}="), ..mailbox.clone() },
        ),
        (
            "under another envelope id",
            ContentBinding { envelope_id: Some(CONTENT_TARGET.into()), ..mailbox.clone() },
        ),
        ("a mailbox kind through the websocket", websocket.clone()),
        (
            "a binding id in upper case",
            ContentBinding { sender_account_id: SENDER.to_uppercase(), ..mailbox.clone() },
        ),
    ];
    let typing_plaintext = s_of(&bound["typing_start"]["plaintext"]);
    let mut unbound: Vec<Value> = unbound_cases
        .into_iter()
        .map(|(name, binding)| {
            let read = decode_content(text_plaintext.clone(), binding.clone());
            assert!(matches!(read, Err(ChatCryptoError::UnboundContent)), "{name}");
            json!({ "name": name, "plaintext": text_plaintext, "binding": binding_json(&binding) })
        })
        .collect();
    assert!(decode_content(typing_plaintext.clone(), mailbox.clone()).is_err());
    unbound.push(json!({ "name": "a typing signal through the mailbox", "plaintext": typing_plaintext, "binding": binding_json(&mailbox) }));

    let v2: Value = serde_json::from_str(include_str!("../vectors/v2.json")).unwrap();
    let v2_text = s_of(&v2["v2"]["text"]["plaintext"]);
    let v2_envelope =
        serde_json::from_str::<Value>(&v2_text).unwrap()["envelope_id"].as_str().unwrap().to_owned();
    let legacy = ContentBinding {
        envelope_id: Some(v2_envelope),
        legacy_conversation_id: Some(OLD_CONVERSATION.into()),
        ..mailbox.clone()
    };
    assert_eq!(decode_content(v2_text.clone(), legacy.clone()).unwrap().version, 2);
    let without = ContentBinding { legacy_conversation_id: None, ..legacy.clone() };
    let other = ContentBinding { legacy_conversation_id: Some(STRANGER.into()), ..legacy.clone() };
    for b in [&without, &other] {
        assert!(decode_content(v2_text.clone(), b.clone()).is_err());
    }
    unbound.push(json!({ "name": "version 2 without the old conversation id", "plaintext": v2_text, "binding": binding_json(&without) }));
    unbound.push(json!({ "name": "version 2 with the old conversation id of another contact", "plaintext": v2_text, "binding": binding_json(&other) }));

    // What 0.8.0 wrote, with the binding it was read with then (and the keys since asked).
    let version_3_envelope =
        serde_json::from_str::<Value>(version_3).unwrap()["envelope_id"].as_str().unwrap().to_owned();
    let version_3_binding = ContentBinding { envelope_id: Some(version_3_envelope), ..mailbox.clone() };
    assert!(matches!(
        decode_content(version_3.to_owned(), version_3_binding.clone()),
        Err(ChatCryptoError::UnsupportedContent { .. })
    ));

    json!({
        "bound": bound,
        "unbound": unbound,
        "legacy_read": { "plaintext": v2_text, "binding": binding_json(&legacy), "version": 2 },
        "version_3_refused": { "plaintext": version_3, "binding": binding_json(&version_3_binding), "error": "UnsupportedContent" },
    })
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
