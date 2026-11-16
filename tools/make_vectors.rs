//! Writes vectors/v4.json (since 0.8.0): alias attestations the module accepts and the
//! ones it refuses, each with every input of `verify_alias_attestation`, and the test
//! signing seeds so a server can sign the same texts again and get the same signatures;
//! then the version 3 content of every kind, how each is bound to its element, and the
//! contents and bindings that must be refused. Running it again gives the same file;
//! tests/attestation.rs and tests/vectors.rs check it.
//!
//! vectors/v1.json (0.4.0), vectors/v2.json (content version 2, 0.5.0 and 0.6.0) and
//! vectors/v3.json (the account key, 0.7.0) stay as they are: since 0.8.0 the module
//! writes only content version 3, so their contents cannot be written again. Their
//! generators are in the history of this file. Never use these ids for anything real.

use serde_json::{json, Value};
use sombe_chat_crypto::{
    decode_content, encode_content, prove_rotation, verify_alias_attestation, AccountRotationContent,
    ContentBinding, ContentBody, ContentChannel, OutgoingContent, ReceiptStatus, TrustedAttestationKey,
    TypingState,
};
use vodozemac::Ed25519SecretKey;

/// A test account key seed (the one of vectors/v3.json).
const ACCOUNT_SEED: [u8; 32] = [
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, 62, 63,
];
/// The test wallet seed, used here only as another account key.
const WALLET_SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31,
];

fn main() {
    write_v4();
}

fn public_of(seed: &[u8; 32]) -> String {
    bs58::encode(Ed25519SecretKey::from_slice(seed).public_key().as_bytes()).into_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Test attestation signing seeds (never use them for anything real): `t1` and `t2` are
/// trusted, `t9` is not.
const ATTESTATION_SEED_T1: [u8; 32] = [0x11; 32];
const ATTESTATION_SEED_T2: [u8; 32] = [0x22; 32];
const ATTESTATION_SEED_T9: [u8; 32] = [0x99; 32];
const ATTESTED_ACCOUNT_ID: &str = "8f14e45f-ceea-4c6b-9a3d-2b1c0d9e8f7a";
const OTHER_ACCOUNT_ID: &str = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f";
/// 2026-11-17T12:00:00Z.
const ATTESTATION_EXPIRES: i64 = 1_794_916_800;

fn attestation_text(kid: &str, alias: &str, account_id: &str, account: &str, expires: &str) -> String {
    format!("SOMBE alias attestation v1\nkid:{kid}\nalias:{alias}\naccount_id:{account_id}\naccount:{account}\nexpires:{expires}")
}

fn sign_b58(seed: &[u8; 32], text: &str) -> String {
    bs58::encode(Ed25519SecretKey::from_slice(seed).sign(text.as_bytes()).to_bytes()).into_string()
}

fn write_v4() {
    let account = public_of(&ACCOUNT_SEED);
    let other_account = public_of(&WALLET_SEED);
    let trusted = vec![
        TrustedAttestationKey { kid: "t1".into(), public_key: public_of(&ATTESTATION_SEED_T1) },
        TrustedAttestationKey { kid: "t2".into(), public_key: public_of(&ATTESTATION_SEED_T2) },
    ];
    let expires = ATTESTATION_EXPIRES.to_string();
    let good = attestation_text("t1", "alice_01", ATTESTED_ACCOUNT_ID, &account, &expires);
    let good_signature = sign_b58(&ATTESTATION_SEED_T1, &good);
    let before = "2026-11-17T11:59:59.999Z";

    struct Case {
        name: &'static str,
        text: String,
        signature: String,
        trusted: Vec<TrustedAttestationKey>,
        sender_account_id: String,
        sender_account_public_key: String,
        deposited_at: String,
    }
    let case = |name: &'static str, text: &str, seed: &[u8; 32]| Case {
        name,
        text: text.to_owned(),
        signature: sign_b58(seed, text),
        trusted: trusted.clone(),
        sender_account_id: ATTESTED_ACCOUNT_ID.into(),
        sender_account_public_key: account.clone(),
        deposited_at: before.into(),
    };

    let mut accepted = vec![case("valid", &good, &ATTESTATION_SEED_T1)];
    let mut at_expiry = case("deposited exactly at expires", &good, &ATTESTATION_SEED_T1);
    at_expiry.deposited_at = "2026-11-17T12:00:00.000Z".into();
    accepted.push(at_expiry);
    accepted.push(case(
        "signed by the second trusted key",
        &attestation_text("t2", "alice_01", ATTESTED_ACCOUNT_ID, &account, &expires),
        &ATTESTATION_SEED_T2,
    ));
    let mut without_millis = case("deposited_at without milliseconds", &good, &ATTESTATION_SEED_T1);
    without_millis.deposited_at = "2026-11-17T11:59:59Z".into();
    accepted.push(without_millis);

    let mut refused = Vec::new();
    let mut late = case("deposited one millisecond after expires", &good, &ATTESTATION_SEED_T1);
    late.deposited_at = "2026-11-17T12:00:00.001Z".into();
    refused.push(late);
    let mut replay = case("replay: carried by another account's envelope", &good, &ATTESTATION_SEED_T1);
    replay.sender_account_id = OTHER_ACCOUNT_ID.into();
    replay.sender_account_public_key = other_account.clone();
    refused.push(replay);
    let mut other_key = case("sender account key differs from the attested one", &good, &ATTESTATION_SEED_T1);
    other_key.sender_account_public_key = other_account.clone();
    refused.push(other_key);
    let mut other_id = case("sender account_id differs from the attested one", &good, &ATTESTATION_SEED_T1);
    other_id.sender_account_id = OTHER_ACCOUNT_ID.into();
    refused.push(other_id);
    let mut tampered = case("alias changed after signing", &good, &ATTESTATION_SEED_T1);
    tampered.text = good.replace("alice_01", "alice_02");
    tampered.signature = good_signature.clone();
    refused.push(tampered);
    let mut flipped = case("signature does not hold", &good, &ATTESTATION_SEED_T1);
    flipped.signature = sign_b58(&ATTESTATION_SEED_T1, &good.replace("alice_01", "mallory"));
    refused.push(flipped);
    refused.push(case(
        "unknown kid",
        &attestation_text("t9", "alice_01", ATTESTED_ACCOUNT_ID, &account, &expires),
        &ATTESTATION_SEED_T9,
    ));
    refused.push(case("known kid, signed by another key", &good, &ATTESTATION_SEED_T9));
    refused.push(case(
        "alias with a newline, signed",
        &attestation_text("t1", "alice\nbob", ATTESTED_ACCOUNT_ID, &account, &expires),
        &ATTESTATION_SEED_T1,
    ));
    refused.push(case(
        "alias in upper case, signed",
        &attestation_text("t1", "Alice_01", ATTESTED_ACCOUNT_ID, &account, &expires),
        &ATTESTATION_SEED_T1,
    ));
    refused.push(case(
        "alias too short, signed",
        &attestation_text("t1", "al", ATTESTED_ACCOUNT_ID, &account, &expires),
        &ATTESTATION_SEED_T1,
    ));
    refused.push(case("CRLF line ends, signed", &good.replace('\n', "\r\n"), &ATTESTATION_SEED_T1));
    refused.push(case("final newline, signed", &format!("{good}\n"), &ATTESTATION_SEED_T1));
    refused.push(case(
        "expires with a leading zero, signed",
        &attestation_text("t1", "alice_01", ATTESTED_ACCOUNT_ID, &account, &format!("0{expires}")),
        &ATTESTATION_SEED_T1,
    ));
    refused.push(case(
        "account_id in upper case, signed",
        &attestation_text("t1", "alice_01", &ATTESTED_ACCOUNT_ID.to_uppercase(), &account, &expires),
        &ATTESTATION_SEED_T1,
    ));
    let mut duplicate = case("the same kid twice in trusted_keys", &good, &ATTESTATION_SEED_T1);
    duplicate
        .trusted
        .push(TrustedAttestationKey { kid: "t1".into(), public_key: public_of(&ATTESTATION_SEED_T9) });
    refused.push(duplicate);
    let mut bad_date = case("deposited_at is not a date that exists", &good, &ATTESTATION_SEED_T1);
    bad_date.deposited_at = "2026-02-30T00:00:00.000Z".into();
    refused.push(bad_date);

    let to_json = |c: &Case, alias: Option<String>| {
        json!({
            "name": c.name,
            "text": c.text,
            "signature": c.signature,
            "trusted_keys": c.trusted.iter().map(|k| json!({"kid": k.kid, "public_key": k.public_key})).collect::<Vec<_>>(),
            "sender_account_id": c.sender_account_id,
            "sender_account_public_key": c.sender_account_public_key,
            "deposited_at": c.deposited_at,
            "alias": alias,
        })
    };
    let run = |c: &Case| {
        verify_alias_attestation(
            c.text.clone(),
            c.signature.clone(),
            c.trusted.clone(),
            c.sender_account_id.clone(),
            c.sender_account_public_key.clone(),
            c.deposited_at.clone(),
        )
    };
    let accepted: Vec<Value> = accepted
        .iter()
        .map(|c| to_json(c, Some(run(c).unwrap_or_else(|e| panic!("{}: {e}", c.name)))))
        .collect();
    let refused: Vec<Value> = refused
        .iter()
        .map(|c| {
            assert!(run(c).is_err(), "{} was accepted", c.name);
            to_json(c, None)
        })
        .collect();

    let contents = content_vectors(&good, &good_signature);

    let vectors = json!({
        "description": "SOMBE alias attestation test vectors (sombe-chat-crypto 0.8.0). Test seeds and test keys only: never use them for anything real. Every text is UTF-8, lines separated by \\n, no final \\n. Signatures are Ed25519 (deterministic), base58; public keys base58 of 32 bytes.",
        "signing_keys": [
            {"kid": "t1", "seed_hex": hex(&ATTESTATION_SEED_T1), "public_key": public_of(&ATTESTATION_SEED_T1), "trusted": true},
            {"kid": "t2", "seed_hex": hex(&ATTESTATION_SEED_T2), "public_key": public_of(&ATTESTATION_SEED_T2), "trusted": true},
            {"kid": "t9", "seed_hex": hex(&ATTESTATION_SEED_T9), "public_key": public_of(&ATTESTATION_SEED_T9), "trusted": false},
        ],
        "server_signs": {
            "kid": "t1",
            "alias": "alice_01",
            "account_id": ATTESTED_ACCOUNT_ID,
            "account": account,
            "expires": ATTESTATION_EXPIRES,
            "text": good,
            "signature": good_signature,
        },
        "accepted": accepted,
        "refused": refused,
        "content_v3": contents,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v4.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
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
        "my_account_id": b.my_account_id,
        "legacy_conversation_id": b.legacy_conversation_id,
    })
}

/// Every version 3 kind the app sends most, bound to its element; then contents that
/// must be refused as `UnboundContent`, and a version 2 content of vectors/v2.json read
/// with and without the old conversation id.
fn content_vectors(attestation: &str, attestation_signature: &str) -> Value {
    let mailbox = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(CONTENT_ENVELOPE.into()),
        sender_account_id: SENDER.into(),
        my_account_id: RECIPIENT.into(),
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
            recipient_account_id: RECIPIENT.into(),
            envelope_id: binding.envelope_id.clone(),
            body: body.clone(),
        };
        let plaintext = encode_content(content).unwrap();
        let read = decode_content(plaintext.clone(), binding.clone()).unwrap();
        assert_eq!((read.version, read.body), (3, body), "{name}");
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
            assert!(decode_content(text_plaintext.clone(), binding.clone()).is_err(), "{name}");
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

    json!({
        "bound": bound,
        "unbound": unbound,
        "legacy_read": { "plaintext": v2_text, "binding": binding_json(&legacy), "version": 2 },
    })
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
