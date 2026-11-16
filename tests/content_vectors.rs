//! Checks the version 4 contents of vectors/v5.json (since 0.8.1): each is bound to its
//! element and encodes back to the same bytes; each unbound case is `UnboundContent`; the
//! version 2 content reads only with the old conversation id of its contact; and the
//! version 3 contents of vectors/v4.json (0.8.0) are no longer read.

use serde_json::Value;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v5.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn binding(b: &Value) -> ContentBinding {
    let opt = |field: &str| b[field].as_str().map(str::to_owned);
    ContentBinding {
        channel: match b["channel"].as_str().unwrap() {
            "mailbox" => ContentChannel::Mailbox,
            "websocket" => ContentChannel::Websocket,
            other => panic!("unknown channel {other}"),
        },
        envelope_id: opt("envelope_id"),
        sender_account_id: s(&b["sender_account_id"]),
        sender_ed25519_key: s(&b["sender_ed25519_key"]),
        my_account_id: s(&b["my_account_id"]),
        my_ed25519_key: s(&b["my_ed25519_key"]),
        legacy_conversation_id: opt("legacy_conversation_id"),
    }
}

#[test]
fn bound_contents_read_and_encode_back_to_the_same_bytes() {
    let v = vectors();
    let bound = v["content_v4"]["bound"].as_object().unwrap();
    assert_eq!(bound.len(), 8);
    for (name, vector) in bound {
        let plaintext = s(&vector["plaintext"]);
        assert_eq!(plaintext.len() as u64, vector["bytes"].as_u64().unwrap(), "{name}");
        let b = binding(&vector["binding"]);
        let read = decode_content(plaintext.clone(), b.clone()).unwrap();
        assert_eq!(read.version, 4, "{name}");
        let again = OutgoingContent {
            sender_account_id: b.sender_account_id.clone(),
            sender_ed25519_key: b.sender_ed25519_key.clone(),
            recipient_account_id: b.my_account_id.clone(),
            recipient_ed25519_key: b.my_ed25519_key.clone(),
            envelope_id: read.envelope_id,
            body: read.body,
        };
        assert_eq!(encode_content(again).unwrap(), plaintext, "{name}");
    }
    assert_eq!(v["content_v4"]["bound"]["typing_start"]["bytes"], 512);
    assert_eq!(v["content_v4"]["bound"]["contact_request"]["bytes"], 1024);
    assert_eq!(v["content_v4"]["bound"]["account_rotation"]["bytes"], 1024);
}

#[test]
fn unbound_contents_say_nothing_more() {
    let v = vectors();
    let unbound = v["content_v4"]["unbound"].as_array().unwrap();
    assert!(unbound.len() >= 8);
    for case in unbound {
        let read = decode_content(s(&case["plaintext"]), binding(&case["binding"]));
        assert!(matches!(read, Err(ChatCryptoError::UnboundContent)), "{}", case["name"]);
    }
    let names: Vec<String> = unbound.iter().map(|c| s(&c["name"])).collect();
    assert!(names.iter().any(|n| n.contains("another recipient")));
    assert!(names.iter().any(|n| n.contains("another sender")));
    assert!(names.iter().any(|n| n.contains("has another key")));
    assert!(names.iter().any(|n| n.contains("another identity key than mine")));
}

#[test]
fn version_3_of_0_8_0_is_no_longer_read() {
    let v = vectors();
    let refused = &v["content_v4"]["version_3_refused"];
    let read = decode_content(s(&refused["plaintext"]), binding(&refused["binding"]));
    assert!(matches!(read, Err(ChatCryptoError::UnsupportedContent { .. })));

    // Every version 3 content of the frozen vectors/v4.json, whatever its binding.
    let frozen: Value = serde_json::from_str(include_str!("../vectors/v4.json")).unwrap();
    let keys = binding(&v["content_v4"]["bound"]["text"]["binding"]);
    for (name, vector) in frozen["content_v3"]["bound"].as_object().unwrap() {
        let b = &vector["binding"];
        let old = ContentBinding {
            channel: if b["channel"] == "websocket" {
                ContentChannel::Websocket
            } else {
                ContentChannel::Mailbox
            },
            envelope_id: b["envelope_id"].as_str().map(str::to_owned),
            sender_account_id: s(&b["sender_account_id"]),
            my_account_id: s(&b["my_account_id"]),
            legacy_conversation_id: None,
            ..keys.clone()
        };
        let read = decode_content(s(&vector["plaintext"]), old);
        assert!(matches!(read, Err(ChatCryptoError::UnsupportedContent { .. })), "{name}");
    }
}

#[test]
fn the_vectors_are_what_the_generator_writes() {
    // The identity keys of the vectors are the public keys of their seeds.
    let v = vectors();
    for who in ["sender", "recipient", "stranger"] {
        let key = &v["identity_keys"][who];
        let seed: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s(&key["seed_hex"])[i..i + 2], 16).unwrap())
            .collect();
        let seed: [u8; 32] = seed.try_into().unwrap();
        assert_eq!(
            vodozemac::Ed25519SecretKey::from_slice(&seed).public_key().to_base64(),
            s(&key["ed25519"])
        );
    }
}

#[test]
fn version_2_reads_only_with_its_old_conversation_id() {
    let v = vectors();
    let legacy = &v["content_v4"]["legacy_read"];
    let read = decode_content(s(&legacy["plaintext"]), binding(&legacy["binding"])).unwrap();
    assert_eq!(read.version as u64, legacy["version"].as_u64().unwrap());
}
