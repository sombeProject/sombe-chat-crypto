//! Checks vectors/v6.json (since 0.9.0): each access key and verifier is what the module
//! derives, each refused key is `InvalidKey`, each bound content reads and encodes back to
//! the same bytes, and each refused content gives its error.

use serde_json::Value;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v6.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
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
fn access_keys_and_verifiers_are_what_the_module_derives() {
    let v = vectors();
    let derived = v["access_key"]["derived"].as_array().unwrap();
    assert_eq!(derived.len(), 2);
    for d in derived {
        let access_key = derive_access_key(unhex(&s(&d["profile_key_hex"]))).unwrap();
        assert_eq!(access_key, s(&d["access_key"]));
        assert_eq!(access_key_verifier(access_key).unwrap(), s(&d["verifier"]));
    }
    for r in v["access_key"]["refused_profile_keys"].as_array().unwrap() {
        let read = derive_access_key(unhex(&s(&r["profile_key_hex"])));
        assert!(matches!(read, Err(ChatCryptoError::InvalidKey { .. })), "{}", r["name"]);
    }
    let refused = v["access_key"]["refused_access_keys"].as_array().unwrap();
    assert!(refused.len() >= 5);
    for r in refused {
        let read = access_key_verifier(s(&r["access_key"]));
        assert!(matches!(read, Err(ChatCryptoError::InvalidKey { .. })), "{}", r["name"]);
    }
}

#[test]
fn bound_contents_read_and_encode_back_to_the_same_bytes() {
    let v = vectors();
    let bound = v["content_v4"]["bound"].as_object().unwrap();
    assert_eq!(bound.len(), 4);
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
    assert_eq!(bound["access_key"]["bytes"], 512);
    assert_eq!(bound["access_key_last_generation"]["bytes"], 512);
    let accept = |name: &str| {
        decode_content(s(&bound[name]["plaintext"]), binding(&bound[name]["binding"])).unwrap().body
    };
    assert!(matches!(
        accept("contact_accept_with_access_key"),
        ContentBody::ContactAccept { access_key: Some(_), .. }
    ));
    assert!(matches!(
        accept("contact_accept_without_access_key"),
        ContentBody::ContactAccept { access_key: None, .. }
    ));
}

#[test]
fn an_acceptance_of_0_8_1_still_reads() {
    let v5: Value = serde_json::from_str(include_str!("../vectors/v5.json")).unwrap();
    let vector = &v5["content_v4"]["bound"]["contact_accept"];
    let read = decode_content(s(&vector["plaintext"]), binding(&vector["binding"])).unwrap();
    assert!(matches!(read.body, ContentBody::ContactAccept { access_key: None, .. }));
}

#[test]
fn refused_contents_give_their_error() {
    let v = vectors();
    let refused = v["content_v4"]["refused"].as_array().unwrap();
    assert!(refused.len() >= 10);
    for case in refused {
        let read = decode_content(s(&case["plaintext"]), binding(&case["binding"]));
        let got = match read {
            Err(ChatCryptoError::InvalidContent { .. }) => "InvalidContent",
            Err(ChatCryptoError::UnsupportedContent { .. }) => "UnsupportedContent",
            Err(ChatCryptoError::UnboundContent) => "UnboundContent",
            other => panic!("{}: {other:?}", case["name"]),
        };
        assert_eq!(got, s(&case["error"]), "{}", case["name"]);
    }
}
