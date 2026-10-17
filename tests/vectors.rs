//! Checks vectors/v1.json, so a change to a wire format cannot slip in unnoticed.

use serde_json::Value;
use sombe_chat_crypto::*;
use vodozemac::Ed25519SecretKey;

fn vectors() -> Value {
    let text = include_str!("../vectors/v1.json");
    serde_json::from_str(text).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn wallet_signature_is_reproducible() {
    let v = vectors();
    let seed: [u8; 32] = unhex(v["wallet"]["seed_hex"].as_str().unwrap()).try_into().unwrap();
    let wallet = Ed25519SecretKey::from_slice(&seed);
    assert_eq!(bs58::encode(wallet.public_key().as_bytes()).into_string(), s(&v["wallet"]["address"]));
    // ed25519 signatures are deterministic: the same seed signs the same bytes.
    let signature =
        bs58::encode(wallet.sign(s(&v["identity"]["statement"]).as_bytes()).to_bytes()).into_string();
    assert_eq!(signature, s(&v["identity"]["wallet_signature"]));
}

#[test]
fn statement_verifies_and_matches_the_account() {
    let v = vectors();
    let id = &v["identity"];
    let verified =
        verify_identity(s(&id["statement"]), s(&v["wallet"]["address"]), s(&id["wallet_signature"])).unwrap();
    assert_eq!(verified.curve25519_key, s(&id["curve25519_key"]));
    assert_eq!(verified.ed25519_key, s(&id["ed25519_key"]));
    assert_eq!(verified.created_at, s(&id["created_at"]));

    let account =
        ChatCrypto::restore_account(s(&id["account_pickle"]), unhex(v["pickle_key_hex"].as_str().unwrap()))
            .unwrap();
    assert_eq!(
        account.identity_statement(s(&v["wallet"]["address"]), s(&id["created_at"])).unwrap(),
        s(&id["statement"])
    );
}

#[test]
fn one_time_key_signature() {
    let v = vectors();
    let k = &v["one_time_key"];
    let key = SignedOneTimeKey {
        key_id: s(&k["key_id"]),
        public_key: s(&k["public_key"]),
        signature: s(&k["signature"]),
        is_fallback: k["is_fallback"].as_bool().unwrap(),
    };
    assert_eq!(one_time_key_signed_text(key.clone()), s(&k["signed_text"]));
    let identity = IdentityKeys {
        curve25519_key: s(&v["identity"]["curve25519_key"]),
        ed25519_key: s(&v["identity"]["ed25519_key"]),
    };
    assert!(verify_one_time_key(identity, key));
}

#[test]
fn first_message_decrypts_with_the_pickled_account() {
    let v = vectors();
    let m = &v["first_message"];
    let key = unhex(v["pickle_key_hex"].as_str().unwrap());
    let bob = ChatCrypto::restore_account(s(&v["identity"]["account_pickle"]), key.clone()).unwrap();
    let sender = IdentityKeys {
        curve25519_key: s(&m["sender"]["curve25519_key"]),
        ed25519_key: s(&m["sender"]["ed25519_key"]),
    };
    let envelope = Envelope {
        protocol: s(&m["envelope"]["protocol"]),
        olm_type: m["envelope"]["olm_type"].as_u64().unwrap() as u8,
        ciphertext: s(&m["envelope"]["ciphertext"]),
    };
    let result = bob.decrypt_from(sender, vec![], envelope, key).unwrap();
    assert_eq!(result.plaintext, s(&m["plaintext"]));

    let content = decode_content(result.plaintext).unwrap();
    assert_eq!(content.kind, ContentKind::Text);
    assert_eq!(content.body.as_deref(), Some("Salut ! Tu es rentré ?"));
}

#[test]
fn edit_content_is_reproducible() {
    let v = vectors();
    let e = &v["edit_content"];
    let content = MessageContent {
        conversation_id: s(&e["conversation_id"]),
        client_message_id: s(&e["client_message_id"]),
        kind: ContentKind::Edit,
        body: Some(s(&e["body"])),
        reply_excerpt: None,
        comment: None,
        edits_message_id: Some(s(&e["edits_message_id"])),
    };
    assert_eq!(encode_content(content.clone()).unwrap(), s(&e["plaintext"]));
    assert_eq!(decode_content(s(&e["plaintext"])).unwrap(), content);
}
