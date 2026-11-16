//! Checks vectors/v4.json (the alias attestation, since 0.8.0): every accepted case gives
//! its alias, every refused case is `InvalidAttestation`, and the server's signature can be
//! made again from the test seed alone.

use serde_json::Value;
use sombe_chat_crypto::{verify_alias_attestation, ChatCryptoError, TrustedAttestationKey};
use vodozemac::Ed25519SecretKey;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v4.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn run(case: &Value) -> Result<String, ChatCryptoError> {
    let trusted = case["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TrustedAttestationKey { kid: s(&k["kid"]), public_key: s(&k["public_key"]) })
        .collect();
    verify_alias_attestation(
        s(&case["text"]),
        s(&case["signature"]),
        trusted,
        s(&case["sender_account_id"]),
        s(&case["sender_account_public_key"]),
        s(&case["deposited_at"]),
    )
}

#[test]
fn accepted_attestations_give_their_alias() {
    let v = vectors();
    let accepted = v["accepted"].as_array().unwrap();
    assert!(accepted.len() >= 4);
    for case in accepted {
        assert_eq!(run(case), Ok(s(&case["alias"])), "{}", case["name"]);
    }
}

#[test]
fn refused_attestations_say_nothing_more() {
    let v = vectors();
    let refused = v["refused"].as_array().unwrap();
    assert!(refused.len() >= 17);
    for case in refused {
        assert_eq!(run(case), Err(ChatCryptoError::InvalidAttestation), "{}", case["name"]);
    }
}

#[test]
fn the_replay_case_is_there() {
    let v = vectors();
    assert!(v["refused"].as_array().unwrap().iter().any(|c| s(&c["name"]).starts_with("replay")));
}

#[test]
fn the_server_signature_is_made_again_from_the_seed() {
    let v = vectors();
    let signs = &v["server_signs"];
    let text = format!(
        "SOMBE alias attestation v1\nkid:{}\nalias:{}\naccount_id:{}\naccount:{}\nexpires:{}",
        s(&signs["kid"]),
        s(&signs["alias"]),
        s(&signs["account_id"]),
        s(&signs["account"]),
        signs["expires"].as_i64().unwrap()
    );
    assert_eq!(text, s(&signs["text"]));
    let key = v["signing_keys"].as_array().unwrap().iter().find(|k| k["kid"] == signs["kid"]).unwrap();
    let seed: Vec<u8> =
        (0..64).step_by(2).map(|i| u8::from_str_radix(&s(&key["seed_hex"])[i..i + 2], 16).unwrap()).collect();
    let secret = Ed25519SecretKey::from_slice(seed.as_slice().try_into().unwrap());
    assert_eq!(bs58::encode(secret.public_key().as_bytes()).into_string(), s(&key["public_key"]));
    let signature = bs58::encode(secret.sign(text.as_bytes()).to_bytes()).into_string();
    assert_eq!(signature, s(&signs["signature"]));
}

#[test]
fn an_oversized_text_is_refused_unread() {
    let v = vectors();
    let mut case = v["accepted"][0].clone();
    case["text"] = Value::from(format!("{}{}", s(&case["text"]), " ".repeat(600)));
    assert_eq!(run(&case), Err(ChatCryptoError::InvalidAttestation));
}

#[test]
fn an_empty_trusted_list_trusts_nothing() {
    let v = vectors();
    let mut case = v["accepted"][0].clone();
    case["trusted_keys"] = Value::Array(vec![]);
    assert_eq!(run(&case), Err(ChatCryptoError::InvalidAttestation));
}
