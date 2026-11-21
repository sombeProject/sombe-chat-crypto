//! Checks vectors/v9.json (since 0.12.0): the secret of the alias seal for each account and
//! epoch, the epochs refused, and that every normalized alias and every seal keeps the alias
//! rule. The ChatPay API replays the normalization and the seals.

use serde_json::Value;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v9.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn key(v: &Value, account_id: &str) -> std::sync::Arc<AliasVaultKey> {
    derive_alias_vault_key(unhex(v["wallet_seed"].as_str().unwrap()), account_id.into()).unwrap()
}

#[test]
fn every_seal_secret_is_what_the_module_derives() {
    let v = vectors();
    let secrets = v["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 3);
    for entry in secrets {
        let k = key(&v, entry["account_id"].as_str().unwrap());
        assert_eq!(k.alias_seal_secret(s(&entry["epoch"])).unwrap(), s(&entry["secret"]));
    }
    let distinct: std::collections::HashSet<_> = secrets.iter().map(|e| s(&e["secret"])).collect();
    assert_eq!(distinct.len(), 3, "two epochs and two accounts give three secrets");
    for entry in v["seals"].as_array().unwrap() {
        assert!(secrets.iter().any(|e| e["secret"] == entry["secret"] && e["epoch"] == entry["epoch"]));
    }
}

#[test]
fn every_refused_epoch_is_invalid_key() {
    let v = vectors();
    let k = key(&v, "a1a1a1a1-0000-4000-8000-0000000000a1");
    for entry in v["refused_epochs"].as_array().unwrap() {
        assert_eq!(entry["error"], "InvalidKey");
        assert!(matches!(k.alias_seal_secret(s(&entry["epoch"])), Err(ChatCryptoError::InvalidKey { .. })));
    }
}

#[test]
fn every_normalized_alias_keeps_the_alias_rule() {
    let v = vectors();
    let rule = |a: &str| {
        let b = a.as_bytes();
        (3..=20).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b[1..].iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    };
    for entry in v["normalization"].as_array().unwrap() {
        assert_eq!(
            unhex(entry["input_utf8_hex"].as_str().unwrap()),
            entry["input"].as_str().unwrap().as_bytes()
        );
        if let Some(alias) = entry["alias"].as_str() {
            assert!(rule(alias), "{alias}");
        }
    }
    for entry in v["seals"].as_array().unwrap() {
        assert!(rule(entry["alias"].as_str().unwrap()));
    }
}
