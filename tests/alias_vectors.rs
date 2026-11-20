//! Checks vectors/v8.json (since 0.11.0): the vault key and its sealed form, the block that
//! opens to its vault, every refused block with its error, the alias token (verified,
//! refused, and its memo), and the `alias_change` content. The ChatPay and wallet APIs replay
//! the same file.

use serde_json::Value;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v8.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn unbase64(text: &str) -> Vec<u8> {
    vodozemac::base64_decode(text.trim_end_matches('=')).unwrap()
}

fn error_name(e: &ChatCryptoError) -> &'static str {
    match e {
        ChatCryptoError::InvalidSealedKey => "InvalidSealedKey",
        ChatCryptoError::InvalidVault => "InvalidVault",
        ChatCryptoError::UnsupportedVault => "UnsupportedVault",
        ChatCryptoError::InvalidToken => "InvalidToken",
        ChatCryptoError::InvalidContent { .. } => "InvalidContent",
        ChatCryptoError::UnsupportedContent { .. } => "UnsupportedContent",
        ChatCryptoError::UnboundContent => "UnboundContent",
        other => panic!("unexpected {other:?}"),
    }
}

fn token(t: &Value) -> VaultToken {
    match t["state"].as_str().unwrap() {
        "preparing" => VaultToken::Preparing {
            key_id: s(&t["key_id"]),
            nonce: s(&t["nonce"]),
            blinded_msg: s(&t["blinded_msg"]),
            secret: s(&t["secret"]),
            idem: s(&t["idem"]),
            burn_signature: t.get("burn_signature").map(s),
        },
        _ => VaultToken::Ready {
            key_id: s(&t["key_id"]),
            nonce: s(&t["nonce"]),
            signature: s(&t["signature"]),
        },
    }
}

fn vault_from(v: &Value) -> AliasVault {
    AliasVault {
        seq: v["seq"].as_i64().unwrap(),
        alias: s(&v["alias"]),
        retired: v["retired"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| RetiredAlias { alias: s(&r["alias"]), retired_at: r["retired_at"].as_i64().unwrap() })
            .collect(),
        tokens: v["tokens"].as_array().unwrap().iter().map(token).collect(),
    }
}

fn key() -> std::sync::Arc<AliasVaultKey> {
    let v = &vectors()["vault"];
    derive_alias_vault_key(unhex(&s(&v["wallet_seed_hex"])), s(&v["account_id"])).unwrap()
}

#[test]
fn the_sealed_key_opens_to_the_same_vault_key() {
    let v = &vectors()["vault"];
    let restored =
        AliasVaultKey::unseal(s(&v["sealed_key"]), unhex(&s(&v["sealing_key_hex"])), s(&v["account_id"]))
            .unwrap();
    assert_eq!(restored.open_vault(s(&v["sealed"])).unwrap(), vault_from(&v["vault"]));
    // Not for another account, not with another sealing key.
    assert_eq!(
        AliasVaultKey::unseal(
            s(&v["sealed_key"]),
            unhex(&s(&v["sealing_key_hex"])),
            s(&v["other_account_id"])
        )
        .err(),
        Some(ChatCryptoError::InvalidSealedKey)
    );
    assert_eq!(
        AliasVaultKey::unseal(s(&v["sealed_key"]), vec![0; 32], s(&v["account_id"])).err(),
        Some(ChatCryptoError::InvalidSealedKey)
    );
    assert_eq!(unbase64(&s(&v["sealed_key"])).len(), 73);
}

#[test]
fn the_block_opens_to_its_vault() {
    let v = &vectors()["vault"];
    let sealed = s(&v["sealed"]);
    assert_eq!(sealed.len(), 21848);
    assert_eq!(unbase64(&sealed).len(), 16384);
    assert_eq!(unbase64(&sealed)[0], 1);
    let vault = key().open_vault(sealed).unwrap();
    assert_eq!(vault, vault_from(&v["vault"]));
    // The tokens are written by their bytes.
    assert_eq!(vault.tokens.len(), 2);
}

#[test]
fn every_refused_block_gives_its_error() {
    let v = &vectors()["vault"];
    let other = derive_alias_vault_key(unhex(&s(&v["wallet_seed_hex"])), s(&v["other_account_id"])).unwrap();
    let refused = v["refused"].as_array().unwrap();
    assert!(refused.len() >= 14);
    for r in refused {
        let by = if r["opened_by"] == "other_account" { &other } else { &key() };
        let error = by.open_vault(s(&r["sealed"])).expect_err(&s(&r["name"]));
        assert_eq!(error_name(&error), s(&r["error"]), "{}", r["name"]);
    }
}

#[test]
fn tokens_are_sorted_by_their_bytes_and_not_their_text() {
    let o = &vectors()["vault"]["byte_order"];
    let given = o["tokens_given"].as_array().unwrap();
    let written = o["tokens_written"].as_array().unwrap();
    // The text of the 0xfb... nonce sorts before the text of the 0x00... one, the bytes after.
    assert!(s(&given[0]) < s(&given[1]));
    assert!(unbase64(&s(&given[0])) > unbase64(&s(&given[1])));
    let opened = key().open_vault(s(&o["sealed"])).unwrap();
    let nonces: Vec<String> = opened
        .tokens
        .iter()
        .map(|t| match t {
            VaultToken::Ready { nonce, .. } | VaultToken::Preparing { nonce, .. } => nonce.clone(),
        })
        .collect();
    assert_eq!(nonces, written.iter().map(s).collect::<Vec<_>>());
    let json = s(&o["json"]);
    assert!(json.find(&s(&written[0])).unwrap() < json.find(&s(&written[1])).unwrap());
}

#[test]
fn the_worst_case_fits_and_comes_back() {
    let w = &vectors()["vault"]["worst_case"];
    assert_eq!(w["json_bytes"], 11376);
    let vault = key().open_vault(s(&w["sealed"])).unwrap();
    assert_eq!(vault, vault_from(&w["vault"]));
    assert_eq!((vault.retired.len(), vault.tokens.len()), (20, 10));
}

#[test]
fn the_token_verifies_and_is_refused_where_it_must() {
    let t = &vectors()["token"];
    let spki = s(&t["key"]["spki"]);
    let p = &t["prepared"];
    assert!(alias_token_verify(spki.clone(), s(&p["nonce"]), s(&p["token_signature"])).unwrap());
    assert_eq!(alias_token_memo(s(&p["blinded_msg"])).unwrap(), s(&p["memo"]));
    // The finalization of the blind signature gives that very token signature.
    let finalized = alias_token_finalize(
        spki.clone(),
        s(&p["nonce"]),
        s(&p["blinded_msg"]),
        s(&p["secret"]),
        s(&p["blind_signature"]),
    )
    .unwrap();
    assert_eq!(finalized, s(&p["token_signature"]));
    let second = &t["second"];
    assert!(alias_token_verify(spki.clone(), s(&second["nonce"]), s(&second["token_signature"])).unwrap());
    for f in t["verify_false"].as_array().unwrap() {
        assert!(
            !alias_token_verify(spki.clone(), s(&f["nonce"]), s(&f["token_signature"])).unwrap(),
            "{}",
            f["name"]
        );
    }
    for r in t["refused_finalize"].as_array().unwrap() {
        let error = alias_token_finalize(
            spki.clone(),
            s(&p["nonce"]),
            s(&p["blinded_msg"]),
            s(&r["secret"]),
            s(&r["blind_signature"]),
        )
        .expect_err(&s(&r["name"]));
        assert_eq!(error_name(&error), s(&r["error"]), "{}", r["name"]);
    }
    for r in t["refused_keys"].as_array().unwrap() {
        let error = alias_token_verify(s(&r["spki"]), s(&p["nonce"]), s(&p["token_signature"]))
            .expect_err(&s(&r["name"]));
        assert_eq!(error_name(&error), s(&r["error"]), "{}", r["name"]);
    }
    // The nonce is the prefix then the message, 64 bytes.
    assert_eq!(unbase64(&s(&p["nonce"])).len(), 64);
    assert_eq!(&unbase64(&s(&p["nonce"]))[32..], unhex(&s(&p["message_hex"])).as_slice());
}

#[test]
fn the_alias_change_reads_and_is_refused_where_it_must() {
    let c = &vectors()["alias_change"];
    let a = &c["attestation"];
    let trusted: Vec<TrustedAttestationKey> = a["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TrustedAttestationKey { kid: s(&k["kid"]), public_key: s(&k["public_key"]) })
        .collect();
    let verified = verify_alias_change(
        s(&a["text"]),
        s(&a["signature"]),
        trusted,
        s(&a["sender_account_id"]),
        s(&a["sender_account_public_key"]),
        s(&a["deposited_at"]),
    )
    .unwrap();
    assert_eq!((verified.alias, verified.expires), (s(&a["alias"]), a["expires"].as_i64().unwrap()));

    let binding = |b: &Value| ContentBinding {
        channel: if b["channel"] == "mailbox" { ContentChannel::Mailbox } else { ContentChannel::Websocket },
        envelope_id: b["envelope_id"].as_str().map(str::to_owned),
        sender_account_id: s(&b["sender_account_id"]),
        sender_ed25519_key: s(&b["sender_ed25519_key"]),
        my_account_id: s(&b["my_account_id"]),
        my_ed25519_key: s(&b["my_ed25519_key"]),
        legacy_conversation_id: b["legacy_conversation_id"].as_str().map(str::to_owned),
    };
    let bound = &c["bound"];
    let read = decode_content(s(&bound["plaintext"]), binding(&bound["binding"])).unwrap();
    assert_eq!(
        read.body,
        ContentBody::AliasChange { attestation: s(&a["text"]), attestation_signature: s(&a["signature"]) }
    );
    for r in c["refused"].as_array().unwrap() {
        let error = decode_content(s(&r["plaintext"]), binding(&r["binding"])).expect_err(&s(&r["name"]));
        assert_eq!(error_name(&error), s(&r["error"]), "{}", r["name"]);
    }
}

/// The generator gives the same file again: run with `--features vectors`.
#[cfg(feature = "vectors")]
#[test]
fn the_vault_vectors_are_what_the_module_writes() {
    let v = &vectors()["vault"];
    let key = key();
    let vault = vault_from(&v["vault"]);
    let nonce: [u8; 24] = unhex(&s(&v["vault_nonce_hex"])).try_into().unwrap();
    assert_eq!(alias_vectors::seal_vault(&key, vault, nonce).unwrap(), s(&v["sealed"]));
    let sealing: [u8; 32] = unhex(&s(&v["sealing_key_hex"])).try_into().unwrap();
    let key_nonce: [u8; 24] = unhex(&s(&v["key_seal_nonce_hex"])).try_into().unwrap();
    assert_eq!(alias_vectors::seal_key(&key, sealing, key_nonce).unwrap(), s(&v["sealed_key"]));
    let worst = vault_from(&v["worst_case"]["vault"]);
    assert_eq!(alias_vectors::seal_vault(&key, worst, nonce).unwrap(), s(&v["worst_case"]["sealed"]));
}

#[cfg(feature = "vectors")]
#[test]
fn the_token_vectors_are_what_the_module_writes() {
    let t = &vectors()["token"];
    let p = &t["prepared"];
    let message: [u8; 32] = unhex(&s(&p["message_hex"])).try_into().unwrap();
    let prepared = alias_vectors::prepare(
        &s(&t["key"]["spki"]),
        &s(&p["key_id"]),
        &s(&p["idem"]),
        message,
        s(&p["rng_seed"]).as_bytes(),
    )
    .unwrap();
    assert_eq!(prepared.nonce, s(&p["nonce"]));
    assert_eq!(prepared.blinded_msg, s(&p["blinded_msg"]));
    assert_eq!(prepared.secret, s(&p["secret"]));
}
