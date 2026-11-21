//! Checks vectors/v10.json (since 0.13.0): aliases with digits in the alias rule, the
//! attestation, the `alias_change` content, the vault and its worst case, the normalization
//! and the seal. The ChatPay API and the app replay it.

use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v10.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn b64(bytes: &[u8]) -> String {
    vodozemac::base64_encode(bytes)
}

fn key() -> std::sync::Arc<AliasVaultKey> {
    let v = &vectors()["vault"];
    derive_alias_vault_key(unhex(&s(&v["wallet_seed_hex"])), s(&v["account_id"])).unwrap()
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
        tokens: v["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| VaultToken::Preparing {
                key_id: s(&t["key_id"]),
                nonce: s(&t["nonce"]),
                blinded_msg: s(&t["blinded_msg"]),
                secret: s(&t["secret"]),
                idem: s(&t["idem"]),
                burn_signature: t.get("burn_signature").map(s),
            })
            .collect(),
    }
}

/// The alias rule, through the vault: an alias the module reads seals, any other is refused.
fn module_reads(alias: &str) -> bool {
    let vault = AliasVault { seq: 0, alias: alias.into(), retired: vec![], tokens: vec![] };
    match key().seal_vault(vault) {
        Ok(_) => true,
        Err(ChatCryptoError::InvalidVault) => false,
        Err(other) => panic!("unexpected {other:?}"),
    }
}

fn trusted(a: &Value) -> Vec<TrustedAttestationKey> {
    a["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TrustedAttestationKey { kid: s(&k["kid"]), public_key: s(&k["public_key"]) })
        .collect()
}

#[test]
fn the_alias_rule_reads_both_forms() {
    let r = &vectors()["alias_rule"];
    let accepted = r["accepted"].as_array().unwrap();
    assert!(accepted.iter().any(|a| a == "blaise46"), "the form without digits is still read");
    for alias in accepted {
        assert!(module_reads(alias.as_str().unwrap()), "{alias}");
    }
    for entry in r["refused"].as_array().unwrap() {
        let alias = s(&entry["alias"]);
        assert_eq!(unhex(&s(&entry["utf8_hex"])), alias.as_bytes());
        assert!(!module_reads(&alias), "{alias}");
    }
}

#[test]
fn an_attestation_with_digits_is_accepted_and_refused_where_it_must() {
    let a = &vectors()["attestation"];
    let check = |text: &Value, signature: &Value| {
        verify_alias_attestation(
            s(text),
            s(signature),
            trusted(a),
            s(&a["sender_account_id"]),
            s(&a["sender_account_public_key"]),
            s(&a["deposited_at"]),
        )
    };
    let accepted = a["accepted"].as_array().unwrap();
    assert_eq!(accepted.len(), 2);
    for entry in accepted {
        assert_eq!(check(&entry["text"], &entry["signature"]).unwrap(), s(&entry["alias"]));
    }
    assert_eq!(accepted[1]["alias"].as_str().unwrap().len(), 30);
    for entry in a["refused"].as_array().unwrap() {
        assert_eq!(entry["error"], "InvalidAttestation");
        assert_eq!(check(&entry["text"], &entry["signature"]), Err(ChatCryptoError::InvalidAttestation));
    }
}

#[test]
fn the_alias_change_with_digits_reads() {
    let v = vectors();
    let c = &v["alias_change"];
    let b = &c["bound"]["binding"];
    let binding = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(s(&b["envelope_id"])),
        sender_account_id: s(&b["sender_account_id"]),
        sender_ed25519_key: s(&b["sender_ed25519_key"]),
        my_account_id: s(&b["my_account_id"]),
        my_ed25519_key: s(&b["my_ed25519_key"]),
        legacy_conversation_id: None,
    };
    assert_eq!(b["channel"], "mailbox");
    let decoded = decode_content(s(&c["bound"]["plaintext"]), binding).unwrap();
    let ContentBody::AliasChange { attestation, attestation_signature } = decoded.body else {
        panic!("not an alias_change");
    };
    let a = &v["attestation"];
    let verified = verify_alias_change(
        attestation,
        attestation_signature,
        trusted(a),
        s(&a["sender_account_id"]),
        s(&a["sender_account_public_key"]),
        s(&a["deposited_at"]),
    )
    .unwrap();
    assert_eq!(verified.alias, s(&c["alias"]));
    assert_eq!(verified.alias, "blaise.46");
    assert_eq!(verified.expires, c["expires"].as_i64().unwrap());
}

#[test]
fn the_vault_with_digits_and_its_worst_case_come_back() {
    let v = &vectors()["vault"];
    let after = &v["after_digits"];
    let opened = key().open_vault(s(&after["sealed"])).unwrap();
    assert_eq!(opened, vault_from(&after["vault"]));
    assert_eq!((opened.alias.as_str(), opened.retired[0].alias.as_str()), ("blaise.46", "blaise"));

    let w = &v["worst_case"];
    assert_eq!(w["json_bytes"], 11774);
    assert!(w["json_bytes"].as_u64().unwrap() <= 16341);
    let worst = key().open_vault(s(&w["sealed"])).unwrap();
    assert_eq!(worst, vault_from(&w["vault"]));
    assert_eq!((worst.alias.len(), worst.retired.len(), worst.tokens.len()), (30, 20, 10));
    assert!(worst.retired.iter().all(|r| r.alias.len() == 30));
}

#[test]
fn every_normalized_alias_is_one_the_module_reads() {
    for entry in vectors()["normalization"].as_array().unwrap() {
        assert_eq!(unhex(&s(&entry["input_utf8_hex"])), entry["input"].as_str().unwrap().as_bytes());
        if let Some(alias) = entry["alias"].as_str() {
            assert!(module_reads(alias), "{alias}");
        }
    }
}

#[test]
fn every_seal_is_the_hmac_of_the_alias_with_the_secret() {
    let k = key();
    for entry in vectors()["seals"].as_array().unwrap() {
        assert_eq!(k.alias_seal_secret(s(&entry["epoch"])).unwrap(), s(&entry["secret"]));
        let secret = vodozemac::base64_decode(s(&entry["secret"]).trim_end_matches('=')).unwrap();
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&secret), s(&entry["alias"]).as_bytes());
        let mut seal = b64(&prk);
        while !seal.len().is_multiple_of(4) {
            seal.push('=');
        }
        assert_eq!(seal, s(&entry["seal"]));
        assert!(module_reads(&s(&entry["alias"])));
    }
}

/// The generator gives the same file again: run with `--features vectors`.
#[cfg(feature = "vectors")]
#[test]
fn the_vault_vectors_with_digits_are_what_the_module_writes() {
    let v = &vectors()["vault"];
    let nonce: [u8; 24] = unhex(&s(&v["vault_nonce_hex"])).try_into().unwrap();
    for name in ["after_digits", "worst_case"] {
        let vault = vault_from(&v[name]["vault"]);
        assert_eq!(alias_vectors::seal_vault(&key(), vault, nonce).unwrap(), s(&v[name]["sealed"]), "{name}");
    }
}
