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
use sombe_chat_crypto::{verify_alias_attestation, TrustedAttestationKey};
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
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v4.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}
