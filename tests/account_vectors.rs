//! Checks vectors/v3.json (the account key, since 0.7.0), so a change to one of its
//! formats cannot slip in unnoticed. The ChatPay server replays the same file.

use serde_json::Value;
use sha2::{Digest, Sha256};
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v3.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wallet() -> Vec<u8> {
    unhex(&s(&vectors()["wallet"]["seed_hex"]))
}

fn first_key() -> DerivedAccount {
    derive_account_key(wallet(), 1).unwrap()
}

#[test]
fn account_keys_of_each_generation() {
    let v = vectors();
    for k in v["account_keys"].as_array().unwrap() {
        let generation = k["generation"].as_u64().unwrap() as u16;
        let derived = derive_account_key(wallet(), generation).unwrap();
        assert_eq!(derived.key.public_key(), s(&k["public_key"]));
        assert_eq!(s(&k["info"]), format!("sombe:chat_account:{generation}"));
    }
    let house = &v["house_vector"];
    for k in house["keys"].as_array().unwrap() {
        let derived = derive_account_key(
            unhex(&s(&house["wallet_seed_hex"])),
            k["generation"].as_u64().unwrap() as u16,
        )
        .unwrap();
        assert_eq!(derived.key.public_key(), s(&k["public_key"]));
    }
}

#[test]
fn the_sealed_key_opens() {
    let v = &vectors()["sealed_key"];
    let key = ChatAccountKey::unseal(s(&v["sealed"]), unhex(&s(&v["sealing_key_hex"]))).unwrap();
    assert_eq!(key.public_key(), first_key().key.public_key());
    assert_eq!(key.generation(), 1);
    let bytes = vodozemac::base64_decode(s(&v["sealed"])).unwrap();
    assert_eq!(bytes.len(), 75);
    assert_eq!(bytes[0], 1);
    assert_eq!(hex(&bytes[1..25]), s(&v["nonce_hex"]));
}

#[test]
fn wallet_card_and_its_fingerprint() {
    let v = &vectors()["wallet_card"];
    let card = first_key().card;
    assert_eq!(card.wallet_address, s(&v["wallet_address"]));
    assert_eq!(card.account_public_key, s(&v["account_public_key"]));
    assert_eq!(card.wallet_signature, s(&v["wallet_signature"]));
    let text =
        format!("SOMBE wallet card v1\nwallet:{}\naccount:{}", card.wallet_address, card.account_public_key);
    assert_eq!(text, s(&v["text"]));
    // The fingerprint is of the text alone, signature excluded.
    assert_eq!(hex(&Sha256::digest(text.as_bytes())), s(&v["fingerprint"]));
    assert_eq!(verify_wallet_card(card), Ok(()));
}

#[test]
fn identity_statement_v3() {
    let v = &vectors()["identity_v3"];
    let olm = ChatCrypto::restore_account(s(&v["account_pickle"]), unhex(&s(&v["pickle_key_hex"]))).unwrap();
    let signed = first_key().key.sign_identity_statement(olm, s(&v["created_at"])).unwrap();
    assert_eq!(signed.statement, s(&v["statement"]));
    assert_eq!(signed.identity_signature, s(&v["identity_signature"]));
    assert_eq!(signed.account_signature, s(&v["account_signature"]));
    assert_eq!(
        signed.statement,
        format!("{}\nidentity_signature:{}", s(&v["body"]), s(&v["identity_signature"]))
    );

    let verified = verify_identity(StatementFields {
        account_public_key: s(&v["account_public_key"]),
        curve25519_key: s(&v["curve25519_key"]),
        ed25519_key: s(&v["ed25519_key"]),
        created_at: s(&v["created_at"]),
        identity_signature: s(&v["identity_signature"]),
        account_signature: s(&v["account_signature"]),
    })
    .unwrap();
    assert_eq!(verified.account_public_key, s(&v["account_public_key"]));
}

#[test]
fn sign_in_and_account_move() {
    let v = vectors();
    let der = unhex(&s(&v["device"]["public_key_der_hex"]));
    assert_eq!(hex(&Sha256::digest(&der)), s(&v["device"]["fingerprint"]));
    let derived = first_key();
    assert_eq!(
        derived.key.sign_sign_in(s(&v["sign_in"]["message"]), der.clone()).unwrap(),
        s(&v["sign_in"]["account_signature"])
    );
    for m in v["account_move"].as_array().unwrap() {
        let identity = m["identity_id"].as_str().map(str::to_owned);
        let signature = derived.key.sign_move(derived.card.clone(), der.clone(), identity).unwrap();
        assert_eq!(signature, s(&m["account_signature"]));
    }
}

#[test]
fn rotation_proofs() {
    let v = vectors();
    let check = |proof: &RotationProof, card: &WalletCard, expected: &Value| {
        assert_eq!(proof.old_account_public_key, s(&expected["old_account_public_key"]));
        assert_eq!(proof.new_account_public_key, s(&expected["new_account_public_key"]));
        assert_eq!(u64::from(proof.generation), expected["generation"].as_u64().unwrap());
        assert_eq!(proof.old_signature, s(&expected["old_signature"]));
        assert_eq!(proof.new_signature, s(&expected["new_signature"]));
        assert_eq!(card.wallet_signature, s(&expected["card"]["wallet_signature"]));
        assert_eq!(
            s(&expected["text"]),
            format!(
                "SOMBE account rotate v1\nold:{}\nnew:{}\ngeneration:{}",
                proof.old_account_public_key, proof.new_account_public_key, proof.generation
            )
        );
    };
    let rotation = first_key().key.rotate(wallet()).unwrap();
    check(&rotation.proof, &rotation.card, &v["rotation"]);
    let proven = prove_rotation(wallet(), 1, 3).unwrap();
    check(&proven.proof, &proven.card, &v["rotation_1_to_3"]);
}

#[test]
fn account_rotation_contents() {
    let v = vectors();
    let plaintext = s(&v["account_rotation_content"]["plaintext"]);
    assert_eq!(plaintext.len() as u64, v["account_rotation_content"]["bytes"].as_u64().unwrap());
    let content = decode_content(plaintext.clone()).unwrap();
    assert_eq!(encode_content(content.clone()).unwrap(), plaintext);
    let ContentBody::AccountRotation { rotation } = content.body else { panic!("an account rotation") };
    assert_eq!(rotation.new_account_public_key, s(&v["rotation"]["new_account_public_key"]));
    for invalid in v["invalid_account_rotation_content"].as_array().unwrap() {
        assert!(
            matches!(decode_content(s(invalid)), Err(ChatCryptoError::InvalidContent { .. })),
            "{invalid}"
        );
    }
}

#[test]
fn safety_number_v2() {
    let v = &vectors()["safety_number"];
    let identity = |i: &Value| VerifiedIdentity {
        account_public_key: s(&i["account_public_key"]),
        curve25519_key: s(&i["curve25519_key"]),
        ed25519_key: s(&i["ed25519_key"]),
        created_at: "2026-11-11T09:00:00Z".into(),
    };
    let (local, remote) = (identity(&v["local"]), identity(&v["remote"]));
    let number = safety_number(local.clone(), remote.clone()).unwrap();
    assert_eq!(number.digits, s(&v["digits"]));
    assert_eq!(number.qr_payload, s(&v["qr_payload"]));
    assert_eq!(safety_number(remote, local).unwrap(), number);
}
