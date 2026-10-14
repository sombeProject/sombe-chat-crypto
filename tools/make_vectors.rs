//! Writes vectors/v1.json: fixed inputs and outputs any implementation of PROTOCOL.md
//! must reproduce (wallet signature, statement, one time key signature, content, and a
//! first message that decrypts with the pickled account). Run once; the file is
//! committed and checked by tests/vectors.rs. Never use these keys for anything real.

use serde_json::json;
use sombe_chat_crypto::{encode_content, ChatCrypto, ContentKind, MessageContent};
use vodozemac::Ed25519SecretKey;

const PICKLE_KEY: [u8; 32] = [0x42; 32];
const CREATED: &str = "2026-10-14T18:30:01.183Z";

fn main() {
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let wallet = Ed25519SecretKey::from_slice(&seed);
    let wallet_address = bs58::encode(wallet.public_key().as_bytes()).into_string();

    let bob = ChatCrypto::create_account();
    let statement = bob.identity_statement(wallet_address.clone(), CREATED.into()).unwrap();
    let wallet_signature = bs58::encode(wallet.sign(statement.as_bytes()).to_bytes()).into_string();
    let one_time_key = bob.generate_one_time_keys(1).remove(0);
    bob.mark_keys_published();
    let bob_pickle = bob.pickle(PICKLE_KEY.to_vec()).unwrap();

    let content = MessageContent {
        conversation_id: "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01".into(),
        client_message_id: "1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12".into(),
        kind: ContentKind::Text,
        body: Some("Salut ! Tu es rentré ?".into()),
        reply_excerpt: None,
        comment: None,
    };
    let plaintext = encode_content(content).unwrap();

    let alice = ChatCrypto::create_account();
    let first = alice
        .encrypt_for(
            bob.identity_keys(),
            None,
            Some(one_time_key.clone()),
            plaintext.clone(),
            PICKLE_KEY.to_vec(),
        )
        .unwrap();

    let vectors = json!({
        "description": "SOMBE chat crypto test vectors, protocol olm-v1. Test keys only.",
        "pickle_key_hex": hex(&PICKLE_KEY),
        "wallet": {
            "seed_hex": hex(&seed),
            "address": wallet_address,
        },
        "identity": {
            "curve25519_key": bob.identity_keys().curve25519_key,
            "ed25519_key": bob.identity_keys().ed25519_key,
            "created_at": CREATED,
            "statement": statement,
            "wallet_signature": wallet_signature,
            "account_pickle": bob_pickle,
        },
        "one_time_key": {
            "key_id": one_time_key.key_id,
            "public_key": one_time_key.public_key,
            "is_fallback": one_time_key.is_fallback,
            "signed_text": sombe_chat_crypto::one_time_key_signed_text(one_time_key.clone()),
            "signature": one_time_key.signature,
        },
        "first_message": {
            "sender": {
                "curve25519_key": alice.identity_keys().curve25519_key,
                "ed25519_key": alice.identity_keys().ed25519_key,
            },
            "envelope": {
                "protocol": first.envelope.protocol,
                "olm_type": first.envelope.olm_type,
                "ciphertext": first.envelope.ciphertext,
            },
            "plaintext": plaintext,
        },
    });

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
