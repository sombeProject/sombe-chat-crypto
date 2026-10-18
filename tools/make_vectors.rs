//! Writes vectors/v1.json: fixed inputs and outputs any implementation of PROTOCOL.md
//! must reproduce (wallet signature, statement, one time key signature, content, an edit
//! and a reaction content (since 0.2.0), a first message that decrypts with the pickled
//! account, and a safety number (since 0.3.0)). Run once; the file is
//! committed and checked by tests/vectors.rs. Never use these keys for anything real.

use serde_json::json;
use sombe_chat_crypto::{
    encode_content, safety_number, verify_identity, ChatCrypto, ContentKind, MessageContent, VerifiedIdentity,
};
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
        edits_message_id: None,
        reacts_to_message_id: None,
    };
    let plaintext = encode_content(content).unwrap();

    let edit = MessageContent {
        conversation_id: "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01".into(),
        client_message_id: "2d9a6f8c-5e3b-4a0c-9f4d-7b8c9e0f1a23".into(),
        kind: ContentKind::Edit,
        body: Some("Salut ! Tu es rentrée ?".into()),
        reply_excerpt: None,
        comment: None,
        edits_message_id: Some("3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34".into()),
        reacts_to_message_id: None,
    };
    let edit_plaintext = encode_content(edit.clone()).unwrap();

    let reaction = MessageContent {
        conversation_id: "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01".into(),
        client_message_id: "4f1c8b0e-7a5d-4c2e-9b6f-9d0e1f2a3c45".into(),
        kind: ContentKind::Reaction,
        body: Some("❤️".into()),
        reply_excerpt: None,
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: Some("3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34".into()),
    };
    let reaction_plaintext = encode_content(reaction.clone()).unwrap();

    let alice = ChatCrypto::create_account();
    let alice_seed: [u8; 32] = std::array::from_fn(|i| 32 + i as u8);
    let alice_wallet = Ed25519SecretKey::from_slice(&alice_seed);
    let alice_address = bs58::encode(alice_wallet.public_key().as_bytes()).into_string();
    let alice_statement = alice.identity_statement(alice_address.clone(), CREATED.into()).unwrap();
    let alice_signature =
        bs58::encode(alice_wallet.sign(alice_statement.as_bytes()).to_bytes()).into_string();
    let alice_identity =
        verify_identity(alice_statement.clone(), alice_address, alice_signature.clone()).unwrap();
    let bob_identity =
        verify_identity(statement.clone(), wallet_address.clone(), wallet_signature.clone()).unwrap();
    let safety = safety_number(alice_identity.clone(), bob_identity.clone()).unwrap();

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
        "edit_content": {
            "conversation_id": edit.conversation_id,
            "client_message_id": edit.client_message_id,
            "edits_message_id": edit.edits_message_id,
            "body": edit.body,
            "plaintext": edit_plaintext,
        },
        "safety_number": {
            "local": identity_json(&alice_identity),
            "local_statement": alice_statement,
            "local_wallet_signature": alice_signature,
            "remote": identity_json(&bob_identity),
            "digits": safety.digits,
            "qr_payload": safety.qr_payload,
        },
        "reaction_content": {
            "conversation_id": reaction.conversation_id,
            "client_message_id": reaction.client_message_id,
            "reacts_to_message_id": reaction.reacts_to_message_id,
            "body": reaction.body,
            "plaintext": reaction_plaintext,
        },
    });

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn identity_json(identity: &VerifiedIdentity) -> serde_json::Value {
    json!({
        "wallet_address": identity.wallet_address,
        "curve25519_key": identity.curve25519_key,
        "ed25519_key": identity.ed25519_key,
        "created_at": identity.created_at,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
