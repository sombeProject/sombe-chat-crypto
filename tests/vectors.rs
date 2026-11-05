//! Checks vectors/v1.json and vectors/v2.json, so a change to a wire format cannot slip
//! in unnoticed.

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

    // A version 1 content, still read since 0.5.0.
    let content = decode_content(result.plaintext).unwrap();
    assert_eq!(content.version, 1);
    assert_eq!(content.envelope_id, None);
    assert!(matches!(content.body, ContentBody::Text { ref body, .. } if body == "Salut ! Tu es rentré ?"));
}

#[test]
fn safety_number_is_reproducible() {
    let v = vectors();
    let n = &v["safety_number"];
    let identity = |i: &Value| VerifiedIdentity {
        wallet_address: s(&i["wallet_address"]),
        curve25519_key: s(&i["curve25519_key"]),
        ed25519_key: s(&i["ed25519_key"]),
        created_at: s(&i["created_at"]),
    };
    let (local, remote) = (identity(&n["local"]), identity(&n["remote"]));
    let verified = verify_identity(
        s(&n["local_statement"]),
        local.wallet_address.clone(),
        s(&n["local_wallet_signature"]),
    )
    .unwrap();
    assert_eq!(verified, local);

    let on_local = safety_number(local.clone(), remote.clone()).unwrap();
    assert_eq!(on_local.digits, s(&n["digits"]));
    assert_eq!(on_local.qr_payload, s(&n["qr_payload"]));
    assert_eq!(safety_number(remote, local).unwrap(), on_local);
}

/// The version 1 contents of vectors/v1.json (written by 0.4.0) are still read, each into
/// its own variant.
#[test]
fn version_1_contents_of_0_4_0_are_still_read() {
    let v = vectors();
    let read = |name: &str| decode_content(s(&v[name]["plaintext"])).unwrap();
    let edit = read("edit_content");
    assert_eq!((edit.version, edit.envelope_id.clone()), (1, None));
    assert_eq!(
        edit.body,
        ContentBody::Edit {
            client_message_id: s(&v["edit_content"]["client_message_id"]),
            edits_message_id: s(&v["edit_content"]["edits_message_id"]),
            body: s(&v["edit_content"]["body"]),
        }
    );
    assert_eq!(
        read("reaction_content").body,
        ContentBody::Reaction {
            client_message_id: s(&v["reaction_content"]["client_message_id"]),
            reacts_to_message_id: s(&v["reaction_content"]["reacts_to_message_id"]),
            body: s(&v["reaction_content"]["body"]),
        }
    );
    assert_eq!(
        read("reaction_remove_content").body,
        ContentBody::ReactionRemove {
            client_message_id: s(&v["reaction_remove_content"]["client_message_id"]),
            reacts_to_message_id: s(&v["reaction_remove_content"]["reacts_to_message_id"]),
        }
    );
    assert_eq!(
        read("delete_content").body,
        ContentBody::Delete {
            client_message_id: s(&v["delete_content"]["client_message_id"]),
            deletes_message_id: s(&v["delete_content"]["deletes_message_id"]),
        }
    );
}

fn v2_vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v2.json")).unwrap()
}

/// Every version 2 vector decodes, encodes back to the same bytes, and has its bucket size.
#[test]
fn version_2_contents_are_reproducible() {
    let v = v2_vectors();
    let kinds = v["v2"].as_object().unwrap();
    assert_eq!(kinds.len(), 11);
    for (name, vector) in kinds {
        let plaintext = s(&vector["plaintext"]);
        assert_eq!(plaintext.len() as u64, vector["bytes"].as_u64().unwrap(), "{name}");
        let content = decode_content(plaintext.clone()).unwrap();
        assert_eq!(content.version, 2, "{name}");
        assert_eq!(encode_content(content).unwrap(), plaintext, "{name}");
    }
    assert_eq!(v["v2"]["typing_start"]["bytes"], 256);
    assert_eq!(v["v2"]["typing_stop"]["bytes"], 256);
    assert_eq!(v["v2"]["receipt_delivered"]["bytes"], 512);
    assert_eq!(v["v2"]["receipt_read"]["bytes"], 512);
}

/// Each version 1 kind is read into the variant the vector names.
#[test]
fn version_1_vectors_read_into_their_variant() {
    let v = v2_vectors();
    let kinds = v["v1_read"].as_object().unwrap();
    assert_eq!(kinds.len(), 7);
    for (name, vector) in kinds {
        let content = decode_content(s(&vector["plaintext"])).unwrap();
        let read = &vector["read"];
        assert_eq!(content.version as u64, read["version"].as_u64().unwrap(), "{name}");
        assert_eq!(content.conversation_id, s(&read["conversation_id"]), "{name}");
        assert_eq!(content.envelope_id, None, "{name}");
        let b = &read["body"];
        let opt = |field: &str| b[field].as_str().map(str::to_owned);
        let expected = match b["variant"].as_str().unwrap() {
            "Text" => ContentBody::Text {
                client_message_id: s(&b["client_message_id"]),
                body: s(&b["body"]),
                reply_to_message_id: opt("reply_to_message_id"),
                reply_excerpt: opt("reply_excerpt"),
            },
            "Payment" => {
                ContentBody::Payment { client_message_id: s(&b["client_message_id"]), body: s(&b["body"]) }
            }
            "Edit" => ContentBody::Edit {
                client_message_id: s(&b["client_message_id"]),
                edits_message_id: s(&b["edits_message_id"]),
                body: s(&b["body"]),
            },
            "Reaction" => ContentBody::Reaction {
                client_message_id: s(&b["client_message_id"]),
                reacts_to_message_id: s(&b["reacts_to_message_id"]),
                body: s(&b["body"]),
            },
            "ReactionRemove" => ContentBody::ReactionRemove {
                client_message_id: s(&b["client_message_id"]),
                reacts_to_message_id: s(&b["reacts_to_message_id"]),
            },
            "Delete" => ContentBody::Delete {
                client_message_id: s(&b["client_message_id"]),
                deletes_message_id: s(&b["deletes_message_id"]),
            },
            other => panic!("unexpected variant {other}"),
        };
        assert_eq!(content.body, expected, "{name}");
    }
    // Upper case ids come out in lower case.
    assert_eq!(s(&kinds["text"]["read"]["conversation_id"]), "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01");
    assert_eq!(s(&kinds["edit"]["read"]["body"]["edits_message_id"]), "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34");
    // A version 1 card's comment becomes the body.
    assert_eq!(s(&kinds["payment"]["read"]["body"]["body"]), "Pour le marché");
}

#[test]
fn refused_vectors_give_their_error() {
    let v = v2_vectors();
    for json in v["unsupported_content"].as_array().unwrap() {
        assert!(matches!(decode_content(s(json)), Err(ChatCryptoError::UnsupportedContent { .. })), "{json}");
    }
    for json in v["invalid_content"].as_array().unwrap() {
        assert!(matches!(decode_content(s(json)), Err(ChatCryptoError::InvalidContent { .. })), "{json}");
    }
}
