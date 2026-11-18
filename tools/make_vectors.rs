//! Writes vectors/v7.json (since 0.10.0): the identity statement v4 and statements refused,
//! a sealing key and its pickle, envelopes sealed for it (each Olm message type) and sealed
//! envelopes the recipient must refuse, and the `identity_statement` content with contents
//! refused. Fixed keys and fixed randomness come from the `vectors` feature:
//! `cargo run --features vectors --bin make-vectors`. Running it again gives the same file;
//! tests/sealed_vectors.rs checks it.
//!
//! vectors/v1.json to vectors/v6.json stay as they are and are still checked; their
//! generators are in the history of this file (v6.json: commit 7142c9e). Never use these
//! ids, seeds or keys for anything real.

use serde_json::{json, Map, Value};
use sombe_chat_crypto::vectors::{
    clear_text, pickle_with_nonce, seal_clear, seal_with_ephemeral, sealing_key_from_ikm,
};
use sombe_chat_crypto::{
    decode_content, encode_content, verify_identity, ChatCryptoError, ChatSealingKey, ContentBinding,
    ContentBody, ContentChannel, Envelope, OutgoingContent, SealedRecipient, SealedSender, StatementFields,
};
use vodozemac::{base64_decode, base64_encode, Ed25519SecretKey};

const ACCOUNT_SEED: [u8; 32] = [0x5a; 32];
const IDENTITY_SEED: [u8; 32] = [0xa1; 32];
const CURVE_IKM: [u8; 32] = [0xc3; 32];
const SENDER_SEALING_IKM: [u8; 32] = [0xd4; 32];
const RECIPIENT_SEALING_IKM: [u8; 32] = [0xe5; 32];
const RECIPIENT_KEY_SEED: [u8; 32] = [0xb2; 32];
const PICKLE_KEY: [u8; 32] = [0x42; 32];
const PICKLE_NONCE: [u8; 24] = [0x24; 24];
const EPHEMERALS: [[u8; 32]; 3] = [[0x01; 32], [0x02; 32], [0x03; 32]];

const SENDER: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
const SENDER_IDENTITY: &str = "a1a1a1a1-1111-4111-8111-1111111111a1";
const RECIPIENT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const RECIPIENT_IDENTITY: &str = "b2b2b2b2-1111-4111-8111-1111111111b2";
const ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
const OTHER_ENVELOPE: &str = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89";
const CREATED: &str = "2026-11-18T09:00:00.183Z";
const OTHER_CREATED: &str = "2026-11-18T09:00:01.183Z";

fn main() {
    let (statement, statement_vectors) = statement_vectors();
    let recipient_key = sealing_key_from_ikm(RECIPIENT_SEALING_IKM);
    let pickle = pickle_with_nonce(&recipient_key, PICKLE_KEY, PICKLE_NONCE);
    let recipient = SealedRecipient {
        account_id: RECIPIENT.into(),
        identity_id: RECIPIENT_IDENTITY.into(),
        sealing_key: recipient_key.public_key(),
    };
    let sender = SealedSender { account_id: SENDER.into(), identity_id: SENDER_IDENTITY.into(), statement };

    let vectors = json!({
        "description": "SOMBE test vectors of sombe-chat-crypto 0.10.0: the identity statement v4 (the v3 text under the header SOMBE chat identity v4, plus a last body line sealing:<X25519 key>) and statements refused; a sealing key, its public key and its pickle; envelopes sealed with HPKE (RFC 9180, base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, info sombe:sealed:1, aad recipient_account_id, recipient_identity_id and envelope_id joined by a newline) and sealed envelopes refused; the identity_statement content and contents refused. Test seeds and test keys only: never use them for anything real.",
        "statement_v4": statement_vectors,
        "sealing_key": {
            "ikm_hex": hex(&RECIPIENT_SEALING_IKM),
            "public_key": recipient_key.public_key(),
            "pickle_key_hex": hex(&PICKLE_KEY),
            "pickle": pickle,
        },
        "sealed": sealed_vectors(&recipient, &sender, &recipient_key),
        "identity_statement": content_vectors(&sender.statement),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v7.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn fields_json(f: &StatementFields) -> Value {
    json!({
        "account_public_key": f.account_public_key,
        "curve25519_key": f.curve25519_key,
        "ed25519_key": f.ed25519_key,
        "sealing_key": f.sealing_key,
        "created_at": f.created_at,
        "identity_signature": f.identity_signature,
        "account_signature": f.account_signature,
    })
}

/// A statement signed with raw keys, written here from PROTOCOL.md and not by the module, so
/// that the module's reading is checked against the text of the format. `header` and
/// `sealing` let it write the statements a reader must refuse.
fn signed(header: &str, sealing: Option<&str>, created_at: &str) -> (String, StatementFields) {
    let account = Ed25519SecretKey::from_slice(&ACCOUNT_SEED);
    let identity = Ed25519SecretKey::from_slice(&IDENTITY_SEED);
    let account_public_key = b58(account.public_key().as_bytes());
    let curve25519_key = sealing_key_from_ikm(CURVE_IKM).public_key();
    let ed25519_key = identity.public_key().to_base64();
    let mut body = format!(
        "{header}\nprotocol:olm-v1\naccount:{account_public_key}\ncurve25519:{curve25519_key}\ned25519:{ed25519_key}\ncreated:{created_at}"
    );
    if let Some(sealing) = sealing {
        body.push_str(&format!("\nsealing:{sealing}"));
    }
    let identity_signature = identity.sign(body.as_bytes()).to_base64();
    let statement = format!("{body}\nidentity_signature:{identity_signature}");
    let account_signature = b58(&account.sign(statement.as_bytes()).to_bytes());
    let fields = StatementFields {
        account_public_key,
        curve25519_key,
        ed25519_key,
        sealing_key: sealing.map(str::to_owned),
        created_at: created_at.into(),
        identity_signature,
        account_signature,
    };
    (statement, fields)
}

fn error_name(e: &ChatCryptoError) -> &'static str {
    match e {
        ChatCryptoError::InvalidKey { .. } => "InvalidKey",
        ChatCryptoError::InvalidSignature => "InvalidSignature",
        ChatCryptoError::InvalidStatement { .. } => "InvalidStatement",
        ChatCryptoError::InvalidContent { .. } => "InvalidContent",
        ChatCryptoError::UnsupportedContent { .. } => "UnsupportedContent",
        ChatCryptoError::UnboundContent => "UnboundContent",
        ChatCryptoError::InvalidSealed => "InvalidSealed",
        other => panic!("unexpected {other:?}"),
    }
}

fn statement_vectors() -> (StatementFields, Value) {
    let sealing = sealing_key_from_ikm(SENDER_SEALING_IKM).public_key();
    let (text, fields) = signed("SOMBE chat identity v4", Some(&sealing), CREATED);
    let verified = verify_identity(fields.clone()).unwrap();
    assert_eq!(verified.sealing_key.as_deref(), Some(sealing.as_str()));
    let body = text.rsplit_once("\nidentity_signature:").unwrap().0.to_owned();

    let other_sealing = sealing_key_from_ikm([0xf6; 32]).public_key();
    let (_, under_v3_header) = signed("SOMBE chat identity v3", Some(&sealing), CREATED);
    let (_, v3) = signed("SOMBE chat identity v3", None, CREATED);
    let (_, v4_without_sealing) = signed("SOMBE chat identity v4", None, CREATED);
    let cases: Vec<(&str, StatementFields)> = vec![
        (
            "another sealing key than the one signed",
            StatementFields { sealing_key: Some(other_sealing), ..fields.clone() },
        ),
        ("the sealing key left out (read as a v3)", StatementFields { sealing_key: None, ..fields.clone() }),
        ("a v3 header with a sealing line, signed", under_v3_header),
        ("a v4 header without a sealing line, signed", v4_without_sealing),
        (
            "the sealing key with padding",
            StatementFields { sealing_key: Some(format!("{sealing}=")), ..fields.clone() },
        ),
        (
            "a sealing key of 31 bytes",
            StatementFields { sealing_key: Some(base64_encode([7u8; 31])), ..fields.clone() },
        ),
        ("the sealing key empty", StatementFields { sealing_key: Some(String::new()), ..fields.clone() }),
    ];
    let refused: Vec<Value> = cases
        .into_iter()
        .map(|(name, f)| {
            let error = error_name(&verify_identity(f.clone()).expect_err(name));
            json!({ "name": name, "fields": fields_json(&f), "error": error })
        })
        .collect();
    // A v3 still verifies, without a sealing key.
    assert_eq!(verify_identity(v3.clone()).unwrap().sealing_key, None);

    let value = json!({
        "account_seed_hex": hex(&ACCOUNT_SEED),
        "identity_seed_hex": hex(&IDENTITY_SEED),
        "sealing_ikm_hex": hex(&SENDER_SEALING_IKM),
        "body": body,
        "statement": text,
        "fields": fields_json(&fields),
        "v3_fields": fields_json(&v3),
        "refused": refused,
    });
    (fields, value)
}

fn sealed_vectors(
    recipient: &SealedRecipient,
    sender: &SealedSender,
    recipient_key: &ChatSealingKey,
) -> Value {
    let olm = |olm_type: u8, bytes: usize| Envelope {
        protocol: "olm-v1".into(),
        olm_type,
        ciphertext: base64_encode((0..bytes).map(|i| (i * 7 % 251) as u8).collect::<Vec<u8>>()),
    };
    let envelopes =
        [("a first message (olm_type 0)", olm(0, 780)), ("a following message (olm_type 1)", olm(1, 650))];
    let opened: Vec<Value> = envelopes
        .iter()
        .zip(EPHEMERALS)
        .map(|((name, envelope), ephemeral)| {
            let ciphertext = seal_with_ephemeral(ephemeral, recipient, ENVELOPE, sender, envelope).unwrap();
            let read = recipient_key
                .open_sealed(ciphertext.clone(), RECIPIENT.into(), RECIPIENT_IDENTITY.into(), ENVELOPE.into())
                .unwrap();
            assert_eq!(&read.sender, sender);
            assert_eq!(&read.envelope, envelope);
            json!({
                "name": name,
                "ephemeral_ikm_hex": hex(&ephemeral),
                "envelope_id": ENVELOPE,
                "olm_type": envelope.olm_type,
                "olm_ciphertext": envelope.ciphertext,
                "clear": clear_text(sender, envelope),
                "ciphertext": ciphertext,
            })
        })
        .collect();

    let good = opened[1]["ciphertext"].as_str().unwrap().to_owned();
    let clear: Map<String, Value> = serde_json::from_str(opened[1]["clear"].as_str().unwrap()).unwrap();
    // A changed clear text, padded again to a multiple of 256 bytes so that only the change
    // is refused.
    let reclear = |change: &dyn Fn(&mut Map<String, Value>)| {
        let mut m = clear.clone();
        change(&mut m);
        m.remove("pad");
        let unpadded = serde_json::to_string(&m).unwrap().len();
        let target = (unpadded + 9).div_ceil(256) * 256;
        m.insert("pad".into(), Value::from(" ".repeat(target - unpadded - 9)));
        seal_clear(EPHEMERALS[2], recipient, ENVELOPE, &serde_json::to_string(&m).unwrap())
    };
    let short_pad = serde_json::to_string(&clear).unwrap().replacen("\"pad\":\" ", "\"pad\":\"", 1);
    let mut flipped = base64_decode(&good).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let mine = (RECIPIENT, RECIPIENT_IDENTITY, ENVELOPE);
    let cases: Vec<(&str, String, (&str, &str, &str))> = vec![
        ("another envelope id", good.clone(), (RECIPIENT, RECIPIENT_IDENTITY, OTHER_ENVELOPE)),
        ("another recipient account", good.clone(), (SENDER, RECIPIENT_IDENTITY, ENVELOPE)),
        ("another recipient identity", good.clone(), (RECIPIENT, SENDER_IDENTITY, ENVELOPE)),
        ("a changed byte", base64_encode(&flipped), mine),
        ("cut inside the encapsulated key", good[..40].to_owned(), mine),
        ("base64 with padding", format!("{good}="), mine),
        (
            "clear text version 2",
            reclear(&|m| {
                m.insert("v".into(), 2.into());
            }),
            mine,
        ),
        (
            "clear text with an unknown field",
            reclear(&|m| {
                m.insert("x".into(), "y".into());
            }),
            mine,
        ),
        (
            "clear text with an upper case sender id",
            reclear(&|m| {
                m.insert("sender_account_id".into(), SENDER.to_uppercase().into());
            }),
            mine,
        ),
        (
            "clear text whose statement does not hold",
            reclear(&|m| {
                m.insert("created_at".into(), OTHER_CREATED.into());
            }),
            mine,
        ),
        (
            "clear text with olm_type 2",
            reclear(&|m| {
                m.insert("olm_type".into(), 2.into());
            }),
            mine,
        ),
        (
            "clear text not a multiple of 256 bytes",
            seal_clear(EPHEMERALS[2], recipient, ENVELOPE, &short_pad),
            mine,
        ),
    ];
    let refused: Vec<Value> = cases
        .into_iter()
        .map(|(name, ciphertext, (account, identity, envelope_id))| {
            let read = recipient_key.open_sealed(
                ciphertext.clone(),
                account.into(),
                identity.into(),
                envelope_id.into(),
            );
            assert_eq!(read, Err(ChatCryptoError::InvalidSealed), "{name}");
            json!({
                "name": name,
                "ciphertext": ciphertext,
                "my_account_id": account,
                "my_identity_id": identity,
                "envelope_id": envelope_id,
                "error": "InvalidSealed",
            })
        })
        .collect();

    json!({
        "recipient": {
            "account_id": recipient.account_id,
            "identity_id": recipient.identity_id,
            "sealing_key": recipient.sealing_key,
        },
        "sender": {
            "account_id": sender.account_id,
            "identity_id": sender.identity_id,
            "statement": fields_json(&sender.statement),
        },
        "opened": opened,
        "refused": refused,
    })
}

fn binding_json(b: &ContentBinding) -> Value {
    json!({
        "channel": match b.channel { ContentChannel::Mailbox => "mailbox", ContentChannel::Websocket => "websocket" },
        "envelope_id": b.envelope_id,
        "sender_account_id": b.sender_account_id,
        "sender_ed25519_key": b.sender_ed25519_key,
        "my_account_id": b.my_account_id,
        "my_ed25519_key": b.my_ed25519_key,
        "legacy_conversation_id": b.legacy_conversation_id,
    })
}

fn content_vectors(statement: &StatementFields) -> Value {
    let sender_key = statement.ed25519_key.clone();
    let recipient_key = Ed25519SecretKey::from_slice(&RECIPIENT_KEY_SEED).public_key().to_base64();
    let mailbox = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(ENVELOPE.into()),
        sender_account_id: SENDER.into(),
        sender_ed25519_key: sender_key.clone(),
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: recipient_key.clone(),
        legacy_conversation_id: None,
    };
    let body = ContentBody::IdentityStatement { statement: statement.clone() };
    let plaintext = encode_content(OutgoingContent {
        sender_account_id: SENDER.into(),
        sender_ed25519_key: sender_key,
        recipient_account_id: RECIPIENT.into(),
        recipient_ed25519_key: recipient_key,
        envelope_id: Some(ENVELOPE.into()),
        body: body.clone(),
    })
    .unwrap();
    assert_eq!(decode_content(plaintext.clone(), mailbox.clone()).unwrap().body, body);

    let map: Map<String, Value> = serde_json::from_str(&plaintext).unwrap();
    let edit = |change: &dyn Fn(&mut Map<String, Value>)| {
        let mut m = map.clone();
        change(&mut m);
        serde_json::to_string(&m).unwrap()
    };
    let websocket =
        ContentBinding { channel: ContentChannel::Websocket, envelope_id: None, ..mailbox.clone() };
    let other_identity = Ed25519SecretKey::from_slice(&[0x77; 32]).public_key().to_base64();
    let other_sender = ContentBinding { sender_ed25519_key: other_identity.clone(), ..mailbox.clone() };
    let (_, v3) = signed("SOMBE chat identity v3", None, CREATED);
    let cases: Vec<(&str, String, &ContentBinding)> = vec![
        ("an identity_statement through the websocket", plaintext.clone(), &websocket),
        (
            "an identity_statement in version 2",
            edit(&|m| {
                m.insert("v".into(), 2.into());
            }),
            &mailbox,
        ),
        (
            "an identity_statement without its sealing key",
            edit(&|m| {
                m.remove("sealing_key");
            }),
            &mailbox,
        ),
        (
            "an identity_statement whose statement does not hold",
            edit(&|m| {
                m.insert("created_at".into(), OTHER_CREATED.into());
            }),
            &mailbox,
        ),
        (
            "an identity_statement of another identity than the sender's",
            edit(&|m| {
                m.insert("sender_ed25519".into(), other_identity.clone().into());
            }),
            &other_sender,
        ),
        (
            "an identity_statement with an unknown field",
            edit(&|m| {
                m.insert("statement_version".into(), 4.into());
            }),
            &mailbox,
        ),
        (
            "an identity_statement carrying the signatures of a v3",
            edit(&|m| {
                m.insert("account_signature".into(), v3.account_signature.clone().into());
                m.insert("identity_signature".into(), v3.identity_signature.clone().into());
            }),
            &mailbox,
        ),
    ];
    let refused: Vec<Value> = cases
        .into_iter()
        .map(|(name, plaintext, binding)| {
            let error = error_name(&decode_content(plaintext.clone(), binding.clone()).expect_err(name));
            json!({ "name": name, "plaintext": plaintext, "binding": binding_json(binding), "error": error })
        })
        .collect();
    json!({
        "bound": { "plaintext": plaintext, "binding": binding_json(&mailbox), "statement": fields_json(statement) },
        "refused": refused,
    })
}
