//! Writes vectors/v6.json (since 0.9.0): the access key drawn from a profile key and its
//! verifier, the keys refused for their form, the `access_key` content, an acceptance with
//! and without an access key (the latter as 0.8.1 wrote it), and the contents refused for
//! their form or their channel. Running it again gives the same file; tests/access_vectors.rs
//! checks it.
//!
//! vectors/v1.json (0.4.0), vectors/v2.json (content version 2, 0.5.0 and 0.6.0),
//! vectors/v3.json (the account key, 0.7.0), vectors/v4.json (the alias attestation and
//! content version 3, 0.8.0) and vectors/v5.json (content version 4, 0.8.1) stay as they
//! are: tests/content_vectors.rs still reads v5.json and encodes each of its contents back
//! to the same bytes. Their generators are in the history of this file. Never use these
//! ids, seeds or keys for anything real.

use serde_json::{json, Value};
use sombe_chat_crypto::{
    access_key_verifier, decode_content, derive_access_key, encode_content, AccessKeyGrant, ChatCryptoError,
    ContentBinding, ContentBody, ContentChannel, OutgoingContent,
};
use vodozemac::Ed25519SecretKey;

/// The seeds of the test identities' ed25519 keys: the sender, the recipient.
const SENDER_KEY_SEED: [u8; 32] = [0xa1; 32];
const RECIPIENT_KEY_SEED: [u8; 32] = [0xb2; 32];
/// Test profile keys: counting bytes, then all ones.
const PROFILE_KEYS: [[u8; 32]; 2] = [
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31,
    ],
    [0xff; 32],
];

fn main() {
    let v4: Value = serde_json::from_str(include_str!("../vectors/v4.json")).unwrap();
    let attestation = s_of(&v4["server_signs"]["text"]);
    let attestation_signature = s_of(&v4["server_signs"]["signature"]);

    let derived: Vec<Value> = PROFILE_KEYS
        .iter()
        .map(|profile_key| {
            let access_key = derive_access_key(profile_key.to_vec()).unwrap();
            let verifier = access_key_verifier(access_key.clone()).unwrap();
            json!({ "profile_key_hex": hex(profile_key), "access_key": access_key, "verifier": verifier })
        })
        .collect();
    let access_key = s_of(&derived[0]["access_key"]);

    let refused_profile_keys: Vec<Value> = [31usize, 33, 0]
        .into_iter()
        .map(|len| {
            assert!(matches!(derive_access_key(vec![7; len]), Err(ChatCryptoError::InvalidKey { .. })));
            json!({ "name": format!("a profile key of {len} bytes"), "profile_key_hex": hex(&vec![7; len]) })
        })
        .collect();
    let refused_access_keys: Vec<Value> = [
        ("15 bytes", "AAECAwQFBgcICQoLDA0O".to_owned()),
        ("17 bytes", "AAECAwQFBgcICQoLDA0ODxA".to_owned()),
        ("base64 with padding", format!("{access_key}==")),
        ("URL safe base64", "_-_-_-_-_-_-_-_-_-_-_w".to_owned()),
        ("a spelling that is not the one of its bytes", "AAECAwQFBgcICQoLDA0ODx".to_owned()),
        ("empty", String::new()),
    ]
    .into_iter()
    .map(|(name, key)| {
        assert!(
            matches!(access_key_verifier(key.clone()), Err(ChatCryptoError::InvalidKey { .. })),
            "{name}"
        );
        json!({ "name": name, "access_key": key })
    })
    .collect();

    let vectors = json!({
        "description": "SOMBE test vectors of sombe-chat-crypto 0.9.0: the access key (HKDF-SHA256 of the 32 byte profile key, empty salt, info sombe:access_key:1, 16 bytes) and its verifier (SHA-256 of the 16 bytes), both base64 without padding; keys refused for their form; the access_key content and an acceptance with and without an access key; contents refused. Test seeds and test keys only: never use them for anything real.",
        "access_key": {
            "derived": derived,
            "refused_profile_keys": refused_profile_keys,
            "refused_access_keys": refused_access_keys,
        },
        "identity_keys": {
            "sender": {"seed_hex": hex(&SENDER_KEY_SEED), "ed25519": identity_key(&SENDER_KEY_SEED)},
            "recipient": {"seed_hex": hex(&RECIPIENT_KEY_SEED), "ed25519": identity_key(&RECIPIENT_KEY_SEED)},
        },
        "content_v4": content_vectors(&access_key, &attestation, &attestation_signature),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v6.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The ed25519 public key of a seed, as an identity writes it: base64 without padding.
fn identity_key(seed: &[u8; 32]) -> String {
    Ed25519SecretKey::from_slice(seed).public_key().to_base64()
}

const SENDER: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
const RECIPIENT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const CONTENT_ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
const CONTENT_REQUEST: &str = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89";

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

/// The contents of 0.9.0 bound to their element, then contents refused with their error.
fn content_vectors(access_key: &str, attestation: &str, attestation_signature: &str) -> Value {
    let mailbox = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(CONTENT_ENVELOPE.into()),
        sender_account_id: SENDER.into(),
        sender_ed25519_key: identity_key(&SENDER_KEY_SEED),
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: identity_key(&RECIPIENT_KEY_SEED),
        legacy_conversation_id: None,
    };
    let grant = AccessKeyGrant { access_key: access_key.into(), generation: 1 };
    let accept = |access_key: Option<AccessKeyGrant>| ContentBody::ContactAccept {
        request_id: CONTENT_REQUEST.into(),
        attestation: attestation.into(),
        attestation_signature: attestation_signature.into(),
        access_key,
    };
    let kinds: Vec<(&str, ContentBody)> = vec![
        ("access_key", ContentBody::AccessKey { grant: grant.clone() }),
        (
            "access_key_last_generation",
            ContentBody::AccessKey {
                grant: AccessKeyGrant { access_key: access_key.into(), generation: 2_147_483_647 },
            },
        ),
        ("contact_accept_with_access_key", accept(Some(grant.clone()))),
        ("contact_accept_without_access_key", accept(None)),
    ];
    let mut bound = serde_json::Map::new();
    for (name, body) in kinds {
        let content = OutgoingContent {
            sender_account_id: SENDER.into(),
            sender_ed25519_key: mailbox.sender_ed25519_key.clone(),
            recipient_account_id: RECIPIENT.into(),
            recipient_ed25519_key: mailbox.my_ed25519_key.clone(),
            envelope_id: mailbox.envelope_id.clone(),
            body: body.clone(),
        };
        let plaintext = encode_content(content).unwrap();
        let read = decode_content(plaintext.clone(), mailbox.clone()).unwrap();
        assert_eq!((read.version, read.body), (4, body), "{name}");
        bound.insert(
            name.into(),
            json!({ "bytes": plaintext.len(), "plaintext": plaintext, "binding": binding_json(&mailbox) }),
        );
    }

    // Each refused content is a bound one with one change, padding left as it was.
    let edit = |name: &str, change: &dyn Fn(&mut serde_json::Map<String, Value>)| -> String {
        let mut map: serde_json::Map<String, Value> =
            serde_json::from_str(&s_of(&bound[name]["plaintext"])).unwrap();
        change(&mut map);
        serde_json::to_string(&map).unwrap()
    };
    let websocket =
        ContentBinding { channel: ContentChannel::Websocket, envelope_id: None, ..mailbox.clone() };
    let cases: Vec<(&str, String, &ContentBinding, &str)> = vec![
        (
            "an acceptance with access_key but no access_key_generation",
            edit("contact_accept_with_access_key", &|m| {
                m.remove("access_key_generation");
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "an acceptance with access_key_generation but no access_key",
            edit("contact_accept_with_access_key", &|m| {
                m.remove("access_key");
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "an access key of 15 bytes",
            edit("access_key", &|m| {
                m.insert("access_key".into(), "AAECAwQFBgcICQoLDA0O".into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "an access key with base64 padding",
            edit("access_key", &|m| {
                m.insert("access_key".into(), format!("{access_key}==").into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "generation 0",
            edit("access_key", &|m| {
                m.insert("generation".into(), 0.into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "generation above 2147483647",
            edit("access_key", &|m| {
                m.insert("generation".into(), 2_147_483_648u64.into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "generation written as a string",
            edit("access_key", &|m| {
                m.insert("generation".into(), "1".into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "an unknown field in an access_key content",
            edit("access_key", &|m| {
                m.insert("access_key_generation".into(), 1.into());
            }),
            &mailbox,
            "InvalidContent",
        ),
        (
            "an access_key content in version 2",
            edit("access_key", &|m| {
                m.insert("v".into(), 2.into());
            }),
            &mailbox,
            "UnsupportedContent",
        ),
        (
            "an access_key content through the websocket",
            s_of(&bound["access_key"]["plaintext"]),
            &websocket,
            "UnboundContent",
        ),
    ];
    let refused: Vec<Value> = cases
        .into_iter()
        .map(|(name, plaintext, binding, error)| {
            let read = decode_content(plaintext.clone(), binding.clone());
            let got = match read {
                Err(ChatCryptoError::InvalidContent { .. }) => "InvalidContent",
                Err(ChatCryptoError::UnsupportedContent { .. }) => "UnsupportedContent",
                Err(ChatCryptoError::UnboundContent) => "UnboundContent",
                other => panic!("{name}: {other:?}"),
            };
            assert_eq!(got, error, "{name}");
            json!({ "name": name, "plaintext": plaintext, "binding": binding_json(binding), "error": error })
        })
        .collect();

    json!({ "bound": bound, "refused": refused })
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
