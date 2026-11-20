//! Writes vectors/v8.json (since 0.11.0): the alias vault (its key, the key sealed, the
//! block, the blocks a reader must refuse), the alias token (prepared, signed blind,
//! finalized, verified, refused, and its memo) and the `alias_change` content. Fixed keys and
//! fixed randomness come from the `vectors` feature:
//! `cargo run --features vectors --bin make-vectors`. Running it again gives the same file;
//! tests/alias_vectors.rs checks it.
//!
//! vectors/v1.json to vectors/v7.json stay as they are and are still checked; their
//! generators are in the history of this file (v7.json: commit 964067a). Never use these ids,
//! seeds or keys for anything real.

use blind_rsa_signatures::{Randomized, SecretKey, Sha384, PSS};
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use sombe_chat_crypto::alias_vectors;
use sombe_chat_crypto::{
    alias_token_finalize, alias_token_memo, alias_token_verify, decode_content, derive_alias_vault_key,
    encode_content, verify_alias_change, AliasVault, AliasVaultKey, ChatCryptoError, ContentBinding,
    ContentBody, ContentChannel, OutgoingContent, RetiredAlias, TrustedAttestationKey, VaultToken,
};
use vodozemac::{base64_decode, base64_encode, Ed25519SecretKey};

#[path = "../tests/common/rsa.rs"]
mod rsa;

const WALLET_SEED: [u8; 32] = [0x77; 32];
const SEALING_KEY: [u8; 32] = [0x42; 32];
const KEY_SEAL_NONCE: [u8; 24] = [0x24; 24];
const VAULT_NONCE: [u8; 24] = [0x31; 24];
const ACCOUNT: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
const OTHER_ACCOUNT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const KEY_ID: &str = "k1";
const IDEM: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";
const OTHER_IDEM: &str = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89";
const MESSAGE: [u8; 32] = [0x6d; 32];
const OTHER_MESSAGE: [u8; 32] = [0x6e; 32];
const RNG_SEED: &[u8] = b"sombe-alias-token-vector-1";
const OTHER_RNG_SEED: &[u8] = b"sombe-alias-token-vector-2";
const BURN_SIGNATURE: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

const RECIPIENT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
const SENDER_IDENTITY_SEED: [u8; 32] = [0xa1; 32];
const RECIPIENT_IDENTITY_SEED: [u8; 32] = [0xb2; 32];
const ENVELOPE: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";

fn main() {
    let key = derive_alias_vault_key(WALLET_SEED.to_vec(), ACCOUNT.into()).unwrap();
    let spki = base64_std(&rsa::spki(&rsa::test_key()));
    let tokens = token_vectors(&spki);
    let vault = vault_vectors(&key, &tokens);
    let vectors = json!({
        "description": "SOMBE test vectors of sombe-chat-crypto 0.11.0: the alias vault (HKDF key info sombe:alias_vault:1 from a wallet seed, the key sealed with XChaCha20-Poly1305, the block of 16 384 bytes: format byte 0x01, a 24 byte nonce, XChaCha20-Poly1305 of a 2 byte length, the JSON and zeros up to 16 343 bytes, associated data `sombe alias vault v1`, 0x01 and the account id; and blocks refused), the alias token (RFC 9474 RSABSSA-SHA384-PSS-Randomized with a 2 048 bit key: prepared, signed blind, finalized, verified, refused, and the memo of its burn) and the alias_change content (the attestation of vectors/v4.json). Everything the APIs take (the block, nonce, token_signature, blinded_msg, secret) is base64 standard with padding; the key sealed is base64 without padding. The signing key is in vectors/alias-token-test-key.json: a test key, never used for anything real. Test seeds only.",
        "vault": vault,
        "token": tokens.json,
        "alias_change": alias_change_vectors(),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v8.json");
    std::fs::write(&path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
    println!("wrote {}", path.display());
}

fn base64_std(bytes: &[u8]) -> String {
    let unpadded = base64_encode(bytes);
    let missing = (4 - unpadded.len() % 4) % 4;
    unpadded + &"=".repeat(missing)
}

fn unbase64(text: &str) -> Vec<u8> {
    base64_decode(text.trim_end_matches('=')).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error_name(e: &ChatCryptoError) -> &'static str {
    match e {
        ChatCryptoError::InvalidKey { .. } => "InvalidKey",
        ChatCryptoError::InvalidSealedKey => "InvalidSealedKey",
        ChatCryptoError::InvalidVault => "InvalidVault",
        ChatCryptoError::UnsupportedVault => "UnsupportedVault",
        ChatCryptoError::InvalidToken => "InvalidToken",
        ChatCryptoError::InvalidAttestation => "InvalidAttestation",
        ChatCryptoError::InvalidContent { .. } => "InvalidContent",
        ChatCryptoError::UnsupportedContent { .. } => "UnsupportedContent",
        ChatCryptoError::UnboundContent => "UnboundContent",
        other => panic!("unexpected {other:?}"),
    }
}

struct Tokens {
    json: Value,
    ready: VaultToken,
    preparing: VaultToken,
}

fn token_vectors(spki: &str) -> Tokens {
    let signer =
        SecretKey::<Sha384, PSS, Randomized>::from_der(&rsa::pkcs1_private(&rsa::test_key())).unwrap();
    let sign = |blinded: &str| base64_std(&signer.blind_sign(unbase64(blinded)).unwrap().0);

    let prepared = alias_vectors::prepare(spki, KEY_ID, IDEM, MESSAGE, RNG_SEED).unwrap();
    let blind_signature = sign(&prepared.blinded_msg);
    let token_signature = alias_token_finalize(
        spki.into(),
        prepared.nonce.clone(),
        prepared.blinded_msg.clone(),
        prepared.secret.clone(),
        blind_signature.clone(),
    )
    .unwrap();
    assert!(alias_token_verify(spki.into(), prepared.nonce.clone(), token_signature.clone()).unwrap());

    let second = alias_vectors::prepare(spki, KEY_ID, OTHER_IDEM, OTHER_MESSAGE, OTHER_RNG_SEED).unwrap();
    let second_signature = sign(&second.blinded_msg);

    // A signature with one bit changed.
    let mut changed = unbase64(&token_signature);
    changed[100] ^= 1;
    let changed = base64_std(&changed);
    // A signature that is the other token's.
    let other_token_signature = alias_token_finalize(
        spki.into(),
        second.nonce.clone(),
        second.blinded_msg.clone(),
        second.secret.clone(),
        second_signature.clone(),
    )
    .unwrap();

    let memo = alias_token_memo(prepared.blinded_msg.clone()).unwrap();
    let rfc_spki = base64_std(&rsa::spki(&rsa::rfc()));
    let refused_finalize: Vec<Value> = vec![
        ("the blind signature of another token", second_signature.clone(), prepared.secret.clone()),
        ("another token's unblinding factor", blind_signature.clone(), second.secret.clone()),
    ]
    .into_iter()
    .map(|(name, signature, secret)| {
        let error = alias_token_finalize(
            spki.into(),
            prepared.nonce.clone(),
            prepared.blinded_msg.clone(),
            secret.clone(),
            signature.clone(),
        )
        .expect_err(name);
        json!({ "name": name, "blind_signature": signature, "secret": secret, "error": error_name(&error) })
    })
    .collect();
    let refused_keys: Vec<Value> = vec![
        ("a 4 096 bit key (the RFC 9474 test key)", rfc_spki),
        ("a PKCS#1 public key", base64_std(&rsa::pkcs1_public(&rsa::test_key()))),
    ]
    .into_iter()
    .map(|(name, key)| {
        let error =
            alias_token_verify(key.clone(), prepared.nonce.clone(), token_signature.clone()).expect_err(name);
        json!({ "name": name, "spki": key, "error": error_name(&error) })
    })
    .collect();

    let ready = VaultToken::Ready {
        key_id: KEY_ID.into(),
        nonce: prepared.nonce.clone(),
        signature: token_signature.clone(),
    };
    let preparing = VaultToken::Preparing {
        key_id: KEY_ID.into(),
        nonce: second.nonce.clone(),
        blinded_msg: second.blinded_msg.clone(),
        secret: second.secret.clone(),
        idem: OTHER_IDEM.into(),
        burn_signature: Some(BURN_SIGNATURE.into()),
    };
    let json = json!({
        "key": { "key_id": KEY_ID, "spki": spki, "bits": 2048, "exponent": 65537, "signing_key": "vectors/alias-token-test-key.json" },
        "rfc9474": {
            "variant": "RSABSSA-SHA384-PSS-Randomized",
            "note": "The module's own key is 2 048 bits; the RFC's Appendix A test key has 4 096 bits, so the RFC vector (vectors/rfc9474-pss-randomized.json) is replayed through the library the module uses (tests/alias_token.rs), byte for byte, and not through the module's functions. The nonce is msg_prefix (32 bytes) followed by msg (32 bytes); the signature is verified as RSASSA-PSS, SHA-384, MGF1 SHA-384, salt 48 bytes, over the nonce."
        },
        "prepared": {
            "message_hex": hex(&MESSAGE),
            "rng_seed": String::from_utf8(RNG_SEED.to_vec()).unwrap(),
            "key_id": prepared.key_id,
            "idem": prepared.idem,
            "nonce": prepared.nonce,
            "blinded_msg": prepared.blinded_msg,
            "secret": prepared.secret,
            "blind_signature": blind_signature,
            "token_signature": token_signature,
            "memo": memo,
            "memo_prefix": "sombe-alias-token:",
        },
        "second": {
            "message_hex": hex(&OTHER_MESSAGE),
            "rng_seed": String::from_utf8(OTHER_RNG_SEED.to_vec()).unwrap(),
            "key_id": second.key_id,
            "idem": second.idem,
            "nonce": second.nonce,
            "blinded_msg": second.blinded_msg,
            "secret": second.secret,
            "blind_signature": second_signature,
            "token_signature": other_token_signature,
        },
        "verify_false": [
            { "name": "a signature with one bit changed", "nonce": prepared_nonce(&ready), "token_signature": changed },
            { "name": "the other token's signature", "nonce": prepared_nonce(&ready), "token_signature": other_token_signature },
        ],
        "refused_finalize": refused_finalize,
        "refused_keys": refused_keys,
    });
    Tokens { json, ready, preparing }
}

fn prepared_nonce(token: &VaultToken) -> String {
    match token {
        VaultToken::Ready { nonce, .. } | VaultToken::Preparing { nonce, .. } => nonce.clone(),
    }
}

fn vault_json(vault: &AliasVault) -> Value {
    let token = |t: &VaultToken| match t {
        VaultToken::Preparing { key_id, nonce, blinded_msg, secret, idem, burn_signature } => {
            let mut item = json!({ "state": "preparing", "key_id": key_id, "nonce": nonce, "blinded_msg": blinded_msg, "secret": secret, "idem": idem });
            if let Some(signature) = burn_signature {
                item["burn_signature"] = json!(signature);
            }
            item
        }
        VaultToken::Ready { key_id, nonce, signature } => {
            json!({ "state": "ready", "key_id": key_id, "nonce": nonce, "signature": signature })
        }
    };
    json!({
        "seq": vault.seq,
        "alias": vault.alias,
        "retired": vault.retired.iter().map(|r| json!({ "alias": r.alias, "retired_at": r.retired_at })).collect::<Vec<_>>(),
        "tokens": vault.tokens.iter().map(token).collect::<Vec<_>>(),
    })
}

/// The JSON text and padded clear text of a vault, as the module writes them.
fn clear_of(vault: &AliasVault) -> (String, Vec<u8>) {
    let clear = alias_vectors::clear_text(vault.clone()).unwrap();
    let length = usize::from(u16::from_be_bytes([clear[0], clear[1]]));
    (String::from_utf8(clear[2..2 + length].to_vec()).unwrap(), clear)
}

/// A clear text from a JSON text: the length, the text, zeros.
fn clear_from(json: &str) -> Vec<u8> {
    let mut clear = (json.len() as u16).to_be_bytes().to_vec();
    clear.extend_from_slice(json.as_bytes());
    clear.resize(16343, 0);
    clear
}

fn vault_vectors(key: &AliasVaultKey, tokens: &Tokens) -> Value {
    let vault = AliasVault {
        seq: 7,
        alias: "marie_k".into(),
        retired: vec![
            RetiredAlias { alias: "marie_old".into(), retired_at: 1_795_000_000 },
            RetiredAlias { alias: "mk_2025".into(), retired_at: 1_790_000_000 },
        ],
        tokens: vec![tokens.ready.clone(), tokens.preparing.clone()],
    };
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, &WALLET_SEED).expand(b"sombe:alias_vault:1", &mut okm).unwrap();
    let sealed_key = alias_vectors::seal_key(key, SEALING_KEY, KEY_SEAL_NONCE).unwrap();
    let sealed = alias_vectors::seal_vault(key, vault.clone(), VAULT_NONCE).unwrap();
    let restored = AliasVaultKey::unseal(sealed_key.clone(), SEALING_KEY.to_vec(), ACCOUNT.into()).unwrap();
    assert_eq!(restored.open_vault(sealed.clone()).unwrap(), vault);
    let (json_text, clear) = clear_of(&vault);

    let other_account = derive_alias_vault_key(WALLET_SEED.to_vec(), OTHER_ACCOUNT.into()).unwrap();
    let block = unbase64(&sealed);
    let mut flipped = block.clone();
    flipped[5000] ^= 1;
    let seal_text = |text: &str| alias_vectors::seal_clear(key, &clear_from(text), VAULT_NONCE, 1);
    let mut padded_wrong = clear.clone();
    *padded_wrong.last_mut().unwrap() = 1;
    let mut format_two = block.clone();
    format_two[0] = 2;

    // The tokens in the reverse of the written order.
    let by_text = {
        let (written, _) = clear_of(&vault);
        let mut value: Value = serde_json::from_str(&written).unwrap();
        let mut list = value["tokens"].as_array().unwrap().clone();
        list.reverse();
        value["tokens"] = Value::Array(list);
        serde_json::to_string(&value).unwrap()
    };
    let retired_swapped = {
        let mut value: Value = serde_json::from_str(&json_text).unwrap();
        let mut list = value["retired"].as_array().unwrap().clone();
        list.reverse();
        value["retired"] = Value::Array(list);
        serde_json::to_string(&value).unwrap()
    };

    let mut refused: Vec<Value> = Vec::new();
    let mut add = |name: &str, opened_by: &str, sealed: String| {
        let by = if opened_by == "other_account" { &other_account } else { key };
        let error = by.open_vault(sealed.clone()).expect_err(name);
        refused.push(
            json!({ "name": name, "opened_by": opened_by, "sealed": sealed, "error": error_name(&error) }),
        );
    };
    add("another account", "other_account", sealed.clone());
    add("a changed byte", "account", base64_std(&flipped));
    add("a block cut short", "account", base64_std(&block[..16383]));
    add("a block without its padding characters", "account", sealed.trim_end_matches('=').to_owned());
    add("an unknown format byte", "account", base64_std(&format_two));
    add("an unknown schema version", "account", seal_text(&json_text.replacen("\"v\":1", "\"v\":2", 1)));
    add("a space in the JSON", "account", seal_text(&json_text.replacen("\"seq\":7", "\"seq\": 7", 1)));
    add("an extra field", "account", seal_text(&json_text.replacen('}', ",\"extra\":1}", 1)));
    add(
        "a number with a leading zero",
        "account",
        seal_text(&json_text.replacen("\"seq\":7", "\"seq\":07", 1)),
    );
    add(
        "a number written as a float",
        "account",
        seal_text(&json_text.replacen("\"seq\":7", "\"seq\":7.0", 1)),
    );
    add("the retired aliases in the wrong order", "account", seal_text(&retired_swapped));
    add("the tokens in the wrong order", "account", seal_text(&by_text));
    add(
        "a padding that is not only zeros",
        "account",
        alias_vectors::seal_clear(key, &padded_wrong, VAULT_NONCE, 1),
    );
    add(
        "a length longer than the JSON",
        "account",
        alias_vectors::seal_clear(
            key,
            &{
                let mut c = clear.clone();
                let longer = (json_text.len() as u16 + 1).to_be_bytes();
                c[0] = longer[0];
                c[1] = longer[1];
                c
            },
            VAULT_NONCE,
            1,
        ),
    );

    // 20 retired aliases and 10 tokens being prepared.
    let worst = {
        let mut big = vault.clone();
        big.retired = (0..20)
            .map(|i| RetiredAlias { alias: format!("abcdefghijklmnop{i:04}"), retired_at: (1 << 53) - i })
            .collect();
        big.tokens = (0..10u8)
            .map(|i| VaultToken::Preparing {
                key_id: KEY_ID.into(),
                nonce: base64_std(&[i; 64]),
                blinded_msg: base64_std(&[0x11; 256]),
                secret: base64_std(&[0x22; 256]),
                idem: IDEM.into(),
                burn_signature: Some(BURN_SIGNATURE.into()),
            })
            .collect();
        big
    };
    let (worst_json, _) = clear_of(&worst);
    let worst_sealed = alias_vectors::seal_vault(key, worst.clone(), VAULT_NONCE).unwrap();
    // Two nonces whose base64 texts sort the other way round than their bytes: 0xfb... gives a
    // text that starts with `+` (before `A` in ASCII), 0x00... one that starts with `A`.
    let order = {
        let ready = |n: u8| VaultToken::Ready {
            key_id: KEY_ID.into(),
            nonce: base64_std(&[n; 64]),
            signature: base64_std(&[9; 256]),
        };
        let mut v = vault.clone();
        v.tokens = vec![ready(0xfb), ready(0x00)];
        let (text, _) = clear_of(&v);
        let sealed = alias_vectors::seal_vault(key, v.clone(), VAULT_NONCE).unwrap();
        json!({
            "tokens_given": [base64_std(&[0xfb; 64]), base64_std(&[0x00; 64])],
            "tokens_written": [base64_std(&[0x00; 64]), base64_std(&[0xfb; 64])],
            "json": text,
            "sealed": sealed,
        })
    };
    json!({
        "byte_order": order,
        "wallet_seed_hex": hex(&WALLET_SEED),
        "account_id": ACCOUNT,
        "other_account_id": OTHER_ACCOUNT,
        "key_info": "sombe:alias_vault:1",
        "key_hex": hex(&okm),
        "sealing_key_hex": hex(&SEALING_KEY),
        "key_seal_nonce_hex": hex(&KEY_SEAL_NONCE),
        "key_seal_aad": "sombe:alias_vault_key_seal:v1 || 0x01 || account_id",
        "sealed_key": sealed_key,
        "vault": vault_json(&vault),
        "vault_nonce_hex": hex(&VAULT_NONCE),
        "vault_aad": "sombe alias vault v1 || 0x01 || account_id",
        "json": json_text,
        "sealed": sealed,
        "sealed_bytes": 16384,
        "worst_case": { "json_bytes": worst_json.len(), "sealed": worst_sealed, "vault": vault_json(&worst) },
        "refused": refused,
    })
}

fn alias_change_vectors() -> Value {
    let v4: Value = serde_json::from_str(include_str!("../vectors/v4.json")).unwrap();
    let case = &v4["accepted"][0];
    let text = |name: &str| case[name].as_str().unwrap().to_owned();
    let trusted: Vec<TrustedAttestationKey> = case["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TrustedAttestationKey {
            kid: k["kid"].as_str().unwrap().to_owned(),
            public_key: k["public_key"].as_str().unwrap().to_owned(),
        })
        .collect();
    let verified = verify_alias_change(
        text("text"),
        text("signature"),
        trusted,
        text("sender_account_id"),
        text("sender_account_public_key"),
        text("deposited_at"),
    )
    .unwrap();
    let sender_key = Ed25519SecretKey::from_slice(&SENDER_IDENTITY_SEED).public_key().to_base64();
    let recipient_key = Ed25519SecretKey::from_slice(&RECIPIENT_IDENTITY_SEED).public_key().to_base64();
    let sender_account = text("sender_account_id");
    let body =
        ContentBody::AliasChange { attestation: text("text"), attestation_signature: text("signature") };
    let plaintext = encode_content(OutgoingContent {
        sender_account_id: sender_account.clone(),
        sender_ed25519_key: sender_key.clone(),
        recipient_account_id: RECIPIENT.into(),
        recipient_ed25519_key: recipient_key.clone(),
        envelope_id: Some(ENVELOPE.into()),
        body,
    })
    .unwrap();
    let mailbox = ContentBinding {
        channel: ContentChannel::Mailbox,
        envelope_id: Some(ENVELOPE.into()),
        sender_account_id: sender_account,
        sender_ed25519_key: sender_key,
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: recipient_key,
        legacy_conversation_id: None,
    };
    let websocket =
        ContentBinding { channel: ContentChannel::Websocket, envelope_id: None, ..mailbox.clone() };
    let other_envelope = ContentBinding {
        envelope_id: Some("27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89".into()),
        ..mailbox.clone()
    };
    let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut value: Value = serde_json::from_str(&plaintext).unwrap();
        f(value.as_object_mut().unwrap());
        value.to_string()
    };
    let cases: Vec<(&str, String, &ContentBinding)> = vec![
        ("an alias_change through the websocket", plaintext.clone(), &websocket),
        (
            "an alias_change in version 3",
            edit(&|m| {
                m.insert("v".into(), 3.into());
            }),
            &mailbox,
        ),
        (
            "an alias_change with an unknown field",
            edit(&|m| {
                m.insert("alias".into(), "marie_k".into());
            }),
            &mailbox,
        ),
        (
            "an alias_change without its signature",
            edit(&|m| {
                m.remove("attestation_signature");
            }),
            &mailbox,
        ),
        ("an alias_change for another envelope", plaintext.clone(), &other_envelope),
    ];
    let refused: Vec<Value> = cases
        .into_iter()
        .map(|(name, plaintext, binding)| {
            let error = error_name(&decode_content(plaintext.clone(), binding.clone()).expect_err(name));
            json!({ "name": name, "plaintext": plaintext, "binding": binding_json(binding), "error": error })
        })
        .collect();
    json!({
        "attestation": {
            "text": text("text"),
            "signature": text("signature"),
            "trusted_keys": case["trusted_keys"],
            "sender_account_id": text("sender_account_id"),
            "sender_account_public_key": text("sender_account_public_key"),
            "deposited_at": text("deposited_at"),
            "alias": verified.alias,
            "expires": verified.expires,
            "source": "vectors/v4.json, accepted[0]"
        },
        "bound": { "plaintext": plaintext, "binding": binding_json(&mailbox) },
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
