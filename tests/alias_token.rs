//! The alias token (since 0.11.0): the RFC 9474 vector replayed byte for byte, then the
//! module's four functions against a signer built from the same test key. The signer lives
//! in this test only: the module never holds a private key.

mod common;

use std::convert::Infallible;

use blind_rsa_signatures::{BlindSignature, KeyPair, Randomized, SecretKey, Sha384, Signature, PSS};
use common::rsa::{pkcs1_private, pkcs1_public, rfc, spki, test_key, unhex};
use sha2::{Digest, Sha256};
use sombe_chat_crypto::*;

type Key = blind_rsa_signatures::PublicKey<Sha384, PSS, Randomized>;
type Secret = SecretKey<Sha384, PSS, Randomized>;

const IDEM: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";

fn b64(bytes: &[u8]) -> String {
    use base64_std::encode;
    encode(bytes)
}

mod base64_std {
    pub fn encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let g = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(A[((g >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub fn decode(text: &str) -> Vec<u8> {
        vodozemac::base64_decode(text.trim_end_matches('=')).unwrap()
    }
}

fn spki_b64() -> String {
    b64(&spki(&test_key()))
}

fn signer() -> Secret {
    Secret::from_der(&pkcs1_private(&test_key())).unwrap()
}

/// Hands out fixed bytes in order, whatever sizes are asked.
struct Script {
    bytes: Vec<u8>,
    at: usize,
}

impl rand_core::TryRng for Script {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("blind draws bytes only")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("blind draws bytes only")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.copy_from_slice(&self.bytes[self.at..self.at + dst.len()]);
        self.at += dst.len();
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Script {}

#[test]
fn the_rfc_9474_vector_replays_byte_for_byte() {
    // The RFC's key has 4 096 bits: the library takes it, the module's functions do not (they
    // take 2 048 bits only), so this checks the library the module is built on.
    let v = rfc();
    let signer = Secret::from_der(&pkcs1_private(&v)).unwrap();
    let hex = |name: &str| unhex(v[name].as_str().unwrap());
    let key = Key::from_der(&spki(&v)).unwrap();
    // `blind` draws the 32 byte prefix, the 48 byte salt, then the factor r as 256 little
    // endian bytes (the modulus has 4 096 bits, so 512 bytes and no mask).
    let mut script = hex("msg_prefix");
    script.extend(hex("salt"));
    script.extend(hex("r").into_iter().rev());
    let result = key.blind(&mut Script { bytes: script, at: 0 }, hex("msg")).unwrap();
    assert_eq!(result.msg_randomizer.unwrap().0.to_vec(), hex("msg_prefix"));
    assert_eq!(result.blind_message.0, hex("blinded_msg"));
    assert_eq!(result.secret.0, hex("inv"));

    let blind_signature = signer.blind_sign(&result.blind_message).unwrap();
    assert_eq!(blind_signature.0, hex("blind_sig"));
    let signature = key.finalize(&blind_signature, &result, hex("msg")).unwrap();
    assert_eq!(signature.0, hex("sig"));
    assert!(key.verify(&Signature(hex("sig")), result.msg_randomizer, hex("msg")).is_ok());
}

#[test]
fn a_token_goes_from_prepare_to_a_verified_signature() {
    let spki = spki_b64();
    let prepared = alias_token_prepare(spki.clone(), "k1".into(), IDEM.into()).unwrap();
    assert_eq!((prepared.key_id.as_str(), prepared.idem.as_str()), ("k1", IDEM));
    let nonce = base64_std::decode(&prepared.nonce);
    let blinded = base64_std::decode(&prepared.blinded_msg);
    assert_eq!((nonce.len(), blinded.len(), base64_std::decode(&prepared.secret).len()), (64, 256, 256));

    let blind_signature = b64(&signer().blind_sign(&blinded).unwrap().0);
    let token_signature = alias_token_finalize(
        spki.clone(),
        prepared.nonce.clone(),
        prepared.blinded_msg.clone(),
        prepared.secret.clone(),
        blind_signature.clone(),
    )
    .unwrap();
    assert_eq!(base64_std::decode(&token_signature).len(), 256);
    assert!(alias_token_verify(spki.clone(), prepared.nonce.clone(), token_signature.clone()).unwrap());

    // The signature is the one of the message `msg_prefix || msg`, as RFC 9474 prepares it:
    // the library accepts it from the two halves of the nonce.
    let key = Key::from_der(&spki_bytes()).unwrap();
    let randomizer: [u8; 32] = nonce[..32].try_into().unwrap();
    key.verify(&Signature(base64_std::decode(&token_signature)), Some(randomizer.into()), &nonce[32..])
        .unwrap();

    // Another message, another key, a changed signature: false, never an error.
    let other = alias_token_prepare(spki.clone(), "k1".into(), IDEM.into()).unwrap();
    assert!(!alias_token_verify(spki.clone(), other.nonce.clone(), token_signature.clone()).unwrap());
    let mut changed = base64_std::decode(&token_signature);
    changed[100] ^= 1;
    assert!(!alias_token_verify(spki, prepared.nonce, b64(&changed)).unwrap());
}

fn spki_bytes() -> Vec<u8> {
    spki(&test_key())
}

#[test]
fn two_tokens_never_share_a_message_or_a_blinding() {
    let a = alias_token_prepare(spki_b64(), "k1".into(), IDEM.into()).unwrap();
    let b = alias_token_prepare(spki_b64(), "k1".into(), IDEM.into()).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.blinded_msg, b.blinded_msg);
    assert_ne!(a.secret, b.secret);
}

#[test]
fn finalize_gives_nothing_unless_the_signature_holds() {
    let spki = spki_b64();
    let t = alias_token_prepare(spki.clone(), "k1".into(), IDEM.into()).unwrap();
    let good = b64(&signer().blind_sign(base64_std::decode(&t.blinded_msg)).unwrap().0);
    let run = |nonce: &str, blinded: &str, secret: &str, sig: &str| {
        alias_token_finalize(spki.clone(), nonce.into(), blinded.into(), secret.into(), sig.into())
    };
    assert!(run(&t.nonce, &t.blinded_msg, &t.secret, &good).is_ok());
    // A signature of another blinded message, a wrong factor, another nonce.
    let u = alias_token_prepare(spki.clone(), "k1".into(), IDEM.into()).unwrap();
    let other = b64(&signer().blind_sign(base64_std::decode(&u.blinded_msg)).unwrap().0);
    assert_eq!(run(&t.nonce, &t.blinded_msg, &t.secret, &other), Err(ChatCryptoError::InvalidToken));
    assert_eq!(run(&t.nonce, &t.blinded_msg, &u.secret, &good), Err(ChatCryptoError::InvalidToken));
    assert_eq!(run(&u.nonce, &t.blinded_msg, &t.secret, &good), Err(ChatCryptoError::InvalidToken));
    // Shapes.
    let short = b64(&[1u8; 255]);
    assert_eq!(run(&t.nonce, &t.blinded_msg, &t.secret, &short), Err(ChatCryptoError::InvalidToken));
    assert_eq!(run(&b64(&[1u8; 63]), &t.blinded_msg, &t.secret, &good), Err(ChatCryptoError::InvalidToken));
    assert_eq!(
        run(&t.nonce, &t.blinded_msg, &t.secret, good.trim_end_matches('=')),
        Err(ChatCryptoError::InvalidToken)
    );
}

#[test]
fn only_a_2048_bit_rsa_key_in_spki_with_exponent_65537_is_taken() {
    let v = test_key();
    let good = spki_b64();
    assert!(alias_token_prepare(good.clone(), "k1".into(), IDEM.into()).is_ok());
    let bad_keys: Vec<(&str, String)> = vec![
        ("PKCS#1 public key", b64(&pkcs1_public(&v))),
        ("RSASSA-PSS SPKI", {
            let key = Key::from_der(&spki(&v)).unwrap();
            b64(&key.to_spki().unwrap())
        }),
        ("the RFC's 4 096 bit key", b64(&spki(&rfc()))),
        ("a 3 072 bit key", {
            let pair =
                KeyPair::<Sha384, PSS, Randomized>::generate(&mut blind_rsa_signatures::DefaultRng, 3072)
                    .unwrap();
            b64(&pair.pk.to_der().unwrap())
        }),
        ("a trailing space", format!("{good} ")),
        ("empty", String::new()),
        ("trailing bytes", {
            let mut der = spki(&v);
            der.push(0);
            b64(&der)
        }),
        ("not base64", "%%%".to_owned()),
    ];
    for (name, key) in bad_keys {
        assert_eq!(
            alias_token_prepare(key.clone(), "k1".into(), IDEM.into()).err(),
            Some(ChatCryptoError::InvalidToken),
            "{name}"
        );
        assert_eq!(
            alias_token_verify(key, b64(&[1; 64]), b64(&[1; 256])).err(),
            Some(ChatCryptoError::InvalidToken),
            "{name}"
        );
    }
}

#[test]
fn prepare_refuses_a_bad_key_id_or_idempotency_key() {
    for key_id in ["", "K1", "k-1", "abcdefghijklmnopq"] {
        assert_eq!(
            alias_token_prepare(spki_b64(), key_id.into(), IDEM.into()).err(),
            Some(ChatCryptoError::InvalidToken),
            "{key_id:?}"
        );
    }
    for idem in [
        "",
        "7C4F1E3B-0D8A-4F5B-9E9C-2A3B4C5D6E78",
        "7c4f1e3b-0d8a-1f5b-9e9c-2a3b4c5d6e78",
        "7c4f1e3b-0d8a-4f5b-1e9c-2a3b4c5d6e78",
    ] {
        assert_eq!(
            alias_token_prepare(spki_b64(), "k1".into(), idem.into()).err(),
            Some(ChatCryptoError::InvalidToken),
            "{idem:?}"
        );
    }
}

#[test]
fn the_memo_is_the_hash_of_the_bytes_of_the_blinded_message() {
    let blinded = [0x5au8; 256];
    let memo = alias_token_memo(b64(&blinded)).unwrap();
    assert_eq!(memo.len(), "sombe-alias-token:".len() + 43);
    let digest = Sha256::digest(blinded);
    let url = b64(&digest).trim_end_matches('=').replace('+', "-").replace('/', "_");
    assert_eq!(memo, format!("sombe-alias-token:{url}"));
    assert_eq!(alias_token_memo(b64(&blinded[..255])), Err(ChatCryptoError::InvalidToken));
    assert_eq!(alias_token_memo("AAAA".into()), Err(ChatCryptoError::InvalidToken));
    let _ = BlindSignature(Vec::new());
}
