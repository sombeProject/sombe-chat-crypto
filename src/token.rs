//! The alias token (since 0.11.0): an RSA blind signature (RFC 9474,
//! RSABSSA-SHA384-PSS-Randomized, 2 048 bit key). The phone blinds a message, the wallet API
//! signs it without seeing it, the phone unblinds it and ChatPay checks it without knowing
//! who paid. The module never signs a token: it has no function that holds a private key.
//!
//! The formats are described in PROTOCOL.md; any change here is a protocol change.

use std::convert::Infallible;
use std::panic::{catch_unwind, AssertUnwindSafe};

use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, MessageRandomizer, PublicKey, Randomized, Secret, Sha384,
    Signature, PSS,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::vault::{is_key_id, is_uuid_v4};
use crate::{b64, ChatCryptoError};

type Result<T> = std::result::Result<T, ChatCryptoError>;
type Key = PublicKey<Sha384, PSS, Randomized>;

const MODULUS_BYTES: usize = 256;
/// `SubjectPublicKeyInfo` of an RSA key of 2 048 bits: the sequence, `rsaEncryption` with its
/// null parameters, the bit string, then `RSAPublicKey` whose modulus has a leading zero.
const SPKI_HEADER: [u8; 33] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
];
/// `INTEGER 65537`.
const SPKI_EXPONENT: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
const SPKI_BYTES: usize = SPKI_HEADER.len() + MODULUS_BYTES + SPKI_EXPONENT.len();
const RANDOMIZER_BYTES: usize = 32;
const MESSAGE_BYTES: usize = 32;
/// The prepared message of the RFC: the 32 byte randomizer, then the 32 byte message.
const NONCE_BYTES: usize = RANDOMIZER_BYTES + MESSAGE_BYTES;
pub(crate) const MEMO_PREFIX: &str = "sombe-alias-token:";

/// What `alias_token_prepare` returns: everything is base64 with padding, standard alphabet.
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
pub struct PreparedAliasToken {
    pub key_id: String,
    /// 64 bytes: the RFC's `msg_prefix || msg`. It names the token.
    pub nonce: String,
    /// 256 bytes, what the wallet API signs.
    pub blinded_msg: String,
    /// 256 bytes, the unblinding factor. Keep it in the vault, never log it.
    pub secret: String,
    /// The `client_idempotency_key` of the burn, as given.
    pub idem: String,
}

impl std::fmt::Debug for PreparedAliasToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PreparedAliasToken {{ key_id: {:?}, .. }}", self.key_id)
    }
}

/// Prepares a token for the key `public_key_spki` (named `key_id` in the APK).
pub(crate) fn prepare(public_key_spki: &str, key_id: &str, idem: &str) -> Result<PreparedAliasToken> {
    if !is_key_id(key_id) || !is_uuid_v4(idem) {
        return Err(ChatCryptoError::InvalidToken);
    }
    let key = parse_key(public_key_spki)?;
    let mut message = [0u8; MESSAGE_BYTES];
    getrandom::fill(&mut message).map_err(|_| no_randomness())?;
    // The library draws its randomness from the generator it is given; a failure of the
    // system is a panic of this generator, caught here and reported.
    let mut result = catch_unwind(AssertUnwindSafe(|| key.blind(&mut SystemRng, message)))
        .map_err(|_| no_randomness())?
        .map_err(|_| ChatCryptoError::InvalidToken)?;
    let randomizer = result.msg_randomizer.ok_or(ChatCryptoError::InvalidToken)?;
    let ok = result.blind_message.len() == MODULUS_BYTES && result.secret.0.len() == MODULUS_BYTES;
    let prepared = ok.then(|| {
        let mut nonce = Vec::with_capacity(NONCE_BYTES);
        nonce.extend_from_slice(&randomizer.0);
        nonce.extend_from_slice(&message);
        PreparedAliasToken {
            key_id: key_id.to_owned(),
            nonce: b64::encode(&nonce),
            blinded_msg: b64::encode(&result.blind_message),
            secret: b64::encode(&result.secret.0),
            idem: idem.to_owned(),
        }
    });
    result.secret.0.zeroize();
    message.zeroize();
    prepared.ok_or(ChatCryptoError::InvalidToken)
}

/// Unblinds `blind_signature`. The text it returns (`token_signature`) is given only if it
/// verifies under the key, for the prepared message.
pub(crate) fn finalize(
    public_key_spki: &str,
    nonce: &str,
    blinded_msg: &str,
    secret: &str,
    blind_signature: &str,
) -> Result<String> {
    let key = parse_key(public_key_spki)?;
    let (randomizer, message) = split_nonce(nonce)?;
    let blinded = decode(blinded_msg, MODULUS_BYTES)?;
    let mut secret = decode(secret, MODULUS_BYTES)?;
    let blind_signature = decode(blind_signature, MODULUS_BYTES)?;
    let result = BlindingResult {
        blind_message: BlindMessage(blinded),
        secret: Secret(secret.clone()),
        msg_randomizer: Some(randomizer),
    };
    let signature = key.finalize(&BlindSignature(blind_signature), &result, message);
    secret.zeroize();
    let mut held = result.secret;
    held.0.zeroize();
    let signature = signature.map_err(|_| ChatCryptoError::InvalidToken)?;
    if signature.len() != MODULUS_BYTES {
        return Err(ChatCryptoError::InvalidToken);
    }
    Ok(b64::encode(&signature))
}

/// True if `token_signature` is a signature of the prepared message `nonce` under the key.
/// An unreadable key or a text of the wrong size is `InvalidToken`.
pub(crate) fn verify(public_key_spki: &str, nonce: &str, token_signature: &str) -> Result<bool> {
    let key = parse_key(public_key_spki)?;
    let (randomizer, message) = split_nonce(nonce)?;
    let signature = decode(token_signature, MODULUS_BYTES)?;
    Ok(key.verify(&Signature(signature), Some(randomizer), message).is_ok())
}

/// `sombe-alias-token:` and the SHA-256 of the bytes of `blinded_msg`, in base64url without
/// padding (43 characters).
pub(crate) fn memo(blinded_msg: &str) -> Result<String> {
    let blinded = decode(blinded_msg, MODULUS_BYTES)?;
    Ok(format!("{MEMO_PREFIX}{}", b64::encode_url_no_pad(&Sha256::digest(&blinded))))
}

fn decode(text: &str, size: usize) -> Result<Vec<u8>> {
    b64::decode_exact(text, size).ok_or(ChatCryptoError::InvalidToken)
}

fn split_nonce(nonce: &str) -> Result<(MessageRandomizer, Vec<u8>)> {
    let bytes = decode(nonce, NONCE_BYTES)?;
    let randomizer: [u8; RANDOMIZER_BYTES] = bytes[..RANDOMIZER_BYTES].try_into().expect("size checked");
    Ok((MessageRandomizer(randomizer), bytes[RANDOMIZER_BYTES..].to_vec()))
}

/// A public key in DER SPKI `rsaEncryption`, base64 with padding: RSA, 2 048 bits, exponent
/// 65 537. It is read with `from_der`, never `from_spki` (which takes only the RSASSA-PSS
/// template). The library's PKCS#1 fallback is refused by writing the key back and comparing
/// the bytes.
fn parse_key(public_key_spki: &str) -> Result<Key> {
    let invalid = || ChatCryptoError::InvalidToken;
    let der = b64::decode(public_key_spki).ok_or_else(invalid)?;
    let key = Key::from_der(&der).map_err(|_| invalid())?;
    if key.to_der().map_err(|_| invalid())? != der {
        return Err(invalid());
    }
    // The one DER of a 2 048 bit key with exponent 65 537: the library accepts 2 048 to
    // 4 096 bits and the exponent 3, and this module takes neither. The header fixes the
    // lengths (a modulus of 2 047 bits would not have this header), the tail the exponent.
    if der.len() != SPKI_BYTES
        || der[..SPKI_HEADER.len()] != SPKI_HEADER
        || der[SPKI_BYTES - 5..] != SPKI_EXPONENT
    {
        return Err(invalid());
    }
    Ok(key)
}

fn no_randomness() -> ChatCryptoError {
    ChatCryptoError::Encryption { reason: "no randomness".to_owned() }
}

/// The system's randomness for the library's `blind`. The library cannot take a failing
/// generator, so a failure panics and `prepare` catches it. Never used for anything else.
struct SystemRng;

impl rand_core::TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Infallible> {
        getrandom::fill(dst).expect("the system has no randomness");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SystemRng {}

/// Fixed randomness for the vectors: the draws of `blind` come from a stream of bytes.
#[cfg(feature = "vectors")]
pub(crate) mod fixed {
    use super::*;

    /// A generator that hands out the bytes of `seed` expanded by counter mode SHA-256.
    pub struct StreamRng {
        seed: Vec<u8>,
        block: u64,
        buffer: Vec<u8>,
    }

    impl StreamRng {
        pub fn new(seed: &[u8]) -> Self {
            Self { seed: seed.to_vec(), block: 0, buffer: Vec::new() }
        }
    }

    impl rand_core::TryRng for StreamRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
            let mut bytes = [0u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
            let mut bytes = [0u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Infallible> {
            for byte in dst {
                if self.buffer.is_empty() {
                    let mut hash = Sha256::new();
                    hash.update(&self.seed);
                    hash.update(self.block.to_be_bytes());
                    self.block += 1;
                    self.buffer = hash.finalize().to_vec();
                    self.buffer.reverse();
                }
                *byte = self.buffer.pop().expect("a block was just made");
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for StreamRng {}

    /// `alias_token_prepare` with fixed randomness: the 32 byte message and the generator.
    pub fn prepare(
        public_key_spki: &str,
        key_id: &str,
        idem: &str,
        message: [u8; MESSAGE_BYTES],
        seed: &[u8],
    ) -> Result<PreparedAliasToken> {
        if !is_key_id(key_id) || !is_uuid_v4(idem) {
            return Err(ChatCryptoError::InvalidToken);
        }
        let key = parse_key(public_key_spki)?;
        let result =
            key.blind(&mut StreamRng::new(seed), message).map_err(|_| ChatCryptoError::InvalidToken)?;
        let randomizer = result.msg_randomizer.ok_or(ChatCryptoError::InvalidToken)?;
        let mut nonce = randomizer.0.to_vec();
        nonce.extend_from_slice(&message);
        Ok(PreparedAliasToken {
            key_id: key_id.to_owned(),
            nonce: b64::encode(&nonce),
            blinded_msg: b64::encode(&result.blind_message),
            secret: b64::encode(&result.secret.0),
            idem: idem.to_owned(),
        })
    }
}
