//! The access key (since 0.9.0): a capability a person gives only to their contacts, so
//! that the server can keep a share of their mailbox for them. It is drawn from a profile
//! key the phone picks at random; the server keeps only its SHA-256, the verifier.
//!
//! The formats are described in PROTOCOL.md (*Access key*); any change here is a protocol
//! change.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use vodozemac::{base64_decode, base64_encode};
use zeroize::Zeroizing;

use crate::ChatCryptoError;

pub const PROFILE_KEY_BYTES: usize = 32;
pub const ACCESS_KEY_BYTES: usize = 16;
/// Base64 without padding of 16 bytes.
const ACCESS_KEY_CHARS: usize = 22;
const ACCESS_KEY_INFO: &[u8] = b"sombe:access_key:1";

/// HKDF-SHA256 of the profile key, empty salt, info `sombe:access_key:1`, 16 bytes.
pub(crate) fn derive(profile_key: Vec<u8>) -> Result<String, ChatCryptoError> {
    let profile_key = Zeroizing::new(profile_key);
    if profile_key.len() != PROFILE_KEY_BYTES {
        return Err(ChatCryptoError::InvalidKey { reason: "profile key must be 32 bytes".to_owned() });
    }
    let mut access_key = Zeroizing::new([0u8; ACCESS_KEY_BYTES]);
    Hkdf::<Sha256>::new(None, &profile_key)
        .expand(ACCESS_KEY_INFO, access_key.as_mut_slice())
        .expect("16 bytes is a valid HKDF length");
    Ok(base64_encode(access_key.as_slice()))
}

/// SHA-256 of the 16 bytes of the access key, base64 without padding.
pub(crate) fn verifier(access_key: &str) -> Result<String, ChatCryptoError> {
    let bytes = decode(access_key)
        .ok_or_else(|| ChatCryptoError::InvalidKey { reason: invalid_reason("access_key") })?;
    Ok(base64_encode(Sha256::digest(bytes.as_slice())))
}

/// The bytes of an access key written in its one spelling, base64 without padding.
fn decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    if text.len() != ACCESS_KEY_CHARS {
        return None;
    }
    let bytes = Zeroizing::new(base64_decode(text).ok()?);
    (bytes.len() == ACCESS_KEY_BYTES && base64_encode(bytes.as_slice()) == text).then_some(bytes)
}

/// Checks the form of an access key carried in a content.
pub(crate) fn checked(text: &str, name: &str) -> Result<String, ChatCryptoError> {
    decode(text).ok_or_else(|| ChatCryptoError::InvalidContent { reason: invalid_reason(name) })?;
    Ok(text.to_owned())
}

fn invalid_reason(name: &str) -> String {
    format!("{name} is not base64 without padding of 16 bytes")
}
