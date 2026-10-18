//! The profile a person shows their contacts (display name, about text, avatar), encrypted
//! end to end. The server stores only ciphertext; the 32 byte profile key travels to each
//! contact inside an encrypted `profile_key` content. The format is described in
//! PROTOCOL.md; any change here is a protocol change.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use vodozemac::{base64_decode, base64_encode};
use zeroize::Zeroizing;

use crate::{statement, ChatCryptoError, Profile};

pub const PROFILE_KEY_BYTES: usize = 32;
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
pub const MAX_ABOUT_CHARS: usize = 140;
pub const MAX_AVATAR_BYTES: usize = 512 * 1024;

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const AAD_HEADER: &str = "SOMBE profile v1";
const PROFILE_VERSION: u32 = 1;
/// Profiles pad to the next power of two from here, so a name's length shows little.
const MIN_PADDED_PROFILE: usize = 256;
/// What the `pad` field adds around its spaces: `,"pad":""`.
const PAD_FIELD_BYTES: usize = 9;
/// Avatars pad to the next power of two from here (after a 4 byte length).
const MIN_PADDED_AVATAR: usize = 4096;

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pad: Option<String>,
}

pub(crate) fn generate_key() -> Result<Vec<u8>, ChatCryptoError> {
    let mut key = vec![0u8; PROFILE_KEY_BYTES];
    getrandom::fill(&mut key).map_err(|e| ChatCryptoError::Encryption { reason: e.to_string() })?;
    Ok(key)
}

/// The profile key as a `profile_key` content carries it: unpadded base64.
pub(crate) fn encode_key(key: &[u8]) -> Result<String, ChatCryptoError> {
    check_key(key)?;
    Ok(base64_encode(key))
}

pub(crate) fn decode_key(text: &str) -> Result<Vec<u8>, ChatCryptoError> {
    let key = base64_decode(text).map_err(|_| invalid_key("profile key is not base64"))?;
    check_key(&key)?;
    Ok(key)
}

pub(crate) fn encrypt(
    profile: &Profile,
    key: &[u8],
    wallet_address: &str,
) -> Result<String, ChatCryptoError> {
    validate(profile)?;
    let mut wire = Wire {
        v: PROFILE_VERSION,
        display_name: profile.display_name.clone(),
        about: profile.about.clone(),
        pad: None,
    };
    let unpadded = serde_json::to_string(&wire).map_err(|e| invalid(&e.to_string()))?.len();
    let target = (unpadded + PAD_FIELD_BYTES).max(MIN_PADDED_PROFILE).next_power_of_two();
    wire.pad = Some(" ".repeat(target - unpadded - PAD_FIELD_BYTES));
    let json = Zeroizing::new(serde_json::to_vec(&wire).map_err(|e| invalid(&e.to_string()))?);
    Ok(base64_encode(seal(&json, key, wallet_address, "profile")?))
}

pub(crate) fn decrypt(
    ciphertext: &str,
    key: &[u8],
    wallet_address: &str,
) -> Result<Profile, ChatCryptoError> {
    let bytes = base64_decode(ciphertext).map_err(|_| decryption("profile is not base64"))?;
    let json = open(&bytes, key, wallet_address, "profile")?;
    let wire: Wire = serde_json::from_slice(&json).map_err(|e| invalid(&e.to_string()))?;
    if wire.v != PROFILE_VERSION {
        return Err(invalid("unknown profile version"));
    }
    let profile = Profile { display_name: wire.display_name, about: wire.about };
    validate(&profile)?;
    Ok(profile)
}

pub(crate) fn encrypt_avatar(
    image: &[u8],
    key: &[u8],
    wallet_address: &str,
) -> Result<Vec<u8>, ChatCryptoError> {
    if image.is_empty() || image.len() > MAX_AVATAR_BYTES {
        return Err(invalid("avatar must be 1 byte to 512 KiB"));
    }
    // A 4 byte big endian length, the image, then zeros up to the size bucket.
    let target = (image.len() + 4).max(MIN_PADDED_AVATAR).next_power_of_two();
    let mut padded = Zeroizing::new(Vec::with_capacity(target));
    padded.extend_from_slice(&(image.len() as u32).to_be_bytes());
    padded.extend_from_slice(image);
    padded.resize(target, 0);
    seal(&padded, key, wallet_address, "avatar")
}

pub(crate) fn decrypt_avatar(
    ciphertext: &[u8],
    key: &[u8],
    wallet_address: &str,
) -> Result<Vec<u8>, ChatCryptoError> {
    let padded = open(ciphertext, key, wallet_address, "avatar")?;
    let (length, rest) = padded.split_at_checked(4).ok_or_else(|| invalid("avatar is too short"))?;
    let length = u32::from_be_bytes(length.try_into().expect("4 bytes")) as usize;
    if length == 0 || length > MAX_AVATAR_BYTES || length > rest.len() {
        return Err(invalid("avatar length is out of range"));
    }
    Ok(rest[..length].to_vec())
}

/// `version || nonce || ciphertext and tag`, bound to the wallet and to which part it is,
/// so a server can neither swap two people's profiles nor serve an avatar as a profile.
fn seal(plaintext: &[u8], key: &[u8], wallet_address: &str, part: &str) -> Result<Vec<u8>, ChatCryptoError> {
    let cipher = cipher(key)?;
    let aad = aad(wallet_address, part)?;
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|e| ChatCryptoError::Encryption { reason: e.to_string() })?;
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| ChatCryptoError::Encryption { reason: "profile encryption failed".to_owned() })?;
    let mut out = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(
    bytes: &[u8],
    key: &[u8],
    wallet_address: &str,
    part: &str,
) -> Result<Zeroizing<Vec<u8>>, ChatCryptoError> {
    let cipher = cipher(key)?;
    let aad = aad(wallet_address, part)?;
    let Some((&version, rest)) = bytes.split_first() else {
        return Err(decryption("empty ciphertext"));
    };
    if version != FORMAT_VERSION {
        return Err(decryption("unknown profile format"));
    }
    let (nonce, sealed) =
        rest.split_at_checked(NONCE_BYTES).ok_or_else(|| decryption("ciphertext is too short"))?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().expect("24 bytes");
    let plaintext = cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad: aad.as_bytes() })
        .map_err(|_| decryption("wrong profile key, wallet or part, or a modified ciphertext"))?;
    Ok(Zeroizing::new(plaintext))
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, ChatCryptoError> {
    check_key(key)?;
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid_key("profile key must be 32 bytes"))
}

fn aad(wallet_address: &str, part: &str) -> Result<String, ChatCryptoError> {
    statement::wallet_public_key(wallet_address)?;
    Ok(format!("{AAD_HEADER}\nwallet:{wallet_address}\npart:{part}"))
}

fn check_key(key: &[u8]) -> Result<(), ChatCryptoError> {
    if key.len() == PROFILE_KEY_BYTES {
        Ok(())
    } else {
        Err(invalid_key("profile key must be 32 bytes"))
    }
}

fn validate(profile: &Profile) -> Result<(), ChatCryptoError> {
    if let Some(name) = &profile.display_name {
        if name.trim().is_empty() || name.chars().count() > MAX_DISPLAY_NAME_CHARS {
            return Err(invalid("display name must be 1 to 64 characters"));
        }
        if name.chars().any(char::is_control) {
            return Err(invalid("display name has a control character"));
        }
    }
    if profile.about.as_deref().is_some_and(|a| a.chars().count() > MAX_ABOUT_CHARS) {
        return Err(invalid("about is longer than 140 characters"));
    }
    Ok(())
}

fn invalid(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidProfile { reason: reason.to_owned() }
}

fn invalid_key(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidKey { reason: reason.to_owned() }
}

fn decryption(reason: &str) -> ChatCryptoError {
    ChatCryptoError::Decryption { reason: reason.to_owned() }
}
