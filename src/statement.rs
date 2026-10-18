//! The identity statement a wallet signs, and the text a one time key signature covers.
//! Both formats are described in PROTOCOL.md; any change here is a protocol change.

use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

use crate::{ChatCryptoError, IdentityKeys, IdentityUpdate, SignedOneTimeKey, VerifiedIdentity, PROTOCOL};

const STATEMENT_HEADER: &str = "SOMBE chat identity v2";
const V1_STATEMENT_HEADER: &str = "SOMBE chat identity v1";
const ONE_TIME_KEY_HEADER: &str = "SOMBE one-time key v1";

/// The first six lines of a statement: what the identity's own ed25519 key signs.
pub(crate) fn body(
    wallet_address: &str,
    keys: &IdentityKeys,
    created_at: &str,
) -> Result<String, ChatCryptoError> {
    wallet_public_key(wallet_address)?;
    check_timestamp(created_at)?;
    Ok(format!(
        "{STATEMENT_HEADER}\nprotocol:{PROTOCOL}\nwallet:{wallet_address}\ncurve25519:{}\ned25519:{}\ncreated:{created_at}",
        keys.curve25519_key, keys.ed25519_key
    ))
}

/// The whole statement the wallet signs: the body, then the identity's signature of it.
pub(crate) fn build(body: &str, identity_signature: &str) -> String {
    format!("{body}\nidentity_signature:{identity_signature}")
}

pub(crate) fn verify(
    statement: &str,
    wallet_address: &str,
    wallet_signature: &str,
) -> Result<VerifiedIdentity, ChatCryptoError> {
    let wallet_key = wallet_public_key(wallet_address)?;
    let signature_bytes =
        bs58::decode(wallet_signature).into_vec().map_err(|_| ChatCryptoError::InvalidSignature)?;
    let signature =
        Ed25519Signature::from_slice(&signature_bytes).map_err(|_| ChatCryptoError::InvalidSignature)?;
    wallet_key.verify(statement.as_bytes(), &signature).map_err(|_| ChatCryptoError::InvalidSignature)?;

    // The signature is good; now the text must be exactly the format we sign.
    let lines: Vec<&str> = statement.split('\n').collect();
    if lines.first() == Some(&V1_STATEMENT_HEADER) {
        return Err(invalid_statement("version 1 statements are no longer accepted"));
    }
    let [header, protocol, wallet, curve, ed, created, identity_signature] = lines.as_slice() else {
        return Err(invalid_statement("expected 7 lines"));
    };
    if *header != STATEMENT_HEADER {
        return Err(invalid_statement("unknown header"));
    }
    let protocol = field(protocol, "protocol")?;
    if protocol != PROTOCOL {
        return Err(ChatCryptoError::UnsupportedProtocol { protocol: protocol.to_owned() });
    }
    if field(wallet, "wallet")? != wallet_address {
        return Err(invalid_statement("wallet address does not match"));
    }
    let curve25519_key = field(curve, "curve25519")?;
    Curve25519PublicKey::from_base64(curve25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let ed25519_key = field(ed, "ed25519")?;
    let identity_key = Ed25519PublicKey::from_base64(ed25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let created_at = field(created, "created")?;
    check_timestamp(created_at)?;

    // The identity must vouch for this wallet too, or a wallet could claim someone else's keys.
    let identity_signature = Ed25519Signature::from_base64(field(identity_signature, "identity_signature")?)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;
    let (body, _) = statement.rsplit_once('\n').ok_or_else(|| invalid_statement("expected 7 lines"))?;
    identity_key
        .verify(body.as_bytes(), &identity_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;

    Ok(VerifiedIdentity {
        wallet_address: wallet_address.to_owned(),
        curve25519_key: curve25519_key.to_owned(),
        ed25519_key: ed25519_key.to_owned(),
        created_at: created_at.to_owned(),
    })
}

/// The exact bytes an identity's ed25519 key signs for one of its one time keys.
pub(crate) fn one_time_key_text(key_id: &str, public_key: &str, is_fallback: bool) -> String {
    format!("{ONE_TIME_KEY_HEADER}\nkey_id:{key_id}\ncurve25519:{public_key}\nfallback:{is_fallback}")
}

pub(crate) fn verify_one_time_key(
    identity_ed25519: &str,
    key: &SignedOneTimeKey,
) -> Result<Curve25519PublicKey, ChatCryptoError> {
    let signer = Ed25519PublicKey::from_base64(identity_ed25519).map_err(|e| invalid_key(e.to_string()))?;
    let signature =
        Ed25519Signature::from_base64(&key.signature).map_err(|_| ChatCryptoError::InvalidSignature)?;
    signer
        .verify(one_time_key_text(&key.key_id, &key.public_key, key.is_fallback).as_bytes(), &signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;
    Curve25519PublicKey::from_base64(&key.public_key).map_err(|e| invalid_key(e.to_string()))
}

/// Compares a contact's identity with the one the app pinned for them. A new identity is
/// accepted only when it is strictly newer, so a server cannot bring back an old one.
pub(crate) fn check_update(
    pinned: Option<&VerifiedIdentity>,
    candidate: &VerifiedIdentity,
) -> Result<IdentityUpdate, ChatCryptoError> {
    let Some(pinned) = pinned else {
        return Ok(IdentityUpdate::New);
    };
    if candidate.wallet_address != pinned.wallet_address {
        return Err(ChatCryptoError::WalletChanged);
    }
    if candidate.curve25519_key == pinned.curve25519_key && candidate.ed25519_key == pinned.ed25519_key {
        return Ok(IdentityUpdate::Unchanged);
    }
    if instant(&candidate.created_at)? > instant(&pinned.created_at)? {
        Ok(IdentityUpdate::Changed)
    } else {
        Err(ChatCryptoError::StaleIdentity)
    }
}

/// A checked timestamp as (seconds part, milliseconds), which compare in time order.
fn instant(value: &str) -> Result<(&str, &str), ChatCryptoError> {
    check_timestamp(value)?;
    Ok((&value[..19], value.get(20..23).unwrap_or("000")))
}

/// A Solana address is the base58 form of an ed25519 public key.
fn wallet_public_key(wallet_address: &str) -> Result<Ed25519PublicKey, ChatCryptoError> {
    let bytes = bs58::decode(wallet_address)
        .into_vec()
        .map_err(|_| invalid_key("wallet address is not base58".to_owned()))?;
    let bytes: [u8; 32] =
        bytes.try_into().map_err(|_| invalid_key("wallet address is not 32 bytes".to_owned()))?;
    Ed25519PublicKey::from_slice(&bytes).map_err(|e| invalid_key(e.to_string()))
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str, ChatCryptoError> {
    line.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(':'))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_statement(&format!("missing {name}")))
}

/// UTC, second precision or milliseconds: `2026-10-14T18:30:01Z` or `2026-10-14T18:30:01.183Z`.
fn check_timestamp(value: &str) -> Result<(), ChatCryptoError> {
    let bytes = value.as_bytes();
    let shape_ok = match bytes.len() {
        20 => true,
        24 => bytes[19] == b'.' && bytes[20..23].iter().all(u8::is_ascii_digit),
        _ => false,
    };
    let digits = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    let ok = shape_ok
        && digits.iter().all(|&i| bytes[i].is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[bytes.len() - 1] == b'Z';
    if ok {
        Ok(())
    } else {
        Err(invalid_statement("created must be ISO 8601 UTC"))
    }
}

fn invalid_statement(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidStatement { reason: reason.to_owned() }
}

fn invalid_key(reason: String) -> ChatCryptoError {
    ChatCryptoError::InvalidKey { reason }
}
