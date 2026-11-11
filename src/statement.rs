//! The identity statement (version 3 since 0.7.0), signed by the identity and by the
//! account key, the text a one time key signature covers, and how a contact's identity
//! is judged against the one pinned for them. The formats are described in PROTOCOL.md;
//! any change here is a protocol change.

use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

use crate::account::{self, AccountRotationContent, WalletCard, LAST_GENERATION};
use crate::{
    ChatCryptoError, IdentityKeys, IdentityUpdate, PinnedIdentity, PinnedOlm, SignedOneTimeKey,
    StatementFields, VerifiedIdentity, PROTOCOL,
};

const STATEMENT_HEADER: &str = "SOMBE chat identity v3";
const ONE_TIME_KEY_HEADER: &str = "SOMBE one-time key v1";

/// The first six lines of a statement: what the identity's own ed25519 key signs.
pub(crate) fn body(
    account_public_key: &str,
    keys: &IdentityKeys,
    created_at: &str,
) -> Result<String, ChatCryptoError> {
    account::public_key(account_public_key, "account key")?;
    check_timestamp(created_at)?;
    Ok(format!(
        "{STATEMENT_HEADER}\nprotocol:{PROTOCOL}\naccount:{account_public_key}\ncurve25519:{}\ned25519:{}\ncreated:{created_at}",
        keys.curve25519_key, keys.ed25519_key
    ))
}

/// The whole statement the account key signs: the body, then the identity's signature of it.
pub(crate) fn build(body: &str, identity_signature: &str) -> String {
    format!("{body}\nidentity_signature:{identity_signature}")
}

/// Rebuilds the seven lines from the server's columns, then checks the identity's
/// signature of the first six and the account key's signature of all seven.
pub(crate) fn verify(fields: &StatementFields) -> Result<VerifiedIdentity, ChatCryptoError> {
    let account_key = account::public_key(&fields.account_public_key, "account key")?;
    Curve25519PublicKey::from_base64(&fields.curve25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let identity_key =
        Ed25519PublicKey::from_base64(&fields.ed25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let keys = IdentityKeys {
        curve25519_key: fields.curve25519_key.clone(),
        ed25519_key: fields.ed25519_key.clone(),
    };
    let body = body(&fields.account_public_key, &keys, &fields.created_at)?;

    let identity_signature = Ed25519Signature::from_base64(&fields.identity_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;
    identity_key
        .verify(body.as_bytes(), &identity_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;

    let statement = build(&body, &fields.identity_signature);
    let account_signature = bs58::decode(&fields.account_signature)
        .into_vec()
        .ok()
        .and_then(|bytes| Ed25519Signature::from_slice(&bytes).ok())
        .ok_or(ChatCryptoError::InvalidSignature)?;
    account_key
        .verify(statement.as_bytes(), &account_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;

    Ok(VerifiedIdentity {
        account_public_key: fields.account_public_key.clone(),
        curve25519_key: fields.curve25519_key.clone(),
        ed25519_key: fields.ed25519_key.clone(),
        created_at: fields.created_at.clone(),
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

/// Compares a contact's identity with the one pinned for them. Under the same account key,
/// a new identity is accepted only when it is strictly newer. Under another account key,
/// only with a rotation proof from the pinned key, signed by both keys and carried with a
/// wallet card from the pinned wallet.
pub(crate) fn check_update(
    pinned: Option<&PinnedIdentity>,
    candidate: &VerifiedIdentity,
    rotation: Option<&AccountRotationContent>,
) -> Result<IdentityUpdate, ChatCryptoError> {
    let Some(pinned) = pinned else {
        return Ok(IdentityUpdate::New);
    };
    let same_olm = |olm: &PinnedOlm| {
        olm.curve25519_key == candidate.curve25519_key && olm.ed25519_key == candidate.ed25519_key
    };
    if candidate.account_public_key == pinned.account_public_key {
        let Some(olm) = &pinned.olm else {
            return Ok(IdentityUpdate::New);
        };
        if same_olm(olm) {
            return Ok(IdentityUpdate::Unchanged);
        }
        return if instant(&candidate.created_at)? > instant(&olm.created_at)? {
            Ok(IdentityUpdate::Changed)
        } else {
            Err(ChatCryptoError::StaleIdentity)
        };
    }
    if !rotation.is_some_and(|r| rotation_holds(pinned, candidate, r)) {
        return Err(ChatCryptoError::AccountChanged);
    }
    Ok(match &pinned.olm {
        Some(olm) if same_olm(olm) => IdentityUpdate::AccountRotated,
        _ => IdentityUpdate::AccountRotatedAndChanged,
    })
}

/// Every condition of a rotation, all required. Any malformed value is a failed condition.
fn rotation_holds(
    pinned: &PinnedIdentity,
    candidate: &VerifiedIdentity,
    rotation: &AccountRotationContent,
) -> bool {
    let Some(wallet_address) = &pinned.wallet_address else {
        return false;
    };
    let card = WalletCard {
        wallet_address: rotation.wallet_address.clone(),
        account_public_key: rotation.new_account_public_key.clone(),
        wallet_signature: rotation.wallet_signature.clone(),
    };
    let newer = match &pinned.olm {
        None => true,
        Some(olm) => {
            matches!((instant(&candidate.created_at), instant(&olm.created_at)), (Ok(c), Ok(p)) if c > p)
        }
    };
    (2..=LAST_GENERATION).contains(&rotation.generation)
        && rotation.old_account_public_key == pinned.account_public_key
        && rotation.new_account_public_key == candidate.account_public_key
        && rotation.old_account_public_key != rotation.new_account_public_key
        && account::rotation_signatures_hold(rotation)
        && pinned.account_generation.is_none_or(|known| rotation.generation > known)
        && rotation.wallet_address == *wallet_address
        && account::verify_wallet_card(&card).is_ok()
        && newer
}

/// A checked timestamp as (seconds part, milliseconds), which compare in time order.
fn instant(value: &str) -> Result<(&str, &str), ChatCryptoError> {
    check_timestamp(value)?;
    Ok((&value[..19], value.get(20..23).unwrap_or("000")))
}

/// UTC, second precision or milliseconds: `2026-10-14T18:30:01Z` or `2026-10-14T18:30:01.183Z`.
pub(crate) fn check_timestamp(value: &str) -> Result<(), ChatCryptoError> {
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

pub(crate) fn invalid_statement(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidStatement { reason: reason.to_owned() }
}

fn invalid_key(reason: String) -> ChatCryptoError {
    ChatCryptoError::InvalidKey { reason }
}
