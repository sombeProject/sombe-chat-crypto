//! The identity statement (version 3 since 0.7.0, version 4 with a sealing key since
//! 0.10.0), signed by the identity and by the account key, the text a one time key signature covers, and how a contact's identity
//! is judged against the one pinned for them. The formats are described in PROTOCOL.md;
//! any change here is a protocol change.

use std::time::{SystemTime, UNIX_EPOCH};

use vodozemac::{base64_decode, base64_encode, Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

use crate::account::{self, AccountRotationContent, WalletCard, LAST_GENERATION};
use crate::{
    ChatCryptoError, IdentityKeys, IdentityUpdate, PinnedIdentity, PinnedOlm, SignedOneTimeKey,
    StatementFields, VerifiedIdentity, PROTOCOL,
};

const STATEMENT_HEADER_V3: &str = "SOMBE chat identity v3";
const STATEMENT_HEADER_V4: &str = "SOMBE chat identity v4";
const ONE_TIME_KEY_HEADER: &str = "SOMBE one-time key v1";
/// How far ahead of this phone's clock a statement may be dated (since 0.7.1): the bound
/// the server applies too, checked again here because the server is not trusted.
const MAX_AHEAD_SECONDS: i64 = 24 * 60 * 60;

/// What the identity's own ed25519 key signs: the first six lines of a statement v3, or
/// the seven of a statement v4, whose last line is `sealing:` (since 0.10.0).
pub(crate) fn body(
    account_public_key: &str,
    keys: &IdentityKeys,
    sealing_key: Option<&str>,
    created_at: &str,
) -> Result<String, ChatCryptoError> {
    account::public_key(account_public_key, "account key")?;
    check_timestamp(created_at)?;
    let header = if sealing_key.is_some() { STATEMENT_HEADER_V4 } else { STATEMENT_HEADER_V3 };
    let mut body = format!(
        "{header}\nprotocol:{PROTOCOL}\naccount:{account_public_key}\ncurve25519:{}\ned25519:{}\ncreated:{created_at}",
        keys.curve25519_key, keys.ed25519_key
    );
    if let Some(sealing_key) = sealing_key {
        crate::sealed::public_key(sealing_key)?;
        body.push_str("\nsealing:");
        body.push_str(sealing_key);
    }
    Ok(body)
}

/// The whole statement the account key signs: the body, then the identity's signature of it.
pub(crate) fn build(body: &str, identity_signature: &str) -> String {
    format!("{body}\nidentity_signature:{identity_signature}")
}

/// Rebuilds the text from the server's columns (seven lines for a v3, eight for a v4 that
/// has `sealing_key`), then checks the identity's signature of the body and the account
/// key's signature of the whole text.
pub(crate) fn verify(fields: &StatementFields) -> Result<VerifiedIdentity, ChatCryptoError> {
    let account_key = account::public_key(&fields.account_public_key, "account key")?;
    // One spelling per key (since 0.7.1): the text is signed and compared as written.
    canonical_base64(&fields.curve25519_key).map_err(invalid_key)?;
    canonical_base64(&fields.ed25519_key).map_err(invalid_key)?;
    canonical_base64(&fields.identity_signature).map_err(|_| ChatCryptoError::InvalidSignature)?;
    Curve25519PublicKey::from_base64(&fields.curve25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let identity_key =
        Ed25519PublicKey::from_base64(&fields.ed25519_key).map_err(|e| invalid_key(e.to_string()))?;
    let keys = IdentityKeys {
        curve25519_key: fields.curve25519_key.clone(),
        ed25519_key: fields.ed25519_key.clone(),
    };
    let body = body(&fields.account_public_key, &keys, fields.sealing_key.as_deref(), &fields.created_at)?;

    let identity_signature = Ed25519Signature::from_base64(&fields.identity_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;
    identity_key
        .verify(body.as_bytes(), &identity_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;

    let statement = build(&body, &fields.identity_signature);
    let account_signature =
        account::signature(&fields.account_signature).ok_or(ChatCryptoError::InvalidSignature)?;
    account_key
        .verify(statement.as_bytes(), &account_signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)?;

    Ok(VerifiedIdentity {
        account_public_key: fields.account_public_key.clone(),
        curve25519_key: fields.curve25519_key.clone(),
        ed25519_key: fields.ed25519_key.clone(),
        created_at: fields.created_at.clone(),
        sealing_key: fields.sealing_key.clone(),
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
    canonical_base64(identity_ed25519).map_err(invalid_key)?;
    canonical_base64(&key.public_key).map_err(invalid_key)?;
    canonical_base64(&key.signature).map_err(|_| ChatCryptoError::InvalidSignature)?;
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
    check_update_at(pinned, candidate, rotation, now_seconds())
}

/// `check_update` at a given time, in seconds since 1970. An identity that would be pinned
/// may not be dated more than 24 hours after it: a date at the end of time would otherwise
/// make every later identity of the contact stale.
fn check_update_at(
    pinned: Option<&PinnedIdentity>,
    candidate: &VerifiedIdentity,
    rotation: Option<&AccountRotationContent>,
    now: i64,
) -> Result<IdentityUpdate, ChatCryptoError> {
    let Some(pinned) = pinned else {
        not_ahead(&candidate.created_at, now)?;
        return Ok(IdentityUpdate::New);
    };
    let same_olm = |olm: &PinnedOlm| {
        olm.curve25519_key == candidate.curve25519_key && olm.ed25519_key == candidate.ed25519_key
    };
    if candidate.account_public_key == pinned.account_public_key {
        let Some(olm) = &pinned.olm else {
            not_ahead(&candidate.created_at, now)?;
            return Ok(IdentityUpdate::New);
        };
        if same_olm(olm) {
            return Ok(IdentityUpdate::Unchanged);
        }
        if instant(&candidate.created_at)? <= instant(&olm.created_at)? {
            return Err(ChatCryptoError::StaleIdentity);
        }
        not_ahead(&candidate.created_at, now)?;
        return Ok(IdentityUpdate::Changed);
    }
    if !rotation.is_some_and(|r| rotation_holds(pinned, candidate, r, now)) {
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
    now: i64,
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
        && not_ahead(&candidate.created_at, now).is_ok()
}

/// Refuses a `created` more than 24 hours after `now` (seconds since 1970).
fn not_ahead(created_at: &str, now: i64) -> Result<(), ChatCryptoError> {
    if epoch_seconds(created_at)? > now.saturating_add(MAX_AHEAD_SECONDS) {
        return Err(invalid_statement("created is more than 24 hours ahead of this phone's clock"));
    }
    Ok(())
}

/// This phone's clock, in seconds since 1970 (0 if it is set before 1970).
fn now_seconds() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A checked timestamp in seconds since 1970, milliseconds dropped.
fn epoch_seconds(value: &str) -> Result<i64, ChatCryptoError> {
    let [year, month, day, hour, minute, second] = date_fields(value)?;
    // Days from 1970-01-01 in the proleptic Gregorian calendar.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y.rem_euclid(400);
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Year, month, day, hour, minute and second of a timestamp, each within its calendar range.
pub(crate) fn date_fields(value: &str) -> Result<[i64; 6], ChatCryptoError> {
    let bad = || invalid_statement("created must be ISO 8601 UTC");
    check_shape(value)?;
    let number = |from: usize, to: usize| value[from..to].parse::<i64>().map_err(|_| bad());
    let fields =
        [number(0, 4)?, number(5, 7)?, number(8, 10)?, number(11, 13)?, number(14, 16)?, number(17, 19)?];
    let [year, month, day, hour, minute, second] = fields;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(bad()),
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(bad());
    }
    Ok(fields)
}

/// Standard base64 without padding, the one spelling vodozemac writes.
fn canonical_base64(text: &str) -> Result<(), String> {
    match base64_decode(text) {
        Ok(bytes) if base64_encode(&bytes) == text => Ok(()),
        _ => Err("not base64 without padding".to_owned()),
    }
}

/// A checked timestamp as (seconds part, milliseconds), which compare in time order.
fn instant(value: &str) -> Result<(&str, &str), ChatCryptoError> {
    check_timestamp(value)?;
    Ok((&value[..19], value.get(20..23).unwrap_or("000")))
}

/// UTC, second precision or milliseconds: `2026-10-14T18:30:01Z` or `2026-10-14T18:30:01.183Z`,
/// a date and a time that exist (since 0.7.1).
pub(crate) fn check_timestamp(value: &str) -> Result<(), ChatCryptoError> {
    date_fields(value).map(|_| ())
}

fn check_shape(value: &str) -> Result<(), ChatCryptoError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_convert_to_seconds_since_1970() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(epoch_seconds("2000-03-01T00:00:00.999Z").unwrap(), 951_868_800);
        assert_eq!(epoch_seconds("2026-11-12T16:45:00Z").unwrap(), 1_794_501_900);
        assert_eq!(epoch_seconds("2024-02-29T23:59:59Z").unwrap(), 1_709_251_199);
    }

    #[test]
    fn dates_that_do_not_exist_are_refused() {
        for bad in [
            "9999-99-99T99:99:99.999Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-11-12T24:00:00Z",
            "2026-11-12T23:60:00Z",
            "2026-11-12T23:59:60Z",
        ] {
            assert!(check_timestamp(bad).is_err(), "{bad}");
        }
        assert!(check_timestamp("2024-02-29T23:59:59.000Z").is_ok());
    }

    #[test]
    fn a_statement_may_be_dated_at_most_24_hours_ahead() {
        let now = epoch_seconds("2026-11-12T12:00:00Z").unwrap();
        assert!(not_ahead("2026-11-13T12:00:00Z", now).is_ok());
        assert!(not_ahead("2026-11-13T12:00:01Z", now).is_err());
        assert!(not_ahead("2020-01-01T00:00:00Z", now).is_ok());
    }
}
