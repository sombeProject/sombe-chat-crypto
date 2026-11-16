//! The alias attestation (since 0.8.0): a short text the server signs to say "this alias
//! belongs to this account", checked here offline before a contact request is shown.
//! Every refusal is the same `InvalidAttestation`, so a caller learns nothing about which
//! check failed.

use std::collections::HashSet;

use crate::account::{public_key, signature};
use crate::statement::date_fields;
use crate::ChatCryptoError;

pub(crate) const HEADER: &str = "SOMBE alias attestation v1";
/// Far more than the six lines ever take; a longer text is refused unread.
const MAX_TEXT_BYTES: usize = 512;
const MAX_KID_CHARS: usize = 16;

/// One server key the app trusts to sign attestations, as built into the APK.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct TrustedAttestationKey {
    /// 1 to 16 characters among `a` to `z` and `0` to `9`.
    pub kid: String,
    /// The Ed25519 public key, base58 of 32 bytes.
    pub public_key: String,
}

pub(crate) fn text(kid: &str, alias: &str, account_id: &str, account: &str, expires: i64) -> String {
    format!(
        "{HEADER}\nkid:{kid}\nalias:{alias}\naccount_id:{account_id}\naccount:{account}\nexpires:{expires}"
    )
}

pub(crate) fn verify(
    text: &str,
    signature_text: &str,
    trusted_keys: &[TrustedAttestationKey],
    sender_account_id: &str,
    sender_account_public_key: &str,
    deposited_at: &str,
) -> Result<String, ChatCryptoError> {
    check(text, signature_text, trusted_keys, sender_account_id, sender_account_public_key, deposited_at)
        .ok_or(ChatCryptoError::InvalidAttestation)
}

fn check(
    text_in: &str,
    signature_text: &str,
    trusted_keys: &[TrustedAttestationKey],
    sender_account_id: &str,
    sender_account_public_key: &str,
    deposited_at: &str,
) -> Option<String> {
    if text_in.len() > MAX_TEXT_BYTES {
        return None;
    }
    let lines: Vec<&str> = text_in.split('\n').collect();
    let [header, kid, alias, account_id, account, expires] = lines.as_slice() else { return None };
    if *header != HEADER {
        return None;
    }
    let kid = kid.strip_prefix("kid:")?;
    let alias = alias.strip_prefix("alias:")?;
    let account_id = account_id.strip_prefix("account_id:")?;
    let account = account.strip_prefix("account:")?;
    let expires = expires.strip_prefix("expires:")?;

    if !is_kid(kid) || !is_alias(alias) || !is_uuid(account_id) {
        return None;
    }
    let expires = unix_seconds(expires)?;
    // Rebuilt from the parsed values: any other spelling (CRLF, a final newline, padding)
    // is not the text the server signed.
    if text(kid, alias, account_id, account, expires) != text_in {
        return None;
    }

    let trusted = trusted_key(trusted_keys, kid)?;
    let signed = signature(signature_text)?;
    trusted.verify(text_in.as_bytes(), &signed).ok()?;

    if !is_uuid(sender_account_id) || sender_account_id != account_id {
        return None;
    }
    let attested = public_key(account, "account").ok()?;
    let sender = public_key(sender_account_public_key, "sender account").ok()?;
    if attested.as_bytes() != sender.as_bytes() {
        return None;
    }

    let deposited = epoch_millis(deposited_at)?;
    if deposited > expires.checked_mul(1000)? {
        return None;
    }
    Some(alias.to_owned())
}

/// The key named `kid`, when the list is well formed: every kid valid and listed once,
/// every key canonical base58 of 32 bytes.
fn trusted_key(trusted_keys: &[TrustedAttestationKey], kid: &str) -> Option<vodozemac::Ed25519PublicKey> {
    let mut seen = HashSet::new();
    let mut found = None;
    for key in trusted_keys {
        if !is_kid(&key.kid) || !seen.insert(key.kid.as_str()) {
            return None;
        }
        let parsed = public_key(&key.public_key, "attestation key").ok()?;
        if key.kid == kid {
            found = Some(parsed);
        }
    }
    found
}

fn is_kid(kid: &str) -> bool {
    (1..=MAX_KID_CHARS).contains(&kid.len())
        && kid.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `^[a-z][a-z0-9_]{2,19}$`, checked on bytes.
pub(crate) fn is_alias(alias: &str) -> bool {
    let bytes = alias.as_bytes();
    (3..=20).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A lower case UUID, 8-4-4-4-12.
fn is_uuid(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len && group.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Decimal digits without sign or leading zero, at least 1, that fit an i64.
fn unix_seconds(value: &str) -> Option<i64> {
    let digits_only = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    if !digits_only || value.starts_with('0') {
        return None;
    }
    value.parse::<i64>().ok()
}

/// Milliseconds since 1970 of `2026-10-14T18:30:01Z` or `2026-10-14T18:30:01.183Z`.
fn epoch_millis(value: &str) -> Option<i64> {
    let [year, month, day, hour, minute, second] = date_fields(value).ok()?;
    let millis = value.get(20..23).map_or(Some(0), |ms| ms.parse::<i64>().ok())?;
    let days = days_from_civil(year, month, day);
    Some((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_of_known_dates() {
        assert_eq!(epoch_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_millis("2000-03-01T00:00:00.001Z"), Some(951_868_800_001));
        assert_eq!(epoch_millis("2026-11-16T12:00:00Z"), Some(1_794_830_400_000));
    }

    #[test]
    fn alias_rule() {
        for good in ["abc", "a_1", "abcdefghijklmnopqrst"] {
            assert!(is_alias(good), "{good}");
        }
        for bad in ["ab", "1ab", "_ab", "Abc", "abcdefghijklmnopqrstu", "ab-c", "abé", "ab c", "abc\n"] {
            assert!(!is_alias(bad), "{bad}");
        }
    }

    #[test]
    fn seconds_rule() {
        assert_eq!(unix_seconds("1794830400"), Some(1_794_830_400));
        for bad in ["", "0", "01", "+1", "-1", "1.5", "99999999999999999999"] {
            assert_eq!(unix_seconds(bad), None, "{bad}");
        }
    }
}
