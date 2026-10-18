//! The safety number two people compare, in person or on a video call, to check that no
//! one sits between their phones. Its format is described in PROTOCOL.md; any change here
//! is a protocol change.

use sha2::{Digest, Sha512};

use crate::{ChatCryptoError, SafetyNumber, ScanResult, VerifiedIdentity};

const FINGERPRINT_HEADER: &str = "SOMBE safety number v1";
const QR_PREFIX: &str = "SOMBE-SN1:";
/// As in Signal: makes a key that collides with someone's 30 digits far more costly to find.
const ITERATIONS: usize = 5200;
const DIGITS: usize = 60;
const GROUP: usize = 5;

pub(crate) fn compute(
    local: &VerifiedIdentity,
    remote: &VerifiedIdentity,
) -> Result<SafetyNumber, ChatCryptoError> {
    if local.wallet_address == remote.wallet_address {
        return Err(ChatCryptoError::InvalidKey {
            reason: "a safety number needs two different wallets".to_owned(),
        });
    }
    // Sorted, so both phones put the two halves in the same order.
    let mut halves = [fingerprint(local), fingerprint(remote)];
    halves.sort();
    let digits = halves.concat();
    let groups = digits.as_bytes().chunks(GROUP).map(|g| String::from_utf8_lossy(g).into_owned()).collect();
    Ok(SafetyNumber { qr_payload: format!("{QR_PREFIX}{digits}"), digits, groups })
}

pub(crate) fn compare_scan(
    local: &VerifiedIdentity,
    remote: &VerifiedIdentity,
    scanned: &str,
) -> Result<ScanResult, ChatCryptoError> {
    let Some(digits) = scanned.strip_prefix(QR_PREFIX) else {
        return Ok(ScanResult::NotASafetyCode);
    };
    if digits.len() != DIGITS || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(ScanResult::NotASafetyCode);
    }
    Ok(if digits == compute(local, remote)?.digits { ScanResult::Match } else { ScanResult::Mismatch })
}

/// 30 digits for one identity: its wallet and both its keys, hashed `ITERATIONS` times.
fn fingerprint(identity: &VerifiedIdentity) -> String {
    let input = format!(
        "{FINGERPRINT_HEADER}\nwallet:{}\ncurve25519:{}\ned25519:{}",
        identity.wallet_address, identity.curve25519_key, identity.ed25519_key
    );
    let mut hash = Sha512::digest(input.as_bytes());
    for _ in 1..ITERATIONS {
        let mut hasher = Sha512::new();
        hasher.update(hash.as_slice());
        hasher.update(input.as_bytes());
        hash = hasher.finalize();
    }
    // Six chunks of 5 bytes, each read as a big endian number and kept modulo 100000.
    hash[..30]
        .chunks(5)
        .map(|chunk| {
            let n = chunk.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b));
            format!("{:05}", n % 100_000)
        })
        .collect()
}
