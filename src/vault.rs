//! The alias vault (since 0.11.0): what a person keeps about their aliases, sealed by the
//! phone before it goes to the server. The server holds one block of exactly 16 384 bytes
//! and can never read it. The key comes from the wallet's seed and is never returned.
//!
//! The formats are described in PROTOCOL.md; any change here is a protocol change.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, Generate, Payload};
use chacha20poly1305::XNonce;
use serde_json::{Map, Value};
use vodozemac::{base64_decode, base64_encode};
use zeroize::Zeroizing;

use crate::account::{cipher, hkdf_sha256, is_lower_uuid, secret_array};
use crate::attestation::is_alias;
use crate::{b64, ChatCryptoError};

type Result<T> = std::result::Result<T, ChatCryptoError>;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// The format of the encryption, the first byte of the block.
const FORMAT: u8 = 1;
/// The version of the JSON, its `v`.
const SCHEMA: i64 = 1;
const BLOCK_BYTES: usize = 16384;
const CLEAR_BYTES: usize = BLOCK_BYTES - 1 - NONCE_BYTES - TAG_BYTES;
/// The clear text is a 2 byte length, the JSON, then zeros.
const MAX_JSON_BYTES: usize = CLEAR_BYTES - 2;
const MAX_RETIRED: usize = 20;
const MAX_TOKENS: usize = 10;
/// 2^53, the largest integer every JSON reader keeps whole.
const MAX_INTEGER: i64 = 1 << 53;
const NONCE_TOKEN_BYTES: usize = 64;
const MODULUS_BYTES: usize = 256;

const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const KEY_INFO: &[u8] = b"sombe:alias_vault:1";
const KEY_SEAL_AAD: &str = "sombe:alias_vault_key_seal:v1";
const VAULT_AAD: &[u8] = b"sombe alias vault v1";
const SEALED_KEY_BYTES: usize = 1 + NONCE_BYTES + KEY_BYTES + TAG_BYTES;

/// An alias given up, kept so the person can take it back.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct RetiredAlias {
    pub alias: String,
    /// Seconds since 1970, 1 to 2^53.
    pub retired_at: i64,
}

/// An alias token the person has bought or is buying. Never log it.
#[derive(uniffi::Enum, Clone, PartialEq, Eq)]
pub enum VaultToken {
    /// Blinded and about to be paid. `secret` is the unblinding factor, kept until the
    /// token is ready.
    Preparing {
        key_id: String,
        nonce: String,
        blinded_msg: String,
        secret: String,
        /// The `client_idempotency_key` of the burn: a lower case UUID v4.
        idem: String,
        /// Base58, 64 to 90 characters, once the burn is known.
        burn_signature: Option<String>,
    },
    /// Signed by the wallet API and unblinded: `nonce` and `signature` are what ChatPay takes.
    Ready { key_id: String, nonce: String, signature: String },
}

impl std::fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparing { key_id, .. } => write!(f, "VaultToken::Preparing {{ key_id: {key_id:?}, .. }}"),
            Self::Ready { key_id, .. } => write!(f, "VaultToken::Ready {{ key_id: {key_id:?}, .. }}"),
        }
    }
}

/// What the vault holds, schema version 1.
#[derive(uniffi::Record, Clone, PartialEq, Eq)]
pub struct AliasVault {
    /// 0 to 2^53; goes up at each change of content.
    pub seq: i64,
    pub alias: String,
    /// At most 20, by `retired_at` from the latest, then by alias.
    pub retired: Vec<RetiredAlias>,
    /// At most 10, by decoded `nonce`.
    pub tokens: Vec<VaultToken>,
}

impl std::fmt::Debug for AliasVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AliasVault {{ seq: {}, .. }}", self.seq)
    }
}

/// The key of one account's vault, held in memory by the module and erased when dropped.
#[derive(uniffi::Object)]
pub struct AliasVaultKey {
    key: Zeroizing<[u8; KEY_BYTES]>,
    account_id: String,
}

#[uniffi::export]
impl AliasVaultKey {
    /// Opens a key written by `seal_key`. A wrong sealing key, another account, a changed or
    /// truncated text or another format is `InvalidSealedKey`, with no detail.
    #[uniffi::constructor]
    pub fn unseal(sealed: String, sealing_key: Vec<u8>, account_id: String) -> Result<Arc<Self>> {
        let sealing = secret_array(sealing_key, "sealing key")?;
        check_account_id(&account_id)?;
        let bytes = base64_decode(&sealed).map_err(|_| ChatCryptoError::InvalidSealedKey)?;
        if base64_encode(&bytes) != sealed || bytes.len() != SEALED_KEY_BYTES || bytes[0] != FORMAT {
            return Err(ChatCryptoError::InvalidSealedKey);
        }
        let nonce =
            XNonce::try_from(&bytes[1..1 + NONCE_BYTES]).map_err(|_| ChatCryptoError::InvalidSealedKey)?;
        let clear = Zeroizing::new(
            cipher(&sealing)?
                .decrypt(&nonce, Payload { msg: &bytes[1 + NONCE_BYTES..], aad: &key_seal_aad(&account_id) })
                .map_err(|_| ChatCryptoError::InvalidSealedKey)?,
        );
        let mut key = Zeroizing::new([0u8; KEY_BYTES]);
        if clear.len() != KEY_BYTES {
            return Err(ChatCryptoError::InvalidSealedKey);
        }
        key.copy_from_slice(&clear);
        Ok(Arc::new(Self { key, account_id }))
    }

    /// The key, sealed with a 32 byte key: base64 without padding of `0x01`, a fresh 24 byte
    /// nonce, then the XChaCha20-Poly1305 output. Never log it, never send it.
    pub fn seal_key(&self, sealing_key: Vec<u8>) -> Result<String> {
        let sealing = secret_array(sealing_key, "sealing key")?;
        let nonce = random_nonce()?;
        self.seal_key_with_nonce(&sealing, &nonce)
    }

    /// The vault as one block of 16 384 bytes, in base64 with padding. A new nonce is drawn
    /// at every call. The retired aliases are sorted and cut to 20; more than 10 tokens, a nonce used
    /// twice, an alias twice or the current alias among the retired ones is `InvalidVault`.
    pub fn seal_vault(&self, vault: AliasVault) -> Result<String> {
        let nonce = random_nonce()?;
        self.seal_vault_with_nonce(vault, &nonce)
    }

    /// Opens a block written by `seal_vault`. A format byte or a schema `v` that this module
    /// does not know is `UnsupportedVault`; any other failure (wrong key, another account, a
    /// changed or cut block, a JSON that is not exactly the one written) is `InvalidVault`.
    pub fn open_vault(&self, sealed: String) -> Result<AliasVault> {
        let bytes = b64::decode(&sealed).ok_or(ChatCryptoError::InvalidVault)?;
        match bytes.first() {
            None => return Err(ChatCryptoError::InvalidVault),
            Some(&FORMAT) => {}
            Some(_) => return Err(ChatCryptoError::UnsupportedVault),
        }
        if bytes.len() != BLOCK_BYTES {
            return Err(ChatCryptoError::InvalidVault);
        }
        let nonce =
            XNonce::try_from(&bytes[1..1 + NONCE_BYTES]).map_err(|_| ChatCryptoError::InvalidVault)?;
        let clear = Zeroizing::new(
            cipher(&self.key)?
                .decrypt(&nonce, Payload { msg: &bytes[1 + NONCE_BYTES..], aad: &self.vault_aad() })
                .map_err(|_| ChatCryptoError::InvalidVault)?,
        );
        read_clear(&clear)
    }
}

impl AliasVaultKey {
    fn seal_key_with_nonce(&self, sealing: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> Result<String> {
        let sealed = cipher(sealing)?
            .encrypt(
                &XNonce::from(*nonce),
                Payload { msg: self.key.as_slice(), aad: &key_seal_aad(&self.account_id) },
            )
            .map_err(|_| ChatCryptoError::Encryption { reason: "could not seal".to_owned() })?;
        let mut out = Vec::with_capacity(SEALED_KEY_BYTES);
        out.push(FORMAT);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&sealed);
        Ok(base64_encode(out))
    }

    fn seal_vault_with_nonce(&self, vault: AliasVault, nonce: &[u8; NONCE_BYTES]) -> Result<String> {
        let json = write_json(&normalized(vault)?);
        if json.len() > MAX_JSON_BYTES {
            return Err(ChatCryptoError::InvalidVault);
        }
        let mut clear = Zeroizing::new(Vec::with_capacity(CLEAR_BYTES));
        clear.extend_from_slice(&(json.len() as u16).to_be_bytes());
        clear.extend_from_slice(json.as_bytes());
        clear.resize(CLEAR_BYTES, 0);
        let sealed = cipher(&self.key)?
            .encrypt(&XNonce::from(*nonce), Payload { msg: &clear, aad: &self.vault_aad() })
            .map_err(|_| ChatCryptoError::Encryption { reason: "could not seal".to_owned() })?;
        let mut block = Vec::with_capacity(BLOCK_BYTES);
        block.push(FORMAT);
        block.extend_from_slice(nonce);
        block.extend_from_slice(&sealed);
        debug_assert_eq!(block.len(), BLOCK_BYTES);
        Ok(b64::encode(&block))
    }

    /// The text `sombe alias vault v1`, `0x01`, then the account id: a vault opens only for
    /// its account and its format.
    fn vault_aad(&self) -> Vec<u8> {
        let mut aad = VAULT_AAD.to_vec();
        aad.push(FORMAT);
        aad.extend_from_slice(self.account_id.as_bytes());
        aad
    }
}

/// Derives the vault key of `account_id` from the 32 byte wallet seed (HKDF-SHA256, empty
/// salt, info `sombe:alias_vault:1`). The seed is erased from the module's memory.
pub(crate) fn derive(wallet_secret: Vec<u8>, account_id: String) -> Result<Arc<AliasVaultKey>> {
    let wallet = secret_array(wallet_secret, "wallet secret")?;
    check_account_id(&account_id)?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf_sha256(&[], wallet.as_slice(), KEY_INFO, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF length");
    Ok(Arc::new(AliasVaultKey { key, account_id }))
}

/// Seals a vault under a fixed key and nonce, for vectors only.
#[cfg(feature = "vectors")]
pub(crate) fn seal_with_nonce(
    key: &AliasVaultKey,
    vault: AliasVault,
    nonce: [u8; NONCE_BYTES],
) -> Result<String> {
    key.seal_vault_with_nonce(vault, &nonce)
}

/// Seals a vault key under a fixed sealing key and nonce, for vectors only.
#[cfg(feature = "vectors")]
pub(crate) fn seal_key_with_nonce(
    key: &AliasVaultKey,
    sealing: [u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<String> {
    key.seal_key_with_nonce(&sealing, &nonce)
}

/// Seals any clear text (already padded to its size) under the key, to write the blocks a
/// reader must refuse. For vectors only.
#[cfg(feature = "vectors")]
pub(crate) fn seal_clear(key: &AliasVaultKey, clear: &[u8], nonce: [u8; NONCE_BYTES], format: u8) -> String {
    let sealed = cipher(&key.key)
        .unwrap()
        .encrypt(&XNonce::from(nonce), Payload { msg: clear, aad: &key.vault_aad() })
        .unwrap();
    let mut block = vec![format];
    block.extend_from_slice(&nonce);
    block.extend_from_slice(&sealed);
    b64::encode(&block)
}

/// The exact clear text of a vault: the length, the JSON, zeros up to 16 343 bytes. For
/// vectors only.
#[cfg(feature = "vectors")]
pub(crate) fn clear_text(vault: AliasVault) -> Result<Vec<u8>> {
    let json = write_json(&normalized(vault)?);
    let mut clear = (json.len() as u16).to_be_bytes().to_vec();
    clear.extend_from_slice(json.as_bytes());
    clear.resize(CLEAR_BYTES, 0);
    Ok(clear)
}

fn random_nonce() -> Result<[u8; NONCE_BYTES]> {
    <[u8; NONCE_BYTES]>::try_generate()
        .map_err(|_| ChatCryptoError::Encryption { reason: "no randomness".to_owned() })
}

fn key_seal_aad(account_id: &str) -> Vec<u8> {
    let mut aad = KEY_SEAL_AAD.as_bytes().to_vec();
    aad.push(FORMAT);
    aad.extend_from_slice(account_id.as_bytes());
    aad
}

/// A lower case UUID, 36 characters.
fn check_account_id(account_id: &str) -> Result<()> {
    if is_lower_uuid(account_id) {
        Ok(())
    } else {
        Err(ChatCryptoError::InvalidKey { reason: "account id is not a lower case UUID".to_owned() })
    }
}

/// Reads the clear text of a block: the length, the JSON, only zeros after it.
fn read_clear(clear: &[u8]) -> Result<AliasVault> {
    let invalid = || ChatCryptoError::InvalidVault;
    if clear.len() != CLEAR_BYTES {
        return Err(invalid());
    }
    let length = usize::from(u16::from_be_bytes([clear[0], clear[1]]));
    if length == 0 || length > MAX_JSON_BYTES {
        return Err(invalid());
    }
    let (json, padding) = clear[2..].split_at(length);
    if padding.iter().any(|&b| b != 0) {
        return Err(invalid());
    }
    let json = std::str::from_utf8(json).map_err(|_| invalid())?;
    let value: Value = serde_json::from_str(json).map_err(|_| invalid())?;
    let Value::Object(map) = &value else { return Err(invalid()) };
    match map.get("v").and_then(Value::as_i64) {
        Some(SCHEMA) => {}
        Some(_) => return Err(ChatCryptoError::UnsupportedVault),
        None => return Err(invalid()),
    }
    let vault = read_vault(map).ok_or_else(invalid)?;
    check(&vault).ok_or_else(invalid)?;
    // Exactly the text this module writes, byte for byte: no space, no extra field, no
    // other order, no other spelling of a number.
    if write_json(&vault) != json {
        return Err(invalid());
    }
    Ok(vault)
}

fn read_vault(map: &Map<String, Value>) -> Option<AliasVault> {
    let retired = map
        .get("retired")?
        .as_array()?
        .iter()
        .map(|item| {
            let item = item.as_object()?;
            Some(RetiredAlias {
                alias: item.get("alias")?.as_str()?.to_owned(),
                retired_at: item.get("retired_at")?.as_i64()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let tokens = map.get("tokens")?.as_array()?.iter().map(read_token).collect::<Option<Vec<_>>>()?;
    Some(AliasVault {
        seq: map.get("seq")?.as_i64()?,
        alias: map.get("alias")?.as_str()?.to_owned(),
        retired,
        tokens,
    })
}

fn read_token(item: &Value) -> Option<VaultToken> {
    let item = item.as_object()?;
    let text = |name: &str| item.get(name)?.as_str().map(str::to_owned);
    match item.get("state")?.as_str()? {
        "preparing" => Some(VaultToken::Preparing {
            key_id: text("key_id")?,
            nonce: text("nonce")?,
            blinded_msg: text("blinded_msg")?,
            secret: text("secret")?,
            idem: text("idem")?,
            burn_signature: match item.get("burn_signature") {
                None => None,
                Some(value) => Some(value.as_str()?.to_owned()),
            },
        }),
        "ready" => Some(VaultToken::Ready {
            key_id: text("key_id")?,
            nonce: text("nonce")?,
            signature: text("signature")?,
        }),
        _ => None,
    }
}

/// The JSON of a vault that `check` accepts: fixed order, no space.
fn write_json(vault: &AliasVault) -> String {
    let mut map = Map::new();
    map.insert("v".into(), Value::from(SCHEMA));
    map.insert("seq".into(), Value::from(vault.seq));
    map.insert("alias".into(), Value::from(vault.alias.as_str()));
    let retired = vault
        .retired
        .iter()
        .map(|r| {
            let mut item = Map::new();
            item.insert("alias".into(), Value::from(r.alias.as_str()));
            item.insert("retired_at".into(), Value::from(r.retired_at));
            Value::Object(item)
        })
        .collect();
    map.insert("retired".into(), Value::Array(retired));
    let tokens = vault.tokens.iter().map(token_json).collect();
    map.insert("tokens".into(), Value::Array(tokens));
    serde_json::to_string(&Value::Object(map)).expect("a map of strings and integers is written")
}

fn token_json(token: &VaultToken) -> Value {
    let mut item = Map::new();
    let mut put = |name: &str, value: &str| item.insert(name.into(), Value::from(value));
    match token {
        VaultToken::Preparing { key_id, nonce, blinded_msg, secret, idem, burn_signature } => {
            put("state", "preparing");
            put("key_id", key_id);
            put("nonce", nonce);
            put("blinded_msg", blinded_msg);
            put("secret", secret);
            put("idem", idem);
            if let Some(signature) = burn_signature {
                put("burn_signature", signature);
            }
        }
        VaultToken::Ready { key_id, nonce, signature } => {
            put("state", "ready");
            put("key_id", key_id);
            put("nonce", nonce);
            put("signature", signature);
        }
    }
    Value::Object(item)
}

/// The vault as `seal_vault` writes it: the retired aliases sorted and cut to 20, the tokens
/// sorted by nonce. Anything that cannot be written is `InvalidVault`.
fn normalized(mut vault: AliasVault) -> Result<AliasVault> {
    let invalid = || ChatCryptoError::InvalidVault;
    if !(0..=MAX_INTEGER).contains(&vault.seq) || !is_alias(&vault.alias) {
        return Err(invalid());
    }
    if vault.tokens.len() > MAX_TOKENS {
        return Err(invalid());
    }
    for retired in &vault.retired {
        if !is_alias(&retired.alias)
            || !(1..=MAX_INTEGER).contains(&retired.retired_at)
            || retired.alias == vault.alias
        {
            return Err(invalid());
        }
    }
    vault.retired.sort_by(|a, b| b.retired_at.cmp(&a.retired_at).then_with(|| a.alias.cmp(&b.alias)));
    let mut aliases: Vec<&str> = vault.retired.iter().map(|r| r.alias.as_str()).collect();
    aliases.sort_unstable();
    if aliases.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid());
    }
    vault.retired.truncate(MAX_RETIRED);
    let mut keyed = Vec::with_capacity(vault.tokens.len());
    for token in vault.tokens.drain(..) {
        let nonce = b64::decode_exact(token_nonce(&token), NONCE_TOKEN_BYTES).ok_or_else(invalid)?;
        keyed.push((nonce, token));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    vault.tokens = keyed.into_iter().map(|(_, token)| token).collect();
    check(&vault).ok_or_else(invalid)?;
    Ok(vault)
}

fn token_nonce(token: &VaultToken) -> &str {
    match token {
        VaultToken::Preparing { nonce, .. } | VaultToken::Ready { nonce, .. } => nonce,
    }
}

/// Every rule of the schema, on a vault already in its written order.
fn check(vault: &AliasVault) -> Option<()> {
    if !(0..=MAX_INTEGER).contains(&vault.seq) || !is_alias(&vault.alias) {
        return None;
    }
    if vault.retired.len() > MAX_RETIRED || vault.tokens.len() > MAX_TOKENS {
        return None;
    }
    for retired in &vault.retired {
        if !is_alias(&retired.alias)
            || !(1..=MAX_INTEGER).contains(&retired.retired_at)
            || retired.alias == vault.alias
        {
            return None;
        }
    }
    let ordered = vault.retired.windows(2).all(|pair| {
        (pair[0].retired_at, std::cmp::Reverse(pair[0].alias.as_str()))
            > (pair[1].retired_at, std::cmp::Reverse(pair[1].alias.as_str()))
    });
    if !ordered {
        return None;
    }
    let mut previous: Option<Vec<u8>> = None;
    for token in &vault.tokens {
        let nonce = check_token(token)?;
        if previous.as_ref().is_some_and(|before| *before >= nonce) {
            return None;
        }
        previous = Some(nonce);
    }
    Some(())
}

/// The decoded nonce of a token whose fields all hold.
fn check_token(token: &VaultToken) -> Option<Vec<u8>> {
    match token {
        VaultToken::Preparing { key_id, nonce, blinded_msg, secret, idem, burn_signature } => {
            if !is_key_id(key_id) || !is_uuid_v4(idem) {
                return None;
            }
            b64::decode_exact(blinded_msg, MODULUS_BYTES)?;
            b64::decode_exact(secret, MODULUS_BYTES)?;
            if let Some(signature) = burn_signature {
                let base58 = signature.bytes().all(|b| BASE58.as_bytes().contains(&b));
                if !(64..=90).contains(&signature.len()) || !base58 {
                    return None;
                }
            }
            b64::decode_exact(nonce, NONCE_TOKEN_BYTES)
        }
        VaultToken::Ready { key_id, nonce, signature } => {
            if !is_key_id(key_id) {
                return None;
            }
            b64::decode_exact(signature, MODULUS_BYTES)?;
            b64::decode_exact(nonce, NONCE_TOKEN_BYTES)
        }
    }
}

/// `^[a-z0-9]{1,16}$`.
pub(crate) fn is_key_id(key_id: &str) -> bool {
    (1..=16).contains(&key_id.len()) && key_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A lower case UUID of version 4 (variant 8, 9, a or b).
pub(crate) fn is_uuid_v4(id: &str) -> bool {
    is_lower_uuid(id) && id.as_bytes()[14] == b'4' && matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
    const IDEM: &str = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78";

    fn key() -> Arc<AliasVaultKey> {
        derive(vec![7; 32], ACCOUNT.to_owned()).unwrap()
    }

    fn nonce(n: u8) -> String {
        b64::encode(&[n; NONCE_TOKEN_BYTES])
    }

    fn ready(n: u8) -> VaultToken {
        VaultToken::Ready {
            key_id: "k1".into(),
            nonce: nonce(n),
            signature: b64::encode(&[9; MODULUS_BYTES]),
        }
    }

    fn preparing(n: u8) -> VaultToken {
        VaultToken::Preparing {
            key_id: "k1".into(),
            nonce: nonce(n),
            blinded_msg: b64::encode(&[1; MODULUS_BYTES]),
            secret: b64::encode(&[2; MODULUS_BYTES]),
            idem: IDEM.into(),
            burn_signature: Some("1".repeat(88)),
        }
    }

    fn vault() -> AliasVault {
        AliasVault {
            seq: 3,
            alias: "marie_k".into(),
            retired: vec![
                RetiredAlias { alias: "old_one".into(), retired_at: 1_795_000_000 },
                RetiredAlias { alias: "old_two".into(), retired_at: 1_794_000_000 },
            ],
            tokens: vec![ready(1), preparing(2)],
        }
    }

    #[test]
    fn a_vault_comes_back_as_it_went() {
        let sealed = key().seal_vault(vault()).unwrap();
        assert_eq!(sealed.len(), 21848);
        assert_eq!(key().open_vault(sealed).unwrap(), vault());
    }

    #[test]
    fn the_block_follows_the_format() {
        let sealed = key().seal_vault_with_nonce(vault(), &[0x22; 24]).unwrap();
        let block = b64::decode(&sealed).unwrap();
        assert_eq!((block.len(), block[0], &block[1..25]), (16384, 1, &[0x22u8; 24][..]));
        let mut aad = b"sombe alias vault v1\x01".to_vec();
        aad.extend_from_slice(ACCOUNT.as_bytes());
        let clear = cipher(&key().key)
            .unwrap()
            .decrypt(&XNonce::from([0x22u8; 24]), Payload { msg: &block[25..], aad: &aad })
            .unwrap();
        assert_eq!(clear.len(), 16343);
        let length = usize::from(u16::from_be_bytes([clear[0], clear[1]]));
        let json = std::str::from_utf8(&clear[2..2 + length]).unwrap();
        assert!(json.starts_with(
            r#"{"v":1,"seq":3,"alias":"marie_k","retired":[{"alias":"old_one","retired_at":1795000000}"#
        ));
        assert!(clear[2 + length..].iter().all(|&b| b == 0));
    }

    #[test]
    fn two_writings_differ_by_their_nonce() {
        let a = key().seal_vault(vault()).unwrap();
        let b = key().seal_vault(vault()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_vault_opens_only_for_its_account_and_its_key() {
        let sealed = key().seal_vault(vault()).unwrap();
        let other_account = derive(vec![7; 32], "b2b2b2b2-0000-4000-8000-0000000000b2".to_owned()).unwrap();
        let other_key = derive(vec![8; 32], ACCOUNT.to_owned()).unwrap();
        // The same seed gives the same key, so only the account in the AAD tells them apart.
        assert_eq!(other_account.open_vault(sealed.clone()), Err(ChatCryptoError::InvalidVault));
        assert_eq!(other_key.open_vault(sealed), Err(ChatCryptoError::InvalidVault));
    }

    #[test]
    fn a_changed_or_cut_block_is_invalid() {
        let sealed = key().seal_vault(vault()).unwrap();
        let mut block = b64::decode(&sealed).unwrap();
        block[5000] ^= 1;
        assert_eq!(key().open_vault(b64::encode(&block)), Err(ChatCryptoError::InvalidVault));
        let cut = b64::encode(&b64::decode(&sealed).unwrap()[..16383]);
        assert_eq!(key().open_vault(cut), Err(ChatCryptoError::InvalidVault));
        for bad in ["", "not base64"] {
            assert_eq!(key().open_vault(bad.to_owned()), Err(ChatCryptoError::InvalidVault), "{bad:?}");
        }
        // Without its padding, or in the URL alphabet, it is not the text the server holds.
        assert_eq!(
            key().open_vault(sealed.trim_end_matches('=').to_owned()),
            Err(ChatCryptoError::InvalidVault)
        );
    }

    #[test]
    fn an_unknown_format_byte_is_unsupported_whatever_follows() {
        let sealed = key().seal_vault(vault()).unwrap();
        let mut block = b64::decode(&sealed).unwrap();
        block[0] = 2;
        assert_eq!(key().open_vault(b64::encode(&block)), Err(ChatCryptoError::UnsupportedVault));
        assert_eq!(key().open_vault(b64::encode(&block[..100])), Err(ChatCryptoError::UnsupportedVault));
        block[0] = 0;
        assert_eq!(key().open_vault(b64::encode(&block)), Err(ChatCryptoError::UnsupportedVault));
    }

    fn seal_json(json: &str, length: Option<u16>, filler: u8) -> String {
        let mut clear = length.unwrap_or(json.len() as u16).to_be_bytes().to_vec();
        clear.extend_from_slice(json.as_bytes());
        clear.resize(CLEAR_BYTES, filler);
        let nonce = [5u8; 24];
        let sealed = cipher(&key().key)
            .unwrap()
            .encrypt(&XNonce::from(nonce), Payload { msg: &clear, aad: &key().vault_aad() })
            .unwrap();
        let mut block = vec![FORMAT];
        block.extend_from_slice(&nonce);
        block.extend_from_slice(&sealed);
        b64::encode(&block)
    }

    fn written(v: &AliasVault) -> String {
        write_json(&normalized(v.clone()).unwrap())
    }

    #[test]
    fn an_unknown_schema_is_unsupported_after_opening() {
        let text = written(&vault()).replacen(r#""v":1"#, r#""v":2"#, 1);
        assert_eq!(key().open_vault(seal_json(&text, None, 0)), Err(ChatCryptoError::UnsupportedVault));
        let text = written(&vault()).replacen(r#""v":1"#, r#""v":"1""#, 1);
        assert_eq!(key().open_vault(seal_json(&text, None, 0)), Err(ChatCryptoError::InvalidVault));
    }

    #[test]
    fn only_the_exact_json_is_read() {
        let good = written(&vault());
        assert!(key().open_vault(seal_json(&good, None, 0)).is_ok());
        let spaced = good.replacen(r#""seq":3"#, r#""seq": 3"#, 1);
        let extra = good.replacen("}", r#","extra":1}"#, 1);
        let reordered = good.replacen(r#""v":1,"seq":3"#, r#""seq":3,"v":1"#, 1);
        let float = good.replacen(r#""seq":3"#, r#""seq":3.0"#, 1);
        let zero = good.replacen(r#""seq":3"#, r#""seq":03"#, 1);
        let escaped = good.replacen("marie_k", "marie\\u005fk", 1);
        let double = good.replacen(r#""seq":3"#, r#""seq":2,"seq":3"#, 1);
        for (name, text) in [
            ("a space", spaced),
            ("an extra field", extra),
            ("another order", reordered),
            ("a float", float),
            ("a leading zero", zero),
            ("an escape", escaped),
            ("a field twice", double),
        ] {
            assert_eq!(
                key().open_vault(seal_json(&text, None, 0)),
                Err(ChatCryptoError::InvalidVault),
                "{name}"
            );
        }
    }

    #[test]
    fn the_length_and_the_padding_are_checked() {
        let good = written(&vault());
        let longer = good.len() as u16 + 1;
        assert_eq!(key().open_vault(seal_json(&good, Some(longer), 0)), Err(ChatCryptoError::InvalidVault));
        assert_eq!(key().open_vault(seal_json(&good, Some(0), 0)), Err(ChatCryptoError::InvalidVault));
        assert_eq!(key().open_vault(seal_json(&good, Some(16342), 0)), Err(ChatCryptoError::InvalidVault));
        assert_eq!(key().open_vault(seal_json(&good, None, 1)), Err(ChatCryptoError::InvalidVault));
    }

    #[test]
    fn the_worst_case_fits() {
        let mut v = vault();
        v.retired = (0..20)
            .map(|i| RetiredAlias { alias: format!("abcdefghijklmnop{i:04}"), retired_at: MAX_INTEGER - i })
            .collect();
        v.tokens = (0..10).map(|i| preparing(i as u8)).collect();
        let json = written(&v);
        // 20 retired aliases and 10 tokens being prepared: 11 376 bytes of the 16 341 allowed.
        assert_eq!(json.len(), 11_376);
        assert!(json.len() <= MAX_JSON_BYTES);
        assert_eq!(key().open_vault(key().seal_vault(v.clone()).unwrap()).unwrap(), v);
    }

    #[test]
    fn limits_of_the_integers_are_inclusive() {
        let mut v = vault();
        v.seq = MAX_INTEGER;
        v.retired[0].retired_at = MAX_INTEGER;
        assert!(key().open_vault(key().seal_vault(v.clone()).unwrap()).is_ok());
        v.seq = 0;
        v.retired[0].retired_at = 1;
        assert!(key().seal_vault(v.clone()).is_ok());
        for bad in [-1, MAX_INTEGER + 1] {
            let mut w = vault();
            w.seq = bad;
            assert_eq!(key().seal_vault(w), Err(ChatCryptoError::InvalidVault), "seq {bad}");
        }
        for bad in [0, -1, MAX_INTEGER + 1] {
            let mut w = vault();
            w.retired[0].retired_at = bad;
            assert_eq!(key().seal_vault(w), Err(ChatCryptoError::InvalidVault), "retired_at {bad}");
        }
    }

    #[test]
    fn the_writer_sorts_and_cuts_the_retired_aliases() {
        let mut v = vault();
        v.retired =
            (1..=22).map(|i| RetiredAlias { alias: format!("old_{i:02}"), retired_at: 1000 + i }).collect();
        v.retired.reverse();
        v.retired.swap(3, 9);
        let opened = key().open_vault(key().seal_vault(v).unwrap()).unwrap();
        assert_eq!(opened.retired.len(), 20);
        assert_eq!(opened.retired[0].alias, "old_22");
        assert_eq!(opened.retired[19].alias, "old_03");
        // The same moment: by alias.
        let mut v = vault();
        v.retired = vec![
            RetiredAlias { alias: "bbb".into(), retired_at: 5 },
            RetiredAlias { alias: "aaa".into(), retired_at: 5 },
        ];
        let opened = key().open_vault(key().seal_vault(v).unwrap()).unwrap();
        assert_eq!(opened.retired[0].alias, "aaa");
    }

    #[test]
    fn the_writer_sorts_tokens_by_their_bytes_not_their_text() {
        // 0xfb... gives a text starting with `+`, 0x00... one starting with `A`: `+` comes
        // before `A` in ASCII, after it by the bytes.
        let low = VaultToken::Ready {
            key_id: "k".into(),
            nonce: b64::encode(&[0u8; 64]),
            signature: b64::encode(&[9; 256]),
        };
        let high = VaultToken::Ready {
            key_id: "k".into(),
            nonce: b64::encode(&[0xfb; 64]),
            signature: b64::encode(&[9; 256]),
        };
        assert!(token_nonce(&high) < token_nonce(&low));
        let mut v = vault();
        v.tokens = vec![high.clone(), low.clone()];
        let opened = key().open_vault(key().seal_vault(v).unwrap()).unwrap();
        assert_eq!(opened.tokens, vec![low, high]);
    }

    #[test]
    fn what_cannot_be_written_is_refused() {
        let mut cases: Vec<(&str, AliasVault)> = Vec::new();
        let mut v = vault();
        v.tokens = (0..11).map(ready).collect();
        cases.push(("eleven tokens", v));
        let mut v = vault();
        v.tokens = vec![ready(1), preparing(1)];
        cases.push(("a nonce twice", v));
        let mut v = vault();
        v.retired.push(RetiredAlias { alias: v.alias.clone(), retired_at: 5 });
        cases.push(("the current alias among the retired", v));
        let mut v = vault();
        v.retired.push(RetiredAlias { alias: "old_one".into(), retired_at: 5 });
        cases.push(("a retired alias twice", v));
        let mut v = vault();
        v.alias = "Bad".into();
        cases.push(("a bad alias", v));
        let mut v = vault();
        v.tokens = vec![VaultToken::Ready {
            key_id: "K".into(),
            nonce: nonce(1),
            signature: b64::encode(&[9; 256]),
        }];
        cases.push(("a bad key id", v));
        let mut v = vault();
        v.tokens = vec![VaultToken::Ready {
            key_id: "k".into(),
            nonce: b64::encode(&[1; 63]),
            signature: b64::encode(&[9; 256]),
        }];
        cases.push(("a short nonce", v));
        let mut v = vault();
        v.tokens = vec![VaultToken::Ready {
            key_id: "k".into(),
            nonce: nonce(1),
            signature: b64::encode(&[9; 255]),
        }];
        cases.push(("a short signature", v));
        let mut bad = preparing(1);
        if let VaultToken::Preparing { idem, .. } = &mut bad {
            *idem = "7c4f1e3b-0d8a-1f5b-9e9c-2a3b4c5d6e78".into();
        }
        let mut v = vault();
        v.tokens = vec![bad];
        cases.push(("an idem that is not a UUID v4", v));
        let mut bad = preparing(1);
        if let VaultToken::Preparing { burn_signature, .. } = &mut bad {
            *burn_signature = Some("0".repeat(88));
        }
        let mut v = vault();
        v.tokens = vec![bad];
        cases.push(("a burn signature outside base58", v));
        let mut bad = preparing(1);
        if let VaultToken::Preparing { burn_signature, .. } = &mut bad {
            *burn_signature = Some("1".repeat(91));
        }
        let mut v = vault();
        v.tokens = vec![bad];
        cases.push(("a burn signature of 91 characters", v));
        for (name, v) in cases {
            assert_eq!(key().seal_vault(v), Err(ChatCryptoError::InvalidVault), "{name}");
        }
    }

    #[test]
    fn a_burn_signature_is_optional_and_comes_last() {
        let mut v = vault();
        v.tokens = vec![VaultToken::Preparing {
            key_id: "k1".into(),
            nonce: nonce(1),
            blinded_msg: b64::encode(&[1; 256]),
            secret: b64::encode(&[2; 256]),
            idem: IDEM.into(),
            burn_signature: None,
        }];
        let json = written(&v);
        assert!(json.contains(&format!(r#""idem":"{IDEM}"}}"#)));
        assert_eq!(key().open_vault(key().seal_vault(v.clone()).unwrap()).unwrap(), v);
    }

    #[test]
    fn the_key_seals_like_the_account_key() {
        let key = key();
        let sealing = vec![4u8; 32];
        let sealed = key.seal_key(sealing.clone()).unwrap();
        assert_eq!(base64_decode(&sealed).unwrap().len(), 73);
        let opened = AliasVaultKey::unseal(sealed.clone(), sealing.clone(), ACCOUNT.into()).unwrap();
        assert_eq!(opened.key.as_slice(), key.key.as_slice());
        assert_ne!(sealed, key.seal_key(sealing.clone()).unwrap());
        let other = "b2b2b2b2-0000-4000-8000-0000000000b2".to_owned();
        assert!(matches!(
            AliasVaultKey::unseal(sealed.clone(), sealing, other),
            Err(ChatCryptoError::InvalidSealedKey)
        ));
        assert!(matches!(
            AliasVaultKey::unseal(sealed, vec![5; 32], ACCOUNT.into()),
            Err(ChatCryptoError::InvalidSealedKey)
        ));
    }

    #[test]
    fn the_key_comes_from_the_seed_by_hkdf() {
        let wallet = [0x0bu8; 32];
        let derived = derive(wallet.to_vec(), ACCOUNT.into()).unwrap();
        let mut expected = [0u8; 32];
        hkdf_sha256(&[], &wallet, b"sombe:alias_vault:1", &mut expected).unwrap();
        assert_eq!(derived.key.as_slice(), expected);
        assert!(derive(vec![1; 31], ACCOUNT.into()).is_err());
        assert!(derive(vec![1; 32], "A1A1A1A1-0000-4000-8000-0000000000A1".into()).is_err());
    }
}
