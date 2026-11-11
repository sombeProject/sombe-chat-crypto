//! The account key (since 0.7.0): the Ed25519 key that holds a ChatPay account, drawn
//! from the wallet key. Only this module ever sees its private half: it derives it, seals
//! it, and makes every signature it gives (identity statement v3, sign in, account move,
//! rotation), after checking the exact form of each text. No public function returns the
//! seed or the private key, and none signs a free text.
//!
//! The formats are described in PROTOCOL.md; any change here is a protocol change.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use vodozemac::{base64_decode, base64_encode, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::{statement, ChatCrypto, ChatCryptoError};

type Result<T> = std::result::Result<T, ChatCryptoError>;

/// Generations run from 1 to 32767, the range of the server's and the app's `smallint`.
pub const FIRST_GENERATION: u16 = 1;
pub const LAST_GENERATION: u16 = 32767;

const SEED_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const SEAL_VERSION: u8 = 1;
const SEAL_AAD: &str = "sombe:chat_account_seal:v1";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// The sealed clear text: the generation (2 bytes, big endian), then the seed.
const SEALED_CLEAR_BYTES: usize = 2 + SEED_BYTES;
const SEALED_BYTES: usize = 1 + NONCE_BYTES + SEALED_CLEAR_BYTES + TAG_BYTES;

const CARD_HEADER: &str = "SOMBE wallet card v1";
const SIGN_IN_HEADER: &str = "SOMBE ChatPay sign in";
const MOVE_HEADER: &str = "SOMBE account move v1";
const ROTATE_HEADER: &str = "SOMBE account rotate v1";

/// The wallet card: the wallet address a contact pays, signed by that wallet for this
/// account key. It travels only inside encrypted content.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct WalletCard {
    pub wallet_address: String,
    pub account_public_key: String,
    /// Base58 of the 64 byte Ed25519 signature by the wallet.
    pub wallet_signature: String,
}

/// What `derive_account_key` returns: the key and its wallet card.
#[derive(uniffi::Record, Clone)]
pub struct DerivedAccount {
    pub key: Arc<ChatAccountKey>,
    pub card: WalletCard,
}

/// An identity statement v3, signed by the identity and by the account key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SignedStatement {
    /// The whole text, seven lines, the last one `identity_signature:<base64>`.
    pub statement: String,
    /// Base64 without padding, by the identity's ed25519 key, over the first six lines.
    pub identity_signature: String,
    /// Base58, by the account key, over the seven lines.
    pub account_signature: String,
}

/// The proof that an account key handed over to the next one: both keys sign
/// `SOMBE account rotate v1\nold:<old>\nnew:<new>\ngeneration:<generation>`.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct RotationProof {
    pub old_account_public_key: String,
    pub new_account_public_key: String,
    /// The generation of the new key.
    pub generation: u16,
    pub old_signature: String,
    pub new_signature: String,
}

/// What `ChatAccountKey.rotate` returns.
#[derive(uniffi::Record, Clone)]
pub struct AccountRotation {
    pub new_key: Arc<ChatAccountKey>,
    /// The wallet card of the new key.
    pub card: WalletCard,
    pub proof: RotationProof,
}

/// What `prove_rotation` returns: only public data, the app may keep it in clear.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ProvenRotation {
    pub proof: RotationProof,
    pub card: WalletCard,
}

/// The `account_rotation` content: the rotation proof and the new key's wallet card.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct AccountRotationContent {
    pub old_account_public_key: String,
    pub new_account_public_key: String,
    /// 2 to 32767.
    pub generation: u16,
    pub old_signature: String,
    pub new_signature: String,
    pub wallet_address: String,
    pub wallet_signature: String,
}

/// One account key, held in memory by the module and erased when dropped.
#[derive(uniffi::Object)]
pub struct ChatAccountKey {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    generation: u16,
    /// Built from `seed`; vodozemac erases it when dropped.
    secret: Ed25519SecretKey,
    public_key: String,
}

#[uniffi::export]
impl ChatAccountKey {
    /// Opens a text written by `seal`. A wrong sealing key, a changed or truncated text,
    /// or another format version is `InvalidSealedKey`, with no detail.
    #[uniffi::constructor]
    pub fn unseal(sealed: String, sealing_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = secret_array(sealing_key, "sealing key")?;
        let bytes = base64_decode(&sealed).map_err(|_| ChatCryptoError::InvalidSealedKey)?;
        if bytes.len() != SEALED_BYTES || bytes[0] != SEAL_VERSION {
            return Err(ChatCryptoError::InvalidSealedKey);
        }
        let cipher = cipher(&key)?;
        let nonce =
            XNonce::try_from(&bytes[1..1 + NONCE_BYTES]).map_err(|_| ChatCryptoError::InvalidSealedKey)?;
        let clear = Zeroizing::new(
            cipher
                .decrypt(&nonce, Payload { msg: &bytes[1 + NONCE_BYTES..], aad: &seal_aad() })
                .map_err(|_| ChatCryptoError::InvalidSealedKey)?,
        );
        if clear.len() != SEALED_CLEAR_BYTES {
            return Err(ChatCryptoError::InvalidSealedKey);
        }
        let generation = u16::from_be_bytes([clear[0], clear[1]]);
        if !(FIRST_GENERATION..=LAST_GENERATION).contains(&generation) {
            return Err(ChatCryptoError::InvalidSealedKey);
        }
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        seed.copy_from_slice(&clear[2..]);
        Ok(Arc::new(Self::from_seed(seed, generation)))
    }

    /// The key, sealed with a 32 byte key: base64 without padding of `0x01`, a fresh
    /// 24 byte nonce, then the XChaCha20-Poly1305 output. Never log it, never send it.
    pub fn seal(&self, sealing_key: Vec<u8>) -> Result<String> {
        let key = secret_array(sealing_key, "sealing key")?;
        let nonce = <[u8; NONCE_BYTES]>::try_generate()
            .map_err(|_| ChatCryptoError::Encryption { reason: "no randomness".to_owned() })?;
        seal_with_nonce(&key, &nonce, &self.seed, self.generation)
    }

    /// Base58 of the 32 byte public key, like a Solana address.
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    pub fn generation(&self) -> u16 {
        self.generation
    }

    /// Builds the identity statement v3 of `account`, has the identity sign its first six
    /// lines, then signs the seven lines with this account key.
    pub fn sign_identity_statement(
        &self,
        account: Arc<ChatCrypto>,
        created_at: String,
    ) -> Result<SignedStatement> {
        let body = statement::body(&self.public_key, &account.identity_keys(), &created_at)?;
        let identity_signature = account.sign_text(&body);
        let statement = statement::build(&body, &identity_signature);
        let account_signature = self.sign(&statement);
        Ok(SignedStatement { statement, identity_signature, account_signature })
    }

    /// Signs the server's sign in message, only if it has exactly the five lines of the
    /// format, names this key and the fingerprint of `device_public_key_der`.
    pub fn sign_sign_in(&self, message: String, device_public_key_der: Vec<u8>) -> Result<String> {
        let device = device_fingerprint(&device_public_key_der)?;
        let lines: Vec<&str> = message.split('\n').collect();
        let [header, account, device_line, nonce, issued] = lines.as_slice() else {
            return Err(refused("a sign in message has exactly five lines"));
        };
        if *header != SIGN_IN_HEADER {
            return Err(refused("not a sign in message"));
        }
        if account.strip_prefix("account:") != Some(self.public_key.as_str()) {
            return Err(refused("the message names another account key"));
        }
        if device_line.strip_prefix("device:") != Some(device.as_str()) {
            return Err(refused("the message names another device"));
        }
        let nonce_ok = nonce
            .strip_prefix("nonce:")
            .is_some_and(|n| n.len() == 32 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        if !nonce_ok {
            return Err(refused("the nonce is not 32 lower case hexadecimal digits"));
        }
        let issued_ok = issued.strip_prefix("issued:").is_some_and(|t| statement::check_timestamp(t).is_ok());
        if !issued_ok {
            return Err(refused("issued is not an ISO 8601 UTC date"));
        }
        Ok(self.sign(&message))
    }

    /// Signs the account move of `card` (which must be this key's card) to this device,
    /// for the identity `identity_id` (a lower case UUID) or none.
    pub fn sign_move(
        &self,
        card: WalletCard,
        device_public_key_der: Vec<u8>,
        identity_id: Option<String>,
    ) -> Result<String> {
        verify_wallet_card(&card)?;
        if card.account_public_key != self.public_key {
            return Err(refused("the card names another account key"));
        }
        let device = device_fingerprint(&device_public_key_der)?;
        let identity = match &identity_id {
            None => "-".to_owned(),
            Some(id) if is_lower_uuid(id) => id.clone(),
            Some(_) => return Err(statement::invalid_statement("identity is not a lower case UUID")),
        };
        let text =
            move_text(&card_fingerprint(&card.wallet_address, &card.account_public_key), &device, &identity);
        Ok(self.sign(&text))
    }

    /// Hands this key over to the next generation. `wallet_secret` must give this very key
    /// at this generation (`WrongGeneration` otherwise). Returns the new key, its wallet card
    /// and the proof signed by both keys.
    pub fn rotate(&self, wallet_secret: Vec<u8>) -> Result<AccountRotation> {
        let wallet = secret_array(wallet_secret, "wallet secret")?;
        let current = Self::from_seed(derive_seed(&wallet, self.generation), self.generation);
        if current.public_key != self.public_key {
            return Err(ChatCryptoError::WrongGeneration);
        }
        if self.generation == LAST_GENERATION {
            return Err(ChatCryptoError::GenerationExhausted);
        }
        let next = self.generation + 1;
        let new_key = Self::from_seed(derive_seed(&wallet, next), next);
        let card = sign_card(&wallet, &new_key.public_key);
        let proof = proof(self, &new_key);
        Ok(AccountRotation { new_key: Arc::new(new_key), card, proof })
    }
}

impl ChatAccountKey {
    fn from_seed(seed: Zeroizing<[u8; SEED_BYTES]>, generation: u16) -> Self {
        let secret = Ed25519SecretKey::from_slice(&seed);
        let public_key = bs58::encode(secret.public_key().as_bytes()).into_string();
        Self { seed, generation, secret, public_key }
    }

    fn sign(&self, text: &str) -> String {
        bs58::encode(self.secret.sign(text.as_bytes()).to_bytes()).into_string()
    }
}

/// Derives the account key of `generation` (1 to 32767) from the 32 byte wallet seed
/// (`m/44'/501'/0'/0'`), and signs its wallet card with the wallet key.
pub(crate) fn derive(wallet_secret: Vec<u8>, generation: u16) -> Result<DerivedAccount> {
    let wallet = secret_array(wallet_secret, "wallet secret")?;
    check_generation(generation)?;
    let key = ChatAccountKey::from_seed(derive_seed(&wallet, generation), generation);
    let card = sign_card(&wallet, &key.public_key);
    Ok(DerivedAccount { key: Arc::new(key), card })
}

/// The rotation proof from generation `from` to generation `to` (1 ≤ from < to ≤ 32767),
/// and the wallet card of the key `to`.
pub(crate) fn prove(wallet_secret: Vec<u8>, from: u16, to: u16) -> Result<ProvenRotation> {
    let wallet = secret_array(wallet_secret, "wallet secret")?;
    check_generation(from)?;
    check_generation(to)?;
    if from >= to {
        return Err(invalid_key("from_generation must be lower than to_generation".to_owned()));
    }
    let old = ChatAccountKey::from_seed(derive_seed(&wallet, from), from);
    let new = ChatAccountKey::from_seed(derive_seed(&wallet, to), to);
    Ok(ProvenRotation { card: sign_card(&wallet, &new.public_key), proof: proof(&old, &new) })
}

/// Checks a wallet card: canonical base58 fields, and the wallet's signature of the text.
pub(crate) fn verify_wallet_card(card: &WalletCard) -> Result<()> {
    let wallet = public_key(&card.wallet_address, "wallet address")?;
    public_key(&card.account_public_key, "account key")?;
    let signature = signature(&card.wallet_signature).ok_or(ChatCryptoError::InvalidSignature)?;
    wallet
        .verify(card_text(&card.wallet_address, &card.account_public_key).as_bytes(), &signature)
        .map_err(|_| ChatCryptoError::InvalidSignature)
}

/// True when both signatures of a rotation proof hold on its text.
pub(crate) fn rotation_signatures_hold(rotation: &AccountRotationContent) -> bool {
    let text =
        rotate_text(&rotation.old_account_public_key, &rotation.new_account_public_key, rotation.generation);
    let holds = |key: &str, signature_text: &str| -> bool {
        match (public_key(key, "account key"), signature(signature_text)) {
            (Ok(key), Some(signature)) => key.verify(text.as_bytes(), &signature).is_ok(),
            _ => false,
        }
    };
    holds(&rotation.old_account_public_key, &rotation.old_signature)
        && holds(&rotation.new_account_public_key, &rotation.new_signature)
}

pub(crate) fn card_text(wallet_address: &str, account_public_key: &str) -> String {
    format!("{CARD_HEADER}\nwallet:{wallet_address}\naccount:{account_public_key}")
}

/// SHA 256, lower case hexadecimal, of the card text alone (signature excluded).
pub(crate) fn card_fingerprint(wallet_address: &str, account_public_key: &str) -> String {
    hex(&Sha256::digest(card_text(wallet_address, account_public_key).as_bytes()))
}

pub(crate) fn move_text(card_fingerprint: &str, device_fingerprint: &str, identity: &str) -> String {
    format!("{MOVE_HEADER}\ncard:{card_fingerprint}\ndevice:{device_fingerprint}\nidentity:{identity}")
}

pub(crate) fn rotate_text(old: &str, new: &str, generation: u16) -> String {
    format!("{ROTATE_HEADER}\nold:{old}\nnew:{new}\ngeneration:{generation}")
}

/// The canonical base58 form of a 32 byte Ed25519 public key.
pub(crate) fn public_key(text: &str, name: &str) -> Result<Ed25519PublicKey> {
    let bytes = canonical_base58(text, SEED_BYTES)
        .ok_or_else(|| invalid_key(format!("{name} is not base58 of 32 bytes")))?;
    let bytes: [u8; SEED_BYTES] = bytes.try_into().expect("length checked");
    Ed25519PublicKey::from_slice(&bytes).map_err(|e| invalid_key(e.to_string()))
}

fn signature(text: &str) -> Option<Ed25519Signature> {
    canonical_base58(text, SIGNATURE_BYTES).and_then(|bytes| Ed25519Signature::from_slice(&bytes).ok())
}

/// The bytes of `text` if it is the base58 form of exactly `size` bytes.
fn canonical_base58(text: &str, size: usize) -> Option<Vec<u8>> {
    let bytes = bs58::decode(text).into_vec().ok()?;
    (bytes.len() == size && bs58::encode(&bytes).into_string() == text).then_some(bytes)
}

fn derive_seed(wallet: &[u8; SEED_BYTES], generation: u16) -> Zeroizing<[u8; SEED_BYTES]> {
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    hkdf_sha256(&[], wallet, format!("sombe:chat_account:{generation}").as_bytes(), seed.as_mut_slice())
        .expect("32 bytes is a valid HKDF length");
    seed
}

/// HKDF-SHA256 (RFC 5869). An empty salt is 32 zero bytes, as the RFC says.
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> std::result::Result<(), ()> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    Hkdf::<Sha256>::new(salt, ikm).expand(info, okm).map_err(|_| ())
}

fn sign_card(wallet: &[u8; SEED_BYTES], account_public_key: &str) -> WalletCard {
    let wallet_key = Ed25519SecretKey::from_slice(wallet);
    let wallet_address = bs58::encode(wallet_key.public_key().as_bytes()).into_string();
    let wallet_signature =
        bs58::encode(wallet_key.sign(card_text(&wallet_address, account_public_key).as_bytes()).to_bytes())
            .into_string();
    WalletCard { wallet_address, account_public_key: account_public_key.to_owned(), wallet_signature }
}

fn proof(old: &ChatAccountKey, new: &ChatAccountKey) -> RotationProof {
    let text = rotate_text(&old.public_key, &new.public_key, new.generation);
    RotationProof {
        old_account_public_key: old.public_key.clone(),
        new_account_public_key: new.public_key.clone(),
        generation: new.generation,
        old_signature: old.sign(&text),
        new_signature: new.sign(&text),
    }
}

fn seal_with_nonce(
    key: &[u8; SEED_BYTES],
    nonce: &[u8; NONCE_BYTES],
    seed: &[u8; SEED_BYTES],
    generation: u16,
) -> Result<String> {
    let mut clear = Zeroizing::new(Vec::with_capacity(SEALED_CLEAR_BYTES));
    clear.extend_from_slice(&generation.to_be_bytes());
    clear.extend_from_slice(seed);
    let sealed = cipher(key)?
        .encrypt(&XNonce::from(*nonce), Payload { msg: &clear, aad: &seal_aad() })
        .map_err(|_| ChatCryptoError::Encryption { reason: "could not seal".to_owned() })?;
    let mut out = Vec::with_capacity(SEALED_BYTES);
    out.push(SEAL_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(base64_encode(out))
}

fn cipher(key: &[u8; SEED_BYTES]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| invalid_key("sealing key must be 32 bytes".to_owned()))
}

fn seal_aad() -> Vec<u8> {
    let mut aad = SEAL_AAD.as_bytes().to_vec();
    aad.push(SEAL_VERSION);
    aad
}

fn device_fingerprint(der: &[u8]) -> Result<String> {
    if der.is_empty() {
        return Err(invalid_key("the device public key is empty".to_owned()));
    }
    Ok(hex(&Sha256::digest(der)))
}

fn is_lower_uuid(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len && group.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn check_generation(generation: u16) -> Result<()> {
    if (FIRST_GENERATION..=LAST_GENERATION).contains(&generation) {
        Ok(())
    } else {
        Err(invalid_key("generation must be 1 to 32767".to_owned()))
    }
}

/// Moves a secret out of the call's buffer into an array erased on drop.
fn secret_array(secret: Vec<u8>, name: &str) -> Result<Zeroizing<[u8; SEED_BYTES]>> {
    let secret = Zeroizing::new(secret);
    let mut array = Zeroizing::new([0u8; SEED_BYTES]);
    if secret.len() != SEED_BYTES {
        return Err(invalid_key(format!("{name} must be 32 bytes")));
    }
    array.copy_from_slice(&secret);
    Ok(array)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn refused(reason: &str) -> ChatCryptoError {
    ChatCryptoError::RefusedToSign { reason: reason.to_owned() }
}

fn invalid_key(reason: String) -> ChatCryptoError {
    ChatCryptoError::InvalidKey { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    fn okm(salt: &str, ikm: &str, info: &str, length: usize) -> String {
        let mut out = vec![0u8; length];
        hkdf_sha256(&unhex(salt), &unhex(ikm), &unhex(info), &mut out).unwrap();
        hex(&out)
    }

    #[test]
    fn hkdf_matches_rfc_5869() {
        // Test case 1.
        assert_eq!(
            okm(
                "000102030405060708090a0b0c",
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "f0f1f2f3f4f5f6f7f8f9",
                42
            ),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // Test case 2.
        let seq = |from: u8, to: u8| hex(&(from..=to).collect::<Vec<u8>>());
        assert_eq!(
            okm(&seq(0x60, 0xaf), &seq(0x00, 0x4f), &seq(0xb0, 0xff), 82),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
        // Test case 3: empty salt and info, the case the account key uses.
        assert_eq!(
            okm("", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", 42),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn sealed_bytes_follow_the_format() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let seed = [0x33u8; 32];
        let sealed = base64_decode(seal_with_nonce(&key, &nonce, &seed, 0x0102).unwrap()).unwrap();
        assert_eq!(sealed.len(), SEALED_BYTES);
        assert_eq!(sealed[0], 1);
        assert_eq!(&sealed[1..25], &nonce);
        // The clear text is the generation in big endian, then the seed, under the AAD.
        let clear = XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .decrypt(
                &XNonce::from(nonce),
                Payload { msg: &sealed[25..], aad: b"sombe:chat_account_seal:v1\x01" },
            )
            .unwrap();
        assert_eq!(&clear[..2], &[0x01, 0x02]);
        assert_eq!(&clear[2..], &seed);
    }

    #[test]
    fn the_same_seed_seals_differently_each_time() {
        let key = derive(vec![9; 32], 1).unwrap().key;
        let a = key.seal(vec![4; 32]).unwrap();
        let b = key.seal(vec![4; 32]).unwrap();
        assert_ne!(a, b);
    }
}
