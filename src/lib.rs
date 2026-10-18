//! SOMBE ChatPay end-to-end encryption, a thin layer over vodozemac (Olm).
//!
//! The app never sees a vodozemac type: it holds one `ChatCrypto` (the account) and
//! keeps sessions as opaque, encrypted pickles that go in and out of each call, so it
//! can write the advanced session in the same database transaction as the result.
//! The wire formats are described in PROTOCOL.md.

use std::sync::{Arc, Mutex, MutexGuard};

use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::{base64_decode, base64_encode, Curve25519PublicKey};
use zeroize::Zeroizing;

mod content;
mod profile;
mod safety;
mod statement;

pub use content::{ContentKind, MessageContent};

uniffi::setup_scaffolding!();

/// Protocol id written in every envelope and identity statement.
pub const PROTOCOL: &str = "olm-v1";

#[derive(uniffi::Error, thiserror::Error, Debug, PartialEq, Eq)]
pub enum ChatCryptoError {
    #[error("invalid key: {reason}")]
    InvalidKey { reason: String },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid identity statement: {reason}")]
    InvalidStatement { reason: String },
    #[error("unsupported protocol: {protocol}")]
    UnsupportedProtocol { protocol: String },
    #[error("invalid pickle or pickle key")]
    InvalidPickle,
    #[error("invalid message: {reason}")]
    InvalidMessage { reason: String },
    #[error("no session can decrypt this message")]
    NoMatchingSession,
    #[error("could not create a session: {reason}")]
    SessionCreation { reason: String },
    #[error("could not decrypt: {reason}")]
    Decryption { reason: String },
    #[error("could not encrypt: {reason}")]
    Encryption { reason: String },
    #[error("invalid content: {reason}")]
    InvalidContent { reason: String },
    /// The identity names another wallet than the one pinned for this contact.
    #[error("the contact's wallet address changed")]
    WalletChanged,
    /// The identity is not newer than the one pinned for this contact.
    #[error("identity is older than the pinned one")]
    StaleIdentity,
    #[error("invalid profile: {reason}")]
    InvalidProfile { reason: String },
}

type Result<T> = std::result::Result<T, ChatCryptoError>;

/// The public keys of one identity, base64 as vodozemac writes them.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519_key: String,
    pub ed25519_key: String,
}

/// An identity whose statement was checked against its wallet signature.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub wallet_address: String,
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub created_at: String,
}

/// How a contact's identity compares with the one the app pinned for them.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityUpdate {
    /// No identity was pinned yet: pin this one.
    New,
    /// Same keys as the pinned identity.
    Unchanged,
    /// A newer identity (a new phone): pin it, and drop the contact's verified mark.
    Changed,
}

/// The code two people compare to check their conversation.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 60 digits, the same on both phones.
    pub digits: String,
    /// The same digits in 12 groups of 5, as the app shows them.
    pub groups: Vec<String>,
    /// The text to put in the QR code.
    pub qr_payload: String,
}

/// What a scanned QR code says about the conversation.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanResult {
    /// Same safety number: the contact can be marked verified.
    Match,
    /// A SOMBE safety number, but another one.
    Mismatch,
    /// Not a SOMBE safety number at all.
    NotASafetyCode,
}

/// What a person shows their contacts. Encrypted end to end: the server never reads it.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// 1 to 64 characters, no control character.
    pub display_name: Option<String>,
    /// At most 140 characters.
    pub about: Option<String>,
}

/// A one time key (or the fallback key), signed by the identity's ed25519 key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SignedOneTimeKey {
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
    pub is_fallback: bool,
}

/// What the server stores and relays. `olm_type` 0 opens a session, 1 follows one.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub protocol: String,
    pub olm_type: u8,
    pub ciphertext: String,
}

/// A session as the app stores it: its id and its encrypted pickle.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct StoredSession {
    pub session_id: String,
    pub pickle: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EncryptResult {
    pub envelope: Envelope,
    /// The advanced session, to store in the same transaction as the envelope.
    pub session: StoredSession,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct DecryptResult {
    pub plaintext: String,
    /// The advanced (or new) session, to store in the same transaction as the plaintext.
    pub session: StoredSession,
    /// True when a first message opened a new inbound session.
    pub new_session: bool,
    /// True when the account used up a one time key: pickle it again in the same transaction.
    pub account_changed: bool,
}

/// One device's encryption identity (an Olm account).
#[derive(uniffi::Object)]
pub struct ChatCrypto {
    account: Mutex<Account>,
}

#[uniffi::export]
impl ChatCrypto {
    #[uniffi::constructor]
    pub fn create_account() -> Arc<Self> {
        Arc::new(Self { account: Mutex::new(Account::new()) })
    }

    #[uniffi::constructor]
    pub fn restore_account(pickle: String, pickle_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = pickle_key_array(pickle_key)?;
        let pickle =
            AccountPickle::from_encrypted(&pickle, &key).map_err(|_| ChatCryptoError::InvalidPickle)?;
        Ok(Arc::new(Self { account: Mutex::new(Account::from_pickle(pickle)) }))
    }

    /// The account, encrypted with a 32 byte key. Never log it, never send it.
    pub fn pickle(&self, pickle_key: Vec<u8>) -> Result<String> {
        let key = pickle_key_array(pickle_key)?;
        Ok(self.account().pickle().encrypt(&key))
    }

    pub fn identity_keys(&self) -> IdentityKeys {
        let keys = self.account().identity_keys();
        IdentityKeys { curve25519_key: keys.curve25519.to_base64(), ed25519_key: keys.ed25519.to_base64() }
    }

    /// The text the wallet signs to vouch for this identity. It already carries the
    /// identity's own signature of the wallet address, so no wallet can claim these keys.
    pub fn identity_statement(&self, wallet_address: String, created_at: String) -> Result<String> {
        let body = statement::body(&wallet_address, &self.identity_keys(), &created_at)?;
        let identity_signature = self.account().sign(&body).to_base64();
        Ok(statement::build(&body, &identity_signature))
    }

    /// Generates `count` one time keys and returns every unpublished one, signed.
    pub fn generate_one_time_keys(&self, count: u32) -> Vec<SignedOneTimeKey> {
        let mut account = self.account();
        account.generate_one_time_keys(count as usize);
        let mut keys: Vec<_> = account.one_time_keys().into_iter().collect();
        keys.sort_by_key(|(id, _)| id.to_base64());
        keys.into_iter().map(|(id, key)| sign_key(&account, id.to_base64(), key, false)).collect()
    }

    /// Replaces the fallback key and returns the new one, signed.
    pub fn generate_fallback_key(&self) -> SignedOneTimeKey {
        let mut account = self.account();
        account.generate_fallback_key();
        let (id, key) = account.fallback_key().into_iter().next().expect("a fallback key was just generated");
        sign_key(&account, id.to_base64(), key, true)
    }

    /// Call once the server has accepted the keys returned above.
    pub fn mark_keys_published(&self) {
        self.account().mark_keys_as_published();
    }

    /// Encrypts with `session` when given, else opens a session on `claimed_key`
    /// (checked against `remote`'s ed25519 key first).
    pub fn encrypt_for(
        &self,
        remote: IdentityKeys,
        session: Option<StoredSession>,
        claimed_key: Option<SignedOneTimeKey>,
        plaintext: String,
        pickle_key: Vec<u8>,
    ) -> Result<EncryptResult> {
        let key = pickle_key_array(pickle_key)?;
        let mut session = match (session, claimed_key) {
            (Some(stored), _) => restore_session(&stored, &key)?,
            (None, Some(claimed)) => {
                let one_time_key = statement::verify_one_time_key(&remote.ed25519_key, &claimed)?;
                self.account()
                    .create_outbound_session(
                        SessionConfig::version_1(),
                        curve_key(&remote.curve25519_key)?,
                        one_time_key,
                    )
                    .map_err(|e| ChatCryptoError::SessionCreation { reason: e.to_string() })?
            }
            (None, None) => {
                return Err(ChatCryptoError::SessionCreation {
                    reason: "no session and no claimed key".to_owned(),
                })
            }
        };
        let message = session
            .encrypt(plaintext.as_bytes())
            .map_err(|e| ChatCryptoError::Encryption { reason: e.to_string() })?;
        let (olm_type, bytes) = message.to_parts();
        Ok(EncryptResult {
            envelope: Envelope {
                protocol: PROTOCOL.to_owned(),
                olm_type: olm_type as u8,
                ciphertext: base64_encode(bytes),
            },
            session: store_session(&session, &key),
        })
    }

    /// Decrypts a message from `remote`. `sessions` are the stored sessions with that
    /// identity, most recently used first. A first message (type 0) that no session
    /// matches opens a new inbound session; a following message (type 1) never does.
    pub fn decrypt_from(
        &self,
        remote: IdentityKeys,
        sessions: Vec<StoredSession>,
        envelope: Envelope,
        pickle_key: Vec<u8>,
    ) -> Result<DecryptResult> {
        let key = pickle_key_array(pickle_key)?;
        let message = parse_envelope(&envelope)?;

        if let OlmMessage::PreKey(pre_key) = &message {
            let remote_curve = curve_key(&remote.curve25519_key)?;
            if pre_key.identity_key() != remote_curve {
                return Err(ChatCryptoError::InvalidMessage {
                    reason: "sender identity does not match".to_owned(),
                });
            }
            if let Some(stored) = sessions.iter().find(|s| s.session_id == pre_key.session_id()) {
                return decrypt_with(stored, &message, &key);
            }
            let created = self
                .account()
                .create_inbound_session(SessionConfig::version_1(), remote_curve, pre_key)
                .map_err(|e| ChatCryptoError::SessionCreation { reason: e.to_string() })?;
            return Ok(DecryptResult {
                plaintext: utf8(created.plaintext)?,
                session: store_session(&created.session, &key),
                new_session: true,
                account_changed: true,
            });
        }

        for stored in &sessions {
            if let Ok(result) = decrypt_with(stored, &message, &key) {
                return Ok(result);
            }
        }
        Err(ChatCryptoError::NoMatchingSession)
    }
}

impl ChatCrypto {
    fn account(&self) -> MutexGuard<'_, Account> {
        // Every mutation is a single vodozemac call, so a panic cannot leave
        // the account half written behind a poisoned lock.
        self.account.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Checks an identity statement against the wallet that signed it (base58 signature).
#[uniffi::export]
pub fn verify_identity(
    statement: String,
    wallet_address: String,
    wallet_signature: String,
) -> Result<VerifiedIdentity> {
    statement::verify(&statement, &wallet_address, &wallet_signature)
}

/// Compares a contact's verified identity with the one pinned for them (none the first
/// time). Refuses an identity that is not strictly newer, or that names another wallet.
#[uniffi::export]
pub fn check_identity_update(
    pinned: Option<VerifiedIdentity>,
    candidate: VerifiedIdentity,
) -> Result<IdentityUpdate> {
    statement::check_update(pinned.as_ref(), &candidate)
}

/// The safety number of a conversation, from both verified identities (as returned by
/// `verify_identity`). Both phones get the same digits whichever side computes it.
#[uniffi::export]
pub fn safety_number(local: VerifiedIdentity, remote: VerifiedIdentity) -> Result<SafetyNumber> {
    safety::compute(&local, &remote)
}

/// Compares the text of a scanned QR code with this conversation's safety number.
#[uniffi::export]
pub fn compare_scanned_safety_code(
    local: VerifiedIdentity,
    remote: VerifiedIdentity,
    scanned: String,
) -> Result<ScanResult> {
    safety::compare_scan(&local, &remote, &scanned)
}

/// A new random 32 byte profile key. Keep it on the phone; share it with a contact by
/// sending them a `profile_key` content, and make a new one to stop sharing with someone.
#[uniffi::export]
pub fn generate_profile_key() -> Result<Vec<u8>> {
    profile::generate_key()
}

/// The profile key as a `profile_key` content carries it.
#[uniffi::export]
pub fn encode_profile_key(profile_key: Vec<u8>) -> Result<String> {
    profile::encode_key(&Zeroizing::new(profile_key))
}

/// The profile key from a received `profile_key` content.
#[uniffi::export]
pub fn decode_profile_key(encoded: String) -> Result<Vec<u8>> {
    profile::decode_key(&encoded)
}

/// The profile of `wallet_address`, encrypted for the server to store (base64).
#[uniffi::export]
pub fn encrypt_profile(profile: Profile, profile_key: Vec<u8>, wallet_address: String) -> Result<String> {
    profile::encrypt(&profile, &Zeroizing::new(profile_key), &wallet_address)
}

/// A contact's profile, with the profile key they sent and their pinned wallet address.
#[uniffi::export]
pub fn decrypt_profile(ciphertext: String, profile_key: Vec<u8>, wallet_address: String) -> Result<Profile> {
    profile::decrypt(&ciphertext, &Zeroizing::new(profile_key), &wallet_address)
}

/// The avatar image (at most 512 KiB) of `wallet_address`, encrypted for the server to store.
#[uniffi::export]
pub fn encrypt_avatar(image: Vec<u8>, profile_key: Vec<u8>, wallet_address: String) -> Result<Vec<u8>> {
    profile::encrypt_avatar(&image, &Zeroizing::new(profile_key), &wallet_address)
}

/// A contact's avatar image, with the profile key they sent and their pinned wallet address.
#[uniffi::export]
pub fn decrypt_avatar(ciphertext: Vec<u8>, profile_key: Vec<u8>, wallet_address: String) -> Result<Vec<u8>> {
    profile::decrypt_avatar(&ciphertext, &Zeroizing::new(profile_key), &wallet_address)
}

/// Checks that a one time key was signed by this identity.
#[uniffi::export]
pub fn verify_one_time_key(identity: IdentityKeys, key: SignedOneTimeKey) -> bool {
    statement::verify_one_time_key(&identity.ed25519_key, &key).is_ok()
}

/// The exact text an identity signs for one of its one time keys.
#[uniffi::export]
pub fn one_time_key_signed_text(key: SignedOneTimeKey) -> String {
    statement::one_time_key_text(&key.key_id, &key.public_key, key.is_fallback)
}

#[uniffi::export]
pub fn encode_content(content: MessageContent) -> Result<String> {
    content::encode(content)
}

#[uniffi::export]
pub fn decode_content(json: String) -> Result<MessageContent> {
    content::decode(&json)
}

#[uniffi::export]
pub fn protocol_id() -> String {
    PROTOCOL.to_owned()
}

fn sign_key(
    account: &Account,
    key_id: String,
    key: Curve25519PublicKey,
    is_fallback: bool,
) -> SignedOneTimeKey {
    let public_key = key.to_base64();
    let signature = account.sign(statement::one_time_key_text(&key_id, &public_key, is_fallback)).to_base64();
    SignedOneTimeKey { key_id, public_key, signature, is_fallback }
}

fn decrypt_with(stored: &StoredSession, message: &OlmMessage, key: &[u8; 32]) -> Result<DecryptResult> {
    let mut session = restore_session(stored, key)?;
    let plaintext =
        session.decrypt(message).map_err(|e| ChatCryptoError::Decryption { reason: e.to_string() })?;
    Ok(DecryptResult {
        plaintext: utf8(plaintext)?,
        session: store_session(&session, key),
        new_session: false,
        account_changed: false,
    })
}

fn parse_envelope(envelope: &Envelope) -> Result<OlmMessage> {
    if envelope.protocol != PROTOCOL {
        return Err(ChatCryptoError::UnsupportedProtocol { protocol: envelope.protocol.clone() });
    }
    let bytes = base64_decode(&envelope.ciphertext)
        .map_err(|e| ChatCryptoError::InvalidMessage { reason: e.to_string() })?;
    OlmMessage::from_parts(envelope.olm_type as usize, &bytes)
        .map_err(|e| ChatCryptoError::InvalidMessage { reason: e.to_string() })
}

fn restore_session(stored: &StoredSession, key: &[u8; 32]) -> Result<Session> {
    let pickle =
        SessionPickle::from_encrypted(&stored.pickle, key).map_err(|_| ChatCryptoError::InvalidPickle)?;
    Ok(Session::from_pickle(pickle))
}

fn store_session(session: &Session, key: &[u8; 32]) -> StoredSession {
    StoredSession { session_id: session.session_id(), pickle: session.pickle().encrypt(key) }
}

fn pickle_key_array(pickle_key: Vec<u8>) -> Result<Zeroizing<[u8; 32]>> {
    let pickle_key = Zeroizing::new(pickle_key);
    let array: [u8; 32] = pickle_key
        .as_slice()
        .try_into()
        .map_err(|_| ChatCryptoError::InvalidKey { reason: "pickle key must be 32 bytes".to_owned() })?;
    Ok(Zeroizing::new(array))
}

fn curve_key(base64: &str) -> Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_base64(base64)
        .map_err(|e| ChatCryptoError::InvalidKey { reason: e.to_string() })
}

fn utf8(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes)
        .map_err(|_| ChatCryptoError::Decryption { reason: "plaintext is not UTF-8".to_owned() })
}
