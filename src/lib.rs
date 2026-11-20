//! SOMBE ChatPay end-to-end encryption, a thin layer over vodozemac (Olm).
//!
//! The app never sees a vodozemac type: it holds one `ChatCrypto` (the account) and
//! keeps sessions as opaque, encrypted pickles that go in and out of each call, so it
//! can write the advanced session in the same database transaction as the result.
//! Since 0.7.0 it also holds the account key (`ChatAccountKey`): the app never sees its
//! private half, only its public key and the texts it signed. Since 0.10.0 it holds the
//! sealing key of the identity (`ChatSealingKey`) the same way.
//! The wire formats are described in PROTOCOL.md.

use std::sync::{Arc, Mutex, MutexGuard};

use hkdf::Hkdf;
use sha2::Sha256;
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};
use vodozemac::{base64_decode, base64_encode, Curve25519PublicKey};
use zeroize::Zeroizing;

mod access;
mod account;
mod attestation;
mod b64;
mod content;
mod safety;
mod sealed;
mod statement;
mod token;
mod vault;

pub use account::{
    AccountRotation, AccountRotationContent, ChatAccountKey, DerivedAccount, ProvenRotation, RotationProof,
    SignedStatement, WalletCard,
};
pub use attestation::{TrustedAttestationKey, VerifiedAliasChange};
pub use content::{
    AccessKeyGrant, Content, ContentBinding, ContentBody, ContentChannel, OutgoingContent, ReceiptStatus,
    TypingState,
};
#[cfg(feature = "vectors")]
pub use sealed::vectors;
pub use sealed::{ChatSealingKey, OpenedSealed, SealedRecipient, SealedSender, SEALED_PROTOCOL};
pub use token::PreparedAliasToken;
pub use vault::{AliasVault, AliasVaultKey, RetiredAlias, VaultToken};

uniffi::setup_scaffolding!();

/// Protocol id written in every envelope and identity statement.
pub const PROTOCOL: &str = "olm-v1";

/// Starts the pickle of a session bound to its contact (since 0.7.1). A pickle without it
/// was written by 0.7.0 or earlier, under the pickle key itself.
const BOUND_SESSION_PREFIX: &str = "v2:";
const SESSION_KEY_INFO: &[u8] = b"sombe:session_pickle:v2";

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
    /// The content is malformed: keep the message as unreadable.
    #[error("invalid content: {reason}")]
    InvalidContent { reason: String },
    /// A content kind or version this module does not know yet (since 0.5.0): the message
    /// is authentic but cannot be shown. Never read as another kind.
    #[error("unsupported content: {reason}")]
    UnsupportedContent { reason: String },
    /// The identity is not newer than the one pinned for this contact.
    #[error("identity is older than the pinned one")]
    StaleIdentity,
    /// A sealed account key that does not open: wrong sealing key, changed or truncated
    /// text, or another format version (since 0.7.0). Never more detail. (A sealing key of
    /// an identity that does not restore is `InvalidPickle`.)
    #[error("the sealed account key does not open")]
    InvalidSealedKey,
    /// The account key was asked to sign a text that is not exactly one of its formats
    /// (since 0.7.0). Nothing was signed.
    #[error("refused to sign: {reason}")]
    RefusedToSign { reason: String },
    /// The wallet secret does not give this account key at its generation (since 0.7.0).
    #[error("the wallet secret does not give this account key")]
    WrongGeneration,
    /// The account key is at generation 32767 and cannot rotate any more (since 0.7.0).
    #[error("no generation left")]
    GenerationExhausted,
    /// The identity names another account key than the one pinned for this contact, without
    /// a valid rotation proof (since 0.7.0): pause the contact until the safety codes match.
    #[error("the contact's account key changed without proof")]
    AccountChanged,
    /// An alias attestation that does not hold (since 0.8.0): its form, its key, its
    /// signature, its account or its date. Never more detail.
    #[error("invalid alias attestation")]
    InvalidAttestation,
    /// A content that does not belong to the element it came with (since 0.8.0): another
    /// channel, envelope id, sender or recipient, by account id or (since 0.8.1) by identity
    /// key. Drop it without a trace.
    #[error("the content does not belong to this element")]
    UnboundContent,
    /// A sealed envelope that does not open (since 0.10.0): another sealing key, another
    /// recipient, identity or envelope id, a changed or truncated text, or a clear text that
    /// is not exactly the format. Never more detail.
    #[error("the sealed envelope does not open")]
    InvalidSealed,
    /// An alias vault that does not open (since 0.11.0): another key or account, a changed or
    /// cut block, a JSON that is not exactly the one the module writes, or a vault that
    /// cannot be written. Never more detail.
    #[error("the alias vault does not open")]
    InvalidVault,
    /// An alias vault of a format or a schema this module does not know (since 0.11.0). Do
    /// not rewrite it: an older app must not erase a newer vault.
    #[error("the alias vault is of a newer format")]
    UnsupportedVault,
    /// An alias token that does not hold (since 0.11.0): the key, a length, the signature.
    /// Never more detail.
    #[error("invalid alias token")]
    InvalidToken,
}

type Result<T> = std::result::Result<T, ChatCryptoError>;

/// The public keys of one identity, base64 as vodozemac writes them.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct IdentityKeys {
    pub curve25519_key: String,
    pub ed25519_key: String,
}

/// An identity whose statement (v3, or v4 since 0.10.0) was checked against its account key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub account_public_key: String,
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub created_at: String,
    /// The X25519 key to seal envelopes for this identity, base64 without padding (since
    /// 0.10.0): present exactly when the statement is a v4. Once a contact was seen in v4,
    /// the app refuses a v3 of theirs.
    pub sealing_key: Option<String>,
}

/// The columns of an identity statement, as the server returns them: a v3, or a v4 when
/// `sealing_key` is present (since 0.10.0). The module rebuilds the text itself.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct StatementFields {
    pub account_public_key: String,
    pub curve25519_key: String,
    pub ed25519_key: String,
    /// Base64 without padding of 32 bytes; absent in a v3.
    pub sealing_key: Option<String>,
    pub created_at: String,
    /// Base64 without padding.
    pub identity_signature: String,
    /// Base58.
    pub account_signature: String,
}

/// The Olm keys pinned for a contact, with the date of their statement.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct PinnedOlm {
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub created_at: String,
}

/// What the app pinned for a contact. Present as soon as an account key is pinned, even
/// before any Olm keys.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct PinnedIdentity {
    pub account_public_key: String,
    /// Known once a rotation of this contact was accepted.
    pub account_generation: Option<u16>,
    /// Filled by the first wallet card accepted for this contact.
    pub wallet_address: Option<String>,
    pub olm: Option<PinnedOlm>,
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
    /// The contact proved a new account key, same Olm keys: pin the key, keep the session,
    /// drop the verified mark (since 0.7.0).
    AccountRotated,
    /// The contact proved a new account key and has new Olm keys: pin both, as for
    /// `Changed` (since 0.7.0).
    AccountRotatedAndChanged,
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
    /// A version 1 safety number, from a phone not yet on 0.7.0 (since 0.7.0).
    OutdatedCode,
    /// Not a SOMBE safety number at all.
    NotASafetyCode,
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

/// A session as the app stores it: its id and its encrypted pickle. Since 0.7.1 the pickle
/// opens only for the contact (curve25519 key) the session was made with.
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
        let remote_curve = curve_key(&remote.curve25519_key)?;
        let mut session = match (session, claimed_key) {
            (Some(stored), _) => restore_session(&stored, &key, &remote_curve)?,
            (None, Some(claimed)) => {
                let one_time_key = statement::verify_one_time_key(&remote.ed25519_key, &claimed)?;
                self.account()
                    .create_outbound_session(SessionConfig::version_1(), remote_curve, one_time_key)
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
            session: store_session(&session, &key, &remote_curve),
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
        let remote_curve = curve_key(&remote.curve25519_key)?;

        if let OlmMessage::PreKey(pre_key) = &message {
            if pre_key.identity_key() != remote_curve {
                return Err(ChatCryptoError::InvalidMessage {
                    reason: "sender identity does not match".to_owned(),
                });
            }
            if let Some(stored) = sessions.iter().find(|s| s.session_id == pre_key.session_id()) {
                return decrypt_with(stored, &message, &key, &remote_curve);
            }
            let created = self
                .account()
                .create_inbound_session(SessionConfig::version_1(), remote_curve, pre_key)
                .map_err(|e| ChatCryptoError::SessionCreation { reason: e.to_string() })?;
            return Ok(DecryptResult {
                plaintext: utf8(created.plaintext)?,
                session: store_session(&created.session, &key, &remote_curve),
                new_session: true,
                account_changed: true,
            });
        }

        for stored in &sessions {
            if let Ok(result) = decrypt_with(stored, &message, &key, &remote_curve) {
                return Ok(result);
            }
        }
        Err(ChatCryptoError::NoMatchingSession)
    }
}

impl ChatCrypto {
    /// The identity's signature (base64) of a statement body. Only `statement` texts reach it.
    pub(crate) fn sign_text(&self, text: &str) -> String {
        self.account().sign(text).to_base64()
    }

    fn account(&self) -> MutexGuard<'_, Account> {
        // Every mutation is a single vodozemac call, so a panic cannot leave
        // the account half written behind a poisoned lock.
        self.account.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Derives the account key of `generation` (1 to 32767) from the 32 byte wallet seed
/// (`m/44'/501'/0'/0'`), and its wallet card signed by the wallet. The wallet secret is
/// erased from the module's memory before returning.
#[uniffi::export]
pub fn derive_account_key(wallet_secret: Vec<u8>, generation: u16) -> Result<DerivedAccount> {
    account::derive(wallet_secret, generation)
}

/// The rotation proof from the key of `from_generation` to the key of `to_generation`
/// (1 ≤ from < to ≤ 32767), and the wallet card of the latter. Only public data.
#[uniffi::export]
pub fn prove_rotation(
    wallet_secret: Vec<u8>,
    from_generation: u16,
    to_generation: u16,
) -> Result<ProvenRotation> {
    account::prove(wallet_secret, from_generation, to_generation)
}

/// Checks a wallet card: canonical base58 fields (`InvalidKey`) and the wallet's signature
/// (`InvalidSignature`).
#[uniffi::export]
pub fn verify_wallet_card(card: WalletCard) -> Result<()> {
    account::verify_wallet_card(&card)
}

/// Checks an identity statement from the server's columns, a v3 or (since 0.10.0) a v4 when
/// `sealing_key` is given: the module rebuilds the text, then checks the identity's and the
/// account key's signatures.
#[uniffi::export]
pub fn verify_identity(fields: StatementFields) -> Result<VerifiedIdentity> {
    statement::verify(&fields)
}

/// Compares a contact's verified identity with the one pinned for them (none when no
/// account key is pinned yet). Another account key passes only with `rotation`, a valid
/// `account_rotation` content from the pinned key and the pinned wallet.
#[uniffi::export]
pub fn check_identity_update(
    pinned: Option<PinnedIdentity>,
    candidate: VerifiedIdentity,
    rotation: Option<AccountRotationContent>,
) -> Result<IdentityUpdate> {
    statement::check_update(pinned.as_ref(), &candidate, rotation.as_ref())
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

/// Checks an alias attestation carried by a contact request or acceptance (since 0.8.0)
/// and returns its alias. `sender_account_id` and `sender_account_public_key` are the
/// sender's, from the mailbox element and their verified identity v3; `deposited_at` is
/// the element's `created_at`. Any failure is `InvalidAttestation`.
#[uniffi::export]
pub fn verify_alias_attestation(
    text: String,
    signature: String,
    trusted_keys: Vec<TrustedAttestationKey>,
    sender_account_id: String,
    sender_account_public_key: String,
    deposited_at: String,
) -> Result<String> {
    attestation::verify(
        &text,
        &signature,
        &trusted_keys,
        &sender_account_id,
        &sender_account_public_key,
        &deposited_at,
    )
}

/// Checks the attestation of an `alias_change` (since 0.11.0) exactly as
/// `verify_alias_attestation` does, and returns the alias with the `expires` the server
/// signed. A contact applies a change only if its `expires` is later than the last one
/// applied for that sender.
#[uniffi::export]
pub fn verify_alias_change(
    text: String,
    signature: String,
    trusted_keys: Vec<TrustedAttestationKey>,
    sender_account_id: String,
    sender_account_public_key: String,
    deposited_at: String,
) -> Result<VerifiedAliasChange> {
    attestation::verify_change(
        &text,
        &signature,
        &trusted_keys,
        &sender_account_id,
        &sender_account_public_key,
        &deposited_at,
    )
}

/// The key of the alias vault of `account_id` (a lower case UUID), from the 32 byte wallet
/// seed (since 0.11.0). The seed is erased from the module's memory before returning.
#[uniffi::export]
pub fn derive_alias_vault_key(wallet_secret: Vec<u8>, account_id: String) -> Result<Arc<AliasVaultKey>> {
    vault::derive(wallet_secret, account_id)
}

/// Blinds a new alias token for the key `public_key_spki` (DER SPKI, base64 with padding),
/// named `key_id` in the app (since 0.11.0). `idem` is the burn's idempotency key, a lower
/// case UUID v4. Keep the result in the vault before paying.
#[uniffi::export]
pub fn alias_token_prepare(
    public_key_spki: String,
    key_id: String,
    idem: String,
) -> Result<PreparedAliasToken> {
    token::prepare(&public_key_spki, &key_id, &idem)
}

/// Unblinds the wallet API's `blind_signature` and returns the `token_signature` ChatPay
/// takes, only if it verifies under the key (since 0.11.0).
#[uniffi::export]
pub fn alias_token_finalize(
    public_key_spki: String,
    nonce: String,
    blinded_msg: String,
    secret: String,
    blind_signature: String,
) -> Result<String> {
    token::finalize(&public_key_spki, &nonce, &blinded_msg, &secret, &blind_signature)
}

/// True if `token_signature` signs the prepared message `nonce` under the key (since 0.11.0).
/// A key or a length that is not valid is `InvalidToken`.
#[uniffi::export]
pub fn alias_token_verify(public_key_spki: String, nonce: String, token_signature: String) -> Result<bool> {
    token::verify(&public_key_spki, &nonce, &token_signature)
}

/// The memo of the burn that pays a token: `sombe-alias-token:` and the SHA-256 of the bytes
/// of `blinded_msg` in base64url without padding (since 0.11.0).
#[uniffi::export]
pub fn alias_token_memo(blinded_msg: String) -> Result<String> {
    token::memo(&blinded_msg)
}

/// The access key of a profile key (since 0.9.0): HKDF-SHA256 of the 32 byte profile key,
/// empty salt, info `sombe:access_key:1`, 16 bytes in base64 without padding. Another
/// length of profile key is `InvalidKey`. The profile key is erased from the module's memory
/// before returning.
#[uniffi::export]
pub fn derive_access_key(profile_key: Vec<u8>) -> Result<String> {
    access::derive(profile_key)
}

/// The verifier the server keeps for an access key (since 0.9.0): SHA-256 of its 16 bytes,
/// base64 without padding. An access key in any other spelling is `InvalidKey`.
#[uniffi::export]
pub fn access_key_verifier(access_key: String) -> Result<String> {
    access::verifier(&access_key)
}

/// Writes a version 4 content (since 0.8.1), padded to its size bucket: it names the
/// account ids and the ed25519 identity keys of its sender and its recipient. A content
/// whose shape does not match its kind, or a key that is not base64 without padding of 32
/// bytes, is `InvalidContent`.
#[uniffi::export]
pub fn encode_content(content: OutgoingContent) -> Result<String> {
    content::encode(content)
}

/// Reads a decrypted content and binds it to its element (since 0.8.0): a malformed
/// content is `InvalidContent` or `UnsupportedContent`; one that does not belong to the
/// element (channel, envelope id, the account id and the identity key of the sender and of
/// the recipient, or the old conversation id for versions 1 and 2) is `UnboundContent`, to
/// be dropped without a trace. Give as `sender_ed25519_key` the key of the identity whose
/// keys were given to `decrypt_from`, never one read from the content. Version 3 (0.8.0)
/// is `UnsupportedContent`.
#[uniffi::export]
pub fn decode_content(json: String, binding: ContentBinding) -> Result<Content> {
    content::decode(&json, &binding)
}

/// Seals an Olm envelope for one identity of a contact (since 0.10.0), so that the server
/// cannot read who sent it: HPKE (RFC 9180) base mode to `recipient.sealing_key`, bound to
/// the recipient's account id, identity id and `envelope_id`. `sender` is my account id,
/// identity id and my own statement v4 (the columns I published), checked before sealing.
/// Returns the `ciphertext` of a `sealed-v1` envelope.
#[uniffi::export]
pub fn seal(
    recipient: SealedRecipient,
    envelope_id: String,
    sender: SealedSender,
    envelope: Envelope,
) -> Result<String> {
    sealed::seal(&recipient, &envelope_id, &sender, &envelope)
}

#[uniffi::export]
pub fn protocol_id() -> String {
    PROTOCOL.to_owned()
}

/// The `protocol` of a sealed envelope, `sealed-v1` (since 0.10.0).
#[uniffi::export]
pub fn sealed_protocol_id() -> String {
    SEALED_PROTOCOL.to_owned()
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

fn decrypt_with(
    stored: &StoredSession,
    message: &OlmMessage,
    key: &[u8; 32],
    remote: &Curve25519PublicKey,
) -> Result<DecryptResult> {
    let mut session = restore_session(stored, key, remote)?;
    let plaintext =
        session.decrypt(message).map_err(|e| ChatCryptoError::Decryption { reason: e.to_string() })?;
    Ok(DecryptResult {
        plaintext: utf8(plaintext)?,
        session: store_session(&session, key, remote),
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

/// Opens a stored session for `remote`. A bound pickle (since 0.7.1) opens only under the
/// key drawn for that contact, so a session passed with another contact is `InvalidPickle`.
/// A pickle written by 0.7.0 or earlier opens under the pickle key, and is bound when stored.
fn restore_session(stored: &StoredSession, key: &[u8; 32], remote: &Curve25519PublicKey) -> Result<Session> {
    let pickle = match stored.pickle.strip_prefix(BOUND_SESSION_PREFIX) {
        Some(bound) => SessionPickle::from_encrypted(bound, &session_key(key, remote)),
        None => SessionPickle::from_encrypted(&stored.pickle, key),
    }
    .map_err(|_| ChatCryptoError::InvalidPickle)?;
    Ok(Session::from_pickle(pickle))
}

fn store_session(session: &Session, key: &[u8; 32], remote: &Curve25519PublicKey) -> StoredSession {
    let pickle = session.pickle().encrypt(&session_key(key, remote));
    StoredSession { session_id: session.session_id(), pickle: format!("{BOUND_SESSION_PREFIX}{pickle}") }
}

/// The key of one contact's session pickles: HKDF-SHA256 of the pickle key, with the
/// contact's curve25519 key in the info.
fn session_key(key: &[u8; 32], remote: &Curve25519PublicKey) -> Zeroizing<[u8; 32]> {
    let mut info = SESSION_KEY_INFO.to_vec();
    info.extend_from_slice(remote.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(&info, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF length");
    out
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

/// Fixed keys and fixed randomness for the alias vault and the alias token, for
/// tools/make_vectors.rs and its tests only.
#[cfg(feature = "vectors")]
#[doc(hidden)]
pub mod alias_vectors {
    use super::*;

    pub use crate::token::fixed::StreamRng;

    pub fn seal_vault(key: &AliasVaultKey, vault: AliasVault, nonce: [u8; 24]) -> Result<String> {
        vault::seal_with_nonce(key, vault, nonce)
    }

    pub fn seal_key(key: &AliasVaultKey, sealing_key: [u8; 32], nonce: [u8; 24]) -> Result<String> {
        vault::seal_key_with_nonce(key, sealing_key, nonce)
    }

    /// Seals any clear text of 16 343 bytes under a chosen format byte, to write the blocks a
    /// reader must refuse.
    pub fn seal_clear(key: &AliasVaultKey, clear: &[u8], nonce: [u8; 24], format: u8) -> String {
        vault::seal_clear(key, clear, nonce, format)
    }

    /// The padded clear text of a vault: length, JSON, zeros.
    pub fn clear_text(vault: AliasVault) -> Result<Vec<u8>> {
        vault::clear_text(vault)
    }

    pub fn prepare(
        public_key_spki: &str,
        key_id: &str,
        idem: &str,
        message: [u8; 32],
        seed: &[u8],
    ) -> Result<PreparedAliasToken> {
        token::fixed::prepare(public_key_spki, key_id, idem, message, seed)
    }
}
