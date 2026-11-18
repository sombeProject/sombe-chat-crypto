//! The sealed sender (since 0.10.0): an Olm envelope sealed for one identity of a contact
//! with HPKE (RFC 9180), so that the server, which takes it without a token, never reads
//! who sent it. The clear text names the sender and carries their statement v4, which the
//! recipient checks against the account key they pinned: the seal only hides the sender,
//! the Olm session and the statement prove who it is.
//!
//! The formats are described in PROTOCOL.md (*Sealed sender*); any change here is a
//! protocol change.

use std::convert::Infallible;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde_json::{Map, Value};
use vodozemac::{base64_decode, base64_encode};
use zeroize::Zeroizing;

use crate::{account, statement, ChatCryptoError, Envelope, StatementFields, PROTOCOL};

type Result<T> = std::result::Result<T, ChatCryptoError>;
type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

/// The `protocol` of a sealed envelope.
pub const SEALED_PROTOCOL: &str = "sealed-v1";
const INFO: &[u8] = b"sombe:sealed:1";
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const CLEAR_VERSION: u64 = 1;
/// The clear text is padded to a multiple of this.
const CLEAR_BUCKET: usize = 256;
/// What the `pad` field adds around its spaces: `,"pad":""`.
const PAD_FIELD_BYTES: usize = 9;
/// `2026-10-14T18:30:01.183Z`, the longest `created_at`.
const MAX_CREATED_CHARS: usize = 24;
const CLEAR_FIELDS: [&str; 13] = [
    "v",
    "sender_account_id",
    "sender_identity_id",
    "account_public_key",
    "curve25519_key",
    "ed25519_key",
    "sealing_key",
    "created_at",
    "identity_signature",
    "account_signature",
    "olm_type",
    "ciphertext",
    "pad",
];

const PICKLE_VERSION: u8 = 1;
const PICKLE_AAD: &[u8] = b"sombe:sealing_key_pickle:v1";
const NONCE_BYTES: usize = 24;
const PICKLE_BYTES: usize = 1 + NONCE_BYTES + KEY_BYTES + TAG_BYTES;

/// The identity of a contact an envelope is sealed for.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SealedRecipient {
    /// Their account id, a lower case UUID.
    pub account_id: String,
    /// The id of their identity whose keys were given to `encrypt_for`, a lower case UUID.
    pub identity_id: String,
    /// The sealing key of that identity, from its verified statement v4.
    pub sealing_key: String,
}

/// Who sealed an envelope, as the clear text says: an account id and an identity id (lower
/// case UUIDs), and the columns of that identity's statement v4.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct SealedSender {
    pub account_id: String,
    pub identity_id: String,
    pub statement: StatementFields,
}

/// What `open_sealed` reads: the sender, not yet checked against anything pinned, and the
/// Olm envelope to give to `decrypt_from`.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct OpenedSealed {
    pub sender: SealedSender,
    pub envelope: Envelope,
}

/// The X25519 key pair one identity opens its sealed envelopes with (since 0.10.0). The
/// private half stays in the module, erased when dropped; the app keeps it only as a pickle.
#[derive(uniffi::Object)]
pub struct ChatSealingKey {
    private_key: PrivateKey,
    public_key: String,
}

#[uniffi::export]
impl ChatSealingKey {
    /// Draws a new key pair from the system's randomness. No randomness is `Encryption`.
    #[uniffi::constructor]
    pub fn generate() -> Result<Arc<Self>> {
        let ikm = random_bytes::<KEY_BYTES>()?;
        Ok(Arc::new(Self::from_ikm(&ikm)))
    }

    /// Opens a pickle written by `pickle`. A wrong pickle key, a changed or truncated text,
    /// or another format version is `InvalidPickle`.
    #[uniffi::constructor]
    pub fn restore(pickle: String, pickle_key: Vec<u8>) -> Result<Arc<Self>> {
        let key = crate::pickle_key_array(pickle_key)?;
        let bytes = base64_decode(&pickle).map_err(|_| ChatCryptoError::InvalidPickle)?;
        if bytes.len() != PICKLE_BYTES || bytes[0] != PICKLE_VERSION {
            return Err(ChatCryptoError::InvalidPickle);
        }
        let nonce =
            XNonce::try_from(&bytes[1..1 + NONCE_BYTES]).map_err(|_| ChatCryptoError::InvalidPickle)?;
        let clear = Zeroizing::new(
            pickle_cipher(&key)
                .decrypt(&nonce, Payload { msg: &bytes[1 + NONCE_BYTES..], aad: PICKLE_AAD })
                .map_err(|_| ChatCryptoError::InvalidPickle)?,
        );
        let private_key = PrivateKey::from_bytes(&clear).map_err(|_| ChatCryptoError::InvalidPickle)?;
        Ok(Arc::new(Self::from_private(private_key)))
    }

    /// The private key, encrypted with a 32 byte key: base64 without padding of `0x01`, a
    /// fresh 24 byte nonce, then the XChaCha20-Poly1305 output. Never log it, never send it.
    pub fn pickle(&self, pickle_key: Vec<u8>) -> Result<String> {
        let key = crate::pickle_key_array(pickle_key)?;
        let nonce = random_bytes::<NONCE_BYTES>()?;
        self.pickle_with_nonce(&key, &nonce)
    }

    /// Base64 without padding of the 32 byte public key, the `sealing:` line of a statement v4.
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    /// Opens an envelope sealed for this key, for my account id, my identity id and the
    /// element's `envelope_id`. Any failure is `InvalidSealed`. The sender's statement has
    /// the form of a v4 and its own signatures hold; the app still checks it against the
    /// account key and the identity pinned for that contact before it trusts anything.
    pub fn open_sealed(
        &self,
        ciphertext: String,
        my_account_id: String,
        my_identity_id: String,
        envelope_id: String,
    ) -> Result<OpenedSealed> {
        let aad = aad(&my_account_id, &my_identity_id, &envelope_id).ok_or(ChatCryptoError::InvalidSealed)?;
        let bytes = canonical_base64(&ciphertext).ok_or(ChatCryptoError::InvalidSealed)?;
        if bytes.len() < KEY_BYTES + TAG_BYTES {
            return Err(ChatCryptoError::InvalidSealed);
        }
        let enc = EncappedKey::from_bytes(&bytes[..KEY_BYTES]).map_err(|_| ChatCryptoError::InvalidSealed)?;
        let clear = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &self.private_key,
            &enc,
            INFO,
            &bytes[KEY_BYTES..],
            aad.as_bytes(),
        )
        .map_err(|_| ChatCryptoError::InvalidSealed)?;
        read_clear(&clear).ok_or(ChatCryptoError::InvalidSealed)
    }
}

impl ChatSealingKey {
    fn from_ikm(ikm: &[u8; KEY_BYTES]) -> Self {
        let (private_key, _) = Kem::derive_keypair(ikm);
        Self::from_private(private_key)
    }

    fn from_private(private_key: PrivateKey) -> Self {
        let public_key = base64_encode(Kem::sk_to_pk(&private_key).to_bytes());
        Self { private_key, public_key }
    }

    fn pickle_with_nonce(&self, key: &[u8; 32], nonce: &[u8; NONCE_BYTES]) -> Result<String> {
        let clear = Zeroizing::new(self.private_key.to_bytes());
        let sealed = pickle_cipher(key)
            .encrypt(&XNonce::from(*nonce), Payload { msg: clear.as_slice(), aad: PICKLE_AAD })
            .map_err(|_| ChatCryptoError::Encryption { reason: "could not pickle".to_owned() })?;
        let mut out = Vec::with_capacity(PICKLE_BYTES);
        out.push(PICKLE_VERSION);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&sealed);
        Ok(base64_encode(out))
    }
}

/// Checks a sealing key: base64 without padding of 32 bytes (`InvalidKey` otherwise).
pub(crate) fn public_key(text: &str) -> Result<PublicKey> {
    canonical_base64(text)
        .filter(|bytes| bytes.len() == KEY_BYTES)
        .and_then(|bytes| PublicKey::from_bytes(&bytes).ok())
        .ok_or_else(|| ChatCryptoError::InvalidKey {
            reason: "sealing key is not base64 without padding of 32 bytes".to_owned(),
        })
}

pub(crate) fn seal(
    recipient: &SealedRecipient,
    envelope_id: &str,
    sender: &SealedSender,
    envelope: &Envelope,
) -> Result<String> {
    let ephemeral = random_bytes::<KEY_BYTES>()?;
    seal_with_ephemeral(&ephemeral, recipient, envelope_id, sender, envelope)
}

/// `seal` with the 32 bytes the ephemeral key is derived from (`ikmE` in RFC 9180).
fn seal_with_ephemeral(
    ephemeral: &[u8; KEY_BYTES],
    recipient: &SealedRecipient,
    envelope_id: &str,
    sender: &SealedSender,
    envelope: &Envelope,
) -> Result<String> {
    let recipient_key = public_key(&recipient.sealing_key)?;
    let aad = aad(&recipient.account_id, &recipient.identity_id, envelope_id)
        .ok_or_else(|| invalid_message("recipient ids and envelope id must be lower case UUIDs"))?;
    if !is_lower_uuid(&sender.account_id) || !is_lower_uuid(&sender.identity_id) {
        return Err(invalid_message("sender ids must be lower case UUIDs"));
    }
    if sender.statement.sealing_key.is_none() {
        return Err(statement::invalid_statement("the sender's statement is not a v4"));
    }
    statement::verify(&sender.statement)?;
    if envelope.protocol != PROTOCOL {
        return Err(ChatCryptoError::UnsupportedProtocol { protocol: envelope.protocol.clone() });
    }
    if envelope.olm_type > 1 {
        return Err(invalid_message("olm_type must be 0 or 1"));
    }
    if canonical_base64(&envelope.ciphertext).is_none_or(|bytes| bytes.is_empty()) {
        return Err(invalid_message("ciphertext is not base64 without padding"));
    }

    let clear = clear_text(sender, envelope)?;
    let mut rng = OneDraw::new(ephemeral);
    let (enc, sealed) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient_key,
        INFO,
        clear.as_bytes(),
        aad.as_bytes(),
        &mut rng,
    )
    .map_err(|e| ChatCryptoError::Encryption { reason: e.to_string() })?;
    if !rng.drawn_once() {
        return Err(ChatCryptoError::Encryption { reason: "unexpected randomness draw".to_owned() });
    }
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&sealed);
    Ok(base64_encode(out))
}

/// `recipient_account_id`, `recipient_identity_id` and `envelope_id`, joined by `\n`.
fn aad(account_id: &str, identity_id: &str, envelope_id: &str) -> Option<String> {
    [account_id, identity_id, envelope_id]
        .iter()
        .all(|id| is_lower_uuid(id))
        .then(|| format!("{account_id}\n{identity_id}\n{envelope_id}"))
}

/// The clear text, padded to a multiple of 256 bytes. The pad is counted as if the three
/// fields whose length varies (the account key, `created_at` and the account signature)
/// had their longest length, so two senders give the same size for the same Olm envelope.
fn clear_text(sender: &SealedSender, envelope: &Envelope) -> Result<String> {
    let s = &sender.statement;
    let sealing_key = s.sealing_key.clone().unwrap_or_default();
    let mut map = Map::new();
    map.insert("v".into(), Value::from(CLEAR_VERSION));
    map.insert("sender_account_id".into(), Value::from(sender.account_id.clone()));
    map.insert("sender_identity_id".into(), Value::from(sender.identity_id.clone()));
    map.insert("account_public_key".into(), Value::from(s.account_public_key.clone()));
    map.insert("curve25519_key".into(), Value::from(s.curve25519_key.clone()));
    map.insert("ed25519_key".into(), Value::from(s.ed25519_key.clone()));
    map.insert("sealing_key".into(), Value::from(sealing_key));
    map.insert("created_at".into(), Value::from(s.created_at.clone()));
    map.insert("identity_signature".into(), Value::from(s.identity_signature.clone()));
    map.insert("account_signature".into(), Value::from(s.account_signature.clone()));
    map.insert("olm_type".into(), Value::from(envelope.olm_type));
    map.insert("ciphertext".into(), Value::from(envelope.ciphertext.clone()));

    let unpadded = serde_json::to_string(&map).map_err(|e| invalid_message(&e.to_string()))?.len();
    let slack = account::max_base58_chars(32).saturating_sub(s.account_public_key.len())
        + MAX_CREATED_CHARS.saturating_sub(s.created_at.len())
        + account::max_base58_chars(64).saturating_sub(s.account_signature.len());
    let target = (unpadded + slack + PAD_FIELD_BYTES).div_ceil(CLEAR_BUCKET) * CLEAR_BUCKET;
    map.insert("pad".into(), Value::from(" ".repeat(target - unpadded - PAD_FIELD_BYTES)));
    serde_json::to_string(&map).map_err(|e| invalid_message(&e.to_string()))
}

/// Reads a clear text strictly: a multiple of 256 bytes, exactly the fields of the format
/// in their order, `v` 1, lower case UUIDs, a statement v4 whose signatures hold, `olm_type`
/// 0 or 1, a pad of spaces only.
fn read_clear(clear: &[u8]) -> Option<OpenedSealed> {
    if clear.is_empty() || !clear.len().is_multiple_of(CLEAR_BUCKET) {
        return None;
    }
    let map: Map<String, Value> = serde_json::from_slice(clear).ok()?;
    if map.len() != CLEAR_FIELDS.len() || !map.keys().zip(CLEAR_FIELDS).all(|(key, name)| key == name) {
        return None;
    }
    let text = |name: &str| map.get(name).and_then(Value::as_str).map(str::to_owned);
    if map.get("v").and_then(Value::as_u64) != Some(CLEAR_VERSION) {
        return None;
    }
    let account_id = text("sender_account_id").filter(|id| is_lower_uuid(id))?;
    let identity_id = text("sender_identity_id").filter(|id| is_lower_uuid(id))?;
    let statement = StatementFields {
        account_public_key: text("account_public_key")?,
        curve25519_key: text("curve25519_key")?,
        ed25519_key: text("ed25519_key")?,
        sealing_key: Some(text("sealing_key")?),
        created_at: text("created_at")?,
        identity_signature: text("identity_signature")?,
        account_signature: text("account_signature")?,
    };
    statement::verify(&statement).ok()?;
    let olm_type = u8::try_from(map.get("olm_type").and_then(Value::as_u64)?).ok().filter(|t| *t <= 1)?;
    let ciphertext = text("ciphertext")?;
    canonical_base64(&ciphertext).filter(|bytes| !bytes.is_empty())?;
    if !text("pad")?.bytes().all(|b| b == b' ') {
        return None;
    }
    Some(OpenedSealed {
        sender: SealedSender { account_id, identity_id, statement },
        envelope: Envelope { protocol: PROTOCOL.to_owned(), olm_type, ciphertext },
    })
}

fn canonical_base64(text: &str) -> Option<Vec<u8>> {
    base64_decode(text).ok().filter(|bytes| base64_encode(bytes) == text)
}

fn is_lower_uuid(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, len)| {
            group.len() == len && group.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    <[u8; N]>::try_generate()
        .map(Zeroizing::new)
        .map_err(|_| ChatCryptoError::Encryption { reason: "no randomness".to_owned() })
}

fn pickle_cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn invalid_message(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidMessage { reason: reason.to_owned() }
}

/// The randomness HPKE draws for one seal: the 32 bytes of the ephemeral key, drawn before
/// the call where a failure can be reported. Any other draw marks it misused, and the seal
/// is refused, so a change in how the library draws never goes unseen.
struct OneDraw {
    bytes: Zeroizing<[u8; KEY_BYTES]>,
    draws: u32,
    misused: bool,
}

impl OneDraw {
    fn new(bytes: &[u8; KEY_BYTES]) -> Self {
        Self { bytes: Zeroizing::new(*bytes), draws: 0, misused: false }
    }

    fn drawn_once(&self) -> bool {
        self.draws == 1 && !self.misused
    }
}

impl rand_core::TryRng for OneDraw {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        self.misused = true;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        self.misused = true;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Infallible> {
        if self.draws == 0 && dst.len() == KEY_BYTES {
            dst.copy_from_slice(self.bytes.as_slice());
        } else {
            self.misused = true;
            dst.fill(0);
        }
        self.draws = self.draws.saturating_add(1);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OneDraw {}

/// Fixed keys and fixed randomness, for tools/make_vectors.rs only.
#[cfg(feature = "vectors")]
#[doc(hidden)]
pub mod vectors {
    use super::*;

    pub fn sealing_key_from_ikm(ikm: [u8; KEY_BYTES]) -> Arc<ChatSealingKey> {
        Arc::new(ChatSealingKey::from_ikm(&ikm))
    }

    pub fn pickle_with_nonce(key: &ChatSealingKey, pickle_key: [u8; 32], nonce: [u8; NONCE_BYTES]) -> String {
        key.pickle_with_nonce(&pickle_key, &nonce).unwrap()
    }

    pub fn seal_with_ephemeral(
        ephemeral: [u8; KEY_BYTES],
        recipient: &SealedRecipient,
        envelope_id: &str,
        sender: &SealedSender,
        envelope: &Envelope,
    ) -> Result<String> {
        super::seal_with_ephemeral(&ephemeral, recipient, envelope_id, sender, envelope)
    }

    /// Seals any clear text, to write the vectors a recipient must refuse.
    pub fn seal_clear(
        ephemeral: [u8; KEY_BYTES],
        recipient: &SealedRecipient,
        envelope_id: &str,
        clear: &str,
    ) -> String {
        let key = public_key(&recipient.sealing_key).unwrap();
        let aad = aad(&recipient.account_id, &recipient.identity_id, envelope_id).unwrap();
        let mut rng = OneDraw::new(&ephemeral);
        let (enc, sealed) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &key,
            INFO,
            clear.as_bytes(),
            aad.as_bytes(),
            &mut rng,
        )
        .unwrap();
        assert!(rng.drawn_once());
        let mut out = enc.to_bytes().to_vec();
        out.extend_from_slice(&sealed);
        base64_encode(out)
    }

    pub fn clear_text(sender: &SealedSender, envelope: &Envelope) -> String {
        super::clear_text(sender, envelope).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use hpke::{setup_receiver, setup_sender_with_rng};
    use serde_json::Value;

    use super::*;
    use crate::{ChatAccountKey, ChatCrypto};

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    fn rfc() -> Value {
        let file: Value =
            serde_json::from_str(include_str!("../vectors/rfc9180-base-x25519-sha256-chacha20poly1305.json"))
                .unwrap();
        file["vector"].clone()
    }

    fn bytes32(v: &Value, name: &str) -> [u8; 32] {
        unhex(v[name].as_str().unwrap()).try_into().unwrap()
    }

    #[test]
    fn the_rfc_9180_vectors_of_our_suite_replay() {
        let v = rfc();
        assert_eq!(
            (v["mode"].as_u64(), v["kem_id"].as_u64(), v["kdf_id"].as_u64(), v["aead_id"].as_u64()),
            (Some(0), Some(0x20), Some(1), Some(3))
        );
        let (sk_r, pk_r) = Kem::derive_keypair(&bytes32(&v, "ikmR"));
        assert_eq!(pk_r.to_bytes().to_vec(), unhex(v["pkRm"].as_str().unwrap()));
        // Since hpke 0.15 a private key is written clamped (RFC 9180, 7.1.2); the RFC's skRm is not.
        let mut clamped = bytes32(&v, "skRm");
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        assert_eq!(sk_r.to_bytes().to_vec(), clamped.to_vec());
        let (_, pk_e) = Kem::derive_keypair(&bytes32(&v, "ikmE"));
        assert_eq!(pk_e.to_bytes().to_vec(), unhex(v["pkEm"].as_str().unwrap()));

        let info = unhex(v["info"].as_str().unwrap());
        let mut rng = OneDraw::new(&bytes32(&v, "ikmE"));
        let (enc, mut sender) = setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &pk_r,
            &info,
            &mut rng,
        )
        .unwrap();
        assert!(rng.drawn_once());
        assert_eq!(enc.to_bytes().to_vec(), unhex(v["enc"].as_str().unwrap()));
        let mut receiver =
            setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeR::Base, &sk_r, &enc, &info).unwrap();

        let encryptions = v["encryptions"].as_array().unwrap();
        assert_eq!(encryptions.len(), 257);
        for e in encryptions {
            let (aad, pt, ct) = (
                unhex(e["aad"].as_str().unwrap()),
                unhex(e["pt"].as_str().unwrap()),
                unhex(e["ct"].as_str().unwrap()),
            );
            assert_eq!(sender.seal(&pt, &aad).unwrap(), ct);
            assert_eq!(receiver.open(&ct, &aad).unwrap(), pt);
        }
        for x in v["exports"].as_array().unwrap() {
            let context = unhex(x["exporter_context"].as_str().unwrap());
            let mut out = vec![0u8; x["L"].as_u64().unwrap() as usize];
            receiver.export(&context, &mut out).unwrap();
            assert_eq!(out, unhex(x["exported_value"].as_str().unwrap()));
        }

        // The single shot `seal` draws its ephemeral key the same way: the RFC's `enc`.
        let mut rng = OneDraw::new(&bytes32(&v, "ikmE"));
        let (enc, _) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &pk_r,
            &info,
            b"",
            b"",
            &mut rng,
        )
        .unwrap();
        assert!(rng.drawn_once());
        assert_eq!(enc.to_bytes().to_vec(), unhex(v["enc"].as_str().unwrap()));
    }

    #[test]
    fn a_second_draw_is_seen() {
        let mut rng = OneDraw::new(&[1; 32]);
        let mut first = [0u8; 32];
        rand_core::TryRng::try_fill_bytes(&mut rng, &mut first).unwrap();
        assert!(rng.drawn_once());
        rand_core::TryRng::try_fill_bytes(&mut rng, &mut first).unwrap();
        assert!(!rng.drawn_once());
        let mut short = OneDraw::new(&[1; 32]);
        rand_core::TryRng::try_fill_bytes(&mut short, &mut [0u8; 16]).unwrap();
        assert!(!short.drawn_once());
    }

    const ME: &str = "1111aaaa-1111-4111-8111-111111111111";
    const MY_IDENTITY: &str = "22222222-2222-4222-8222-222222222222";
    const CONTACT: &str = "33333333-3333-4333-8333-333333333333";
    const CONTACT_IDENTITY: &str = "44444444-4444-4444-8444-444444444444";
    const ENVELOPE: &str = "5555eeee-5555-4555-8555-555555555555";

    fn sender(wallet: u8, created_at: &str) -> SealedSender {
        let key = crate::derive_account_key(vec![wallet; 32], 1).unwrap().key;
        statement_sender(&key, created_at)
    }

    fn statement_sender(key: &Arc<ChatAccountKey>, created_at: &str) -> SealedSender {
        let olm = ChatCrypto::create_account();
        let sealing = ChatSealingKey::generate().unwrap();
        let signed = key.sign_identity_statement(olm.clone(), sealing.clone(), created_at.into()).unwrap();
        let keys = olm.identity_keys();
        SealedSender {
            account_id: ME.into(),
            identity_id: MY_IDENTITY.into(),
            statement: StatementFields {
                account_public_key: key.public_key(),
                curve25519_key: keys.curve25519_key,
                ed25519_key: keys.ed25519_key,
                sealing_key: Some(sealing.public_key()),
                created_at: created_at.into(),
                identity_signature: signed.identity_signature,
                account_signature: signed.account_signature,
            },
        }
    }

    fn envelope(olm_type: u8, bytes: usize) -> Envelope {
        Envelope { protocol: PROTOCOL.into(), olm_type, ciphertext: base64_encode(vec![7u8; bytes]) }
    }

    fn recipient(key: &ChatSealingKey) -> SealedRecipient {
        SealedRecipient {
            account_id: CONTACT.into(),
            identity_id: CONTACT_IDENTITY.into(),
            sealing_key: key.public_key(),
        }
    }

    fn open(key: &ChatSealingKey, sealed: &str) -> Result<OpenedSealed> {
        key.open_sealed(sealed.into(), CONTACT.into(), CONTACT_IDENTITY.into(), ENVELOPE.into())
    }

    #[test]
    fn a_sealed_envelope_opens_for_its_recipient_only() {
        let key = ChatSealingKey::generate().unwrap();
        let from = sender(3, "2026-11-18T09:00:00.123Z");
        let sealed = seal(&recipient(&key), ENVELOPE, &from, &envelope(0, 300)).unwrap();
        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened.sender, from);
        assert_eq!(opened.envelope, envelope(0, 300));

        let other = ChatSealingKey::generate().unwrap();
        assert_eq!(open(&other, &sealed), Err(ChatCryptoError::InvalidSealed));
        for (account, identity, id) in [
            (ME, CONTACT_IDENTITY, ENVELOPE),
            (CONTACT, MY_IDENTITY, ENVELOPE),
            (CONTACT, CONTACT_IDENTITY, ME),
            ("33333333-3333-4333-8333-33333333333A", CONTACT_IDENTITY, ENVELOPE),
        ] {
            let read = key.open_sealed(sealed.clone(), account.into(), identity.into(), id.into());
            assert_eq!(read, Err(ChatCryptoError::InvalidSealed), "{account} {identity} {id}");
        }
        let mut bytes = base64_decode(&sealed).unwrap();
        for i in [0, 31, 32, bytes.len() - 1] {
            bytes[i] ^= 1;
            assert_eq!(open(&key, &base64_encode(&bytes)), Err(ChatCryptoError::InvalidSealed), "byte {i}");
            bytes[i] ^= 1;
        }
        for bad in [String::new(), format!("{sealed}="), sealed[..40].to_owned(), base64_encode(&bytes[..47])]
        {
            assert_eq!(open(&key, &bad), Err(ChatCryptoError::InvalidSealed));
        }
    }

    #[test]
    fn two_senders_give_the_same_sealed_size_for_the_same_olm_envelope() {
        // The account key and the account signature are base58, so their length varies; so
        // does `created_at`, with or without milliseconds. Look for the shortest and the
        // longest spellings among a few keys.
        let senders: Vec<SealedSender> = (1..=40u8)
            .flat_map(|w| [sender(w, "2026-11-18T09:00:00Z"), sender(w, "2026-11-18T09:00:00.123Z")])
            .collect();
        let length = |s: &SealedSender| {
            s.statement.account_public_key.len()
                + s.statement.created_at.len()
                + s.statement.account_signature.len()
        };
        let shortest = senders.iter().min_by_key(|s| length(s)).unwrap();
        let longest = senders.iter().max_by_key(|s| length(s)).unwrap();
        assert!(length(longest) > length(shortest));
        let key = ChatSealingKey::generate().unwrap();
        // Olm ciphertexts of every content bucket (512 to 16384 bytes) and around them.
        for bytes in (100..2400).step_by(7).chain([600, 1100, 2150, 4250, 8350, 16550]) {
            for olm_type in [0, 1] {
                let sizes: Vec<usize> = [shortest, longest]
                    .iter()
                    .map(|s| clear_text(s, &envelope(olm_type, bytes)).unwrap().len())
                    .collect();
                assert_eq!(sizes[0], sizes[1], "{bytes} bytes, type {olm_type}");
                assert_eq!(sizes[0] % CLEAR_BUCKET, 0);
            }
        }
        let a = seal(&recipient(&key), ENVELOPE, shortest, &envelope(1, 700)).unwrap();
        let b = seal(&recipient(&key), ENVELOPE, longest, &envelope(1, 700)).unwrap();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn a_clear_text_that_is_not_exactly_the_format_is_refused() {
        let from = sender(5, "2026-11-18T09:00:00Z");
        let good = clear_text(&from, &envelope(1, 200)).unwrap();
        assert!(read_clear(good.as_bytes()).is_some());
        let map: Map<String, Value> = serde_json::from_str(&good).unwrap();
        let rewrite = |change: &dyn Fn(&mut Map<String, Value>)| {
            let mut m = map.clone();
            change(&mut m);
            let mut text = serde_json::to_string(&m).unwrap();
            let pad = text.len().div_ceil(CLEAR_BUCKET) * CLEAR_BUCKET - text.len();
            // Keep the length a multiple of 256 with trailing JSON whitespace.
            text.push_str(&" ".repeat(pad));
            text
        };
        let cases: Vec<(&str, String)> = vec![
            (
                "v 2",
                rewrite(&|m| {
                    m.insert("v".into(), Value::from(2));
                }),
            ),
            (
                "v 1.0",
                rewrite(&|m| {
                    m.insert("v".into(), serde_json::json!(1.0));
                }),
            ),
            (
                "v as text",
                rewrite(&|m| {
                    m.insert("v".into(), Value::from("1"));
                }),
            ),
            (
                "an unknown field",
                rewrite(&|m| {
                    m.insert("extra".into(), Value::from("x"));
                }),
            ),
            (
                "a missing field",
                rewrite(&|m| {
                    m.remove("olm_type");
                }),
            ),
            (
                "upper case id",
                rewrite(&|m| {
                    m.insert("sender_account_id".into(), Value::from(ME.to_uppercase()));
                }),
            ),
            (
                "olm_type 2",
                rewrite(&|m| {
                    m.insert("olm_type".into(), Value::from(2));
                }),
            ),
            (
                "a pad with a letter",
                rewrite(&|m| {
                    m.insert("pad".into(), Value::from("  x "));
                }),
            ),
            (
                "an empty ciphertext",
                rewrite(&|m| {
                    m.insert("ciphertext".into(), Value::from(""));
                }),
            ),
            (
                "a v3 statement",
                rewrite(&|m| {
                    m.insert("sealing_key".into(), Value::Null);
                }),
            ),
            (
                "another sealing key",
                rewrite(&|m| {
                    m.insert(
                        "sealing_key".into(),
                        Value::from(ChatSealingKey::generate().unwrap().public_key()),
                    );
                }),
            ),
        ];
        for (name, text) in cases {
            assert!(read_clear(text.as_bytes()).is_none(), "{name}");
        }
        // Fields out of order.
        let mut swapped = Map::new();
        for (k, v) in map.iter().rev() {
            swapped.insert(k.clone(), v.clone());
        }
        let text = serde_json::to_string(&swapped).unwrap();
        assert!(read_clear(text.as_bytes()).is_none());
        // Not a multiple of 256.
        assert!(read_clear(&good.as_bytes()[..good.len() - 1]).is_none());
    }

    #[test]
    fn seal_refuses_what_it_cannot_vouch_for() {
        let key = ChatSealingKey::generate().unwrap();
        let from = sender(6, "2026-11-18T09:00:00Z");
        let olm = envelope(0, 100);
        let mut bad_key = recipient(&key);
        bad_key.sealing_key.push('A');
        assert!(matches!(seal(&bad_key, ENVELOPE, &from, &olm), Err(ChatCryptoError::InvalidKey { .. })));
        assert!(matches!(
            seal(&recipient(&key), &ENVELOPE.to_uppercase(), &from, &olm),
            Err(ChatCryptoError::InvalidMessage { .. })
        ));
        let v3 = SealedSender {
            statement: StatementFields { sealing_key: None, ..from.statement.clone() },
            ..from.clone()
        };
        assert!(matches!(
            seal(&recipient(&key), ENVELOPE, &v3, &olm),
            Err(ChatCryptoError::InvalidStatement { .. })
        ));
        let forged = SealedSender {
            statement: StatementFields {
                sealing_key: Some(ChatSealingKey::generate().unwrap().public_key()),
                ..from.statement.clone()
            },
            ..from.clone()
        };
        assert_eq!(seal(&recipient(&key), ENVELOPE, &forged, &olm), Err(ChatCryptoError::InvalidSignature));
        let other_protocol = Envelope { protocol: SEALED_PROTOCOL.into(), ..olm.clone() };
        assert!(matches!(
            seal(&recipient(&key), ENVELOPE, &from, &other_protocol),
            Err(ChatCryptoError::UnsupportedProtocol { .. })
        ));
        assert!(matches!(
            seal(&recipient(&key), ENVELOPE, &from, &envelope(2, 100)),
            Err(ChatCryptoError::InvalidMessage { .. })
        ));
        // A low order point gives no shared secret: refused, never sealed to a known key.
        let zero = SealedRecipient { sealing_key: base64_encode([0u8; 32]), ..recipient(&key) };
        assert!(matches!(seal(&zero, ENVELOPE, &from, &olm), Err(ChatCryptoError::Encryption { .. })));
    }

    #[test]
    fn a_sealing_key_pickle_restores_under_its_pickle_key_only() {
        let key = ChatSealingKey::generate().unwrap();
        let pickle = key.pickle(vec![9; 32]).unwrap();
        assert_ne!(pickle, key.pickle(vec![9; 32]).unwrap(), "a fresh nonce each time");
        let restored = ChatSealingKey::restore(pickle.clone(), vec![9; 32]).unwrap();
        assert_eq!(restored.public_key(), key.public_key());
        let from = sender(7, "2026-11-18T09:00:00Z");
        let sealed = seal(&recipient(&key), ENVELOPE, &from, &envelope(1, 64)).unwrap();
        assert!(open(&restored, &sealed).is_ok());

        assert!(matches!(
            ChatSealingKey::restore(pickle.clone(), vec![8; 32]),
            Err(ChatCryptoError::InvalidPickle)
        ));
        assert!(matches!(
            ChatSealingKey::restore(pickle.clone(), vec![9; 31]),
            Err(ChatCryptoError::InvalidKey { .. })
        ));
        let mut bytes = base64_decode(&pickle).unwrap();
        bytes[0] = 2;
        assert!(matches!(
            ChatSealingKey::restore(base64_encode(&bytes), vec![9; 32]),
            Err(ChatCryptoError::InvalidPickle)
        ));
        assert!(matches!(
            ChatSealingKey::restore(pickle[..20].to_owned(), vec![9; 32]),
            Err(ChatCryptoError::InvalidPickle)
        ));
        assert!(matches!(
            ChatSealingKey::restore(String::new(), vec![9; 32]),
            Err(ChatCryptoError::InvalidPickle)
        ));
    }
}
