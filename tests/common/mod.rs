#[allow(dead_code)]
pub mod rsa;

use sombe_chat_crypto::ChatCrypto;
use vodozemac::Ed25519SecretKey;

#[allow(dead_code)]
pub const PICKLE_KEY: [u8; 32] = [7; 32];

#[allow(dead_code)]
/// A stand in for a Solana wallet: an ed25519 key whose public half, in base58, is the address.
pub struct TestWallet {
    secret: Ed25519SecretKey,
}

#[allow(dead_code)]
impl TestWallet {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { secret: Ed25519SecretKey::from_slice(&seed) }
    }

    pub fn address(&self) -> String {
        bs58::encode(self.secret.public_key().as_bytes()).into_string()
    }

    pub fn sign(&self, text: &str) -> String {
        bs58::encode(self.secret.sign(text.as_bytes()).to_bytes()).into_string()
    }
}

#[allow(dead_code)]
pub fn key() -> Vec<u8> {
    PICKLE_KEY.to_vec()
}

#[allow(dead_code)]
pub fn device() -> std::sync::Arc<ChatCrypto> {
    ChatCrypto::create_account()
}

/// The test sender and recipient of a version 4 content.
#[allow(dead_code)]
pub const SENDER: &str = "a1a1a1a1-0000-4000-8000-0000000000a1";
#[allow(dead_code)]
pub const RECIPIENT: &str = "b2b2b2b2-0000-4000-8000-0000000000b2";
/// The ed25519 keys of their test identities (since 0.8.1): the public keys of the seeds
/// `[0xa1; 32]`, `[0xb2; 32]` and, for a stranger, `[0xc3; 32]`.
#[allow(dead_code)]
pub const SENDER_KEY: &str = "vHy8tWNjdfodgkNNRmck2SN39TuYBpXdSdJtDOEiBaU";
#[allow(dead_code)]
pub const RECIPIENT_KEY: &str = "VRVPQgZepaG+oFRjgmviaE65LfksEAAnqrquV8pVQgc";
#[allow(dead_code)]
pub const STRANGER_KEY: &str = "1AS8RFZa7buJkVDlsLOzK5RBvwy3iEwzEw2o28J90s8";

/// A version 4 content from `SENDER` to `RECIPIENT`.
#[allow(dead_code)]
pub fn out(
    envelope_id: Option<&str>,
    body: sombe_chat_crypto::ContentBody,
) -> sombe_chat_crypto::OutgoingContent {
    sombe_chat_crypto::OutgoingContent {
        sender_account_id: SENDER.into(),
        sender_ed25519_key: SENDER_KEY.into(),
        recipient_account_id: RECIPIENT.into(),
        recipient_ed25519_key: RECIPIENT_KEY.into(),
        envelope_id: envelope_id.map(str::to_owned),
        body,
    }
}

/// What `RECIPIENT` knows of a mailbox element from `SENDER`.
#[allow(dead_code)]
pub fn mailbox(envelope_id: &str) -> sombe_chat_crypto::ContentBinding {
    sombe_chat_crypto::ContentBinding {
        channel: sombe_chat_crypto::ContentChannel::Mailbox,
        envelope_id: Some(envelope_id.to_lowercase()),
        sender_account_id: SENDER.into(),
        sender_ed25519_key: SENDER_KEY.into(),
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: RECIPIENT_KEY.into(),
        legacy_conversation_id: None,
    }
}

/// What `RECIPIENT` knows of a websocket frame from `SENDER`.
#[allow(dead_code)]
pub fn websocket() -> sombe_chat_crypto::ContentBinding {
    sombe_chat_crypto::ContentBinding {
        channel: sombe_chat_crypto::ContentChannel::Websocket,
        envelope_id: None,
        ..mailbox("00000000-0000-4000-8000-000000000000")
    }
}

/// A mailbox element deposited before the switch, vouched for with its old conversation id.
#[allow(dead_code)]
pub fn legacy(envelope_id: &str, conversation_id: &str) -> sombe_chat_crypto::ContentBinding {
    sombe_chat_crypto::ContentBinding {
        legacy_conversation_id: Some(conversation_id.to_lowercase()),
        ..mailbox(envelope_id)
    }
}

/// The binding a frozen version 1 or 2 vector reads with: its own conversation id given
/// as the old one, its own envelope id, the channel of its kind.
#[allow(dead_code)]
pub fn bound_to(json: &str) -> sombe_chat_crypto::ContentBinding {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
    let lower = |field: &str, or: &str| v[field].as_str().map_or(or.to_owned(), str::to_lowercase);
    let typing = v["kind"] == "typing";
    sombe_chat_crypto::ContentBinding {
        channel: if typing {
            sombe_chat_crypto::ContentChannel::Websocket
        } else {
            sombe_chat_crypto::ContentChannel::Mailbox
        },
        envelope_id: (!typing).then(|| lower("envelope_id", "00000000-0000-4000-8000-0000000000e0")),
        sender_account_id: SENDER.into(),
        sender_ed25519_key: SENDER_KEY.into(),
        my_account_id: RECIPIENT.into(),
        my_ed25519_key: RECIPIENT_KEY.into(),
        legacy_conversation_id: Some(lower("conversation_id", "00000000-0000-4000-8000-000000000000")),
    }
}
