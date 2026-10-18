use sombe_chat_crypto::ChatCrypto;
use vodozemac::Ed25519SecretKey;

#[allow(dead_code)]
pub const PICKLE_KEY: [u8; 32] = [7; 32];

/// A stand in for a Solana wallet: an ed25519 key whose public half, in base58, is the address.
pub struct TestWallet {
    secret: Ed25519SecretKey,
}

impl TestWallet {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { secret: Ed25519SecretKey::from_slice(&seed) }
    }

    pub fn address(&self) -> String {
        bs58::encode(self.secret.public_key().as_bytes()).into_string()
    }

    #[allow(dead_code)]
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
