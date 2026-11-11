//! The account key (since 0.7.0): derivation, sealing, the wallet card, and the texts the
//! key agrees to sign. Its private half never leaves the module.

mod common;

use common::{device, TestWallet};
use sha2::{Digest, Sha256};
use sombe_chat_crypto::*;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

const WALLET: [u8; 32] = [42; 32];
const SEALING_KEY: [u8; 32] = [7; 32];
const DEVICE_DER: &[u8] = b"a device public key, any bytes for these tests";
const IDENTITY_ID: &str = "5d0c7a3e-2b4f-4e8a-9c1d-7e6f5a4b3c21";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn verifies(public_key: &str, text: &str, signature: &str) -> bool {
    let key: [u8; 32] = bs58::decode(public_key).into_vec().unwrap().try_into().unwrap();
    let signature = Ed25519Signature::from_slice(&bs58::decode(signature).into_vec().unwrap()).unwrap();
    Ed25519PublicKey::from_slice(&key).unwrap().verify(text.as_bytes(), &signature).is_ok()
}

fn sign_in_message(account: &str, device: &str) -> String {
    format!(
        "SOMBE ChatPay sign in\naccount:{account}\ndevice:{device}\nnonce:0f1e2d3c4b5a69788796a5b4c3d2e1f0\nissued:2026-11-11T09:30:00.000Z"
    )
}

#[test]
fn derivation_is_stable_and_bounded() {
    let a = derive_account_key(WALLET.to_vec(), 1).unwrap();
    let b = derive_account_key(WALLET.to_vec(), 1).unwrap();
    assert_eq!(a.key.public_key(), b.key.public_key());
    assert_eq!(a.card, b.card);
    assert_eq!(a.key.generation(), 1);
    // Another generation, another key; the account key is never the wallet address.
    let second = derive_account_key(WALLET.to_vec(), 2).unwrap();
    assert_ne!(second.key.public_key(), a.key.public_key());
    assert_ne!(a.key.public_key(), TestWallet::from_seed(WALLET).address());
    assert!(derive_account_key(WALLET.to_vec(), 32767).is_ok());

    for generation in [0u16, 32768, u16::MAX] {
        assert!(matches!(
            derive_account_key(WALLET.to_vec(), generation),
            Err(ChatCryptoError::InvalidKey { .. })
        ));
    }
    for size in [0usize, 31, 33, 64] {
        assert!(matches!(derive_account_key(vec![1; size], 1), Err(ChatCryptoError::InvalidKey { .. })));
    }
}

#[test]
fn the_house_vector_of_the_app() {
    // The test phrase `abandon` (11 times) `about`, wallet key at m/44'/501'/0'/0'.
    let wallet: Vec<u8> = (0..32)
        .map(|i| {
            u8::from_str_radix(
                &"37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445"[2 * i..2 * i + 2],
                16,
            )
            .unwrap()
        })
        .collect();
    let key = derive_account_key(wallet.clone(), 1).unwrap().key;
    assert_eq!(key.public_key(), "FZscPpTgpZTEWBwRPtcFHfyPd5q71514PER6nfxS6Zjm");
    let second = derive_account_key(wallet, 2).unwrap().key;
    assert_eq!(second.public_key(), "6LSVdTXLWjGeNLxMj9Bkq1iedR8fhWgSEcSgBxjMqheE");
}

#[test]
fn seal_then_unseal() {
    let key = derive_account_key(WALLET.to_vec(), 3).unwrap().key;
    let sealed = key.seal(SEALING_KEY.to_vec()).unwrap();
    let opened = ChatAccountKey::unseal(sealed.clone(), SEALING_KEY.to_vec()).unwrap();
    assert_eq!(opened.public_key(), key.public_key());
    assert_eq!(opened.generation(), 3);
    // The opened key signs like the original one.
    let device = hex(&Sha256::digest(DEVICE_DER));
    let message = sign_in_message(&key.public_key(), &device);
    assert_eq!(
        opened.sign_sign_in(message.clone(), DEVICE_DER.to_vec()).unwrap(),
        key.sign_sign_in(message, DEVICE_DER.to_vec()).unwrap()
    );
    // A fresh nonce each time.
    assert_ne!(key.seal(SEALING_KEY.to_vec()).unwrap(), sealed);
}

#[test]
fn a_sealed_key_that_does_not_open() {
    let key = derive_account_key(WALLET.to_vec(), 1).unwrap().key;
    let sealed = key.seal(SEALING_KEY.to_vec()).unwrap();
    let bytes = vodozemac::base64_decode(&sealed).unwrap();
    let encode = |b: &[u8]| vodozemac::base64_encode(b);
    let unseal = |text: String| ChatAccountKey::unseal(text, SEALING_KEY.to_vec()).err();

    assert_eq!(
        ChatAccountKey::unseal(sealed.clone(), vec![8; 32]).err(),
        Some(ChatCryptoError::InvalidSealedKey),
        "wrong sealing key"
    );
    for i in [0usize, 1, 30, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[i] ^= 1;
        assert_eq!(unseal(encode(&changed)), Some(ChatCryptoError::InvalidSealedKey), "byte {i}");
    }
    assert_eq!(
        unseal(encode(&bytes[..bytes.len() - 1])),
        Some(ChatCryptoError::InvalidSealedKey),
        "truncated"
    );
    let mut version_2 = bytes.clone();
    version_2[0] = 2;
    assert_eq!(unseal(encode(&version_2)), Some(ChatCryptoError::InvalidSealedKey), "other version");
    assert_eq!(unseal("not base64 !".into()), Some(ChatCryptoError::InvalidSealedKey));
    assert_eq!(unseal(String::new()), Some(ChatCryptoError::InvalidSealedKey));

    for size in [0usize, 31, 33] {
        assert!(matches!(
            ChatAccountKey::unseal(sealed.clone(), vec![7; size]),
            Err(ChatCryptoError::InvalidKey { .. })
        ));
        assert!(matches!(key.seal(vec![7; size]), Err(ChatCryptoError::InvalidKey { .. })));
    }
}

#[test]
fn the_wallet_card_is_signed_by_the_wallet() {
    let derived = derive_account_key(WALLET.to_vec(), 1).unwrap();
    let card = derived.card.clone();
    assert_eq!(card.wallet_address, TestWallet::from_seed(WALLET).address());
    assert_eq!(card.account_public_key, derived.key.public_key());
    let text =
        format!("SOMBE wallet card v1\nwallet:{}\naccount:{}", card.wallet_address, card.account_public_key);
    assert!(verifies(&card.wallet_address, &text, &card.wallet_signature));
    assert_eq!(verify_wallet_card(card.clone()), Ok(()));

    // One character changed in the address or the key: refused.
    let other = derive_account_key(vec![43; 32], 1).unwrap().card;
    let wrong_wallet = WalletCard { wallet_address: other.wallet_address.clone(), ..card.clone() };
    assert_eq!(verify_wallet_card(wrong_wallet), Err(ChatCryptoError::InvalidSignature));
    let wrong_key = WalletCard { account_public_key: other.account_public_key.clone(), ..card.clone() };
    assert_eq!(verify_wallet_card(wrong_key), Err(ChatCryptoError::InvalidSignature));
    let wrong_signature = WalletCard { wallet_signature: other.wallet_signature, ..card.clone() };
    assert_eq!(verify_wallet_card(wrong_signature), Err(ChatCryptoError::InvalidSignature));
    let not_a_key = WalletCard { wallet_address: "0OIl".into(), ..card.clone() };
    assert!(matches!(verify_wallet_card(not_a_key), Err(ChatCryptoError::InvalidKey { .. })));
    // A leading 1 adds a zero byte: not the canonical base58 of 32 bytes.
    let padded = WalletCard { account_public_key: format!("1{}", card.account_public_key), ..card };
    assert!(matches!(verify_wallet_card(padded), Err(ChatCryptoError::InvalidKey { .. })));
}

#[test]
fn sign_in_only_signs_its_exact_format() {
    let key = derive_account_key(WALLET.to_vec(), 1).unwrap().key;
    let device = hex(&Sha256::digest(DEVICE_DER));
    let message = sign_in_message(&key.public_key(), &device);
    let signature = key.sign_sign_in(message.clone(), DEVICE_DER.to_vec()).unwrap();
    assert!(verifies(&key.public_key(), &message, &signature));

    let other = derive_account_key(vec![43; 32], 1).unwrap().key;
    let other_device = hex(&Sha256::digest(b"another device"));
    let card = derive_account_key(WALLET.to_vec(), 1).unwrap().card;
    let refused = [
        format!("{message}\nextra:line"),
        format!("{message}\n"),
        message.replacen("\n", "\r\n", 1),
        sign_in_message(&other.public_key(), &device),
        sign_in_message(&key.public_key(), &other_device),
        message.replace("nonce:0f1e2d3c4b5a69788796a5b4c3d2e1f0", "nonce:0F1E2D3C4B5A69788796A5B4C3D2E1F0"),
        message.replace("nonce:0f1e2d3c4b5a69788796a5b4c3d2e1f0", "nonce:0f1e2d3c"),
        message.replace("2026-11-11T09:30:00.000Z", "2026-11-11 09:30:00"),
        message.replace("SOMBE ChatPay sign in", "SOMBE ChatPay sign in v2"),
        // Another of the key's formats, presented as a sign in message.
        format!("SOMBE account move v1\ncard:{}\ndevice:{device}\nidentity:-", "0".repeat(64)),
        format!("SOMBE account rotate v1\nold:{}\nnew:{}\ngeneration:2", key.public_key(), other.public_key()),
        format!("SOMBE wallet card v1\nwallet:{}\naccount:{}", card.wallet_address, card.account_public_key),
        format!(
            "SOMBE chat identity v3\nprotocol:olm-v1\naccount:{}\ncurve25519:x\ned25519:y\ncreated:2026-11-11T09:30:00Z",
            key.public_key()
        ),
        String::new(),
    ];
    for text in refused {
        assert!(
            matches!(
                key.sign_sign_in(text.clone(), DEVICE_DER.to_vec()),
                Err(ChatCryptoError::RefusedToSign { .. })
            ),
            "{text:?}"
        );
    }
    assert!(matches!(key.sign_sign_in(message, vec![]), Err(ChatCryptoError::InvalidKey { .. })));
}

#[test]
fn account_move_signs_its_own_card_only() {
    let derived = derive_account_key(WALLET.to_vec(), 1).unwrap();
    let card = derived.card.clone();
    let card_text =
        format!("SOMBE wallet card v1\nwallet:{}\naccount:{}", card.wallet_address, card.account_public_key);
    let fingerprint = hex(&Sha256::digest(card_text.as_bytes()));
    let device = hex(&Sha256::digest(DEVICE_DER));

    for identity in [Some(IDENTITY_ID), None] {
        let signature =
            derived.key.sign_move(card.clone(), DEVICE_DER.to_vec(), identity.map(str::to_owned)).unwrap();
        let text = format!(
            "SOMBE account move v1\ncard:{fingerprint}\ndevice:{device}\nidentity:{}",
            identity.unwrap_or("-")
        );
        assert!(verifies(&derived.key.public_key(), &text, &signature), "{identity:?}");
    }

    // A card of another key, a forged card, an identity not in lower case.
    let other = derive_account_key(vec![43; 32], 1).unwrap();
    assert!(matches!(
        derived.key.sign_move(other.card.clone(), DEVICE_DER.to_vec(), None),
        Err(ChatCryptoError::RefusedToSign { .. })
    ));
    let forged = WalletCard { wallet_signature: other.card.wallet_signature, ..card.clone() };
    assert_eq!(
        derived.key.sign_move(forged, DEVICE_DER.to_vec(), None),
        Err(ChatCryptoError::InvalidSignature)
    );
    for id in [IDENTITY_ID.to_uppercase(), "not-a-uuid".into(), "-".into(), String::new()] {
        assert!(
            matches!(
                derived.key.sign_move(card.clone(), DEVICE_DER.to_vec(), Some(id.clone())),
                Err(ChatCryptoError::InvalidStatement { .. })
            ),
            "{id}"
        );
    }
}

#[test]
fn rotation_needs_the_right_wallet_and_a_generation_left() {
    let first = derive_account_key(WALLET.to_vec(), 1).unwrap();
    let rotation = first.key.rotate(WALLET.to_vec()).unwrap();
    let second = derive_account_key(WALLET.to_vec(), 2).unwrap();
    assert_eq!(rotation.new_key.public_key(), second.key.public_key());
    assert_eq!(rotation.new_key.generation(), 2);
    assert_eq!(rotation.card, second.card);
    let proof = &rotation.proof;
    assert_eq!(proof.old_account_public_key, first.key.public_key());
    assert_eq!(proof.new_account_public_key, second.key.public_key());
    assert_eq!(proof.generation, 2);
    let text = format!(
        "SOMBE account rotate v1\nold:{}\nnew:{}\ngeneration:2",
        proof.old_account_public_key, proof.new_account_public_key
    );
    assert!(verifies(&proof.old_account_public_key, &text, &proof.old_signature));
    assert!(verifies(&proof.new_account_public_key, &text, &proof.new_signature));

    // Another wallet, or this wallet at another generation: nothing is returned.
    assert_eq!(first.key.rotate(vec![43; 32]).err(), Some(ChatCryptoError::WrongGeneration));
    assert_eq!(second.key.rotate(vec![43; 32]).err(), Some(ChatCryptoError::WrongGeneration));
    assert!(matches!(first.key.rotate(vec![1; 31]), Err(ChatCryptoError::InvalidKey { .. })));
    let last = derive_account_key(WALLET.to_vec(), 32767).unwrap().key;
    assert_eq!(last.rotate(WALLET.to_vec()).err(), Some(ChatCryptoError::GenerationExhausted));
}

#[test]
fn a_proof_from_any_generation_to_a_later_one() {
    let proven = prove_rotation(WALLET.to_vec(), 1, 3).unwrap();
    let first = derive_account_key(WALLET.to_vec(), 1).unwrap();
    let third = derive_account_key(WALLET.to_vec(), 3).unwrap();
    assert_eq!(proven.card, third.card);
    assert_eq!(proven.proof.old_account_public_key, first.key.public_key());
    assert_eq!(proven.proof.new_account_public_key, third.key.public_key());
    assert_eq!(proven.proof.generation, 3);
    // A single step is the proof `rotate` gives.
    let step = prove_rotation(WALLET.to_vec(), 1, 2).unwrap();
    assert_eq!(step.proof, first.key.rotate(WALLET.to_vec()).unwrap().proof);

    for (from, to) in [(0u16, 2u16), (2, 2), (3, 2), (1, 32768)] {
        assert!(
            matches!(prove_rotation(WALLET.to_vec(), from, to), Err(ChatCryptoError::InvalidKey { .. })),
            "{from} {to}"
        );
    }
}

#[test]
fn account_rotation_content_round_trips() {
    let rotation = derive_account_key(WALLET.to_vec(), 1).unwrap().key.rotate(WALLET.to_vec()).unwrap();
    let body = AccountRotationContent {
        old_account_public_key: rotation.proof.old_account_public_key.clone(),
        new_account_public_key: rotation.proof.new_account_public_key.clone(),
        generation: 2,
        old_signature: rotation.proof.old_signature.clone(),
        new_signature: rotation.proof.new_signature.clone(),
        wallet_address: rotation.card.wallet_address.clone(),
        wallet_signature: rotation.card.wallet_signature.clone(),
    };
    let content = Content {
        version: 2,
        conversation_id: "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01".into(),
        envelope_id: Some("c3d4e5f6-0718-4a29-8b3c-4d5e6f708192".into()),
        body: ContentBody::AccountRotation { rotation: body.clone() },
    };
    let json = encode_content(content.clone()).unwrap();
    assert_eq!(json.len(), 1024);
    assert!(json.contains(r#""kind":"account_rotation""#));
    assert!(json.contains(r#""generation":2,"#));
    assert_eq!(decode_content(json).unwrap(), content);

    // Refused on write: generation 1, same keys, a field that is not base58 of its size.
    let refused = [
        AccountRotationContent { generation: 1, ..body.clone() },
        AccountRotationContent { generation: 32768, ..body.clone() },
        AccountRotationContent {
            new_account_public_key: body.old_account_public_key.clone(),
            ..body.clone()
        },
        AccountRotationContent { old_signature: body.wallet_address.clone(), ..body.clone() },
        AccountRotationContent { wallet_address: format!("1{}", body.wallet_address), ..body.clone() },
    ];
    for rotation in refused {
        let content = Content { body: ContentBody::AccountRotation { rotation }, ..content.clone() };
        assert!(matches!(encode_content(content), Err(ChatCryptoError::InvalidContent { .. })));
    }
}

#[test]
fn my_own_identity_for_the_safety_number() {
    // The app builds its own VerifiedIdentity from public_key() and its identity keys.
    let me = derive_account_key(WALLET.to_vec(), 1).unwrap().key;
    let my_device = device();
    let keys = my_device.identity_keys();
    let mine = VerifiedIdentity {
        account_public_key: me.public_key(),
        curve25519_key: keys.curve25519_key,
        ed25519_key: keys.ed25519_key,
        created_at: "2026-11-11T09:00:00Z".into(),
    };
    let contact_key = derive_account_key(vec![43; 32], 1).unwrap().key;
    let contact_device = device();
    let contact_keys = contact_device.identity_keys();
    let contact = VerifiedIdentity {
        account_public_key: contact_key.public_key(),
        curve25519_key: contact_keys.curve25519_key,
        ed25519_key: contact_keys.ed25519_key,
        created_at: "2026-11-11T09:00:00Z".into(),
    };
    assert_eq!(safety_number(mine.clone(), contact.clone()), safety_number(contact, mine));
}
