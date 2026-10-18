//! The profile a person shows their contacts, encrypted end to end, and the `profile_key`
//! content that shares its key.

mod common;

use common::TestWallet;
use sombe_chat_crypto::*;

fn awa() -> Profile {
    Profile { display_name: Some("Awa Diallo".into()), about: Some("Couturière à Thiès".into()) }
}

#[test]
fn profile_round_trip_and_the_server_reads_nothing() {
    let wallet = TestWallet::from_seed([1; 32]);
    let key = generate_profile_key().unwrap();
    let sealed = encrypt_profile(awa(), key.clone(), wallet.address()).unwrap();
    assert!(!sealed.contains("Awa") && !sealed.contains("Thiès"));
    assert_eq!(decrypt_profile(sealed.clone(), key.clone(), wallet.address()).unwrap(), awa());

    // A random nonce: the same profile never encrypts to the same bytes twice.
    assert_ne!(encrypt_profile(awa(), key, wallet.address()).unwrap(), sealed);
}

#[test]
fn profiles_are_padded_to_a_size_bucket() {
    let wallet = TestWallet::from_seed([2; 32]);
    let key = generate_profile_key().unwrap();
    let sealed_len =
        |profile: Profile| encrypt_profile(profile, key.clone(), wallet.address()).unwrap().len();
    let short = sealed_len(Profile { display_name: Some("Jo".into()), about: None });
    let long = sealed_len(Profile { display_name: Some("Marie-Christine Ndiaye Fall".into()), about: None });
    assert_eq!(short, long, "a name's length does not show");
    let longest =
        sealed_len(Profile { display_name: Some("é".repeat(64)), about: Some("😀".repeat(140)) });
    assert!(longest > short);
}

#[test]
fn a_profile_only_opens_with_its_key_its_wallet_and_its_part() {
    let wallet = TestWallet::from_seed([3; 32]);
    let other = TestWallet::from_seed([4; 32]);
    let key = generate_profile_key().unwrap();
    let sealed = encrypt_profile(awa(), key.clone(), wallet.address()).unwrap();

    let wrong_key = generate_profile_key().unwrap();
    assert!(matches!(
        decrypt_profile(sealed.clone(), wrong_key, wallet.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
    // A server cannot serve Awa's profile as someone else's.
    assert!(matches!(
        decrypt_profile(sealed.clone(), key.clone(), other.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
    // Nor an avatar as a profile.
    let avatar = encrypt_avatar(vec![9; 100], key.clone(), wallet.address()).unwrap();
    let avatar_text = vodozemac::base64_encode(avatar);
    assert!(matches!(
        decrypt_profile(avatar_text, key.clone(), wallet.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
    // Nor change a single byte.
    let mut bytes = vodozemac::base64_decode(&sealed).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(
        decrypt_profile(vodozemac::base64_encode(bytes), key.clone(), wallet.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
    assert!(matches!(
        decrypt_profile("not base64!".into(), key, wallet.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
}

#[test]
fn profile_rules() {
    let wallet = TestWallet::from_seed([5; 32]);
    let key = generate_profile_key().unwrap();
    let seal = |profile: Profile| encrypt_profile(profile, key.clone(), wallet.address());

    assert!(seal(Profile { display_name: None, about: None }).is_ok());
    assert!(seal(Profile { display_name: Some("x".repeat(64)), about: Some("x".repeat(140)) }).is_ok());
    for wrong in [
        Profile { display_name: Some("  ".into()), about: None },
        Profile { display_name: Some("x".repeat(65)), about: None },
        Profile { display_name: Some("Awa\nAdmin".into()), about: None },
        Profile { display_name: None, about: Some("x".repeat(141)) },
    ] {
        assert!(matches!(seal(wrong.clone()), Err(ChatCryptoError::InvalidProfile { .. })), "{wrong:?}");
    }
    assert!(matches!(
        encrypt_profile(awa(), vec![0; 16], wallet.address()),
        Err(ChatCryptoError::InvalidKey { .. })
    ));
    assert!(matches!(encrypt_profile(awa(), key, "abc".into()), Err(ChatCryptoError::InvalidKey { .. })));
}

#[test]
fn avatar_round_trip_padded_to_a_bucket() {
    let wallet = TestWallet::from_seed([6; 32]);
    let key = generate_profile_key().unwrap();
    let image: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let sealed = encrypt_avatar(image.clone(), key.clone(), wallet.address()).unwrap();
    // Version, nonce, 4096 padded bytes and the tag.
    assert_eq!(sealed.len(), 1 + 24 + 4096 + 16);
    assert_eq!(encrypt_avatar(vec![1; 10], key.clone(), wallet.address()).unwrap().len(), sealed.len());
    assert_eq!(decrypt_avatar(sealed, key.clone(), wallet.address()).unwrap(), image);

    let largest = vec![7; 512 * 1024];
    let sealed = encrypt_avatar(largest.clone(), key.clone(), wallet.address()).unwrap();
    assert_eq!(decrypt_avatar(sealed, key.clone(), wallet.address()).unwrap(), largest);
    assert!(encrypt_avatar(vec![7; 512 * 1024 + 1], key.clone(), wallet.address()).is_err());
    assert!(encrypt_avatar(vec![], key.clone(), wallet.address()).is_err());

    // A profile is not an avatar either.
    let profile =
        vodozemac::base64_decode(encrypt_profile(awa(), key.clone(), wallet.address()).unwrap()).unwrap();
    assert!(matches!(
        decrypt_avatar(profile, key, wallet.address()),
        Err(ChatCryptoError::Decryption { .. })
    ));
}

#[test]
fn profile_keys_are_random_and_travel_as_content() {
    let key = generate_profile_key().unwrap();
    assert_eq!(key.len(), 32);
    assert_ne!(generate_profile_key().unwrap(), key);
    let encoded = encode_profile_key(key.clone()).unwrap();
    assert_eq!(decode_profile_key(encoded.clone()).unwrap(), key);
    assert!(encode_profile_key(vec![0; 31]).is_err());
    assert!(decode_profile_key("AAAA".into()).is_err());

    let content = MessageContent {
        conversation_id: "6f1c2a8e-0000-4000-8000-000000000001".into(),
        client_message_id: "6f1c2a8e-0000-4000-8000-000000000006".into(),
        kind: ContentKind::ProfileKey,
        body: None,
        reply_excerpt: None,
        comment: None,
        edits_message_id: None,
        reacts_to_message_id: None,
        profile_key: Some(encoded.clone()),
    };
    let json = encode_content(content.clone()).unwrap();
    assert_eq!(json.len(), 256);
    assert_eq!(decode_content(json).unwrap(), content);

    for wrong in [
        MessageContent { profile_key: None, ..content.clone() },
        MessageContent { profile_key: Some("AAAA".into()), ..content.clone() },
        MessageContent { body: Some("x".into()), ..content.clone() },
        MessageContent { comment: Some("x".into()), ..content.clone() },
        MessageContent { reacts_to_message_id: Some("c".into()), ..content.clone() },
        MessageContent { kind: ContentKind::Text, body: Some("x".into()), ..content },
    ] {
        assert!(encode_content(wrong.clone()).is_err(), "{wrong:?}");
    }
}
