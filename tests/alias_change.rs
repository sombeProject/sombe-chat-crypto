//! The `alias_change` content and `verify_alias_change` (since 0.11.0): same form and same
//! checks as a contact request, and the signed `expires` as well. Version 4 and the mailbox
//! only. The attestations come from vectors/v4.json.

mod common;

use common::{mailbox, out, websocket};
use serde_json::Value;
use sombe_chat_crypto::*;

const ENVELOPE: &str = "6f1c2a8e-0000-4000-8000-0000000000e1";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v4.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn change(case: &Value) -> Result<VerifiedAliasChange, ChatCryptoError> {
    let trusted = case["trusted_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| TrustedAttestationKey { kid: s(&k["kid"]), public_key: s(&k["public_key"]) })
        .collect();
    verify_alias_change(
        s(&case["text"]),
        s(&case["signature"]),
        trusted,
        s(&case["sender_account_id"]),
        s(&case["sender_account_public_key"]),
        s(&case["deposited_at"]),
    )
}

#[test]
fn it_gives_the_alias_and_the_signed_expires() {
    let v = vectors();
    let accepted = v["accepted"].as_array().unwrap();
    for case in accepted {
        let verified = change(case).unwrap();
        assert_eq!(verified.alias, s(&case["alias"]), "{}", case["name"]);
        let expires = s(&case["text"]).rsplit("expires:").next().unwrap().parse::<i64>().unwrap();
        assert_eq!(verified.expires, expires, "{}", case["name"]);
    }
}

#[test]
fn it_refuses_what_the_attestation_check_refuses() {
    for case in vectors()["refused"].as_array().unwrap() {
        assert_eq!(change(case), Err(ChatCryptoError::InvalidAttestation), "{}", case["name"]);
    }
}

#[test]
fn it_agrees_with_verify_alias_attestation() {
    let v = vectors();
    for case in v["accepted"].as_array().unwrap() {
        let trusted: Vec<TrustedAttestationKey> = case["trusted_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| TrustedAttestationKey { kid: s(&k["kid"]), public_key: s(&k["public_key"]) })
            .collect();
        let alias = verify_alias_attestation(
            s(&case["text"]),
            s(&case["signature"]),
            trusted,
            s(&case["sender_account_id"]),
            s(&case["sender_account_public_key"]),
            s(&case["deposited_at"]),
        )
        .unwrap();
        assert_eq!(alias, change(case).unwrap().alias);
    }
}

fn body() -> ContentBody {
    let case = &vectors()["accepted"][0];
    ContentBody::AliasChange { attestation: s(&case["text"]), attestation_signature: s(&case["signature"]) }
}

#[test]
fn an_alias_change_goes_through_the_mailbox_and_comes_back() {
    let content = out(Some(ENVELOPE), body());
    let json = encode_content(content.clone()).unwrap();
    assert!(json.starts_with(r#"{"v":4,"kind":"alias_change","sender_account_id":""#), "{json}");
    assert!(json.len().is_power_of_two());
    let read = decode_content(json, mailbox(ENVELOPE)).unwrap();
    assert_eq!(read, Content { version: 4, envelope_id: content.envelope_id, body: body() });
}

#[test]
fn it_has_the_form_of_a_contact_request_and_nothing_else() {
    let ContentBody::AliasChange { attestation, attestation_signature } = body() else { unreachable!() };
    let request = encode_content(out(
        Some(ENVELOPE),
        ContentBody::ContactRequest {
            attestation: attestation.clone(),
            attestation_signature: attestation_signature.clone(),
        },
    ))
    .unwrap();
    let change = encode_content(out(Some(ENVELOPE), body())).unwrap();
    // The same fields in the same order; only the pad, which fills the bucket, differs.
    let unpadded = |json: &str| json[..json.rfind(r#","pad""#).unwrap()].to_owned();
    assert_eq!(unpadded(&request).replace("contact_request", "alias_change"), unpadded(&change));
    assert_eq!(request.len(), change.len());

    let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut v: Value = serde_json::from_str(&change).unwrap();
        f(v.as_object_mut().unwrap());
        v.to_string()
    };
    let read = |json: String| decode_content(json, mailbox(ENVELOPE));
    // Same form checks: an empty or long attestation, a signature that is not 64 bytes, a
    // field the kind does not have, a missing field.
    assert!(matches!(
        read(edit(&|m| {
            m.insert("attestation".into(), "".into());
        })),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
    assert!(matches!(
        read(edit(&|m| {
            m.insert("attestation".into(), "x".repeat(513).into());
        })),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
    assert!(matches!(
        read(edit(&|m| {
            m.insert("attestation_signature".into(), "abc".into());
        })),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
    assert!(matches!(
        read(edit(&|m| {
            m.insert("request_id".into(), ENVELOPE.into());
        })),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
    assert!(matches!(
        read(edit(&|m| {
            m.remove("attestation_signature");
        })),
        Err(ChatCryptoError::InvalidContent { .. })
    ));
}

#[test]
fn only_version_4_and_only_the_mailbox() {
    let json = encode_content(out(Some(ENVELOPE), body())).unwrap();
    for version in [1, 2, 3] {
        let older = json.replacen(r#""v":4"#, &format!(r#""v":{version}"#), 1);
        let result = decode_content(older, mailbox(ENVELOPE));
        assert!(
            matches!(
                result,
                Err(ChatCryptoError::UnsupportedContent { .. }) | Err(ChatCryptoError::InvalidContent { .. })
            ),
            "version {version}: {result:?}"
        );
    }
    assert_eq!(decode_content(json.clone(), websocket()), Err(ChatCryptoError::UnboundContent));
    // Another envelope id than the element's.
    assert_eq!(
        decode_content(json, mailbox("6f1c2a8e-0000-4000-8000-0000000000e2")),
        Err(ChatCryptoError::UnboundContent)
    );
    // Without an envelope id it cannot be written.
    assert!(encode_content(out(None, body())).is_err());
}
