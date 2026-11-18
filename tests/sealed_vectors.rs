//! Checks vectors/v7.json (since 0.10.0): the statement v4 verifies and each refused one gives
//! its error; the sealing key restores from its pickle; each sealed envelope opens to its
//! sender and its Olm envelope, each refused one is `InvalidSealed`; the `identity_statement`
//! content reads and encodes back to the same bytes, each refused one gives its error.

use serde_json::Value;
use sombe_chat_crypto::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../vectors/v7.json")).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn fields(f: &Value) -> StatementFields {
    StatementFields {
        account_public_key: s(&f["account_public_key"]),
        curve25519_key: s(&f["curve25519_key"]),
        ed25519_key: s(&f["ed25519_key"]),
        sealing_key: f["sealing_key"].as_str().map(str::to_owned),
        created_at: s(&f["created_at"]),
        identity_signature: s(&f["identity_signature"]),
        account_signature: s(&f["account_signature"]),
    }
}

fn error_name(e: &ChatCryptoError) -> &'static str {
    match e {
        ChatCryptoError::InvalidKey { .. } => "InvalidKey",
        ChatCryptoError::InvalidSignature => "InvalidSignature",
        ChatCryptoError::InvalidStatement { .. } => "InvalidStatement",
        ChatCryptoError::InvalidContent { .. } => "InvalidContent",
        ChatCryptoError::UnsupportedContent { .. } => "UnsupportedContent",
        ChatCryptoError::UnboundContent => "UnboundContent",
        ChatCryptoError::InvalidSealed => "InvalidSealed",
        other => panic!("unexpected {other:?}"),
    }
}

fn binding(b: &Value) -> ContentBinding {
    let opt = |field: &str| b[field].as_str().map(str::to_owned);
    ContentBinding {
        channel: match b["channel"].as_str().unwrap() {
            "mailbox" => ContentChannel::Mailbox,
            "websocket" => ContentChannel::Websocket,
            other => panic!("unknown channel {other}"),
        },
        envelope_id: opt("envelope_id"),
        sender_account_id: s(&b["sender_account_id"]),
        sender_ed25519_key: s(&b["sender_ed25519_key"]),
        my_account_id: s(&b["my_account_id"]),
        my_ed25519_key: s(&b["my_ed25519_key"]),
        legacy_conversation_id: opt("legacy_conversation_id"),
    }
}

#[test]
fn the_statement_v4_verifies_and_the_refused_ones_give_their_error() {
    let v = &vectors()["statement_v4"];
    let f = fields(&v["fields"]);
    let verified = verify_identity(f.clone()).unwrap();
    assert_eq!(verified.sealing_key, f.sealing_key);
    assert_eq!(verified.account_public_key, f.account_public_key);
    let body = s(&v["body"]);
    let lines: Vec<&str> = body.split('\n').collect();
    assert_eq!(lines.len(), 7);
    assert_eq!(lines[0], "SOMBE chat identity v4");
    assert_eq!(lines[6], format!("sealing:{}", f.sealing_key.clone().unwrap()));
    assert_eq!(s(&v["statement"]), format!("{body}\nidentity_signature:{}", f.identity_signature));

    let v3 = verify_identity(fields(&v["v3_fields"])).unwrap();
    assert_eq!(v3.sealing_key, None);

    let refused = v["refused"].as_array().unwrap();
    assert!(refused.len() >= 7);
    for r in refused {
        let read = verify_identity(fields(&r["fields"]));
        assert_eq!(
            error_name(&read.expect_err(r["name"].as_str().unwrap())),
            s(&r["error"]),
            "{}",
            r["name"]
        );
    }
}

#[test]
fn sealed_envelopes_open_to_their_sender_and_the_refused_ones_do_not() {
    let v = vectors();
    let key = ChatSealingKey::restore(
        s(&v["sealing_key"]["pickle"]),
        unhex(&s(&v["sealing_key"]["pickle_key_hex"])),
    )
    .unwrap();
    assert_eq!(key.public_key(), s(&v["sealing_key"]["public_key"]));
    let sealed = &v["sealed"];
    assert_eq!(s(&sealed["recipient"]["sealing_key"]), key.public_key());
    let me = (s(&sealed["recipient"]["account_id"]), s(&sealed["recipient"]["identity_id"]));
    let sender = SealedSender {
        account_id: s(&sealed["sender"]["account_id"]),
        identity_id: s(&sealed["sender"]["identity_id"]),
        statement: fields(&sealed["sender"]["statement"]),
    };

    let opened = sealed["opened"].as_array().unwrap();
    assert_eq!(opened.len(), 2);
    for o in opened {
        let read =
            key.open_sealed(s(&o["ciphertext"]), me.0.clone(), me.1.clone(), s(&o["envelope_id"])).unwrap();
        assert_eq!(read.sender, sender);
        assert_eq!(
            read.envelope,
            Envelope {
                protocol: protocol_id(),
                olm_type: o["olm_type"].as_u64().unwrap() as u8,
                ciphertext: s(&o["olm_ciphertext"]),
            }
        );
        let clear = s(&o["clear"]);
        assert_eq!(clear.len() % 256, 0);
        // The sealed text is the 32 byte encapsulated key, the clear text and a 16 byte tag.
        let bytes = vodozemac::base64_decode(s(&o["ciphertext"])).unwrap();
        assert_eq!(bytes.len(), 32 + clear.len() + 16);
    }

    let refused = sealed["refused"].as_array().unwrap();
    assert!(refused.len() >= 12);
    for r in refused {
        let read = key.open_sealed(
            s(&r["ciphertext"]),
            s(&r["my_account_id"]),
            s(&r["my_identity_id"]),
            s(&r["envelope_id"]),
        );
        assert_eq!(read, Err(ChatCryptoError::InvalidSealed), "{}", r["name"]);
    }
}

#[test]
fn the_identity_statement_content_reads_and_encodes_back() {
    let v = &vectors()["identity_statement"];
    let b = binding(&v["bound"]["binding"]);
    let plaintext = s(&v["bound"]["plaintext"]);
    let read = decode_content(plaintext.clone(), b.clone()).unwrap();
    let statement = fields(&v["bound"]["statement"]);
    assert_eq!(read.body, ContentBody::IdentityStatement { statement: statement.clone() });
    assert_eq!(plaintext.len(), 1024);
    let written = encode_content(OutgoingContent {
        sender_account_id: b.sender_account_id.clone(),
        sender_ed25519_key: b.sender_ed25519_key.clone(),
        recipient_account_id: b.my_account_id.clone(),
        recipient_ed25519_key: b.my_ed25519_key.clone(),
        envelope_id: b.envelope_id.clone(),
        body: read.body,
    })
    .unwrap();
    assert_eq!(written, plaintext);

    for r in v["refused"].as_array().unwrap() {
        let read = decode_content(s(&r["plaintext"]), binding(&r["binding"]));
        assert_eq!(
            error_name(&read.expect_err(r["name"].as_str().unwrap())),
            s(&r["error"]),
            "{}",
            r["name"]
        );
    }
}

/// The generator gives the same bytes again: run with `--features vectors`.
#[cfg(feature = "vectors")]
#[test]
fn the_sealed_vectors_are_what_the_module_writes() {
    let v = vectors();
    let ikm: [u8; 32] = unhex(&s(&v["sealing_key"]["ikm_hex"])).try_into().unwrap();
    let key = vectors::sealing_key_from_ikm(ikm);
    assert_eq!(key.public_key(), s(&v["sealing_key"]["public_key"]));
    let sealed = &v["sealed"];
    let recipient = SealedRecipient {
        account_id: s(&sealed["recipient"]["account_id"]),
        identity_id: s(&sealed["recipient"]["identity_id"]),
        sealing_key: key.public_key(),
    };
    let sender = SealedSender {
        account_id: s(&sealed["sender"]["account_id"]),
        identity_id: s(&sealed["sender"]["identity_id"]),
        statement: fields(&sealed["sender"]["statement"]),
    };
    for o in sealed["opened"].as_array().unwrap() {
        let envelope = Envelope {
            protocol: protocol_id(),
            olm_type: o["olm_type"].as_u64().unwrap() as u8,
            ciphertext: s(&o["olm_ciphertext"]),
        };
        let ephemeral: [u8; 32] = unhex(&s(&o["ephemeral_ikm_hex"])).try_into().unwrap();
        let written =
            vectors::seal_with_ephemeral(ephemeral, &recipient, &s(&o["envelope_id"]), &sender, &envelope)
                .unwrap();
        assert_eq!(written, s(&o["ciphertext"]));
        assert_eq!(vectors::clear_text(&sender, &envelope), s(&o["clear"]));
    }
}
