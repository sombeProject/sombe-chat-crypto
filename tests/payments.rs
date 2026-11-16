//! Since 0.6.0: the wallet card and the payment kinds of content version 2, and the rules
//! the module checks on them when written and when read.

mod common;

use common::{mailbox, out, RECIPIENT, SENDER};
use sombe_chat_crypto::*;

const ENVELOPE: &str = "6f1c2a8e-0000-4000-8000-0000000000e1";
const REQUEST: &str = "6f1c2a8e-0000-4000-8000-0000000000a1";
const SOL: &str = "So11111111111111111111111111111111111111112";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const ADDRESS: &str = "FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF";
const SIGNATURE: &str =
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";

fn v3(body: ContentBody) -> OutgoingContent {
    out(Some(ENVELOPE), body)
}

fn read(json: String) -> Result<Content, ChatCryptoError> {
    decode_content(json, mailbox(ENVELOPE))
}

fn request(amount: i64, mint: &str, decimals: u8, note: Option<&str>) -> ContentBody {
    ContentBody::PaymentRequest {
        request_id: REQUEST.into(),
        amount_base_units: amount,
        mint: mint.into(),
        decimals,
        note: note.map(str::to_owned),
    }
}

fn sent(request_id: Option<&str>, note: Option<&str>) -> ContentBody {
    ContentBody::PaymentSent {
        request_id: request_id.map(str::to_owned),
        signature: SIGNATURE.into(),
        amount_base_units: 1_500_000_000,
        mint: SOL.into(),
        decimals: 9,
        note: note.map(str::to_owned),
    }
}

fn card(wallet_address: &str, account_public_key: &str, wallet_signature: &str) -> ContentBody {
    ContentBody::WalletCard {
        wallet_address: wallet_address.into(),
        account_public_key: account_public_key.into(),
        wallet_signature: wallet_signature.into(),
    }
}

fn is_invalid<T: std::fmt::Debug>(result: Result<T, ChatCryptoError>) -> bool {
    matches!(result, Err(ChatCryptoError::InvalidContent { .. }))
}

/// The JSON of a content, without its `pad` field.
fn unpadded(json: &str) -> String {
    let start = json.rfind(r#","pad":""#).expect("a pad field");
    format!("{}}}", &json[..start])
}

/// A JSON content of `kind`, with the common fields and `own` after them, unpadded.
fn raw(kind: &str, own: &str) -> String {
    format!(
        r#"{{"v":3,"kind":"{kind}","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}","envelope_id":"{ENVELOPE}"{own}}}"#
    )
}

#[test]
fn each_new_kind_round_trips_with_its_fields_in_order() {
    let prefix = format!(
        r#"{{"v":3,"kind":"KIND","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}","envelope_id":"{ENVELOPE}""#
    );
    let cases = [
        (
            card(ADDRESS, USDC, SIGNATURE),
            "wallet_card",
            format!(
                r#","wallet_address":"{ADDRESS}","account_public_key":"{USDC}","wallet_signature":"{SIGNATURE}"}}"#
            ),
        ),
        (ContentBody::WalletCardRequest, "wallet_card_request", "}".to_owned()),
        (
            request(1_500_000_000, SOL, 9, Some("Pour le marché")),
            "payment_request",
            format!(
                r#","request_id":"{REQUEST}","amount_base_units":"1500000000","mint":"{SOL}","decimals":9,"note":"Pour le marché"}}"#
            ),
        ),
        (
            request(25_000_000, USDC, 6, None),
            "payment_request",
            format!(
                r#","request_id":"{REQUEST}","amount_base_units":"25000000","mint":"{USDC}","decimals":6}}"#
            ),
        ),
        (
            sent(Some(REQUEST), None),
            "payment_sent",
            format!(
                r#","request_id":"{REQUEST}","signature":"{SIGNATURE}","amount_base_units":"1500000000","mint":"{SOL}","decimals":9}}"#
            ),
        ),
        (
            sent(None, Some("Merci")),
            "payment_sent",
            format!(
                r#","request_id":null,"signature":"{SIGNATURE}","amount_base_units":"1500000000","mint":"{SOL}","decimals":9,"note":"Merci"}}"#
            ),
        ),
        (
            ContentBody::PaymentRequestDeclined { request_id: REQUEST.into() },
            "payment_request_declined",
            format!(r#","request_id":"{REQUEST}"}}"#),
        ),
        (
            ContentBody::PaymentRequestCancelled { request_id: REQUEST.into() },
            "payment_request_cancelled",
            format!(r#","request_id":"{REQUEST}"}}"#),
        ),
    ];
    for (body, kind, rest) in cases {
        let content = v3(body);
        let json = encode_content(content.clone()).unwrap();
        assert_eq!(unpadded(&json), format!("{}{}", prefix.replace("KIND", kind), rest), "{kind}");
        let expected =
            Content { version: 3, envelope_id: content.envelope_id.clone(), body: content.body.clone() };
        assert_eq!(read(json).unwrap(), expected, "{kind}");
    }
}

#[test]
fn no_new_kind_carries_a_client_message_id_or_another_kinds_field() {
    let extras = [
        r#","client_message_id":"6f1c2a8e-0000-4000-8000-000000000002""#,
        r#","body":"x""#,
        r#","comment":"x""#,
        r#","state":"start""#,
    ];
    for extra in extras {
        let declined = raw("payment_request_declined", &format!(r#","request_id":"{REQUEST}"{extra}"#));
        assert!(is_invalid(read(declined)), "{extra}");
        assert!(is_invalid(read(raw("wallet_card_request", extra))), "{extra}");
    }
    // A refusal carries no amount, a request no signature.
    let declined = raw("payment_request_declined", &format!(r#","request_id":"{REQUEST}","decimals":9"#));
    assert!(is_invalid(read(declined)));
    let request = raw(
        "payment_request",
        &format!(
            r#","request_id":"{REQUEST}","signature":"{SIGNATURE}","amount_base_units":"1","mint":"{SOL}","decimals":9"#
        ),
    );
    assert!(is_invalid(read(request)));
}

#[test]
fn amount_is_digits_from_1_to_i64_max() {
    assert!(encode_content(v3(request(1, SOL, 9, None))).is_ok());
    assert!(encode_content(v3(request(i64::MAX, SOL, 9, None))).is_ok());
    assert!(is_invalid(encode_content(v3(request(0, SOL, 9, None)))));
    assert!(is_invalid(encode_content(v3(request(-1, SOL, 9, None)))));

    let with = |amount: &str| {
        raw(
            "payment_request",
            &format!(r#","request_id":"{REQUEST}","amount_base_units":{amount},"mint":"{SOL}","decimals":9"#),
        )
    };
    let read_amount = |amount: &str| read(with(amount));
    match read_amount(r#""9223372036854775807""#).unwrap().body {
        ContentBody::PaymentRequest { amount_base_units, .. } => assert_eq!(amount_base_units, i64::MAX),
        other => panic!("{other:?}"),
    }
    for bad in [
        r#""0""#,
        r#""01""#,
        r#""-1""#,
        r#""+1""#,
        r#"" 1""#,
        r#""1 ""#,
        r#""1.5""#,
        r#""1,5""#,
        r#""1e9""#,
        r#""""#,
        r#""9223372036854775808""#,
        r#""99999999999999999999999""#,
        "1500000000",
        "null",
    ] {
        assert!(is_invalid(read_amount(bad)), "{bad}");
    }
}

#[test]
fn mint_is_base58_of_32_bytes() {
    // A program derived address is off the curve: still a mint.
    for mint in [SOL, USDC, "11111111111111111111111111111111"] {
        assert!(encode_content(v3(request(1, mint, 9, None))).is_ok(), "{mint}");
    }
    for mint in [
        "",
        "So1111111111111111111111111111111111111111",
        "So111111111111111111111111111111111111111120",
        "0o11111111111111111111111111111111111111112",
        "So11111111111111111111111111111111111111112 ",
    ] {
        assert!(is_invalid(encode_content(v3(request(1, mint, 9, None)))), "{mint:?}");
        let json = raw(
            "payment_request",
            &format!(r#","request_id":"{REQUEST}","amount_base_units":"1","mint":"{mint}","decimals":9"#),
        );
        assert!(is_invalid(read(json)), "{mint:?}");
    }
    let without =
        raw("payment_request", &format!(r#","request_id":"{REQUEST}","amount_base_units":"1","decimals":9"#));
    assert!(is_invalid(read(without)));
    let null = raw(
        "payment_request",
        &format!(r#","request_id":"{REQUEST}","amount_base_units":"1","mint":null,"decimals":9"#),
    );
    assert!(is_invalid(read(null)));
}

#[test]
fn decimals_is_a_json_integer_from_0_to_255() {
    let with = |decimals: &str| {
        read(raw(
            "payment_request",
            &format!(
                r#","request_id":"{REQUEST}","amount_base_units":"1","mint":"{SOL}","decimals":{decimals}"#
            ),
        ))
    };
    assert!(with("0").is_ok());
    assert!(with("255").is_ok());
    for bad in ["256", "-1", "9.0", "6.5", r#""9""#, "null", "true"] {
        assert!(is_invalid(with(bad)), "{bad}");
    }
    let without = raw(
        "payment_request",
        &format!(r#","request_id":"{REQUEST}","amount_base_units":"1","mint":"{SOL}""#),
    );
    assert!(is_invalid(read(without)));
}

#[test]
fn note_is_absent_null_or_1_to_500_code_points_not_blank() {
    let with = |note: &str| {
        read(raw(
            "payment_request",
            &format!(
                r#","request_id":"{REQUEST}","amount_base_units":"1","mint":"{SOL}","decimals":9{note}"#
            ),
        ))
    };
    let note_of = |content: Content| match content.body {
        ContentBody::PaymentRequest { note, .. } => note,
        other => panic!("{other:?}"),
    };
    assert_eq!(note_of(with("").unwrap()), None);
    assert_eq!(note_of(with(r#","note":null"#).unwrap()), None);
    assert_eq!(note_of(with(r#","note":"Merci""#).unwrap()), Some("Merci".into()));
    for bad in [r#","note":"""#, r#","note":"   ""#, r#","note":"\n\t""#, r#","note":5"#] {
        assert!(is_invalid(with(bad)), "{bad}");
    }

    let emoji = "😀".repeat(500);
    let longest = encode_content(v3(request(1, SOL, 9, Some(&emoji)))).unwrap();
    assert_eq!(longest.len(), 4096, "500 emoji land in the 4096 byte bucket");
    assert!(is_invalid(encode_content(v3(request(1, SOL, 9, Some(&"😀".repeat(501)))))));
    assert!(is_invalid(encode_content(v3(request(1, SOL, 9, Some(""))))));
    assert!(is_invalid(encode_content(v3(sent(None, Some(" "))))));
    assert!(encode_content(v3(sent(None, Some(&"a".repeat(500))))).is_ok());
    assert!(is_invalid(encode_content(v3(sent(None, Some(&"a".repeat(501)))))));
}

#[test]
fn request_id_is_a_uuid_in_lower_case_and_null_only_on_a_direct_payment() {
    let upper = REQUEST.to_uppercase();
    let json =
        encode_content(v3(ContentBody::PaymentRequestCancelled { request_id: upper.clone() })).unwrap();
    assert!(json.contains(REQUEST), "written in lower case");
    // Version 3 reads an id only in lower case.
    assert!(is_invalid(read(raw("payment_request_declined", &format!(r#","request_id":"{upper}""#)))));
    let got = read(raw("payment_request_declined", &format!(r#","request_id":"{REQUEST}""#))).unwrap();
    assert_eq!(got.body, ContentBody::PaymentRequestDeclined { request_id: REQUEST.into() });

    assert!(is_invalid(encode_content(v3(ContentBody::PaymentRequestDeclined { request_id: "x".into() }))));
    assert!(is_invalid(encode_content(v3(sent(Some("not-a-uuid"), None)))));
    for kind in ["payment_request_declined", "payment_request_cancelled"] {
        assert!(is_invalid(read(raw(kind, ""))), "{kind}");
        assert!(is_invalid(read(raw(kind, r#","request_id":null"#))), "{kind}");
    }
    let request_without = raw(
        "payment_request",
        &format!(r#","request_id":null,"amount_base_units":"1","mint":"{SOL}","decimals":9"#),
    );
    assert!(is_invalid(read(request_without)));

    // A payment sent without request_id, or with null, is a direct payment.
    let direct = raw(
        "payment_sent",
        &format!(
            r#","signature":"{SIGNATURE}","amount_base_units":"1500000000","mint":"{SOL}","decimals":9"#
        ),
    );
    assert_eq!(read(direct).unwrap().body, sent(None, None));
}

#[test]
fn signatures_are_base58_of_64_bytes_and_keys_of_32() {
    // 32 bytes where a signature needs 64.
    let short = ADDRESS;
    let bad_sent = ContentBody::PaymentSent {
        request_id: None,
        signature: short.into(),
        amount_base_units: 1,
        mint: SOL.into(),
        decimals: 9,
        note: None,
    };
    assert!(is_invalid(encode_content(v3(bad_sent))));
    assert!(is_invalid(encode_content(v3(card(ADDRESS, USDC, short)))));
    assert!(is_invalid(encode_content(v3(card(SIGNATURE, USDC, SIGNATURE)))), "an address is 32 bytes");
    assert!(is_invalid(encode_content(v3(card(ADDRESS, "", SIGNATURE)))));
    assert!(is_invalid(encode_content(v3(card("0OIl", USDC, SIGNATURE)))), "not in the base58 alphabet");
    for missing in ["wallet_address", "account_public_key", "wallet_signature"] {
        let fields =
            [("wallet_address", ADDRESS), ("account_public_key", USDC), ("wallet_signature", SIGNATURE)];
        let own: String =
            fields.iter().filter(|(n, _)| *n != missing).map(|(n, v)| format!(r#","{n}":"{v}""#)).collect();
        assert!(is_invalid(read(raw("wallet_card", &own))), "{missing}");
    }
}

#[test]
fn every_new_kind_needs_its_envelope_id() {
    for body in [
        card(ADDRESS, USDC, SIGNATURE),
        ContentBody::WalletCardRequest,
        request(1, SOL, 9, None),
        sent(None, None),
        ContentBody::PaymentRequestDeclined { request_id: REQUEST.into() },
        ContentBody::PaymentRequestCancelled { request_id: REQUEST.into() },
    ] {
        let content = OutgoingContent { envelope_id: None, ..v3(body) };
        assert!(is_invalid(encode_content(content.clone())), "{content:?}");
    }
    let json = format!(
        r#"{{"v":3,"kind":"wallet_card_request","sender_account_id":"{SENDER}","recipient_account_id":"{RECIPIENT}"}}"#
    );
    assert!(is_invalid(read(json)));
}

/// A phone on 0.5.0 reads these kinds as UnsupportedContent; the old payment kind is still read.
#[test]
fn the_old_payment_kind_is_still_read() {
    let json = raw(
        "payment",
        r#","client_message_id":"6f1c2a8e-0000-4000-8000-000000000002","body":"Pour le marché""#,
    );
    assert!(matches!(read(json).unwrap().body, ContentBody::Payment { .. }));
}
