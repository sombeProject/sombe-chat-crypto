//! What travels inside the ciphertext. The content names its conversation and (since
//! version 2) its envelope id, so a server can neither move it to another conversation nor
//! replay it under another id. Every content is padded to a size bucket, so its length
//! tells the server little.
//!
//! Version 2 (since 0.5.0) carries the kind and the target of every element, delivery
//! and read receipts, and typing signals: the server no longer sees any of them. Version 1
//! is still read, never written. The whole JSON format lives here: the app only sees
//! `Content` and `ContentBody`.
//!
//! Since 0.6.0 version 2 also carries the wallet card (the wallet address a contact pays,
//! signed by that wallet) and the payments themselves: requests, payments sent, refusals
//! and cancellations. The server no longer sees any payment. The old `payment` kind (the
//! comment of a card the server kept) is still read.

use serde_json::{Map, Value};

use crate::ChatCryptoError;

/// The only version `encode_content` writes.
pub const CONTENT_VERSION: u8 = 2;
pub const MAX_BODY_CHARS: usize = 4000;
pub const MAX_REPLY_EXCERPT_CHARS: usize = 200;
/// A payment card's comment or note (`comment` in version 1, `body` in version 2).
pub const MAX_COMMENT_CHARS: usize = 500;
pub const MAX_REACTION_CHARS: usize = 16;
/// A payment's note (since 0.6.0), counted in code points.
pub const MAX_NOTE_CHARS: usize = 500;
/// Bytes of an ed25519 public key or Solana address, and of a signature.
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
/// The smallest padded size, in bytes; larger contents are padded to the next power of two.
pub const MIN_PADDED_BYTES: usize = 256;
/// What the `pad` field adds around its spaces: `,"pad":""`.
const PAD_FIELD_BYTES: usize = 9;
/// The fields every version 2 content may carry, whatever its kind.
const COMMON_FIELDS: [&str; 4] = ["v", "kind", "conversation_id", "envelope_id"];

/// One decrypted content, whatever its version.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct Content {
    /// 1 or 2, as read by `decode_content`; `encode_content` writes only 2.
    pub version: u8,
    /// Lower case UUID.
    pub conversation_id: String,
    /// The envelope id this content was sealed for, lower case. Absent only in a version 1
    /// content and in a `Typing` (which is never stored); required otherwise.
    pub envelope_id: Option<String>,
    pub body: ContentBody,
}

/// What the content says, one variant per kind. Every id is a lower case UUID; a target
/// (`reply_to_message_id`, `edits_message_id`, ...) is the envelope id of the target.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum ContentBody {
    Text {
        client_message_id: String,
        body: String,
        /// Always absent in a version 1 content (its quotes had only an excerpt).
        reply_to_message_id: Option<String>,
        reply_excerpt: Option<String>,
    },
    /// Replaces the body of an earlier text by the same sender.
    Edit { client_message_id: String, edits_message_id: String, body: String },
    /// One emoji set on a text.
    Reaction { client_message_id: String, reacts_to_message_id: String, body: String },
    /// Removes the sender's reaction from a text.
    ReactionRemove { client_message_id: String, reacts_to_message_id: String },
    /// Deletes one of the sender's texts for everyone.
    Delete { client_message_id: String, deletes_message_id: String },
    /// The comment or note of a payment card. Empty only when a version 1 card had none.
    Payment { client_message_id: String, body: String },
    /// Every visible message of the conversation up to this one was delivered or read.
    /// Sent through the mailbox only.
    Receipt { status: ReceiptStatus, up_to_envelope_id: String, up_to_created_at: String },
    /// The sender started or stopped typing. Sent through the websocket only, never stored.
    Typing { state: TypingState },
    /// The sender's wallet card (since 0.6.0): the text
    /// `SOMBE wallet card v1\nwallet:<wallet_address>\naccount:<account_public_key>` and its
    /// signature by the wallet. The module checks only the form of the three fields (base58
    /// of 32, 32 and 64 bytes); the app checks the signature and the account key.
    WalletCard { wallet_address: String, account_public_key: String, wallet_signature: String },
    /// Asks the contact to send their wallet card again (since 0.6.0). No field of its own.
    WalletCardRequest,
    /// A payment request (since 0.6.0). `request_id` is a UUID the requester's phone drew.
    PaymentRequest {
        request_id: String,
        /// 1 to `i64::MAX`, written in the JSON as a string of decimal digits.
        amount_base_units: i64,
        /// Base58 address of 32 bytes; native SOL is `So11111111111111111111111111111111111111112`.
        mint: String,
        decimals: u8,
        /// 1 to 500 code points, not blank; `None` when there is no note.
        note: Option<String>,
    },
    /// A payment the sender made on Solana (since 0.6.0). `request_id` is `None` for a
    /// direct payment.
    PaymentSent {
        request_id: Option<String>,
        /// Base58 of the 64 byte transaction signature.
        signature: String,
        amount_base_units: i64,
        mint: String,
        decimals: u8,
        note: Option<String>,
    },
    /// The person a request was sent to refuses it (since 0.6.0).
    PaymentRequestDeclined { request_id: String },
    /// The requester withdraws a request (since 0.6.0).
    PaymentRequestCancelled { request_id: String },
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypingState {
    Start,
    Stop,
}

pub(crate) fn encode(content: Content) -> Result<String, ChatCryptoError> {
    if content.version != CONTENT_VERSION {
        return Err(invalid("only version 2 is written"));
    }
    let mut map = Map::new();
    map.insert("v".into(), Value::from(CONTENT_VERSION));
    map.insert("kind".into(), Value::from(kind_name(&content.body)));
    put_uuid(&mut map, "conversation_id", &content.conversation_id)?;
    match (&content.body, &content.envelope_id) {
        (ContentBody::Typing { .. }, None) => {}
        (ContentBody::Typing { .. }, Some(_)) => {
            return Err(invalid("a typing signal carries no envelope_id"))
        }
        (_, None) => return Err(invalid("envelope_id is required")),
        (_, Some(id)) => put_uuid(&mut map, "envelope_id", id)?,
    }
    match &content.body {
        ContentBody::Text { client_message_id, body, reply_to_message_id, reply_excerpt } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            map.insert("body".into(), Value::from(text_body(body)?));
            if let Some(target) = reply_to_message_id {
                put_uuid(&mut map, "reply_to_message_id", target)?;
            }
            if let Some(excerpt) = reply_excerpt {
                map.insert("reply_excerpt".into(), Value::from(excerpt_text(excerpt)?));
            }
        }
        ContentBody::Edit { client_message_id, edits_message_id, body } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            put_uuid(&mut map, "edits_message_id", edits_message_id)?;
            map.insert("body".into(), Value::from(text_body(body)?));
        }
        ContentBody::Reaction { client_message_id, reacts_to_message_id, body } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            put_uuid(&mut map, "reacts_to_message_id", reacts_to_message_id)?;
            map.insert("body".into(), Value::from(emoji(body)?));
        }
        ContentBody::ReactionRemove { client_message_id, reacts_to_message_id } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            put_uuid(&mut map, "reacts_to_message_id", reacts_to_message_id)?;
        }
        ContentBody::Delete { client_message_id, deletes_message_id } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            put_uuid(&mut map, "deletes_message_id", deletes_message_id)?;
        }
        ContentBody::Payment { client_message_id, body } => {
            put_uuid(&mut map, "client_message_id", client_message_id)?;
            map.insert("body".into(), Value::from(comment(body, true)?));
        }
        ContentBody::Receipt { status, up_to_envelope_id, up_to_created_at } => {
            let status = match status {
                ReceiptStatus::Delivered => "delivered",
                ReceiptStatus::Read => "read",
            };
            map.insert("status".into(), Value::from(status));
            put_uuid(&mut map, "up_to_envelope_id", up_to_envelope_id)?;
            map.insert("up_to_created_at".into(), Value::from(timestamp(up_to_created_at)?));
        }
        ContentBody::Typing { state } => {
            let state = match state {
                TypingState::Start => "start",
                TypingState::Stop => "stop",
            };
            map.insert("state".into(), Value::from(state));
        }
        ContentBody::WalletCard { wallet_address, account_public_key, wallet_signature } => {
            map.insert(
                "wallet_address".into(),
                Value::from(base58(wallet_address, KEY_BYTES, "wallet_address")?),
            );
            map.insert(
                "account_public_key".into(),
                Value::from(base58(account_public_key, KEY_BYTES, "account_public_key")?),
            );
            map.insert(
                "wallet_signature".into(),
                Value::from(base58(wallet_signature, SIGNATURE_BYTES, "wallet_signature")?),
            );
        }
        ContentBody::WalletCardRequest => {}
        ContentBody::PaymentRequest { request_id, amount_base_units, mint, decimals, note } => {
            put_uuid(&mut map, "request_id", request_id)?;
            put_amount(&mut map, *amount_base_units, mint, *decimals)?;
            put_note(&mut map, note)?;
        }
        ContentBody::PaymentSent { request_id, signature, amount_base_units, mint, decimals, note } => {
            match request_id {
                // Written as null, not left out: a direct payment says so.
                None => {
                    map.insert("request_id".into(), Value::Null);
                }
                Some(id) => put_uuid(&mut map, "request_id", id)?,
            }
            map.insert("signature".into(), Value::from(base58(signature, SIGNATURE_BYTES, "signature")?));
            put_amount(&mut map, *amount_base_units, mint, *decimals)?;
            put_note(&mut map, note)?;
        }
        ContentBody::PaymentRequestDeclined { request_id }
        | ContentBody::PaymentRequestCancelled { request_id } => {
            put_uuid(&mut map, "request_id", request_id)?;
        }
    }
    pad(map)
}

pub(crate) fn decode(json: &str) -> Result<Content, ChatCryptoError> {
    let value: Value = serde_json::from_str(json).map_err(|e| invalid(&e.to_string()))?;
    let Value::Object(map) = value else {
        return Err(invalid("content is not a JSON object"));
    };
    let version = match map.get("v") {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| invalid("v is not a version number"))?,
        _ => return Err(invalid("v is missing")),
    };
    match version {
        1 => decode_v1(&map),
        2 => decode_v2(map),
        0 => Err(invalid("v is not a version number")),
        _ => Err(unsupported("content version is newer than 2")),
    }
}

fn decode_v2(mut map: Map<String, Value>) -> Result<Content, ChatCryptoError> {
    let kind = match map.get("kind") {
        Some(Value::String(kind)) => kind.clone(),
        _ => return Err(invalid("kind is missing")),
    };
    let own: &[&str] = match kind.as_str() {
        "text" => &["client_message_id", "body", "reply_to_message_id", "reply_excerpt"],
        "edit" => &["client_message_id", "edits_message_id", "body"],
        "reaction" => &["client_message_id", "reacts_to_message_id", "body"],
        "reaction_remove" => &["client_message_id", "reacts_to_message_id"],
        "delete" => &["client_message_id", "deletes_message_id"],
        "payment" => &["client_message_id", "body"],
        "receipt" => &["status", "up_to_envelope_id", "up_to_created_at"],
        "typing" => &["state"],
        "wallet_card" => &["wallet_address", "account_public_key", "wallet_signature"],
        "wallet_card_request" => &[],
        "payment_request" => &["request_id", "amount_base_units", "mint", "decimals", "note"],
        "payment_sent" => &["request_id", "signature", "amount_base_units", "mint", "decimals", "note"],
        "payment_request_declined" | "payment_request_cancelled" => &["request_id"],
        _ => return Err(unsupported("unknown content kind")),
    };
    // Exactly the fields of the kind: a later addition is a version 3.
    map.remove("pad");
    if let Some(unknown) =
        map.keys().find(|k| !COMMON_FIELDS.contains(&k.as_str()) && !own.contains(&k.as_str()))
    {
        return Err(invalid(&format!("unknown field {unknown}")));
    }

    let conversation_id = uuid(&required(&map, "conversation_id")?, "conversation_id")?;
    let envelope_id = match (kind.as_str(), optional(&map, "envelope_id")?) {
        ("typing", None) => None,
        ("typing", Some(_)) => return Err(invalid("a typing signal carries no envelope_id")),
        (_, None) => return Err(invalid("envelope_id is required")),
        (_, Some(id)) => Some(uuid(&id, "envelope_id")?),
    };
    let id = |name: &str| -> Result<String, ChatCryptoError> { uuid(&required(&map, name)?, name) };
    let body = match kind.as_str() {
        "text" => ContentBody::Text {
            client_message_id: id("client_message_id")?,
            body: text_body(&required(&map, "body")?)?,
            reply_to_message_id: optional(&map, "reply_to_message_id")?
                .map(|t| uuid(&t, "reply_to_message_id"))
                .transpose()?,
            reply_excerpt: optional(&map, "reply_excerpt")?.map(|e| excerpt_text(&e)).transpose()?,
        },
        "edit" => ContentBody::Edit {
            client_message_id: id("client_message_id")?,
            edits_message_id: id("edits_message_id")?,
            body: text_body(&required(&map, "body")?)?,
        },
        "reaction" => ContentBody::Reaction {
            client_message_id: id("client_message_id")?,
            reacts_to_message_id: id("reacts_to_message_id")?,
            body: emoji(&required(&map, "body")?)?,
        },
        "reaction_remove" => ContentBody::ReactionRemove {
            client_message_id: id("client_message_id")?,
            reacts_to_message_id: id("reacts_to_message_id")?,
        },
        "delete" => ContentBody::Delete {
            client_message_id: id("client_message_id")?,
            deletes_message_id: id("deletes_message_id")?,
        },
        "payment" => ContentBody::Payment {
            client_message_id: id("client_message_id")?,
            body: comment(&required(&map, "body")?, true)?,
        },
        "receipt" => ContentBody::Receipt {
            status: match required(&map, "status")?.as_str() {
                "delivered" => ReceiptStatus::Delivered,
                "read" => ReceiptStatus::Read,
                _ => return Err(invalid("status is delivered or read")),
            },
            up_to_envelope_id: id("up_to_envelope_id")?,
            up_to_created_at: timestamp(&required(&map, "up_to_created_at")?)?,
        },
        "typing" => ContentBody::Typing {
            state: match required(&map, "state")?.as_str() {
                "start" => TypingState::Start,
                "stop" => TypingState::Stop,
                _ => return Err(invalid("state is start or stop")),
            },
        },
        "wallet_card" => ContentBody::WalletCard {
            wallet_address: base58(&required(&map, "wallet_address")?, KEY_BYTES, "wallet_address")?,
            account_public_key: base58(
                &required(&map, "account_public_key")?,
                KEY_BYTES,
                "account_public_key",
            )?,
            wallet_signature: base58(
                &required(&map, "wallet_signature")?,
                SIGNATURE_BYTES,
                "wallet_signature",
            )?,
        },
        "wallet_card_request" => ContentBody::WalletCardRequest,
        "payment_request" => {
            let (amount_base_units, mint, decimals) = read_amount(&map)?;
            ContentBody::PaymentRequest {
                request_id: id("request_id")?,
                amount_base_units,
                mint,
                decimals,
                note: read_note(&map)?,
            }
        }
        "payment_sent" => {
            let (amount_base_units, mint, decimals) = read_amount(&map)?;
            ContentBody::PaymentSent {
                request_id: optional(&map, "request_id")?.map(|r| uuid(&r, "request_id")).transpose()?,
                signature: base58(&required(&map, "signature")?, SIGNATURE_BYTES, "signature")?,
                amount_base_units,
                mint,
                decimals,
                note: read_note(&map)?,
            }
        }
        "payment_request_declined" => ContentBody::PaymentRequestDeclined { request_id: id("request_id")? },
        "payment_request_cancelled" => ContentBody::PaymentRequestCancelled { request_id: id("request_id")? },
        _ => unreachable!("kinds were matched above"),
    };
    Ok(Content { version: 2, conversation_id, envelope_id, body })
}

/// Version 1 is read with the rules of 0.4.0: unknown fields are ignored, ids are only
/// checked to be present (then returned in lower case), and each kind keeps its own fields.
fn decode_v1(map: &Map<String, Value>) -> Result<Content, ChatCryptoError> {
    let kind = match map.get("kind") {
        Some(Value::String(kind)) => kind.clone(),
        _ => return Err(invalid("kind is missing")),
    };
    if !["text", "payment", "edit", "reaction", "reaction_remove", "delete"].contains(&kind.as_str()) {
        return Err(unsupported("unknown version 1 content kind"));
    }
    let conversation_id = v1_id(map, "conversation_id")?;
    let client_message_id = v1_id(map, "client_message_id")?;
    let body = optional(map, "body")?;
    let reply_excerpt = optional(map, "reply_excerpt")?;
    let comment_text = optional(map, "comment")?;
    let edits = optional(map, "edits_message_id")?;
    let reacts = optional(map, "reacts_to_message_id")?;
    let deletes = optional(map, "deletes_message_id")?;

    if !matches!(kind.as_str(), "reaction" | "reaction_remove") && reacts.is_some() {
        return Err(invalid("only a reaction or its removal names reacts_to_message_id"));
    }
    if kind != "delete" && deletes.is_some() {
        return Err(invalid("only a delete names deletes_message_id"));
    }
    if kind != "edit" && edits.is_some() {
        return Err(invalid("only an edit names edits_message_id"));
    }
    if let Some(excerpt) = &reply_excerpt {
        excerpt_text(excerpt)?;
    }
    let target = |id: Option<String>, what: &str| -> Result<String, ChatCryptoError> {
        match id {
            Some(id) if !id.is_empty() => Ok(id.to_lowercase()),
            _ => Err(invalid(&format!("{kind} needs {what}"))),
        }
    };
    let body = match kind.as_str() {
        "text" => {
            if comment_text.is_some() {
                return Err(invalid("text carries no comment"));
            }
            ContentBody::Text {
                client_message_id,
                body: text_body(&body.unwrap_or_default())?,
                reply_to_message_id: None,
                reply_excerpt,
            }
        }
        "edit" => {
            if reply_excerpt.is_some() || comment_text.is_some() {
                return Err(invalid("edit carries neither reply_excerpt nor comment"));
            }
            ContentBody::Edit {
                client_message_id,
                edits_message_id: target(edits, "edits_message_id")?,
                body: text_body(&body.unwrap_or_default())?,
            }
        }
        "reaction" => {
            if reply_excerpt.is_some() || comment_text.is_some() {
                return Err(invalid("reaction carries neither reply_excerpt, comment nor edits_message_id"));
            }
            ContentBody::Reaction {
                client_message_id,
                reacts_to_message_id: target(reacts, "reacts_to_message_id")?,
                body: emoji(&body.unwrap_or_default())?,
            }
        }
        "reaction_remove" => {
            if body.is_some() || reply_excerpt.is_some() || comment_text.is_some() {
                return Err(invalid("reaction removal carries only reacts_to_message_id"));
            }
            ContentBody::ReactionRemove {
                client_message_id,
                reacts_to_message_id: target(reacts, "reacts_to_message_id")?,
            }
        }
        "delete" => {
            if body.is_some() || reply_excerpt.is_some() || comment_text.is_some() {
                return Err(invalid("delete carries only deletes_message_id"));
            }
            ContentBody::Delete {
                client_message_id,
                deletes_message_id: target(deletes, "deletes_message_id")?,
            }
        }
        "payment" => {
            if body.is_some() || reply_excerpt.is_some() {
                return Err(invalid("payment carries only a comment"));
            }
            ContentBody::Payment {
                client_message_id,
                body: comment(&comment_text.unwrap_or_default(), false)?,
            }
        }
        _ => unreachable!("kinds were matched above"),
    };
    Ok(Content { version: 1, conversation_id, envelope_id: None, body })
}

fn kind_name(body: &ContentBody) -> &'static str {
    match body {
        ContentBody::Text { .. } => "text",
        ContentBody::Edit { .. } => "edit",
        ContentBody::Reaction { .. } => "reaction",
        ContentBody::ReactionRemove { .. } => "reaction_remove",
        ContentBody::Delete { .. } => "delete",
        ContentBody::Payment { .. } => "payment",
        ContentBody::Receipt { .. } => "receipt",
        ContentBody::Typing { .. } => "typing",
        ContentBody::WalletCard { .. } => "wallet_card",
        ContentBody::WalletCardRequest => "wallet_card_request",
        ContentBody::PaymentRequest { .. } => "payment_request",
        ContentBody::PaymentSent { .. } => "payment_sent",
        ContentBody::PaymentRequestDeclined { .. } => "payment_request_declined",
        ContentBody::PaymentRequestCancelled { .. } => "payment_request_cancelled",
    }
}

/// Adds, last, the `pad` field of spaces that brings the JSON to its size bucket.
fn pad(mut map: Map<String, Value>) -> Result<String, ChatCryptoError> {
    let unpadded = serde_json::to_string(&map).map_err(|e| invalid(&e.to_string()))?.len();
    let target = (unpadded + PAD_FIELD_BYTES).max(MIN_PADDED_BYTES).next_power_of_two();
    map.insert("pad".into(), Value::from(" ".repeat(target - unpadded - PAD_FIELD_BYTES)));
    serde_json::to_string(&map).map_err(|e| invalid(&e.to_string()))
}

fn required(map: &Map<String, Value>, name: &str) -> Result<String, ChatCryptoError> {
    optional(map, name)?.ok_or_else(|| invalid(&format!("{name} is required")))
}

/// A string field; absent and `null` both read as absent.
fn optional(map: &Map<String, Value>, name: &str) -> Result<Option<String>, ChatCryptoError> {
    match map.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(invalid(&format!("{name} is not a string"))),
    }
}

fn v1_id(map: &Map<String, Value>, name: &str) -> Result<String, ChatCryptoError> {
    match optional(map, name)? {
        Some(id) if !id.is_empty() => Ok(id.to_lowercase()),
        _ => Err(invalid("conversation_id and client_message_id are required")),
    }
}

fn put_uuid(map: &mut Map<String, Value>, name: &str, id: &str) -> Result<(), ChatCryptoError> {
    map.insert(name.into(), Value::from(uuid(id, name)?));
    Ok(())
}

/// A well formed UUID (8-4-4-4-12 hexadecimal digits), returned in lower case.
fn uuid(id: &str, name: &str) -> Result<String, ChatCryptoError> {
    let groups: Vec<&str> = id.split('-').collect();
    let well_formed = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()));
    if !well_formed {
        return Err(invalid(&format!("{name} is not a UUID")));
    }
    Ok(id.to_ascii_lowercase())
}

/// An RFC 3339 date with its offset (`Z` or `+hh:mm`), e.g. `2026-11-04T12:34:56.789Z`.
/// Only its form is checked; the module compares it with nothing.
fn timestamp(text: &str) -> Result<String, ChatCryptoError> {
    let bad = || invalid("up_to_created_at is not an RFC 3339 date with an offset");
    let number = |part: Option<&str>, max: u32| -> bool {
        part.is_some_and(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| n <= max)
        })
    };
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return Err(bad());
    }
    let month = text.get(5..7).and_then(|m| m.parse::<u32>().ok()).unwrap_or(0);
    let day = text.get(8..10).and_then(|d| d.parse::<u32>().ok()).unwrap_or(0);
    let date_ok = number(text.get(0..4), 9999)
        && number(text.get(5..7), 12)
        && number(text.get(8..10), 31)
        && month >= 1
        && day >= 1
        && number(text.get(11..13), 23)
        && number(text.get(14..16), 59)
        && number(text.get(17..19), 60);
    if !date_ok {
        return Err(bad());
    }
    let mut rest = text.get(19..).ok_or_else(bad)?;
    if let Some(fraction) = rest.strip_prefix('.') {
        let count = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if count == 0 {
            return Err(bad());
        }
        rest = &fraction[count..];
    }
    let offset_ok = rest == "Z"
        || (rest.len() == 6
            && (rest.starts_with('+') || rest.starts_with('-'))
            && rest.as_bytes()[3] == b':'
            && number(rest.get(1..3), 23)
            && number(rest.get(4..6), 59));
    if !offset_ok {
        return Err(bad());
    }
    Ok(text.to_owned())
}

fn text_body(body: &str) -> Result<String, ChatCryptoError> {
    if body.trim().is_empty() || body.chars().count() > MAX_BODY_CHARS {
        return Err(invalid("text needs a body of 1 to 4000 characters"));
    }
    Ok(body.to_owned())
}

fn excerpt_text(excerpt: &str) -> Result<String, ChatCryptoError> {
    if excerpt.chars().count() > MAX_REPLY_EXCERPT_CHARS {
        return Err(invalid("reply excerpt is longer than 200 characters"));
    }
    Ok(excerpt.to_owned())
}

fn emoji(body: &str) -> Result<String, ChatCryptoError> {
    let chars = body.chars().count();
    if chars == 0 || chars > MAX_REACTION_CHARS || body.chars().any(char::is_whitespace) {
        return Err(invalid("reaction needs one emoji of 1 to 16 characters, without space"));
    }
    Ok(body.to_owned())
}

/// A card's comment: at most 500 characters. Version 2 sends a payment content only when
/// there is a comment, so it may not be blank there; a version 1 card could carry none.
fn comment(body: &str, required: bool) -> Result<String, ChatCryptoError> {
    if body.chars().count() > MAX_COMMENT_CHARS {
        return Err(invalid("comment is too long"));
    }
    if required && body.trim().is_empty() {
        return Err(invalid("payment needs a comment of 1 to 500 characters"));
    }
    Ok(body.to_owned())
}

/// The base58 form of exactly `bytes` bytes. Base58 has one spelling per byte string, so
/// the text is returned as given.
fn base58(text: &str, bytes: usize, name: &str) -> Result<String, ChatCryptoError> {
    match bs58::decode(text).into_vec() {
        Ok(decoded) if decoded.len() == bytes => Ok(text.to_owned()),
        Ok(_) => Err(invalid(&format!("{name} is not {bytes} bytes"))),
        Err(_) => Err(invalid(&format!("{name} is not base58"))),
    }
}

/// `amount_base_units`, `mint` and `decimals`, in this order, after checking them.
fn put_amount(
    map: &mut Map<String, Value>,
    amount_base_units: i64,
    mint: &str,
    decimals: u8,
) -> Result<(), ChatCryptoError> {
    if amount_base_units < 1 {
        return Err(invalid("amount_base_units is 1 to 9223372036854775807"));
    }
    map.insert("amount_base_units".into(), Value::from(amount_base_units.to_string()));
    map.insert("mint".into(), Value::from(base58(mint, KEY_BYTES, "mint")?));
    map.insert("decimals".into(), Value::from(decimals));
    Ok(())
}

fn read_amount(map: &Map<String, Value>) -> Result<(i64, String, u8), ChatCryptoError> {
    let amount = amount(&required(map, "amount_base_units")?)?;
    let mint = base58(&required(map, "mint")?, KEY_BYTES, "mint")?;
    let decimals = match map.get("decimals") {
        Some(Value::Number(n)) => n.as_u64().and_then(|d| u8::try_from(d).ok()),
        _ => None,
    }
    .ok_or_else(|| invalid("decimals is a JSON integer from 0 to 255"))?;
    Ok((amount, mint, decimals))
}

/// Decimal digits only: no sign, no space, no leading zero, from 1 to `i64::MAX`.
fn amount(text: &str) -> Result<i64, ChatCryptoError> {
    let bad = || invalid("amount_base_units is a string of digits from 1 to 9223372036854775807");
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || text.starts_with('0') {
        return Err(bad());
    }
    text.parse::<i64>().map_err(|_| bad())
}

/// A note is left out when there is none.
fn put_note(map: &mut Map<String, Value>, note: &Option<String>) -> Result<(), ChatCryptoError> {
    if let Some(note) = note {
        map.insert("note".into(), Value::from(note_text(note)?));
    }
    Ok(())
}

/// Absent and `null` both read as no note; an empty or blank note is refused.
fn read_note(map: &Map<String, Value>) -> Result<Option<String>, ChatCryptoError> {
    optional(map, "note")?.map(|n| note_text(&n)).transpose()
}

fn note_text(note: &str) -> Result<String, ChatCryptoError> {
    if note.trim().is_empty() || note.chars().count() > MAX_NOTE_CHARS {
        return Err(invalid("note needs 1 to 500 characters, not blank"));
    }
    Ok(note.to_owned())
}

fn invalid(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidContent { reason: reason.to_owned() }
}

fn unsupported(reason: &str) -> ChatCryptoError {
    ChatCryptoError::UnsupportedContent { reason: reason.to_owned() }
}
