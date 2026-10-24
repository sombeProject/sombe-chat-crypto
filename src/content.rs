//! What travels inside the ciphertext. The two ids bind the content to its server row,
//! so a server can neither move a message to another conversation nor replay it. Every
//! content is padded to a size bucket, so its length tells the server little.

use serde::{Deserialize, Serialize};

use crate::ChatCryptoError;

pub const CONTENT_VERSION: u32 = 1;
pub const MAX_BODY_CHARS: usize = 4000;
pub const MAX_REPLY_EXCERPT_CHARS: usize = 200;
pub const MAX_COMMENT_CHARS: usize = 500;
pub const MAX_REACTION_CHARS: usize = 16;
/// The smallest padded size, in bytes; larger contents are padded to the next power of two.
pub const MIN_PADDED_BYTES: usize = 256;
/// What the `pad` field adds around its spaces: `,"pad":""`.
const PAD_FIELD_BYTES: usize = 9;

#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Text,
    Payment,
    /// Replaces the body of an earlier text by the same sender (`edits_message_id`).
    Edit,
    /// One emoji set on a text (`reacts_to_message_id`).
    Reaction,
    /// Removes the sender's reaction from a text (`reacts_to_message_id`), since 0.3.0.
    ReactionRemove,
    /// Deletes one of the sender's texts for everyone (`deletes_message_id`), since 0.4.0.
    Delete,
}

#[derive(uniffi::Record, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MessageContent {
    pub conversation_id: String,
    pub client_message_id: String,
    pub kind: ContentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Server id of the text an `edit` corrects; absent for every other kind. Last, with a
    /// default, so positional constructors from 0.1.0 keep their meaning.
    #[uniffi(default = None)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edits_message_id: Option<String>,
    /// Server id of the text a `reaction` is set on; absent for every other kind. Added in
    /// 0.2.0 after `edits_message_id`, with a default, for the same reason.
    #[uniffi(default = None)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reacts_to_message_id: Option<String>,
    /// Server id of the text a `delete` removes; absent for every other kind. Added in
    /// 0.4.0 after `reacts_to_message_id`, with a default, for the same reason.
    #[uniffi(default = None)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletes_message_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    #[serde(flatten)]
    content: MessageContent,
    /// Spaces that bring the JSON to its size bucket; ignored when read (and absent
    /// before 0.3.0, whose phones ignore it in turn).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pad: Option<String>,
}

pub(crate) fn encode(content: MessageContent) -> Result<String, ChatCryptoError> {
    validate(&content)?;
    let mut wire = Wire { v: CONTENT_VERSION, content, pad: None };
    let unpadded = serde_json::to_string(&wire).map_err(|e| invalid(&e.to_string()))?.len();
    let target = (unpadded + PAD_FIELD_BYTES).max(MIN_PADDED_BYTES).next_power_of_two();
    wire.pad = Some(" ".repeat(target - unpadded - PAD_FIELD_BYTES));
    serde_json::to_string(&wire).map_err(|e| invalid(&e.to_string()))
}

pub(crate) fn decode(json: &str) -> Result<MessageContent, ChatCryptoError> {
    let wire: Wire = serde_json::from_str(json).map_err(|e| invalid(&e.to_string()))?;
    if wire.v != CONTENT_VERSION {
        return Err(invalid("unknown content version"));
    }
    validate(&wire.content)?;
    Ok(wire.content)
}

fn validate(content: &MessageContent) -> Result<(), ChatCryptoError> {
    if content.conversation_id.is_empty() || content.client_message_id.is_empty() {
        return Err(invalid("conversation_id and client_message_id are required"));
    }
    let names_reaction = matches!(content.kind, ContentKind::Reaction | ContentKind::ReactionRemove);
    if !names_reaction && content.reacts_to_message_id.is_some() {
        return Err(invalid("only a reaction or its removal names reacts_to_message_id"));
    }
    if content.kind != ContentKind::Delete && content.deletes_message_id.is_some() {
        return Err(invalid("only a delete names deletes_message_id"));
    }
    match content.kind {
        ContentKind::Text => {
            let body = content.body.as_deref().unwrap_or("");
            if body.trim().is_empty() || body.chars().count() > MAX_BODY_CHARS {
                return Err(invalid("text needs a body of 1 to 4000 characters"));
            }
            if content.comment.is_some() {
                return Err(invalid("text carries no comment"));
            }
            if content.edits_message_id.is_some() {
                return Err(invalid("only an edit names edits_message_id"));
            }
        }
        ContentKind::Reaction => {
            if content.reacts_to_message_id.as_deref().unwrap_or("").is_empty() {
                return Err(invalid("reaction needs reacts_to_message_id"));
            }
            let body = content.body.as_deref().unwrap_or("");
            let chars = body.chars().count();
            if chars == 0 || chars > MAX_REACTION_CHARS || body.chars().any(char::is_whitespace) {
                return Err(invalid("reaction needs one emoji of 1 to 16 characters, without space"));
            }
            if content.reply_excerpt.is_some()
                || content.comment.is_some()
                || content.edits_message_id.is_some()
            {
                return Err(invalid("reaction carries neither reply_excerpt, comment nor edits_message_id"));
            }
        }
        ContentKind::ReactionRemove => {
            if content.reacts_to_message_id.as_deref().unwrap_or("").is_empty() {
                return Err(invalid("reaction removal needs reacts_to_message_id"));
            }
            if content.body.is_some()
                || content.reply_excerpt.is_some()
                || content.comment.is_some()
                || content.edits_message_id.is_some()
            {
                return Err(invalid("reaction removal carries only reacts_to_message_id"));
            }
        }
        ContentKind::Delete => {
            if content.deletes_message_id.as_deref().unwrap_or("").is_empty() {
                return Err(invalid("delete needs deletes_message_id"));
            }
            if content.body.is_some()
                || content.reply_excerpt.is_some()
                || content.comment.is_some()
                || content.edits_message_id.is_some()
            {
                return Err(invalid("delete carries only deletes_message_id"));
            }
        }
        ContentKind::Edit => {
            if content.edits_message_id.as_deref().unwrap_or("").is_empty() {
                return Err(invalid("edit needs edits_message_id"));
            }
            let body = content.body.as_deref().unwrap_or("");
            if body.trim().is_empty() || body.chars().count() > MAX_BODY_CHARS {
                return Err(invalid("edit needs a body of 1 to 4000 characters"));
            }
            if content.reply_excerpt.is_some() || content.comment.is_some() {
                return Err(invalid("edit carries neither reply_excerpt nor comment"));
            }
        }
        ContentKind::Payment => {
            if content.body.is_some() || content.reply_excerpt.is_some() {
                return Err(invalid("payment carries only a comment"));
            }
            if content.edits_message_id.is_some() {
                return Err(invalid("only an edit names edits_message_id"));
            }
            if content.comment.as_deref().is_some_and(|c| c.chars().count() > MAX_COMMENT_CHARS) {
                return Err(invalid("comment is too long"));
            }
        }
    }
    if content.reply_excerpt.as_deref().is_some_and(|e| e.chars().count() > MAX_REPLY_EXCERPT_CHARS) {
        return Err(invalid("reply excerpt is longer than 200 characters"));
    }
    Ok(())
}

fn invalid(reason: &str) -> ChatCryptoError {
    ChatCryptoError::InvalidContent { reason: reason.to_owned() }
}
