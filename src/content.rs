//! What travels inside the ciphertext. The two ids bind the content to its server row,
//! so a server can neither move a message to another conversation nor replay it.

use serde::{Deserialize, Serialize};

use crate::ChatCryptoError;

pub const CONTENT_VERSION: u32 = 1;
pub const MAX_BODY_CHARS: usize = 4000;
pub const MAX_REPLY_EXCERPT_CHARS: usize = 200;
pub const MAX_COMMENT_CHARS: usize = 500;

#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Text,
    Payment,
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
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u32,
    #[serde(flatten)]
    content: MessageContent,
}

pub(crate) fn encode(content: MessageContent) -> Result<String, ChatCryptoError> {
    validate(&content)?;
    serde_json::to_string(&Wire { v: CONTENT_VERSION, content }).map_err(|e| invalid(&e.to_string()))
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
    match content.kind {
        ContentKind::Text => {
            let body = content.body.as_deref().unwrap_or("");
            if body.trim().is_empty() || body.chars().count() > MAX_BODY_CHARS {
                return Err(invalid("text needs a body of 1 to 4000 characters"));
            }
            if content.comment.is_some() {
                return Err(invalid("text carries no comment"));
            }
        }
        ContentKind::Payment => {
            if content.body.is_some() || content.reply_excerpt.is_some() {
                return Err(invalid("payment carries only a comment"));
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
