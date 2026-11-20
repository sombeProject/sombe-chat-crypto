//! Base64 for what goes through the APIs (since 0.11.0): the standard alphabet with padding,
//! one spelling only. vodozemac's codec writes without padding, so the vault, the alias
//! token and their memo use this one. Reading is strict: a text is accepted only if writing
//! the bytes it gives yields that very text.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn write(bytes: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                out.push(alphabet[((group >> (18 - 6 * i)) & 63) as usize] as char);
            } else if padded {
                out.push('=');
            }
        }
    }
    out
}

/// Standard alphabet, with padding.
pub(crate) fn encode(bytes: &[u8]) -> String {
    write(bytes, STANDARD, true)
}

/// URL safe alphabet, without padding (the memo of an alias token).
pub(crate) fn encode_url_no_pad(bytes: &[u8]) -> String {
    write(bytes, URL_SAFE, false)
}

/// The bytes of a canonical standard text with padding, or `None`.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let symbols = text.as_bytes();
    if !symbols.len().is_multiple_of(4) {
        return None;
    }
    let body = symbols.strip_suffix(b"==").or_else(|| symbols.strip_suffix(b"=")).unwrap_or(symbols);
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &symbol in body {
        let value = STANDARD.iter().position(|&s| s == symbol)? as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    (encode(&out) == text).then_some(out)
}

/// The bytes of `text` if it is canonical and exactly `size` bytes long.
pub(crate) fn decode_exact(text: &str, size: usize) -> Option<Vec<u8>> {
    if text.len() != size.div_ceil(3) * 4 {
        return None;
    }
    decode(text).filter(|bytes| bytes.len() == size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        for (clear, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(clear.as_bytes()), text);
            assert_eq!(decode(text).as_deref(), Some(clear.as_bytes()));
        }
    }

    #[test]
    fn only_the_canonical_spelling_reads() {
        for bad in [
            "Zg",       // no padding
            "Zg=",      // short padding
            "Zh==",     // non zero trailing bits
            "Zm8=Zm8=", // padding in the middle
            "Zm9v\n", "Zm9 v", "Zm9-", // URL alphabet
            "=Zm9", "Zm9v====",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn exact_size_and_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_exact(&encode(&all), 256).as_deref(), Some(all.as_slice()));
        assert_eq!(decode_exact(&encode(&all), 255), None);
        assert_eq!(decode_exact(&encode(&all[..255]), 256), None);
    }

    #[test]
    fn url_safe_without_padding() {
        assert_eq!(encode_url_no_pad(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(encode_url_no_pad(&[0xfb]), "-w");
        assert_eq!(encode_url_no_pad(&[0u8; 32]).len(), 43);
    }
}
