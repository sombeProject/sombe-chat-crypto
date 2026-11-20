//! The RSA test keys (vectors/rfc9474-pss-randomized.json, a 4 096 bit key, and
//! vectors/alias-token-test-key.json, 2 048 bits) as DER, written by hand so a
//! test or the vectors tool can sign: the module itself never holds a private key.

use serde_json::Value;

pub fn rfc() -> Value {
    serde_json::from_str(include_str!("../../vectors/rfc9474-pss-randomized.json")).unwrap()
}

/// A 2 048 bit test key, the one the module's tests and v8.json use.
pub fn test_key() -> Value {
    serde_json::from_str(include_str!("../../vectors/alias-token-test-key.json")).unwrap()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(content.len()));
    out.extend_from_slice(content);
    out
}

fn int(hex: &str) -> Vec<u8> {
    let mut bytes = unhex(hex);
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// `SubjectPublicKeyInfo` with `rsaEncryption`, the form `ALIAS_TOKEN_PUBLIC_KEYS` holds.
pub fn spki(v: &Value) -> Vec<u8> {
    let key = seq(&[int(v["n"].as_str().unwrap()), int(v["e"].as_str().unwrap())]);
    let mut bits = vec![0u8];
    bits.extend(key);
    let algorithm = seq(&[tlv(0x06, &unhex("2a864886f70d010101")), vec![0x05, 0x00]]);
    seq(&[algorithm, tlv(0x03, &bits)])
}

/// `RSAPublicKey` (PKCS#1), a form the module refuses.
pub fn pkcs1_public(v: &Value) -> Vec<u8> {
    seq(&[int(v["n"].as_str().unwrap()), int(v["e"].as_str().unwrap())])
}

/// `RSAPrivateKey` (PKCS#1) of the test key.
pub fn pkcs1_private(v: &Value) -> Vec<u8> {
    let field = |name: &str| int(v[name].as_str().unwrap());
    seq(&[
        int("00"),
        field("n"),
        field("e"),
        field("d"),
        field("p"),
        field("q"),
        field("dp"),
        field("dq"),
        field("qi"),
    ])
}
