//! Decoding steps for C2 payloads, shared by `--decode`, `--learn --transform` (keying
//! encoded requests by their decoded content) and `model` responders (`key_transforms`,
//! which must match what the model was learned with): base64, hex, xor:KEY, rc4:KEY, skip:N.

use anyhow::{bail, Context as _};

/// One step of `--decode`
#[derive(Debug, Clone, PartialEq)]
pub enum Transform {
    Base64,
    Hex,
    Xor(Vec<u8>),
    Rc4(Vec<u8>),
    /// Drop a header of N bytes
    Skip(usize),
}

/// `base64`, `hex`, `xor:KEY`, `rc4:KEY` (KEY as hex, or `text:...`), `skip:N`
pub fn parse_transform(text: &str) -> anyhow::Result<Transform> {
    let key = |value: &str| -> anyhow::Result<Vec<u8>> {
        let key = match value.strip_prefix("text:") {
            Some(text) => text.as_bytes().to_vec(),
            None => (0..value.len()).step_by(2).map(|i| value.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect::<Option<Vec<u8>>>().filter(|_| value.len() % 2 == 0).context("the key must be hex (e.g. 2a or deadbeef) or text:...")?,
        };
        if key.is_empty() {
            bail!("empty key");
        }
        Ok(key)
    };
    Ok(match text.split_once(':') {
        None if text == "base64" => Transform::Base64,
        None if text == "hex" => Transform::Hex,
        Some(("xor", value)) => Transform::Xor(key(value)?),
        Some(("rc4", value)) => Transform::Rc4(key(value)?),
        Some(("skip", value)) => Transform::Skip(value.parse().context("skip:N needs a number")?),
        _ => bail!("unknown transform {text} (base64, hex, xor:KEY, rc4:KEY, skip:N)"),
    })
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

pub fn apply(transforms: &[Transform], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut data = data.to_vec();
    for transform in transforms {
        data = match transform {
            Transform::Base64 => {
                let text: String = String::from_utf8_lossy(&data).chars().filter(|c| !c.is_whitespace()).collect();
                fakenet_schema::decode_base64(&text).context("not base64")?
            }
            Transform::Hex => {
                let text: Vec<u8> = data.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
                if text.len() % 2 != 0 {
                    bail!("odd number of hex digits");
                }
                text.chunks(2).map(|pair| std::str::from_utf8(pair).ok().and_then(|h| u8::from_str_radix(h, 16).ok())).collect::<Option<Vec<u8>>>().context("not hex")?
            }
            Transform::Xor(key) => data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect(),
            Transform::Rc4(key) => rc4(key, &data),
            Transform::Skip(n) => data.get(*n..).unwrap_or_default().to_vec(),
        };
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transforms_chain_and_match_published_vectors() {
        // RC4 test vector (Key = "Key", Plaintext = "Plaintext")
        let hex: String = rc4(b"Key", b"Plaintext").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "bbf316e8d940af0ad3");
        let steps = [parse_transform("skip:2").unwrap(), parse_transform("xor:text:K").unwrap()];
        let encoded: Vec<u8> = b"HDhello".iter().enumerate().map(|(i, b)| if i < 2 { *b } else { b ^ b'K' }).collect();
        assert_eq!(apply(&steps, &encoded).unwrap(), b"hello");
        assert!(parse_transform("nope").is_err());
    }
}
