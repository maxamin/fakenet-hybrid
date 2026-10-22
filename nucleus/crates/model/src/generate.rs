//! Generating answers instead of replaying them: a byte-level Markov model of a key's text
//! answers produces new text with the same local statistics (its words, punctuation and
//! line structure), so a sample that compares answers sees variety, not a loop.
//!
//! - HTTP: the recorded status line and headers are kept; the body is generated and
//!   `Content-Length` set to match.
//! - Other text answers (line protocols, text C2): generated whole, ending like the recorded
//!   ones (`\r\n` or `\n`).
//! - Binary answers, and DNS (structured lines): replayed, never generated.

use std::collections::HashMap;

use crate::Rng;

/// Bytes of training text per model
const MAX_TRAINING: usize = 256 * 1024;
/// States (contexts) per model
const MAX_STATES: usize = 200_000;
/// Longest generated text
const MAX_GENERATED: usize = 16 * 1024;

/// Whether `data` is text worth modelling (nearly all printable ASCII or whitespace)
pub fn is_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(4096)];
    let printable = sample.iter().filter(|&&b| (0x20..0x7f).contains(&b) || b"\r\n\t".contains(&b)).count();
    printable * 100 >= sample.len() * 95
}

/// An order-k byte Markov model
#[derive(Debug, Default)]
pub struct TextModel {
    order: usize,
    /// context -> (next byte, count)
    next: HashMap<Vec<u8>, Vec<(u8, u32)>>,
    /// How texts start (the first `order` bytes of each)
    starts: Vec<Vec<u8>>,
    /// Shortest and longest training text, for the generated length
    lengths: (usize, usize),
}

impl TextModel {
    pub fn train(texts: &[&[u8]], order: usize) -> TextModel {
        let order = order.max(1);
        let mut model = TextModel { order, lengths: (usize::MAX, 0), ..TextModel::default() };
        let mut used = 0;
        for text in texts {
            if text.len() <= order || used >= MAX_TRAINING {
                continue;
            }
            let text = &text[..text.len().min(MAX_TRAINING - used)];
            used += text.len();
            model.lengths = (model.lengths.0.min(text.len()), model.lengths.1.max(text.len()));
            model.starts.push(text[..order].to_vec());
            for window in text.windows(order + 1) {
                let (context, byte) = (&window[..order], window[order]);
                if model.next.len() >= MAX_STATES && !model.next.contains_key(context) {
                    continue;
                }
                let options = model.next.entry(context.to_vec()).or_default();
                match options.iter_mut().find(|(b, _)| *b == byte) {
                    Some((_, count)) => *count += 1,
                    None => options.push((byte, 1)),
                }
            }
        }
        model
    }

    pub fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// New text: from a recorded start, one byte at a time by the observed frequencies, to a
    /// length between the shortest and longest training text (or until the chain ends)
    pub fn generate(&self, rng: &mut Rng) -> Vec<u8> {
        if self.starts.is_empty() {
            return Vec::new();
        }
        let (shortest, longest) = (self.lengths.0.min(MAX_GENERATED), self.lengths.1.min(MAX_GENERATED));
        let target = shortest + rng.below((longest - shortest + 1) as u64) as usize;
        let mut out = self.starts[rng.below(self.starts.len() as u64) as usize].clone();
        while out.len() < target {
            let Some(options) = self.next.get(&out[out.len() - self.order..]) else { break };
            let total: u64 = options.iter().map(|(_, c)| u64::from(*c)).sum();
            let mut point = rng.below(total);
            let mut chosen = options[0].0;
            for (byte, count) in options {
                if point < u64::from(*count) {
                    chosen = *byte;
                    break;
                }
                point -= u64::from(*count);
            }
            out.push(chosen);
        }
        out
    }
}

/// HTTP: (head without the blank line, body)
pub fn split_http(answer: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((&answer[..end], &answer[end + 4..]))
}

/// A recorded HTTP head with a new body (Content-Length replaced, chunking dropped)
pub fn http_with_body(head: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(b"content-length:") || lower.starts_with(b"transfer-encoding:") {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// A generated text, ended like the training texts: cut after the last complete line (when
/// they end with a newline) and given that newline
pub fn end_like(mut text: Vec<u8>, texts: &[&[u8]]) -> Vec<u8> {
    let ending: &[u8] = match texts.iter().all(|t| t.ends_with(b"\r\n")) {
        true => b"\r\n",
        false if texts.iter().all(|t| t.ends_with(b"\n")) => b"\n",
        false => return text,
    };
    if let Some(last) = text.windows(ending.len()).rposition(|w| w == ending) {
        text.truncate(last);
    }
    while text.ends_with(b"\r") || text.ends_with(b"\n") {
        text.pop();
    }
    text.extend_from_slice(ending);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_varied_text_with_the_recorded_vocabulary() {
        let texts: Vec<&[u8]> = vec![
            b"the update server is up to date and ready for the next check\n",
            b"the client is up to date; the server will check again later\n",
            b"no update is ready for the client at the moment, check later\n",
        ];
        let model = TextModel::train(&texts, 3);
        let mut rng = Rng::new(9);
        let mut outputs = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let text = end_like(model.generate(&mut rng), &texts);
            assert!(text.ends_with(b"\n"), "{:?}", String::from_utf8_lossy(&text));
            assert!(is_text(&text));
            // Every 4-byte window was seen in training
            for window in text[..text.len() - 1].windows(4) {
                assert!(texts.iter().any(|t| t.windows(4).any(|w| w == window)), "{:?}", String::from_utf8_lossy(window));
            }
            outputs.insert(text);
        }
        assert!(outputs.len() > 5, "only {} distinct answers", outputs.len());
        assert!(TextModel::train(&[b"ab"], 4).is_empty());
    }

    #[test]
    fn keeps_the_http_head_and_fixes_the_length() {
        let answer = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok";
        let (head, body) = split_http(answer).unwrap();
        assert_eq!(body, b"ok");
        let rebuilt = http_with_body(head, b"a new, longer body");
        assert!(rebuilt.starts_with(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 18\r\n\r\na new, longer body"));
        assert!(is_text(b"plain text\r\n") && !is_text(b"\x00\x01\x02binary") && !is_text(b""));
    }
}
