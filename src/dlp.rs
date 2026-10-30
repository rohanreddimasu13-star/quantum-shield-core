//! Optional textual response-body DLP helpers.
//!
//! These helpers are not attached to the proxy's response path: rewriting compressed,
//! binary, signed, or length-sensitive payloads without a content-encoding adapter can
//! corrupt responses. Integrate only after response content-type/encoding is validated.

#![allow(dead_code)]

use bytes::BytesMut;
use regex::Regex;
use std::sync::OnceLock;

const MAX_DLP_BYTES: usize = 16 * 1024 * 1024;
const CC_REGEX: &str = r"\b(?:\d[ -]?){15}\d\b";
const STACK_REGEX: &str = r"(?i)Internal\s+Server\s+Error";
const SQL_REGEX: &str = r"(?i)SQL\s+STATE\s+\[\d{4,5}\]";

fn cc_regex() -> &'static Regex {
    static INSTANCE: OnceLock<Regex> = OnceLock::new();
    INSTANCE.get_or_init(|| Regex::new(CC_REGEX).expect("valid credit-card pattern"))
}
fn stack_regex() -> &'static Regex {
    static INSTANCE: OnceLock<Regex> = OnceLock::new();
    INSTANCE.get_or_init(|| Regex::new(STACK_REGEX).expect("valid stack-trace pattern"))
}
fn sql_regex() -> &'static Regex {
    static INSTANCE: OnceLock<Regex> = OnceLock::new();
    INSTANCE.get_or_init(|| Regex::new(SQL_REGEX).expect("valid SQL-state pattern"))
}

pub fn scrub_credit_cards(input: &str) -> String {
    cc_regex().replace_all(input, "[REDACTED-CARD]").to_string()
}

pub fn scrub_stack_traces(input: &str) -> String {
    stack_regex().replace_all(input, "[REDACTED]").to_string()
}

pub fn scrub_sql_state(input: &str) -> String {
    sql_regex()
        .replace_all(input, "[SQL-STATE REDACTED]")
        .to_string()
}

pub fn transform_body(body: BytesMut) -> BytesMut {
    #[cfg(not(feature = "dlp"))]
    {
        return body;
    }

    #[cfg(feature = "dlp")]
    {
        if body.len() > MAX_DLP_BYTES || std::str::from_utf8(&body).is_err() {
            return body;
        }
        let text = std::str::from_utf8(&body).expect("UTF-8 checked above");
        let result = scrub_sql_state(&scrub_stack_traces(&scrub_credit_cards(text)));
        BytesMut::from(result.as_bytes())
    }
}

/// Decode HTTP content codings (`gzip`, `deflate`, `identity`) before DLP
/// inspection. Decoding is bounded to `MAX_DLP_BYTES` so a compressed bomb
/// cannot exhaust memory; unknown codings fail closed.
#[cfg(feature = "dlp")]
pub fn decode_content_encoded(encoded: &[u8], header: &str) -> anyhow::Result<BytesMut> {
    use std::io::Read;

    fn read_bounded<R: Read>(mut reader: R) -> anyhow::Result<Vec<u8>> {
        let mut output = Vec::new();
        reader
            .by_ref()
            .take(MAX_DLP_BYTES as u64 + 1)
            .read_to_end(&mut output)?;
        if output.len() > MAX_DLP_BYTES {
            anyhow::bail!("decoded response body exceeds DLP inspection limit");
        }
        Ok(output)
    }

    let mut data = encoded.to_vec();
    let codings: Vec<&str> = header
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    if codings.is_empty() {
        anyhow::bail!("empty Content-Encoding header");
    }
    for coding in codings.iter().rev() {
        let lower = coding.to_ascii_lowercase();
        data = match lower.as_str() {
            "identity" => data,
            "gzip" | "x-gzip" => read_bounded(flate2::read::GzDecoder::new(&data[..]))?,
            "deflate" | "zlib" => {
                match read_bounded(flate2::read::ZlibDecoder::new(&data[..])) {
                    Ok(decoded) => decoded,
                    // Some servers send raw DEFLATE despite the HTTP spelling.
                    Err(_) => read_bounded(flate2::read::DeflateDecoder::new(&data[..]))?,
                }
            }
            other => anyhow::bail!("unsupported Content-Encoding {other}"),
        };
    }
    Ok(BytesMut::from(&data[..]))
}

/// Read from a Tokio async reader with a strict byte limit; only UTF-8 text is redacted.
pub async fn transform_body_async<R>(reader: &mut R) -> anyhow::Result<BytesMut>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buffer = BytesMut::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        if buffer.len().saturating_add(count) > MAX_DLP_BYTES {
            anyhow::bail!("response body exceeds DLP inspection limit");
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
    Ok(transform_body(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_credit_card_format() {
        let out = scrub_credit_cards("Card: 1234 5678 9012 3456");
        assert!(out.contains("[REDACTED-CARD]"));
        assert!(!out.contains("1234 5678 9012 3456"));
    }

    #[test]
    fn scrubs_stack_trace_marker_and_sql_state() {
        assert!(
            !scrub_stack_traces("Internal Server Error at node:internal/modules")
                .contains("Internal Server Error")
        );
        assert!(!scrub_sql_state("SQL STATE [42000] error").contains("SQL STATE"));
    }

    #[test]
    fn default_feature_is_passthrough() {
        #[cfg(not(feature = "dlp"))]
        assert_eq!(&*transform_body(BytesMut::from(&b"hello"[..])), b"hello");
    }

    #[test]
    fn feature_does_not_corrupt_binary_bytes() {
        #[cfg(feature = "dlp")]
        assert_eq!(
            &*transform_body(BytesMut::from(&[0, 1, 255][..])),
            &[0, 1, 255]
        );
    }

    #[cfg(feature = "dlp")]
    #[test]
    fn decodes_gzip_and_deflate_content_codings() {
        use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
        use flate2::Compression;
        use std::io::Write;

        for coding in ["gzip", "deflate", "zlib", "identity"] {
            let encoded = match coding {
                "gzip" => {
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(b"inspect me").unwrap();
                    encoder.finish().unwrap()
                }
                "deflate" => {
                    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(b"inspect me").unwrap();
                    encoder.finish().unwrap()
                }
                "zlib" => {
                    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(b"inspect me").unwrap();
                    encoder.finish().unwrap()
                }
                _ => b"inspect me".to_vec(),
            };
            let decoded = decode_content_encoded(&encoded, coding).expect("decode fixture");
            assert_eq!(&decoded[..], b"inspect me", "coding {coding}");
        }
    }

    #[cfg(feature = "dlp")]
    #[test]
    fn rejects_decompression_bombs_and_unknown_codings() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut bomb = vec![b'A'; MAX_DLP_BYTES + 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&bomb).unwrap();
        let encoded = encoder.finish().unwrap();
        bomb.clear();
        assert!(
            decode_content_encoded(&encoded, "gzip").is_err(),
            "decompression must be bounded by the DLP inspection limit"
        );
        assert!(decode_content_encoded(b"data", "br").is_err());
        assert!(decode_content_encoded(b"data", "").is_err());
    }
}
