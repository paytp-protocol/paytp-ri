//! Canonical unsigned LEB128 (GAP-FILL **F1-a**).
//!
//! The whitepaper says "variable-length integer"; F1 pins it to LEB128 with a
//! strict canonicity rule: **the canonical encoding is the unique one for which
//! decode-then-re-encode is byte-identical.** Zero is exactly the single byte
//! `0x00`; a decoder MUST reject any overlong encoding (including a redundant
//! trailing `…0x80 0x00`) and any value exceeding 2³² − 1.
//!
//! Used for TLV lengths, list count-prefixes, and multi-object frame lengths.

use crate::error::{Error, Result};

/// The F1-a hard cap: LEB128 values never exceed 2³² − 1.
pub const MAX: u64 = u32::MAX as u64;

/// Encode `n` as canonical (minimal) LEB128, appending to `out`.
///
/// # Panics
/// Never for `n <= MAX`. Debug-asserts the caller respected the domain.
pub fn encode_into(n: u64, out: &mut Vec<u8>) {
    debug_assert!(n <= MAX, "leb128 value out of F1-a domain");
    let mut v = n;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Encode `n` as a fresh `Vec`.
pub fn encode(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(n, &mut out);
    out
}

/// Decode a canonical LEB128 from the front of `buf`.
///
/// Returns `(value, bytes_consumed)`. Rejects overlong encodings, values above
/// [`MAX`], and truncated input — canonicalization is validation, never repair.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0u64;
    let mut shift: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        // At most 5 groups can represent a value <= 2^32 - 1.
        if i >= 5 {
            return Err(Error::LebTooLarge);
        }
        let low = (b & 0x7f) as u64;
        result |= low << shift;
        if b & 0x80 == 0 {
            // Terminator. Canonicity: a non-first terminating byte whose 7-bit
            // group is zero is a redundant high group → overlong.
            if i > 0 && low == 0 {
                return Err(Error::LebOverlong);
            }
            if result > MAX {
                return Err(Error::LebTooLarge);
            }
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(Error::LebTruncated)
}

/// Decode expecting the varint to consume the entire slice (no trailing bytes).
pub fn decode_exact(buf: &[u8]) -> Result<u64> {
    let (v, n) = decode(buf)?;
    if n != buf.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_byte_identical() {
        // The canonicity definition: decode ∘ encode = identity on bytes.
        for n in [0u64, 1, 127, 128, 255, 256, 16384, MAX] {
            let enc = encode(n);
            let (v, used) = decode(&enc).unwrap();
            assert_eq!(v, n);
            assert_eq!(used, enc.len());
            assert_eq!(encode(v), enc);
        }
    }

    #[test]
    fn f10_accept_vectors() {
        // F10.3: accept 00, 7f, 80 01, ff ff ff ff 0f.
        assert_eq!(decode(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(decode(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap(), (MAX, 5));
    }

    #[test]
    fn f10_reject_vectors() {
        // F10.3: reject overlong 80 00; reject > 2^32-1.
        assert_eq!(decode(&[0x80, 0x00]), Err(Error::LebOverlong));
        // 2^32 = ff ff ff ff 1f -> value overruns u32.
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff, 0x1f]),
            Err(Error::LebTooLarge)
        );
        // A sixth continuation byte cannot fit the domain.
        assert_eq!(
            decode(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Err(Error::LebTooLarge)
        );
        // Redundant re-encoding of small values.
        assert_eq!(decode(&[0x81, 0x00]), Err(Error::LebOverlong)); // 1, overlong
        assert_eq!(decode(&[0xff, 0x00]), Err(Error::LebOverlong)); // 127, overlong
                                                                    // Truncated: continuation bit set with no follow-up.
        assert_eq!(decode(&[0x80]), Err(Error::LebTruncated));
    }

    #[test]
    fn decode_reports_consumed_and_leaves_trailing() {
        let (v, used) = decode(&[0x80, 0x01, 0xaa]).unwrap();
        assert_eq!((v, used), (128, 2));
        assert_eq!(decode_exact(&[0x80, 0x01, 0xaa]), Err(Error::TrailingBytes));
    }
}
