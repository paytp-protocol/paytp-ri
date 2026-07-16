//! TLV encoding and canonical form (**F1.1**, formalizing §5.2).
//!
//! Each field is `type ‖ length ‖ value`:
//! - **type**: one byte; top bit `0x80` is the critical flag, low 7 bits the
//!   type number. Duplicate detection is by type number (so `0x01` and `0x81`
//!   cannot both appear).
//! - **length**: canonical LEB128 ([`crate::leb128`]).
//! - **value**: `length` bytes.
//!
//! Canonical form: fields sorted by type number ascending, no duplicate type
//! numbers, minimal-length integers, per-field domains (F1-l). A parser MUST
//! reject any deviation — canonicalization is validation, never repair.

use crate::error::{Error, Result};
use crate::leb128;
use num_bigint::{BigInt, BigUint};
use std::collections::BTreeMap;

/// One decoded TLV field, in canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The 7-bit type number (the critical flag is stored separately).
    pub type_num: u8,
    /// The critical flag (top bit of the type byte).
    pub critical: bool,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

impl Field {
    pub fn new(type_num: u8, critical: bool, value: Vec<u8>) -> Self {
        debug_assert!(type_num < 0x80, "type number is 7 bits");
        Field {
            type_num,
            critical,
            value,
        }
    }

    /// The single type byte on the wire.
    fn type_byte(&self) -> u8 {
        self.type_num | if self.critical { 0x80 } else { 0x00 }
    }

    /// Append this field's canonical `type ‖ length ‖ value` bytes.
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.type_byte());
        leb128::encode_into(self.value.len() as u64, out);
        out.extend_from_slice(&self.value);
    }

    /// Is this field an authenticator, excluded from covered bytes (F1-i)?
    ///
    /// Type numbers `0x70`–`0x7F` are the reserved authenticator range in every
    /// object registry. A specific object may declare one further exception
    /// (the slice's `TAG` at `0x02`, §5.3) via `extra`.
    fn is_authenticator(&self, extra: &[u8]) -> bool {
        (0x70..=0x7f).contains(&self.type_num) || extra.contains(&self.type_num)
    }
}

/// A canonical TLV object: fields strictly ascending by type number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Object {
    fields: Vec<Field>,
}

impl Object {
    /// Build from fields given in any order; sorts and validates canonicity
    /// (no duplicate type numbers). Encoders use this.
    pub fn from_fields(mut fields: Vec<Field>) -> Result<Self> {
        fields.sort_by_key(|f| f.type_num);
        for w in fields.windows(2) {
            if w[0].type_num == w[1].type_num {
                return Err(Error::DuplicateType);
            }
        }
        Ok(Object { fields })
    }

    /// Parse canonical TLV bytes, enforcing every F1.1 structural rule:
    /// ascending order, no duplicates, canonical lengths, no overrun, no
    /// trailing bytes. Does *not* apply a criticality/openness schema — call
    /// [`Object::validate`] for that.
    pub fn parse(mut buf: &[u8]) -> Result<Self> {
        let mut fields: Vec<Field> = Vec::new();
        while !buf.is_empty() {
            let type_byte = buf[0];
            let critical = type_byte & 0x80 != 0;
            let type_num = type_byte & 0x7f;
            let (len, len_used) = leb128::decode(&buf[1..])?;
            let value_start = 1 + len_used;
            let value_end = value_start
                .checked_add(len as usize)
                .ok_or(Error::LengthOverrun)?;
            if value_end > buf.len() {
                return Err(Error::LengthOverrun);
            }
            let value = buf[value_start..value_end].to_vec();

            if let Some(prev) = fields.last() {
                if type_num == prev.type_num {
                    return Err(Error::DuplicateType);
                }
                if type_num < prev.type_num {
                    return Err(Error::TypeOrder);
                }
            }
            fields.push(Field {
                type_num,
                critical,
                value,
            });
            buf = &buf[value_end..];
        }
        Ok(Object { fields })
    }

    /// The canonical wire bytes of the whole object (every field included).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.fields {
            f.encode_into(&mut out);
        }
        out
    }

    /// The covered bytes for signing/tagging (F1.1 coverage, F1-i): every
    /// non-authenticator field's canonical TLV bytes, concatenated. `extra`
    /// names authenticator type numbers beyond the reserved `0x70`–`0x7F`
    /// range (the slice's `0x02 TAG` is the one §5.3 case).
    pub fn covered_bytes(&self, extra: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.fields {
            if !f.is_authenticator(extra) {
                f.encode_into(&mut out);
            }
        }
        out
    }

    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Look up a field by type number.
    pub fn get(&self, type_num: u8) -> Option<&Field> {
        self.fields.iter().find(|f| f.type_num == type_num)
    }

    /// Apply a criticality/openness schema (F1.1 rule 6, F1-i, F1-k).
    ///
    /// - a known field carried with the wrong critical flag → `WrongCriticality`;
    /// - an unknown type in the authenticator range `0x70`–`0x7F` → reject (F1-i);
    /// - an unknown *critical* type → reject (F1.1);
    /// - an unknown non-critical type in a [`Openness::Closed`] object → reject (F1-k);
    /// - an unknown non-critical type in an [`Openness::Open`] object → allowed
    ///   (ignored but still covered content, F1-i).
    pub fn validate(&self, schema: &Schema) -> Result<()> {
        for f in &self.fields {
            match schema.known.get(&f.type_num) {
                Some(spec) => {
                    if spec.critical != f.critical {
                        return Err(Error::WrongCriticality);
                    }
                }
                None => {
                    if (0x70..=0x7f).contains(&f.type_num) {
                        return Err(Error::UnknownAuthenticator);
                    }
                    if f.critical {
                        return Err(Error::UnknownCritical);
                    }
                    if schema.openness == Openness::Closed {
                        return Err(Error::UnexpectedType);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Whether an object admits unknown non-critical extension fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Openness {
    /// Unknown non-critical types are ignored-but-covered (the general rule).
    Open,
    /// Every type must be known — the slice (F1-k) and other fixed objects.
    Closed,
}

/// The declared criticality of one known field.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub critical: bool,
}

/// A per-object criticality/openness schema for [`Object::validate`].
#[derive(Debug, Clone)]
pub struct Schema {
    pub openness: Openness,
    pub known: BTreeMap<u8, FieldSpec>,
}

impl Schema {
    /// Build from `(type_num, critical)` pairs.
    pub fn new(openness: Openness, fields: &[(u8, bool)]) -> Self {
        Schema {
            openness,
            known: fields
                .iter()
                .map(|&(t, c)| (t, FieldSpec { critical: c }))
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Integer value codecs (F1.1 rules 3/4)
// ---------------------------------------------------------------------------

/// Validate that `bytes` is a minimal-length unsigned big-endian integer:
/// non-empty, and no leading `0x00` unless the value is exactly the single
/// byte `0x00` (F1.1 rule 3).
pub fn validate_minimal_uint(bytes: &[u8]) -> Result<()> {
    match bytes {
        [] => Err(Error::NonMinimalInt), // empty/zero-length integer rejected
        [0x00] => Ok(()),                // canonical zero
        [0x00, ..] => Err(Error::NonMinimalInt), // leading zero
        _ => Ok(()),
    }
}

/// Decode a minimal unsigned big-endian integer as a [`BigUint`] (F7's exact
/// domain). Rejects non-minimal encodings.
pub fn decode_uint_biguint(bytes: &[u8]) -> Result<BigUint> {
    validate_minimal_uint(bytes)?;
    Ok(BigUint::from_bytes_be(bytes))
}

/// Decode a minimal unsigned integer, requiring it fit `u128` (the µ-unit
/// value domain, F1-l).
pub fn decode_uint_u128(bytes: &[u8]) -> Result<u128> {
    let v = decode_uint_biguint(bytes)?;
    u128::try_from(v).map_err(|_| Error::FieldDomain)
}

/// Decode a minimal unsigned integer that MUST fit `u64` — a value larger than
/// `u64::MAX` (even though minimally encoded and a valid `u128`) is a field-domain
/// error, never a silent truncation. Used for `u64` wire fields (timestamps,
/// validity bounds, amounts) so a mutated oversized encoding cannot re-narrow to a
/// different signed/sealed value.
pub fn decode_uint_u64(bytes: &[u8]) -> Result<u64> {
    let v = decode_uint_biguint(bytes)?;
    u64::try_from(v).map_err(|_| Error::FieldDomain)
}

/// Decode a minimal unsigned integer that MUST fit `u32` (schema/version/registry
/// ids). Oversized values are a field-domain error, never truncated.
pub fn decode_uint_u32(bytes: &[u8]) -> Result<u32> {
    let v = decode_uint_biguint(bytes)?;
    u32::try_from(v).map_err(|_| Error::FieldDomain)
}

/// Decode a minimal unsigned **time/duration** field, enforcing the F1-l time
/// domain (≤ 2⁵³ − 1, the IEEE-safe integer bound). A value in (2⁵³, 2⁶⁴ − 1] —
/// though a valid `u64` — is a field-domain error, never accepted: the time fields
/// (`TIMESTAMP`, `TH_TIME`, the artifact's `NOT_BEFORE`/`NOT_AFTER`, registry
/// `ISSUED`) carry the tighter [`Domain::Time`] cap, not the raw `u64` range, so
/// every F8 window sum a builder forms stays overflow-safe and two implementations
/// cannot diverge on an out-of-domain time. (`RATE_TIME`/`RATE_EXP`/`RATE_GRACE`
/// are F1-l time fields too, but appear only on the off-baseline path, F5-p.)
pub fn decode_uint_time(bytes: &[u8]) -> Result<u64> {
    let v = decode_uint_biguint(bytes)?;
    check_domain(&v, Domain::Time)?;
    // ≤ 2⁵³ − 1 fits u64 by construction — the domain check above is the binding bound.
    u64::try_from(v).map_err(|_| Error::FieldDomain)
}

/// Encode `v` as a minimal unsigned big-endian integer (zero → `0x00`).
pub fn encode_uint_u128(v: u128) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let be = v.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

/// Encode a [`BigUint`] as a minimal unsigned big-endian integer.
pub fn encode_uint_biguint(v: &BigUint) -> Vec<u8> {
    if v == &BigUint::from(0u8) {
        return vec![0x00];
    }
    v.to_bytes_be()
}

/// Encode a minimal two's-complement signed integer (GAP-FILL F1-b): the
/// shortest encoding that preserves the sign bit. Operates over [`BigInt`], so
/// the full signed-balance domain (magnitude to 2¹²⁸ − 1, F1-b/F1-l — a `+2¹²⁷`
/// needs a 17-byte canonical encoding) is representable, not just `i128`.
pub fn encode_sint(n: &BigInt) -> Vec<u8> {
    use num_bigint::Sign;
    match n.sign() {
        Sign::NoSign => vec![0x00],
        Sign::Plus => {
            let mut be = n.to_bytes_be().1;
            // Sign guard: a positive value whose top bit is set needs a 0x00 prefix.
            if be[0] & 0x80 != 0 {
                be.insert(0, 0x00);
            }
            be
        }
        Sign::Minus => {
            // Smallest k with n >= -2^(8k-1); two's complement is 2^(8k) + n.
            let mut k = 1usize;
            loop {
                let low = -(BigInt::from(1) << (8 * k - 1));
                if n >= &low {
                    let modulus = BigInt::from(1) << (8 * k);
                    let tc = (&modulus + n).to_bytes_be().1; // top bit set, exactly k bytes
                    let mut out = tc;
                    while out.len() < k {
                        out.insert(0, 0x00);
                    }
                    return out;
                }
                k += 1;
            }
        }
    }
}

/// Decode a minimal two's-complement signed integer (F1-b) as a [`BigInt`],
/// rejecting non-minimal encodings (a redundant leading `0x00`/`0xFF`).
pub fn decode_sint(bytes: &[u8]) -> Result<BigInt> {
    if bytes.is_empty() {
        return Err(Error::NonMinimalSignedInt);
    }
    // Minimality: reject a leading byte that only duplicates the sign of the next.
    if bytes.len() >= 2 {
        let redundant_zero = bytes[0] == 0x00 && bytes[1] & 0x80 == 0;
        let redundant_ff = bytes[0] == 0xff && bytes[1] & 0x80 != 0;
        if redundant_zero || redundant_ff {
            return Err(Error::NonMinimalSignedInt);
        }
    }
    let mag = BigInt::from_bytes_be(num_bigint::Sign::Plus, bytes);
    if bytes[0] & 0x80 != 0 {
        // Negative: subtract 2^(8*len).
        Ok(mag - (BigInt::from(1) << (8 * bytes.len())))
    } else {
        Ok(mag)
    }
}

/// Encode a signed integer from an `i128` (convenience over [`encode_sint`]).
pub fn encode_sint_i128(v: i128) -> Vec<u8> {
    encode_sint(&BigInt::from(v))
}

/// Decode a signed integer requiring it fit `i128` (convenience over
/// [`decode_sint`]); a wider value is a domain error.
pub fn decode_sint_i128(bytes: &[u8]) -> Result<i128> {
    use num_traits::ToPrimitive;
    decode_sint(bytes)?.to_i128().ok_or(Error::FieldDomain)
}

// ---------------------------------------------------------------------------
// Count-prefixed lists (F1.1 rule 2)
// ---------------------------------------------------------------------------

/// Build a count-prefixed list value: `count (LEB128) ‖ items…` (F1.1 rule 2).
pub fn build_count_prefixed(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    leb128::encode_into(items.len() as u64, &mut out);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Parse a count-prefixed list. `parse_item` consumes one item from the front
/// of the remaining bytes and returns `(item, bytes_consumed)`. The count MUST
/// consume the value exactly (F1.1 rule 2).
pub fn parse_count_prefixed<T>(
    value: &[u8],
    mut parse_item: impl FnMut(&[u8]) -> Result<(T, usize)>,
) -> Result<Vec<T>> {
    let (count, used) = leb128::decode(value)?;
    let mut rest = &value[used..];
    // Bound the pre-allocation by the remaining bytes: every item consumes at least
    // one byte, so a hostile count far larger than the value can never allocate more
    // than `rest.len()` slots (no OOM/panic on a forged huge count).
    let mut out = Vec::with_capacity((count as usize).min(rest.len()));
    for _ in 0..count {
        let (item, n) = parse_item(rest)?;
        if n == 0 || n > rest.len() {
            return Err(Error::CountMismatch);
        }
        out.push(item);
        rest = &rest[n..];
    }
    if !rest.is_empty() {
        return Err(Error::CountMismatch); // count did not consume value exactly
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Multi-object framing (GAP-FILL F1-j)
// ---------------------------------------------------------------------------

/// Frame a multi-object body (GAP-FILL F1-j): each object is
/// `frame_length (canonical LEB128, the object's total byte count) ‖ object bytes`,
/// repeated. The frame length is *outer and additional to* the objects' own
/// type/length bytes, so boundaries survive malformed/extended/future objects.
pub fn frame_objects(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for obj in objects {
        leb128::encode_into(obj.len() as u64, &mut out);
        out.extend_from_slice(obj);
    }
    out
}

/// Parse a framed multi-object body (F1-j), validating each framed object with
/// `validate`. The whole body is rejected on any fault — a bad frame length, a
/// length overrunning the remaining bytes, trailing bytes that cannot form a
/// frame, **or any framed object that fails validation** (partial acceptance of
/// a multi-object body is itself a divergence surface, so there is none).
/// Bare back-to-back TLV objects with no frame lengths are not a valid body and
/// are rejected here (their first byte is read as a frame length and mis-slices).
pub fn parse_frames(
    body: &[u8],
    mut validate: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Vec<Vec<u8>>> {
    let mut rest = body;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (len, used) = leb128::decode(rest).map_err(|_| Error::Framing)?;
        let start = used;
        let end = start.checked_add(len as usize).ok_or(Error::Framing)?;
        if end > rest.len() {
            return Err(Error::Framing); // frame length overruns remaining bytes
        }
        let obj = &rest[start..end];
        validate(obj).map_err(|_| Error::Framing)?; // whole-body reject
        out.push(obj.to_vec());
        rest = &rest[end..];
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Field domains (F1-l)
// ---------------------------------------------------------------------------

/// The three per-field integer domains F1-l defines. Every PayTP TLV integer
/// field belongs to exactly one; a value above its domain is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Time and duration fields: ≤ 2⁵³ − 1 (IEEE-safe).
    Time,
    /// µ-unit value fields (limits, amounts, balances by magnitude): ≤ 2¹²⁸ − 1.
    Value,
    /// Identifier / version / basis-point fields: ≤ 2³² − 1.
    Id,
}

impl Domain {
    pub fn max(self) -> BigUint {
        match self {
            Domain::Time => BigUint::from((1u64 << 53) - 1),
            Domain::Value => (BigUint::from(1u8) << 128u32) - 1u8,
            Domain::Id => BigUint::from(u32::MAX),
        }
    }
}

/// Reject a value that exceeds its field domain (F1-l).
pub fn check_domain(value: &BigUint, domain: Domain) -> Result<()> {
    if value > &domain.max() {
        Err(Error::FieldDomain)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Text values (F1-g)
// ---------------------------------------------------------------------------

/// Validate a signed-text value (GAP-FILL F1-g): UTF-8, NFC-normalized, no BOM,
/// no NUL or other C0/C1 control character. Non-conforming text is rejected,
/// never normalized. IDNA/PSL host rules are F2's (M1).
pub fn validate_text(bytes: &[u8]) -> Result<&str> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::TextNotUtf8)?;
    for ch in s.chars() {
        // U+FEFF BOM anywhere, and any C0 (U+0000–U+001F) / C1 (U+0080–U+009F).
        if ch == '\u{FEFF}' {
            return Err(Error::TextNotNfc);
        }
        let c = ch as u32;
        if c <= 0x1f || (0x80..=0x9f).contains(&c) {
            return Err(Error::TextControlChar);
        }
    }
    use unicode_normalization::UnicodeNormalization;
    if s.nfc().collect::<String>() != s {
        return Err(Error::TextNotNfc);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encode_roundtrip_canonical() {
        let obj = Object::from_fields(vec![
            Field::new(0x01, false, vec![0xaa]),
            Field::new(0x00, false, vec![0x01, 0x02]),
        ])
        .unwrap();
        let bytes = obj.encode();
        // Canonical: 0x00 first, then 0x01.
        assert_eq!(bytes, vec![0x00, 0x02, 0x01, 0x02, 0x01, 0x01, 0xaa]);
        assert_eq!(Object::parse(&bytes).unwrap(), obj);
    }

    #[test]
    fn reject_out_of_order_and_duplicate() {
        // 0x01 before 0x00 → out of order.
        assert_eq!(
            Object::parse(&[0x01, 0x01, 0xaa, 0x00, 0x01, 0xbb]),
            Err(Error::TypeOrder)
        );
        // 0x01 twice → duplicate (this is also the "0x01 + 0x81" case: same type_num).
        assert_eq!(
            Object::parse(&[0x01, 0x01, 0xaa, 0x81, 0x01, 0xbb]),
            Err(Error::DuplicateType)
        );
    }

    #[test]
    fn reject_length_overrun_and_trailing() {
        // length says 5 but only 1 byte follows.
        assert_eq!(
            Object::parse(&[0x00, 0x05, 0xaa]),
            Err(Error::LengthOverrun)
        );
    }

    #[test]
    fn wrong_critical_flag_rejected() {
        // 0x00 defined non-critical, presented critical (0x80).
        let schema = Schema::new(Openness::Open, &[(0x00, false)]);
        let obj = Object::parse(&[0x80, 0x01, 0xaa]).unwrap();
        assert_eq!(obj.validate(&schema), Err(Error::WrongCriticality));
    }

    #[test]
    fn unknown_critical_and_authenticator_rejected() {
        let schema = Schema::new(Openness::Open, &[(0x00, false)]);
        // Unknown critical type 0x05.
        let obj = Object::parse(&[0x85, 0x00]).unwrap();
        assert_eq!(obj.validate(&schema), Err(Error::UnknownCritical));
        // Unknown authenticator-range type 0x71.
        let obj = Object::parse(&[0x71, 0x00]).unwrap();
        assert_eq!(obj.validate(&schema), Err(Error::UnknownAuthenticator));
        // Unknown non-critical 0x05 is allowed in an Open object (covered content).
        let obj = Object::parse(&[0x05, 0x00]).unwrap();
        assert!(obj.validate(&schema).is_ok());
    }

    #[test]
    fn coverage_excludes_authenticators_includes_unknown_noncritical() {
        // Object: 0x00 (content), 0x05 (unknown non-critical, covered), 0x70 (authenticator).
        let obj = Object::from_fields(vec![
            Field::new(0x00, false, vec![0x01]),
            Field::new(0x05, false, vec![0x02]),
            Field::new(0x70, false, vec![0x03]),
        ])
        .unwrap();
        let covered = obj.covered_bytes(&[]);
        // Should contain 0x00 and 0x05 fields, not 0x70.
        assert_eq!(covered, vec![0x00, 0x01, 0x01, 0x05, 0x01, 0x02]);
    }

    #[test]
    fn minimal_uint() {
        assert_eq!(encode_uint_u128(0), vec![0x00]);
        assert_eq!(encode_uint_u128(1), vec![0x01]);
        assert_eq!(encode_uint_u128(256), vec![0x01, 0x00]);
        assert_eq!(decode_uint_u128(&[0x01, 0x00]).unwrap(), 256);
        // reject leading zero and empty
        assert_eq!(decode_uint_u128(&[0x00, 0x01]), Err(Error::NonMinimalInt));
        assert_eq!(decode_uint_u128(&[]), Err(Error::NonMinimalInt));
    }

    #[test]
    fn minimal_sint() {
        // F10.3: accept ff = -1, 80 = -128, 00 80 = +128; reject ff ff for -1.
        assert_eq!(decode_sint_i128(&[0xff]).unwrap(), -1);
        assert_eq!(decode_sint_i128(&[0x80]).unwrap(), -128);
        assert_eq!(decode_sint_i128(&[0x00, 0x80]).unwrap(), 128);
        assert_eq!(
            decode_sint_i128(&[0xff, 0xff]),
            Err(Error::NonMinimalSignedInt)
        );
        assert_eq!(encode_sint_i128(-1), vec![0xff]);
        assert_eq!(encode_sint_i128(-128), vec![0x80]);
        assert_eq!(encode_sint_i128(128), vec![0x00, 0x80]);
        assert_eq!(encode_sint_i128(0), vec![0x00]);
        // round-trip a spread of values
        for v in [
            -129i128, -256, 127, 255, 32767, -32768, 1_000_000, -1_000_000,
        ] {
            assert_eq!(decode_sint_i128(&encode_sint_i128(v)).unwrap(), v);
        }
    }

    #[test]
    fn signed_int_wide_domain() {
        // F1-b/F1-l: +2^127 needs a 17-byte canonical encoding (00 80 00…00);
        // an i128 decoder wrongly rejected it. BigInt handles the full domain.
        let big = BigInt::from(1u8) << 127u32; // +2^127
        let enc = encode_sint(&big);
        assert_eq!(enc.len(), 17);
        assert_eq!(enc[0], 0x00);
        assert_eq!(enc[1], 0x80);
        assert_eq!(decode_sint(&enc).unwrap(), big);
        // The full negative extreme of the balance domain round-trips too.
        let neg = -((BigInt::from(1u8) << 128u32) - 1u8); // -(2^128 - 1)
        assert_eq!(decode_sint(&encode_sint(&neg)).unwrap(), neg);
        // i128 convenience rejects an out-of-range wide value.
        assert_eq!(decode_sint_i128(&enc), Err(Error::FieldDomain));
    }

    #[test]
    fn count_prefixed_roundtrip_and_exact() {
        let items = vec![vec![0xaau8, 0xbb], vec![0xccu8, 0xdd]];
        let v = build_count_prefixed(&items);
        assert_eq!(v[0], 2); // count
        let parsed = parse_count_prefixed(&v, |b| {
            if b.len() < 2 {
                return Err(Error::CountMismatch);
            }
            Ok((b[..2].to_vec(), 2))
        })
        .unwrap();
        assert_eq!(parsed, items);
        // A trailing byte the count does not cover → reject.
        let mut bad = v.clone();
        bad.push(0x99);
        assert!(parse_count_prefixed(&bad, |b| {
            if b.len() < 2 {
                return Err(Error::CountMismatch);
            }
            Ok((b[..2].to_vec(), 2))
        })
        .is_err());
    }

    #[test]
    fn framing_roundtrip_and_rejects() {
        let obj1 = vec![0x00u8, 0x01, 0xaa]; // valid single-field TLV
        let obj2 = vec![0x00u8, 0x01, 0xbb];
        let body = frame_objects(&[obj1.clone(), obj2.clone()]);
        let validate = |o: &[u8]| Object::parse(o).map(|_| ());
        // Accept two framed objects.
        assert_eq!(parse_frames(&body, validate).unwrap(), vec![obj1, obj2]);
        // Reject bare concatenation (no frame lengths).
        assert_eq!(
            parse_frames(&[0x00, 0x01, 0xaa, 0x00, 0x01, 0xbb], validate),
            Err(Error::Framing)
        );
        // Reject a frame length overrunning the body.
        assert_eq!(
            parse_frames(&[0x05, 0x00, 0x01, 0xaa], validate),
            Err(Error::Framing)
        );
        // Reject trailing bytes that cannot form a frame.
        let mut trailing = body.clone();
        trailing.push(0x99); // continuation bit set, no follow-up
        assert_eq!(parse_frames(&trailing, validate), Err(Error::Framing));
        // Reject when one framed object is itself invalid (whole-body).
        let bad = frame_objects(&[vec![0x00u8, 0x05]]); // TLV claims 5 value bytes, has 0
        assert_eq!(parse_frames(&bad, validate), Err(Error::Framing));
    }

    #[test]
    fn domains() {
        assert!(check_domain(&BigUint::from((1u64 << 53) - 1), Domain::Time).is_ok());
        assert!(check_domain(&BigUint::from(1u64 << 53), Domain::Time).is_err());
        assert!(check_domain(&BigUint::from(u32::MAX), Domain::Id).is_ok());
        assert!(check_domain(&(BigUint::from(u32::MAX) + 1u8), Domain::Id).is_err());
        assert!(check_domain(&((BigUint::from(1u8) << 128u32) - 1u8), Domain::Value).is_ok());
        assert!(check_domain(&(BigUint::from(1u8) << 128u32), Domain::Value).is_err());
    }

    #[test]
    fn decode_uint_time_enforces_f1l_cap() {
        // F1-l: `decode_uint_time` accepts the exact boundary 2⁵³ − 1 and
        // rejects any larger value — even one that is a perfectly valid `u64`, which
        // the raw `decode_uint_u64` (used for time fields before) accepted.
        let max = encode_uint_u128((1u128 << 53) - 1);
        assert_eq!(decode_uint_time(&max).unwrap(), (1u64 << 53) - 1);
        let over = encode_uint_u128(1u128 << 53); // 2⁵³ — valid u64, out of the time domain
        assert_eq!(decode_uint_time(&over), Err(Error::FieldDomain));
        // A raw-u64 decode of the same bytes still succeeds — proving the divergence the
        // cap closes (the old time-field decode path accepted this).
        assert_eq!(decode_uint_u64(&over).unwrap(), 1u64 << 53);
        // Non-minimal is still rejected (inherited from `decode_uint_biguint`).
        assert_eq!(decode_uint_time(&[0x00, 0x01]), Err(Error::NonMinimalInt));
    }

    #[test]
    fn text_rules() {
        assert!(validate_text("example.com".as_bytes()).is_ok());
        assert_eq!(validate_text(b"host\x00evil"), Err(Error::TextControlChar));
        assert_eq!(validate_text(b"a\x1bb"), Err(Error::TextControlChar));
        assert_eq!(
            validate_text("\u{FEFF}x".as_bytes()),
            Err(Error::TextNotNfc)
        );
        // Non-NFC: "é" as e + combining acute (U+0065 U+0301) is not NFC.
        assert_eq!(
            validate_text("e\u{0301}".as_bytes()),
            Err(Error::TextNotNfc)
        );
    }
}
