//! The metering slice (**F1.5 / GAP-FILL F1-k**, formalizing §5.3).
//!
//! The slice is a **closed object**: its registry is §5.3's table exactly —
//! `0x00 SEQ` (8 bytes) · `0x01 AMT_µ` (6 bytes) · `0x02 TAG` (16 bytes, the
//! authenticator). A v0.1 receiver MUST reject a slice carrying any other type
//! number (F1-k). The MAC covers `COVERED(slice)` = the domain label, delimiter,
//! and the canonical `SEQ`/`AMT_µ` TLVs, with `TAG` excluded (F1-i).

use crate::crypto;
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::tlv::{Field, Object, Openness, Schema};

/// `SEQ` never wraps (F1-e): the highest value a sender MAY mint is `2⁶³`; a
/// receiver rejects a slice whose `SEQ` **exceeds** it (`> 2⁶³`). `2⁶³` itself
/// is accepted.
pub const SEQ_MAX: u64 = 1u64 << 63;

const T_SEQ: u8 = 0x00;
const T_AMT: u8 = 0x01;
const T_TAG: u8 = 0x02;

/// A decoded slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    /// Sequence number, per channel unique and increasing (§5.3).
    pub seq: u64,
    /// Gross metered amount in µ-units (6-byte field, so < 2⁴⁸).
    pub amt_micro: u64,
    /// The 16-byte Poly1305 authenticator.
    pub tag: [u8; 16],
}

fn slice_schema() -> Schema {
    // Closed: only the three §5.3 types, all non-critical (v0.1 convention).
    Schema::new(
        Openness::Closed,
        &[(T_SEQ, false), (T_AMT, false), (T_TAG, false)],
    )
}

/// The canonical content object (`SEQ`, `AMT_µ`) — everything the MAC covers,
/// `TAG` excluded.
fn content_object(seq: u64, amt_micro: u64) -> Object {
    let seq_bytes = seq.to_be_bytes().to_vec(); // 8 bytes fixed (§5.3)
    let amt_bytes = amt_micro.to_be_bytes()[2..].to_vec(); // low 6 bytes fixed (§5.3)
    Object::from_fields(vec![
        Field::new(T_SEQ, false, seq_bytes),
        Field::new(T_AMT, false, amt_bytes),
    ])
    .expect("distinct types")
}

/// The `COVERED(slice)` bytes: `"PayTPv1-slice" ‖ 0x00 ‖ canonical(SEQ,AMT_µ)`.
pub fn covered_bytes(seq: u64, amt_micro: u64) -> Vec<u8> {
    covered(DomainLabel::Slice, &content_object(seq, amt_micro).encode())
}

impl Slice {
    /// Build and authenticate a slice: derive `subkey(SEQ)` from `K_session`,
    /// MAC `COVERED(slice)`, and attach the tag.
    pub fn seal(seq: u64, amt_micro: u64, k_session: &[u8; 32]) -> Result<Self> {
        if seq > SEQ_MAX {
            return Err(Error::FieldDomain); // F1-e: SEQ never wraps (> 2^63 rejected)
        }
        if amt_micro >= (1u64 << 48) {
            return Err(Error::WrongWidth); // AMT_µ is a 6-byte field
        }
        let subkey = crypto::slice_subkey(k_session, seq);
        let tag = crypto::slice_tag(&subkey, &covered_bytes(seq, amt_micro));
        Ok(Slice {
            seq,
            amt_micro,
            tag,
        })
    }

    /// The full canonical slice bytes (`SEQ`, `AMT_µ`, `TAG`).
    pub fn encode(&self) -> Vec<u8> {
        let obj = Object::from_fields(vec![
            Field::new(T_SEQ, false, self.seq.to_be_bytes().to_vec()),
            Field::new(T_AMT, false, self.amt_micro.to_be_bytes()[2..].to_vec()),
            Field::new(T_TAG, false, self.tag.to_vec()),
        ])
        .expect("distinct types");
        obj.encode()
    }

    /// Parse and structurally validate a slice (closed-object rule F1-k, fixed
    /// widths). Does NOT verify the MAC — call [`Slice::verify`].
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let obj = Object::parse(buf)?;
        obj.validate(&slice_schema())?; // F1-k: reject any non-{SEQ,AMT,TAG} type
        let seq_f = obj.get(T_SEQ).ok_or(Error::MissingField)?;
        let amt_f = obj.get(T_AMT).ok_or(Error::MissingField)?;
        let tag_f = obj.get(T_TAG).ok_or(Error::MissingField)?;
        if seq_f.value.len() != 8 {
            return Err(Error::WrongWidth);
        }
        if amt_f.value.len() != 6 {
            return Err(Error::WrongWidth);
        }
        if tag_f.value.len() != 16 {
            return Err(Error::WrongWidth);
        }
        let seq = u64::from_be_bytes(seq_f.value[..].try_into().expect("8 bytes"));
        if seq > SEQ_MAX {
            return Err(Error::FieldDomain);
        }
        let mut amt_be = [0u8; 8];
        amt_be[2..].copy_from_slice(&amt_f.value);
        let amt_micro = u64::from_be_bytes(amt_be);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_f.value);
        Ok(Slice {
            seq,
            amt_micro,
            tag,
        })
    }

    /// Verify the slice MAC under `K_session` in constant time (F1.5).
    pub fn verify(&self, k_session: &[u8; 32]) -> bool {
        let subkey = crypto::slice_subkey(k_session, self.seq);
        crypto::slice_tag_verify(&subkey, &covered_bytes(self.seq, self.amt_micro), &self.tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_parse_verify_roundtrip() {
        let ks = [9u8; 32];
        let s = Slice::seal(42, 1_000_000, &ks).unwrap();
        let bytes = s.encode();
        let parsed = Slice::parse(&bytes).unwrap();
        assert_eq!(parsed, s);
        assert!(parsed.verify(&ks));
        // Wrong key fails.
        assert!(!parsed.verify(&[8u8; 32]));
    }

    #[test]
    fn closed_object_rejects_extra_tlv() {
        // Append a 4th TLV (type 0x03) after a valid slice → reject (F1-k).
        let ks = [9u8; 32];
        let s = Slice::seal(1, 5, &ks).unwrap();
        let mut bytes = s.encode();
        bytes.extend_from_slice(&[0x03, 0x01, 0xff]); // type 0x03, len 1
        assert_eq!(Slice::parse(&bytes), Err(Error::UnexpectedType));
    }

    #[test]
    fn tampered_amount_fails_mac() {
        let ks = [9u8; 32];
        let s = Slice::seal(7, 100, &ks).unwrap();
        let mut tampered = s.clone();
        tampered.amt_micro = 101;
        assert!(!tampered.verify(&ks));
    }

    #[test]
    fn seq_ceiling_boundary() {
        // F1-e: 2^63 is the max ACCEPTED; only > 2^63 is rejected.
        assert!(Slice::seal(SEQ_MAX, 1, &[0u8; 32]).is_ok());
        assert_eq!(
            Slice::seal(SEQ_MAX + 1, 1, &[0u8; 32]),
            Err(Error::FieldDomain)
        );
    }
}
