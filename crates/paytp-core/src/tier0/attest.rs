//! The attestation and cancellation (**F3.5**, formalizing §5.6; TLV).
//!
//! Two merchant-key signatures over the same `(nonce, entry_id)` pair that MUST
//! never pass for one another (§5.2) — separated by their domain labels
//! (`PayTPv1-attest` vs `PayTPv1-cancel`). Both are TLV objects:
//! `0x00 NONCE (32)` · `0x01 ENTRY_ID (32)` · `0x70 SIG`.

use crate::crypto;
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::tlv::{Field, Object, Openness, Schema};

const T_NONCE: u8 = 0x00;
const T_ENTRY_ID: u8 = 0x01;
const T_SIG: u8 = 0x70;

/// Which of the two objects — they share bytes but never labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Releases the entry to recipients, blocks reclaim (`PayTPv1-attest`).
    Attestation,
    /// Refunds the entry to its recorded pointer at once (`PayTPv1-cancel`).
    Cancellation,
}

impl Kind {
    fn label(self) -> DomainLabel {
        match self {
            Kind::Attestation => DomainLabel::Attest,
            Kind::Cancellation => DomainLabel::Cancel,
        }
    }
}

/// A signed attestation or cancellation (F3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub kind: Kind,
    pub nonce: [u8; 32],
    pub entry_id: [u8; 32],
    pub sig: [u8; 64],
}

fn content_object(nonce: &[u8; 32], entry_id: &[u8; 32]) -> Object {
    Object::from_fields(vec![
        Field::new(T_NONCE, false, nonce.to_vec()),
        Field::new(T_ENTRY_ID, false, entry_id.to_vec()),
    ])
    .expect("distinct types")
}

fn covered_bytes(kind: Kind, nonce: &[u8; 32], entry_id: &[u8; 32]) -> Vec<u8> {
    // TAG/SIG excluded; here only NONCE + ENTRY_ID are content.
    covered(kind.label(), &content_object(nonce, entry_id).encode())
}

impl Signed {
    /// Produce a merchant-signed attestation or cancellation.
    pub fn create(
        kind: Kind,
        nonce: [u8; 32],
        entry_id: [u8; 32],
        merchant_sk: &[u8; 32],
    ) -> Signed {
        let sig = crypto::ed25519_sign(merchant_sk, &covered_bytes(kind, &nonce, &entry_id));
        Signed {
            kind,
            nonce,
            entry_id,
            sig,
        }
    }

    /// Verify this object's signature against `merchant_pk` for its own kind
    /// (an attestation never verifies as a cancellation, §5.2). The instance
    /// checks this against the merchant key bound in the entry's division (F4.3).
    pub fn verify(&self, merchant_pk: &[u8; 32]) -> bool {
        crypto::ed25519_verify_strict(
            merchant_pk,
            &covered_bytes(self.kind, &self.nonce, &self.entry_id),
            &self.sig,
        )
        .is_ok()
    }

    /// Canonical TLV bytes (`NONCE`, `ENTRY_ID`, `SIG`).
    pub fn encode(&self) -> Vec<u8> {
        Object::from_fields(vec![
            Field::new(T_NONCE, false, self.nonce.to_vec()),
            Field::new(T_ENTRY_ID, false, self.entry_id.to_vec()),
            Field::new(T_SIG, false, self.sig.to_vec()),
        ])
        .expect("distinct types")
        .encode()
    }

    /// Parse and verify against the merchant key **for the given kind** — an
    /// attestation MUST NOT verify as a cancellation or vice versa (§5.2).
    pub fn parse_verify(kind: Kind, buf: &[u8], merchant_pk: &[u8; 32]) -> Result<Signed> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[(T_NONCE, false), (T_ENTRY_ID, false), (T_SIG, false)],
        ))?;
        let nonce: [u8; 32] = obj
            .get(T_NONCE)
            .ok_or(Error::MissingField)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let entry_id: [u8; 32] = obj
            .get(T_ENTRY_ID)
            .ok_or(Error::MissingField)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let sig: [u8; 64] = obj
            .get(T_SIG)
            .ok_or(Error::MissingField)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        crypto::ed25519_verify_strict(merchant_pk, &covered_bytes(kind, &nonce, &entry_id), &sig)?;
        Ok(Signed {
            kind,
            nonce,
            entry_id,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attest_and_cancel_do_not_cross_verify() {
        let sk = [0x88u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let nonce = [0x11; 32];
        let entry = [0x22; 32];
        let att = Signed::create(Kind::Attestation, nonce, entry, &sk);
        let bytes = att.encode();
        // Verifies as an attestation...
        assert!(Signed::parse_verify(Kind::Attestation, &bytes, &pk).is_ok());
        // ...but NOT as a cancellation (different domain label).
        assert!(Signed::parse_verify(Kind::Cancellation, &bytes, &pk).is_err());
        // And a cancellation over the same pair is a different object.
        let can = Signed::create(Kind::Cancellation, nonce, entry, &sk);
        assert_ne!(att.sig, can.sig);
        assert!(Signed::parse_verify(Kind::Cancellation, &can.encode(), &pk).is_ok());
        assert!(Signed::parse_verify(Kind::Attestation, &can.encode(), &pk).is_err());
    }

    #[test]
    fn f35_attest_message_is_the_canonical_83_byte_form() {
        // The F3.5 attestation covered bytes are byte-for-byte the on-chain
        // contract's `attest_message(nonce, entry_id)` — one canonical, cross-impl
        // verifiable message committing the NONCE as well as the ENTRY_ID.
        let nonce = [0xAB; 32];
        let entry = [0xCD; 32];
        let got = covered_bytes(Kind::Attestation, &nonce, &entry);
        let mut want = Vec::new();
        want.extend_from_slice(b"PayTPv1-attest");
        want.push(0x00); // F1-h label delimiter
        want.push(0x00); // T_NONCE
        want.push(0x20); // LEB128(32)
        want.extend_from_slice(&nonce);
        want.push(0x01); // T_ENTRY_ID
        want.push(0x20); // LEB128(32)
        want.extend_from_slice(&entry);
        assert_eq!(
            got, want,
            "F3.5 attest message must be the canonical 83-byte form"
        );
        assert_eq!(got.len(), 83);
        // The cancellation shares the 83-byte content shape; only its label differs.
        let can = covered_bytes(Kind::Cancellation, &nonce, &entry);
        assert_eq!(can.len(), 83);
        assert_ne!(got, can);
    }
}
