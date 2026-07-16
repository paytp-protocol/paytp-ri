//! The signing envelope and domain separation (**F1.3**, formalizing §5.2).
//!
//! Every Ed25519 signature and the slice MAC cover
//!
//! ```text
//! COVERED = DOMAIN_LABEL ‖ 0x00 ‖ canonical_bytes(object, authenticators excluded)
//! ```
//!
//! The single `0x00` byte (GAP-FILL F1-h) terminates the label so that a label
//! which is a string prefix of another (`PayTPv1-ckpt` / `PayTPv1-ckpt-req`)
//! cannot let one object type's signature verify as another's.
//!
//! `DomainLabel` is the exact §5.2 registry — the 18 signing labels F1.3
//! enumerates. Derivation/`info` labels (`PayTPv1-hs`, `PayTPv1-conn`,
//! `PayTPv1-seal`, `PayTPv1-split`, `PayTPv1-instance`, `PayTPv1-entry`,
//! `PayTPv1-transcript`, `PayTPv1-payer`, and the `PayTPv1-slice` HKDF info)
//! are distinct and live in [`crate::crypto`], [`crate::derive`], and
//! [`crate::transcript`]; they are deliberately NOT signing labels.

/// The 18 signing/tagging domain labels of the §5.2 registry (F1.3). No two
/// object types share a label, so no signature or tag replays as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLabel {
    Slice,
    ChanAuth,
    ChanAck,
    Ckpt,
    CkptReq,
    Funding,
    SettlePropose,
    SettleProof,
    SettleConfirm,
    Close,
    /// The prepay interim meed-draw completion notice (§6.4/F5-o) — merchant-signed.
    PrepayDraw,
    /// The Tier 0 quote/challenge.
    Reqs,
    /// The Tier 0 receipt.
    Receipt,
    /// The merchant binding artifact (§5.5).
    Artifact,
    /// The payer-signed acknowledgment-retrieval request (§5.4).
    AckReq,
    /// The redemption attestation (§5.6).
    Attest,
    /// The cancellation (§5.6).
    Cancel,
    /// The Foundation-published role-registry snapshot (§10.1/§10.5; F9).
    Registry,
}

impl DomainLabel {
    /// The exact ASCII label string, `"PayTPv1-<object>"`.
    pub fn as_str(self) -> &'static str {
        match self {
            DomainLabel::Slice => "PayTPv1-slice",
            DomainLabel::ChanAuth => "PayTPv1-chan-auth",
            DomainLabel::ChanAck => "PayTPv1-chan-ack",
            DomainLabel::Ckpt => "PayTPv1-ckpt",
            DomainLabel::CkptReq => "PayTPv1-ckpt-req",
            DomainLabel::Funding => "PayTPv1-funding",
            DomainLabel::SettlePropose => "PayTPv1-settle-propose",
            DomainLabel::SettleProof => "PayTPv1-settle-proof",
            DomainLabel::SettleConfirm => "PayTPv1-settle-confirm",
            DomainLabel::Close => "PayTPv1-close",
            DomainLabel::PrepayDraw => "PayTPv1-prepay-draw",
            DomainLabel::Reqs => "PayTPv1-reqs",
            DomainLabel::Receipt => "PayTPv1-receipt",
            DomainLabel::Artifact => "PayTPv1-artifact",
            DomainLabel::AckReq => "PayTPv1-ack-req",
            DomainLabel::Attest => "PayTPv1-attest",
            DomainLabel::Cancel => "PayTPv1-cancel",
            DomainLabel::Registry => "PayTPv1-registry",
        }
    }

    /// Every label in registry order — the full set, for exhaustiveness tests.
    pub const ALL: [DomainLabel; 18] = [
        DomainLabel::Slice,
        DomainLabel::ChanAuth,
        DomainLabel::ChanAck,
        DomainLabel::Ckpt,
        DomainLabel::CkptReq,
        DomainLabel::Funding,
        DomainLabel::SettlePropose,
        DomainLabel::SettleProof,
        DomainLabel::SettleConfirm,
        DomainLabel::Close,
        DomainLabel::PrepayDraw,
        DomainLabel::Reqs,
        DomainLabel::Receipt,
        DomainLabel::Artifact,
        DomainLabel::AckReq,
        DomainLabel::Attest,
        DomainLabel::Cancel,
        DomainLabel::Registry,
    ];
}

/// Construct the covered bytes for signing/verification:
/// `label ‖ 0x00 ‖ canonical_bytes`. The caller supplies the object's
/// authenticator-excluded canonical bytes (from [`crate::tlv::Object::covered_bytes`]
/// for TLV objects, or the JCS bytes of [`crate::jcs`] for the two JSON objects).
pub fn covered(label: DomainLabel, canonical_bytes: &[u8]) -> Vec<u8> {
    let label_bytes = label.as_str().as_bytes();
    let mut out = Vec::with_capacity(label_bytes.len() + 1 + canonical_bytes.len());
    out.extend_from_slice(label_bytes);
    out.push(0x00); // F1-h delimiter
    out.extend_from_slice(canonical_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_ascii_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for l in DomainLabel::ALL {
            let s = l.as_str();
            assert!(s.is_ascii(), "label must be ASCII: {s}");
            assert!(!s.as_bytes().contains(&0x00), "label must not contain NUL");
            assert!(seen.insert(s), "duplicate label {s}");
        }
        assert_eq!(seen.len(), 18);
    }

    #[test]
    fn prefix_labels_are_delimited() {
        // The F1-h motivating case: ckpt is a byte-prefix of ckpt-req, but the
        // 0x00 delimiter makes the covered prefixes diverge immediately.
        let a = covered(DomainLabel::Ckpt, b"XY");
        let b = covered(DomainLabel::CkptReq, b"XY");
        assert_ne!(a, b);
        // "PayTPv1-ckpt" ‖ 0x00 is NOT a prefix of "PayTPv1-ckpt-req" ‖ 0x00.
        assert_eq!(a[12], 0x00);
        assert_eq!(b[12], b'-');
    }

    #[test]
    fn slice_covered_prefix_matches_f10_anchor() {
        // F10.3: the slice COVERED prefix is 506179545076312d736c69636500
        // = "PayTPv1-slice" ‖ 0x00.
        let prefix = covered(DomainLabel::Slice, b"");
        assert_eq!(hex_lower(&prefix), "506179545076312d736c69636500");
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
