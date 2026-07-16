//! Decode/validation errors.
//!
//! These are *codec-level* rejections — the F1 rule an input violated. The
//! protocol-level `PayTP-Error` registry (§5.7/F3.6/F6.8) is a separate,
//! wire-carried enum that lands with the role crates (M1+); it is not this.
//!
//! The canonicalization discipline (F1.1) is: canonicalization is *validation,
//! never transformation*. So every decoder here rejects a non-canonical input
//! rather than repairing it — that is the property that makes a signature over
//! the bytes unambiguous.

use core::fmt;

/// Every distinct reason a canonical decode can fail. Kept coarse enough to be
/// stable, specific enough that a failing conformance vector names the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // --- LEB128 (F1-a) ---
    /// A LEB128 varint used a non-minimal (overlong) encoding.
    LebOverlong,
    /// A LEB128 varint ran off the end of the buffer.
    LebTruncated,
    /// A LEB128 length exceeded 2^32 − 1 (F1-a).
    LebTooLarge,

    // --- TLV (F1.1) ---
    /// A declared length overran the remaining buffer.
    LengthOverrun,
    /// Bytes remained after the object/value was fully consumed.
    TrailingBytes,
    /// Types were not in ascending type-number order (F1.1 rule 1).
    TypeOrder,
    /// A type number appeared twice, regardless of critical bit (F1.1 rule 2).
    DuplicateType,
    /// A recognized type carried a critical flag other than its defined one (F1.1 rule 6).
    WrongCriticality,
    /// An unrecognized *critical* type (top bit set) was encountered (F1.1).
    UnknownCritical,
    /// An unknown type in the reserved authenticator range 0x70–0x7F (F1-i).
    UnknownAuthenticator,
    /// A variable-width unsigned integer used a non-minimal encoding (F1.1 rule 3).
    NonMinimalInt,
    /// A signed integer used a non-minimal two's-complement encoding (F1-b).
    NonMinimalSignedInt,
    /// A fixed-width field carried the wrong number of bytes.
    WrongWidth,
    /// A count-prefix did not consume its value exactly (F1.1 rule 2).
    CountMismatch,
    /// An integer field exceeded its per-field domain maximum (F1-l).
    FieldDomain,
    /// A required field was absent.
    MissingField,
    /// A closed object (e.g. a slice, F1-k) carried a type it does not define.
    UnexpectedType,

    // --- Framing (F1-j) ---
    /// A multi-object body was malformed (bad frame length, trailing bytes, or a
    /// framed object failed validation — the whole body is rejected).
    Framing,

    // --- Text (F1-g) ---
    /// A text field was not valid UTF-8.
    TextNotUtf8,
    /// A text field carried a NUL or other C0/C1 control character (F1-g).
    TextControlChar,
    /// A text field was not NFC-normalized or carried a BOM (F1-g).
    TextNotNfc,

    // --- JSON / JCS (F1.2/F1-c) ---
    /// The JSON document contained duplicate member names anywhere (F1.2).
    JsonDuplicateMember,
    /// A PayTP-native numeric/opaque string violated its anchored grammar (F1-c).
    JsonGrammar,
    /// The JSON was structurally invalid.
    JsonMalformed,

    // --- Envelope (F1.3) ---
    /// An unknown domain-separation label was requested.
    UnknownLabel,

    // --- Crypto (F1.4) ---
    /// An Ed25519 signature or key failed strict verification (F1-d).
    BadSignature,
    /// An HPKE seal/unseal failed (bad tag, aborted DH, F2.5).
    Seal,

    // --- Arithmetic (F7) ---
    /// A settlement proposal's numbers were internally inconsistent (F7.3).
    InconsistentProposal,
    /// A computed or named value exceeded its arithmetic domain (F7-a/F7.2: P ≥ 2^128).
    ArithmeticDomain,

    // --- Governance (F9-e) ---
    /// A value decision tried to resolve a governed destination while this build
    /// still ships the **release-bound PLACEHOLDER governance constants** (the Dev
    /// Fund / independent-OS-fund destinations, F9-e) and has **not** opted into
    /// them via the `demo-governance` feature. This is the fail-closed governance
    /// guard ([`crate::consts::ensure_governance_ready`]): a non-demo build refuses
    /// to settle to a sentinel rather than silently misroute value. A real
    /// deployment replaces the placeholders before it can run the value path.
    PlaceholderGovernance,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
