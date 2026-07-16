//! # paytp-core
//!
//! The canonical PayTP library — "built once and bound into every role's
//! software" (§11.1). It implements the **baseline settlement profile** of the
//! byte-level formal interop spec (F1–F10, at [paytp.org/spec](https://paytp.org/spec))
//! at the commit pinned in `PINNED_SPEC`.
//!
//! Every module cites the F-section that defines its bytes or behavior. The
//! spec is the source of truth: this crate implements it, it does not decide
//! it. A divergence found here moves the spec first, never a silent code
//! workaround. This is a reference / conformance implementation — not
//! production money software (see the repo-root `SCOPE.md`).
//!
//! ## Module index
//!
//! *Encoding & canonical form (F1)*
//! - [`leb128`] — canonical LEB128 (F1-a)
//! - [`tlv`]     — TLV codec, canonical form, coverage, framing (F1.1/F1-i/F1-j/F1-l)
//! - [`jcs`]     — canonical JSON + anchored numeric grammars (F1.2/F1-c)
//! - [`envelope`]— the signing envelope `COVERED` and the domain-label registry (F1.3)
//!
//! *Crypto & metering (F1.4–F1.6 / F5-g)*
//! - [`crypto`]  — the crypto suite behind a narrow provider boundary (F1.4/F1.5/F1.6/F2.5)
//! - [`slice`]   — the metering slice as a closed object (F1.5/F1-k)
//! - [`transcript`] — the slice-transcript hash chain head (F5-g)
//!
//! *Derivation & arithmetic (F4/F7)*
//! - [`derive`]  — split/instance seeds and the entry identifier (F4.1/F4.2)
//! - [`fee`]     — accrual, division, extinguishment, and F6-f reconciliation (F7/F6-f;
//!   the fixed-width core lives in the shared `no_std` `paytp-f7` crate)
//!
//! *Protocol objects & governance (F3/F5/F6/F9)*
//! - [`pointer`] — CAIP/adapter destination pointers, byte-equality (F9.1)
//! - [`registry`]— the Foundation registry snapshot + governed-destination resolution (F9)
//! - [`tier0`]   — Tier-0 quotes, roles, and the governed meed-vector validation (F3)
//! - [`channel`] — channel establishment + the F6 metering state machine (F5/F6)
//! - [`consts`]  — schema/governance constants + the fail-closed placeholder-governance
//!   guard (§10.1/F9-e)
//!
//! *x402 interop (§3)*
//! - [`x402`]     — the x402 mirror rule + PayTP extension embedding (F3-a)
//! - [`x402_net`] — the x402 network/transport glue for the interop path
//!
//! *Support*
//! - [`error`]   — the codec-level decode/validation error enum ([`Error`], [`Result`])

pub mod channel;
pub mod consts;
pub mod crypto;
pub mod derive;
pub mod envelope;
pub mod error;
pub mod fee;
pub mod jcs;
pub mod leb128;
pub mod pointer;
pub mod registry;
pub mod slice;
pub mod tier0;
pub mod tlv;
pub mod transcript;
pub mod x402;
pub mod x402_net;

pub use error::{Error, Result};
