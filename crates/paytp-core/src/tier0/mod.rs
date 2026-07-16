//! Tier 0 objects (**F3**, formalizing §5.6): the `paytp` quote extension, the
//! `PayTP-Roles` header, the receipt, and the attestation/cancellation TLVs.
//!
//! The per-payment profile rides inside x402 V2's JSON. Encoding/signing rules
//! are F1's; address derivation and the redemption state machine are F4's — this
//! module defines the objects those machines exchange.

pub mod attest;
pub mod quote;
pub mod receipt;
pub mod roles;

pub use quote::{MeedEntry, Offer, Quote};
pub use receipt::{PaidLeg, Receipt};
