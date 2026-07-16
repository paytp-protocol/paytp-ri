//! paytp-wallet — the payer side of PayTP (§11.1).
//!
//! Part of the **baseline-profile reference implementation** (see the repo-root
//! `SCOPE.md`) — a conformance artifact, not production money software.
//!
//! Five load-bearing pieces, in the Part-1 module tree:
//! - [`custody`] — the key custody / spend boundary (F2.3): only custody signs.
//! - [`policy`] — the [`WalletPolicy`] trait (Part 1b, §7.2/§10.4): *all* spending
//!   authority, plus the pure §10.3 path-selection hook (`select_path`). Substitution
//!   is a conformance requirement — an interaction layer MUST let the operator select
//!   an external wallet, so the wallet sits behind this trait and M7's substitution
//!   test drives a *second* implementation through it.
//! - [`execute`] — Tier 0 baseline + two-leg execution with the F4.5 meed-first-
//!   means-final ordering as an enforced safety guard, and the §10.3 path-selection
//!   surface (`Wallet::select_path` over a trusted `RateSource`, never the untrusted IL).
//! - [`channel`] — payer-side channel lifecycle (open/slice/close), the F6.5 conformant
//!   halt (meed value **and** `TH_TIME` time trigger), the postpay `L_credit` flow bound,
//!   and reclaim automation (F4.5).
//! - [`clock`] — the wallet-owned monotonic clock (C1-9) that anchors the `TH_TIME`
//!   settlement trigger; injected, so the protocol logic holds no wall-clock (tests
//!   inject a deterministic clock).
//!
//! The crate depends only on `paytp-core` and `paytp-rail`; the merchant is the
//! counterparty, reached over the wire, never linked.

pub mod channel;
pub mod clock;
pub mod custody;
pub mod execute;
pub mod policy;

pub use channel::{ChannelClient, ChannelClientError, ChannelOpenParams, PayerChannelTrust};
pub use clock::{Clock, ManualClock, SystemClock};
pub use custody::{Custody, PayerScope};
pub use execute::{BaselinePayment, OfferPath, RateSource, Wallet, WalletError};
pub use policy::{
    select_cost_minimal, ChannelTerms, Decision, HaltOrContinue, PathCandidate, PathSelection,
    SelectReason, StaticPolicy, WalletPolicy,
};
