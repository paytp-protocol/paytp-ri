//! `paytp-rail` — the settlement-rail abstraction.
//!
//! Part of the **baseline-profile reference implementation** (see the repo-root
//! `SCOPE.md`): [`VirtualRail`] is in-process; real chain/rail adapters are out of scope.
//!
//! [`RailAdapter`] is the trait every settlement path implements; [`VirtualRail`]
//! is the first implementor — an in-process, programmable rail with a
//! deterministic clock, tunable finality, and a native **split contract** (the
//! Tier 0 baseline division, §5.6/F7.2). Real adapters (Solana/EVM) arrive at M5.
//!
//! The virtual rail lets the F4/F6 machine logic run against a rail with no real
//! chain. What it cannot teach — real gas, contention,
//! finality quirks — is exactly the M5 "real-rail-only unknowns" list.

mod adapter;
mod async_rail;
mod instance;
mod virtual_rail;

pub use adapter::{
    AdvancedFact, Finality, RailAdapter, RailCaps, RailError, RailRef, RefInfo, Transfer,
    TransferKind,
};
pub use async_rail::AsyncRail;
pub use instance::{EntryError, EntryStatus, MeedInstance, MeedShare, Payout};
pub use virtual_rail::{SplitRecipient, VirtualRail};
