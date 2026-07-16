//! The channel plane (**F5/F6**) — M3.
//!
//! The settlement-math core: the bilateral [`checkpoint::Checkpoint`] carries the
//! *metering* (`CUM_TOTAL`, per-role `ACCRUALS`) that the F6-f reconciliation
//! reads, and [`settlement::Round`] computes a settlement round (the aggregate
//! `P`/`E` via [`crate::fee`]) and the claim-record it funds. The F6-f
//! reconciliation arithmetic itself lives in [`crate::fee::reconcile`] (built +
//! proptested in M0); this module drives it over a channel lifecycle.
//!
//! Establishment (`CHANNEL_AUTH`/`CHANNEL_OPEN`) and the full message set are
//! carried by the role crates' channel driver; behavior (guards, recovery) is
//! F6's.

pub mod checkpoint;
pub mod establish;
pub mod settle_msg;
pub mod settlement;
pub mod state;
pub mod trigger;

pub use checkpoint::Checkpoint;
pub use establish::{
    AckRequest, BindingArtifact, ChannelAck, ChannelAuth, ChannelOpen, Close, CloseDecision,
    FundingProof, VectorEntry,
};
pub use settle_msg::{
    Conversion, CreditedLeg, InstanceLeg, Output, PrepayDrawCompleted, SettlementConfirmed,
    SettlementProof, SettlementPropose, TxRef,
};
pub use settlement::Round;
pub use state::{ChannelState, Mode, Status};
pub use trigger::Trigger;
