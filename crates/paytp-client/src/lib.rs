//! paytp-client — the interaction layer (§10.3, the `0x10` role).
//!
//! Part of the **baseline-profile reference implementation** (see the repo-root
//! `SCOPE.md`) — a conformance artifact, not production money software.
//!
//! Three units, in the Part-1 module tree:
//! - [`discovery`] (C1) — the control-path / resource-suffix joining rule (F2) and
//!   `PayTP-Roles` assembly.
//! - [`flow`] (C2) — the Tier 0 baseline flow: verify the signed quote, then drive
//!   the operator's wallet.
//! - [`relay`] (C3) — the §10.3 relay validation (assert one's own entry, cross-check
//!   the OS entry) and the **§10.4 external-wallet selection** seam: the IL MUST let
//!   the operator select an external wallet, so the flow drives *any* wallet behind
//!   the [`paytp_wallet::WalletPolicy`] trait rather than a bundled one.

pub mod discovery;
pub mod flow;
pub mod relay;

pub use discovery::{resource_path, validate_control_path, DiscoveryError};
pub use flow::{Client, ClientError, OriginContext, PayerWallet};
pub use relay::{InteractionLayer, RelayError};
