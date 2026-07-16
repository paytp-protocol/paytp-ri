//! The **async, reorg-capable rail mock** (F8.1) — the object the async-finality
//! settlement model is built and certified against. It is NOT the real Solana adapter
//! (M5); it is exactly the F8.1 rail the real adapter will instantiate (Solana
//! `processed → confirmed → finalized` commitment levels + slot reorgs).
//!
//! **The one thing it models that [`crate::VirtualRail`] does not: value moves at
//! FINALITY, not submit, and a not-yet-irreversible transfer can REORG away.** On the
//! synchronous `VirtualRail`, submit *is* settlement (the finality label co-reports with
//! an already-completed value movement). On this rail they are separated by inclusion,
//! finality, and reversal risk — the exact gap the model closes by making conclusive
//! finality the only event that folds, credits, clears, consumes, or refunds.
//!
//! Levels, weakest→strongest (a total order, F8.1):
//! - `submitted` — a pending tx; **no value has moved**, no distribution fact is set.
//! - `confirmed` — included; value has moved (division ran, escrow debited, recipients
//!   credited, the `advanced_channel_meed`/`funds_claim` fact set) but it is
//!   **reversible** (residual reorg risk, §11.1/F8.1).
//! - `finalized` — **irreversible**; the value movement is conclusive.
//!
//! The settlement plane declares its accepted `FIN_MEED`/`FIN_DENOM` = `finalized`
//! and reconciles (folds/credits/clears/refunds) **only** at that level. A reorg can
//! revert a `confirmed` (not-yet-`finalized`) transfer — but the plane never folded it,
//! so no un-fold is needed (the "reconcile only at an accepted-irreversible level"
//! choice, verified sound by the conservation property test's reorg dimension). A
//! `finalized` tx is irreversible and cannot reorg.
//!
//! Transitions are **explicit and test-driven** (`confirm`/`finalize`/`reorg`/`drop_tx`)
//! for deterministic interleaving in the property test; `chain_time` still advances for
//! window checks.

use crate::adapter::{
    AdvancedFact, Finality, RailAdapter, RailCaps, RailError, RailRef, RefInfo, Transfer,
    TransferKind,
};
use crate::instance::{MeedInstance, Payout};
// `MeedShare` is referenced only by the test-only `deploy_instance_unchecked` helper (and the
// in-crate test module), so gate its import to the same cfg — a plain build binds no instance on
// this async mock (it has no production deploy path yet; see the helper's doc).
#[cfg(any(test, feature = "test-helpers"))]
use crate::instance::MeedShare;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The lifecycle level of a submitted transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Submitted,
    Confirmed,
    Finalized,
    Dropped,
}

impl Level {
    fn token(self) -> &'static str {
        match self {
            Level::Submitted => "submitted",
            Level::Confirmed => "confirmed",
            Level::Finalized => "finalized",
            Level::Dropped => "dropped",
        }
    }
}

/// The operation a ref represents — enough to APPLY (at `confirm`) and REVERT (at
/// `reorg`) faithfully; the mock models the reversal, it never hallucinates state.
#[derive(Clone)]
enum Op {
    /// A plain credit (a funding transfer or a payout address). No source debit.
    Plain {
        to: String,
        asset: String,
        amount: u128,
        memo: Option<[u8; 32]>,
    },
    /// A source-debited escrow release (the prepay refund). Keyed for idempotency.
    Release {
        from: String,
        to: String,
        asset: String,
        amount: u128,
    },
    /// A per-channel meed watermark advance (Option W, F6-o).
    Advance {
        from: Option<String>,
        addr: String,
        channel_id: [u8; 8],
        target_p: u128,
        asset: String,
    },
}

/// What an APPLIED (confirmed) op moved — captured so a reorg reverts it exactly.
#[derive(Clone)]
enum Applied {
    Plain {
        to: String,
        amount: u128,
    },
    Release {
        from: String,
        to: String,
        amount: u128,
    },
    Advance {
        from: Option<String>,
        addr: String,
        channel_id: [u8; 8],
        delta: u128,
        payouts: Vec<Payout>,
        /// The watermark snapshot BEFORE this advance (None = the channel's first advance).
        snapshot: Option<(u128, Vec<u128>, u128)>,
    },
}

struct RefRecord {
    level: Level,
    op: Op,
    /// `Some` once the value has moved (Confirmed / Finalized) — the revert data.
    applied: Option<Applied>,
    /// The target info once applied (facts set); `None` while Submitted / after Dropped.
    info: Option<RefInfo>,
}

struct Inner {
    clock: u64,
    ledger: HashMap<String, u128>,
    instances: HashMap<String, MeedInstance>,
    refs: HashMap<String, RefRecord>,
    next_ref: u64,
    outage: bool,
    /// Design A baseline idempotency: payer-presented signed-tx identity → the first
    /// settlement ref. Re-presenting the same authorization returns the same ref and moves no value.
    settle_ids: HashMap<[u8; 32], String>,
    /// Keyed-release idempotency (§5): `(CHANNEL_ID, refund-basis CKPT_REF)` → the
    /// canonical ref of the release already submitted for it, so a retry after an
    /// outage/reorg/restart re-submits the SAME reference the rail dedups.
    release_keys: HashMap<([u8; 8], [u8; 32]), String>,
}

/// The async, reorg-capable rail mock (F8.1). `Clone` shares one `Arc` state.
#[derive(Clone)]
pub struct AsyncRail {
    inner: Arc<Mutex<Inner>>,
    caps: RailCaps,
}

impl Default for AsyncRail {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncRail {
    pub fn new() -> Self {
        AsyncRail {
            inner: Arc::new(Mutex::new(Inner {
                clock: 1_000_000_000,
                ledger: HashMap::new(),
                instances: HashMap::new(),
                refs: HashMap::new(),
                next_ref: 0,
                outage: false,
                settle_ids: HashMap::new(),
                release_keys: HashMap::new(),
            })),
            caps: RailCaps {
                supports_contracts: true,
                // processed/confirmed/finalized (F8.1 total order). The plane accepts
                // `finalized` as FIN_MEED/FIN_DENOM (the irreversible level).
                finality_levels: vec!["submitted".into(), "confirmed".into(), "finalized".into()],
                // Conservative submit→`finalized` delay. NOTE: this mock's `finality()` reports
                // the CURRENT clock (level transitions are test-driven via `confirm`/`finalize`),
                // not `submit + delay`, so this is a forward-looking capability declaration for
                // the MODELLED real rail — no two-leg wallet pre-flight runs against `AsyncRail`
                // today (`plan_two_leg` is `VirtualRail`-typed); wire the real timing with the
                // real adapter.
                finality_delay: 2,
                assets: vec!["virt-usd".into()],
                inclusion_latency: 1,
            },
        }
    }

    pub fn advance_clock(&self, secs: u64) {
        self.inner.lock().unwrap().clock += secs;
    }

    pub fn set_outage(&self, on: bool) {
        self.inner.lock().unwrap().outage = on;
    }

    pub fn balance(&self, addr: &str) -> u128 {
        self.inner
            .lock()
            .unwrap()
            .ledger
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    /// A channel's current cumulative meed watermark `funded_p` at the instance `addr`
    /// (0 if the instance is absent or the channel never advanced) — for conservation
    /// assertions: `funded_p == Σ recipient credits + residue` per channel.
    pub fn channel_funded_p(&self, addr: &str, channel_id: &[u8; 8]) -> u128 {
        self.inner
            .lock()
            .unwrap()
            .instances
            .get(addr)
            .map(|i| i.channel_funded_p(channel_id))
            .unwrap_or(0)
    }

    /// A channel's carried §10.2 sub-unit `residue` at the instance `addr` — the dust the
    /// division floored off, held in the instance (never credited to a recipient, never
    /// lost). Conservation: `initial deposit == remaining deposit + Σ recipient credits +
    /// residue`.
    pub fn channel_residue(&self, addr: &str, channel_id: &[u8; 8]) -> u128 {
        self.inner
            .lock()
            .unwrap()
            .instances
            .get(addr)
            .map(|i| i.channel_residue(channel_id))
            .unwrap_or(0)
    }

    /// **TEST ONLY** — deploy a meed instance at the address `seed` derives (F4.1), from an
    /// arbitrary `(seed, merchant_key, meed)` triple WITHOUT binding them to the seed's canonical
    /// inputs. First deploy wins. The async rail models reorg/finality timing for the
    /// conservation certifications only; its every caller is a low-level rail test, so — like
    /// [`crate::VirtualRail::deploy_instance_unchecked`] — this is `cfg`-gated out of a normal
    /// build (`test` or the `test-helpers` feature). A production async adapter would recompute +
    /// validate the seed from `ADDRESS_INPUTS` exactly as the bound `VirtualRail::deploy_instance`
    /// does (F7.3); no such adapter exists yet.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn deploy_instance_unchecked(
        &self,
        seed: &[u8; 32],
        merchant_key: [u8; 32],
        meed: Vec<MeedShare>,
    ) -> String {
        let addr = self.derive_address(seed);
        let mut inner = self.inner.lock().unwrap();
        inner
            .instances
            .entry(addr.clone())
            .or_insert_with(|| MeedInstance::new(merchant_key, meed, *seed));
        addr
    }

    /// Apply a Submitted op's value movement (inclusion) — the deferred division / debit /
    /// credit runs HERE, not at submit. Returns the applied record + the target info.
    fn apply(inner: &mut Inner, op: &Op) -> (Applied, RefInfo) {
        match op {
            Op::Plain {
                to,
                asset,
                amount,
                memo,
            } => {
                *inner.ledger.entry(to.clone()).or_insert(0) += *amount;
                (
                    Applied::Plain {
                        to: to.clone(),
                        amount: *amount,
                    },
                    RefInfo {
                        to: to.clone(),
                        asset: asset.clone(),
                        amount: *amount,
                        memo: *memo,
                        funds_entry: None,
                        funds_claim: None,
                        advanced_channel_meed: None,
                        canonical: String::new(),
                    },
                )
            }
            Op::Release {
                from,
                to,
                asset,
                amount,
            } => {
                // Source-debit (guarded at submit); credit dest.
                if let Some(b) = inner.ledger.get_mut(from) {
                    *b = b.saturating_sub(*amount);
                }
                let d = inner.ledger.entry(to.clone()).or_insert(0);
                *d = d.saturating_add(*amount);
                (
                    Applied::Release {
                        from: from.clone(),
                        to: to.clone(),
                        amount: *amount,
                    },
                    RefInfo {
                        to: to.clone(),
                        asset: asset.clone(),
                        amount: *amount,
                        memo: None,
                        funds_entry: None,
                        funds_claim: None,
                        advanced_channel_meed: None,
                        canonical: String::new(),
                    },
                )
            }
            Op::Advance {
                from,
                addr,
                channel_id,
                target_p,
                asset,
            } => {
                let inst = inner
                    .instances
                    .get(addr)
                    .expect("advance targets a deployed instance (checked at submit)");
                let seed_instance = inst.seed_instance();
                let snapshot = inst.channel_watermark_snapshot(channel_id);
                let (funded_after, delta, payouts) = {
                    let inst = inner.instances.get_mut(addr).unwrap();
                    inst.advance_channel_meed(*channel_id, *target_p)
                };
                if let Some(src) = from {
                    if delta > 0 {
                        if let Some(b) = inner.ledger.get_mut(src) {
                            *b = b.saturating_sub(delta);
                        }
                    }
                }
                for p in &payouts {
                    *inner.ledger.entry(p.dest.clone()).or_insert(0) += p.amount;
                }
                (
                    Applied::Advance {
                        from: from.clone(),
                        addr: addr.clone(),
                        channel_id: *channel_id,
                        delta,
                        payouts: payouts.clone(),
                        snapshot,
                    },
                    RefInfo {
                        to: addr.clone(),
                        asset: asset.clone(),
                        amount: delta,
                        memo: None,
                        funds_entry: None,
                        funds_claim: None,
                        advanced_channel_meed: Some(AdvancedFact {
                            channel_id: *channel_id,
                            seed_instance,
                            funded_p: funded_after,
                            delta,
                            asset: asset.clone(),
                        }),
                        canonical: String::new(),
                    },
                )
            }
        }
    }

    /// Revert an applied op (a reorg of a not-yet-finalized transfer) — the exact inverse
    /// of [`Self::apply`]: value moves back, the watermark is restored, no dust leaks.
    fn revert(inner: &mut Inner, applied: &Applied) {
        match applied {
            Applied::Plain { to, amount } => {
                if let Some(b) = inner.ledger.get_mut(to) {
                    *b = b.saturating_sub(*amount);
                }
            }
            Applied::Release { from, to, amount } => {
                if let Some(b) = inner.ledger.get_mut(to) {
                    *b = b.saturating_sub(*amount);
                }
                *inner.ledger.entry(from.clone()).or_insert(0) += *amount;
            }
            Applied::Advance {
                from,
                addr,
                channel_id,
                delta,
                payouts,
                snapshot,
            } => {
                // Un-distribute: debit the recipients, restore the watermark, refund the source.
                for p in payouts {
                    if let Some(b) = inner.ledger.get_mut(&p.dest) {
                        *b = b.saturating_sub(p.amount);
                    }
                }
                if let Some(inst) = inner.instances.get_mut(addr) {
                    inst.restore_channel_watermark(*channel_id, snapshot.clone());
                }
                if let Some(src) = from {
                    if *delta > 0 {
                        *inner.ledger.entry(src.clone()).or_insert(0) += *delta;
                    }
                }
            }
        }
    }

    fn record(inner: &mut Inner, op: Op) -> RailRef {
        let id = format!("async-ref:{}", inner.next_ref);
        inner.next_ref += 1;
        inner.refs.insert(
            id.clone(),
            RefRecord {
                level: Level::Submitted,
                op,
                applied: None,
                info: None,
            },
        );
        RailRef(id)
    }

    /// The escrow-release core, run with the rail lock ALREADY HELD (`inner`) — shared by the
    /// plain [`RailAdapter::release`] (lock → call) and the idempotent
    /// [`RailAdapter::release_keyed`] (lock → key check → call → key insert, all under ONE
    /// acquisition), so the keyed release's check-record-insert is ATOMIC. Splitting it across
    /// lock drops (the earlier shape) let two concurrent same-key callers both observe the key
    /// absent and both record an `Op::Release`, double-draining the escrow at confirm/finalize —
    /// F6-h idempotency requires the WHOLE sequence be atomic. Value moves at confirm; the
    /// source-cover is guarded here at submit, as the sync rail does.
    fn release_locked(
        inner: &mut Inner,
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        if inner.outage {
            return Err(RailError::Outage);
        }
        let bal = inner.ledger.get(from).copied().unwrap_or(0);
        if amount == 0 || amount > bal {
            return Err(RailError::Rejected(
                "insufficient escrow balance for release",
            ));
        }
        Ok(Self::record(
            inner,
            Op::Release {
                from: from.to_string(),
                to: to.to_string(),
                asset: asset.to_string(),
                amount,
            },
        ))
    }

    // ---- test-driven lifecycle controls ----

    /// Move a submitted tx to `confirmed` — VALUE MOVES HERE (the deferred division /
    /// debit / credit runs). Idempotent; a no-op on a dropped/already-included tx.
    pub fn confirm(&self, r: &RailRef) {
        let mut inner = self.inner.lock().unwrap();
        let Some(rec) = inner.refs.get(&r.0) else {
            return;
        };
        if rec.level != Level::Submitted {
            return;
        }
        let op = rec.op.clone();
        let (applied, mut info) = Self::apply(&mut inner, &op);
        info.canonical = r.0.clone();
        let rec = inner.refs.get_mut(&r.0).unwrap();
        rec.level = Level::Confirmed;
        rec.applied = Some(applied);
        rec.info = Some(info);
    }

    /// Move a tx to `finalized` (irreversible). Confirms first if still submitted (the
    /// common "finalizes directly" path), so a caller can `finalize` in one step.
    pub fn finalize(&self, r: &RailRef) {
        {
            let inner = self.inner.lock().unwrap();
            match inner.refs.get(&r.0).map(|rec| rec.level) {
                Some(Level::Submitted) => {}
                Some(Level::Confirmed) => {
                    drop(inner);
                    self.inner.lock().unwrap().refs.get_mut(&r.0).unwrap().level = Level::Finalized;
                    return;
                }
                _ => return, // finalized/dropped/absent
            }
        }
        self.confirm(r);
        let mut inner = self.inner.lock().unwrap();
        if let Some(rec) = inner.refs.get_mut(&r.0) {
            if rec.level == Level::Confirmed {
                rec.level = Level::Finalized;
            }
        }
    }

    /// Reorg a tx away. A `confirmed` (not-yet-finalized) tx has its value REVERTED; a
    /// still-`submitted` tx simply drops (value never moved). A `finalized` tx is
    /// irreversible — reorg is refused (returns false). Returns whether it dropped.
    pub fn reorg(&self, r: &RailRef) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(rec) = inner.refs.get(&r.0) else {
            return false;
        };
        match rec.level {
            Level::Finalized | Level::Dropped => false,
            Level::Submitted => {
                inner.refs.get_mut(&r.0).unwrap().level = Level::Dropped;
                true
            }
            Level::Confirmed => {
                let applied = rec.applied.clone();
                if let Some(a) = applied {
                    Self::revert(&mut inner, &a);
                }
                let rec = inner.refs.get_mut(&r.0).unwrap();
                rec.level = Level::Dropped;
                rec.applied = None;
                rec.info = None;
                true
            }
        }
    }

    /// Drop a still-`submitted` tx (eviction). Value never moved. No-op otherwise.
    pub fn drop_tx(&self, r: &RailRef) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(rec) = inner.refs.get_mut(&r.0) {
            if rec.level == Level::Submitted {
                rec.level = Level::Dropped;
            }
        }
    }
}

impl RailAdapter for AsyncRail {
    fn caps(&self) -> RailCaps {
        self.caps.clone()
    }

    fn derive_address(&self, seed: &[u8; 32]) -> String {
        let hex: String = seed[..16].iter().map(|b| format!("{b:02x}")).collect();
        format!("async:0x{hex}")
    }

    fn submit(&self, transfer: Transfer) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.outage {
            return Err(RailError::Outage);
        }
        match transfer.kind {
            TransferKind::Payment => Ok(Self::record(
                &mut inner,
                Op::Plain {
                    to: transfer.to,
                    asset: transfer.asset,
                    amount: transfer.amount,
                    memo: transfer.memo,
                },
            )),
        }
    }

    fn settle(&self, transfer: Transfer, settle_id: [u8; 32]) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.settle_ids.get(&settle_id) {
            return Ok(RailRef(existing.clone()));
        }
        if inner.outage {
            return Err(RailError::Outage);
        }
        let rref = match transfer.kind {
            TransferKind::Payment => Self::record(
                &mut inner,
                Op::Plain {
                    to: transfer.to,
                    asset: transfer.asset,
                    amount: transfer.amount,
                    memo: transfer.memo,
                },
            ),
        };
        inner.settle_ids.insert(settle_id, rref.0.clone());
        Ok(rref)
    }

    fn release(
        &self,
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        Self::release_locked(&mut inner, from, to, asset, amount)
    }

    fn advance_channel_meed(
        &self,
        from: Option<&str>,
        addr: &str,
        channel_id: [u8; 8],
        target_p: u128,
        asset: String,
    ) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.outage {
            return Err(RailError::Outage);
        }
        // The instance must exist, and (prepay) the escrow must cover the delta — checked
        // at SUBMIT so a doomed advance never enters the mempool. The value moves at confirm.
        let funded = {
            let inst = inner.instances.get(addr).ok_or(RailError::NoSuchAccount)?;
            inst.channel_funded_p(&channel_id)
        };
        let delta = target_p.saturating_sub(funded);
        if let Some(src) = from {
            if delta > 0 {
                let bal = inner.ledger.get(src).copied().unwrap_or(0);
                if delta > bal {
                    return Err(RailError::Rejected(
                        "insufficient escrow balance for meed advance",
                    ));
                }
            }
        }
        Ok(Self::record(
            &mut inner,
            Op::Advance {
                from: from.map(|s| s.to_string()),
                addr: addr.to_string(),
                channel_id,
                target_p,
                asset,
            },
        ))
    }

    fn finality(&self, r: &RailRef) -> Option<Finality> {
        let inner = self.inner.lock().unwrap();
        let rec = inner.refs.get(&r.0)?;
        match rec.level {
            // A dropped tx has no finality (the plane treats it as never-happened → safe
            // to re-issue). A submitted/confirmed/finalized tx reports its level + the clock.
            Level::Dropped => None,
            lvl => Some(Finality {
                level: lvl.token().to_string(),
                time: inner.clock,
            }),
        }
    }

    fn ref_target(&self, r: &RailRef) -> Option<RefInfo> {
        let inner = self.inner.lock().unwrap();
        let rec = inner.refs.get(&r.0)?;
        // Value (and the distribution fact) is visible only once APPLIED (confirmed /
        // finalized). A submitted-but-pending or dropped tx exposes no target — a pending
        // advance shows `advanced_channel_meed: None`, a dropped one `ref_target: None`.
        rec.info.clone()
    }

    fn chain_time(&self) -> u64 {
        self.inner.lock().unwrap().clock
    }

    /// A keyed, idempotent escrow release (§5) — the refund equivalent of the claim-record's
    /// `AlreadyFunded`. The key `(CHANNEL_ID, refund-basis CKPT_REF)` dedups a retry after an
    /// outage/reorg/restart to the SAME canonical reference, so a refund is decided-then-submitted,
    /// confirmed on finality, and never double-released.
    fn release_keyed(
        &self,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        // Hold the lock across the WHOLE check-record-insert so the keyed idempotency is ATOMIC:
        // two concurrent same-key calls cannot both observe the key absent and both record an
        // `Op::Release` (the TOCTOU double-drain, applied at confirm/finalize).
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.release_keys.get(&(channel_id, ckpt_ref)) {
            // A release for this (CHANNEL_ID, basis) already exists — return the SAME
            // ref (idempotent), whatever its current level. The rail dedups the retry,
            // so an outage/reorg/restart never double-releases the refund.
            return Ok(RailRef(existing.clone()));
        }
        let rref = Self::release_locked(&mut inner, from, to, asset, amount)?;
        inner
            .release_keys
            .insert((channel_id, ckpt_ref), rref.0.clone());
        Ok(rref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn shares() -> Vec<MeedShare> {
        vec![
            MeedShare {
                dest: "il".into(),
                bp: 50,
            },
            MeedShare {
                dest: "wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: "fund".into(),
                bp: 20,
            },
        ]
    }

    /// A rail with a deployed instance and a funded deposit at `settle-ptr`.
    fn setup(deposit: u128) -> (AsyncRail, String) {
        let rail = AsyncRail::new();
        let addr = rail.deploy_instance_unchecked(&[0x77; 32], [0x88; 32], shares());
        // Fund the deposit (confirm+finalize the funding so it is spendable).
        let f = rail
            .submit(Transfer {
                to: "settle-ptr".into(),
                asset: "virt-usd".into(),
                amount: deposit,
                kind: TransferKind::Payment,
                memo: None,
            })
            .unwrap();
        rail.finalize(&f);
        (rail, addr)
    }

    #[test]
    fn value_moves_at_confirm_not_submit() {
        let (rail, addr) = setup(10_000);
        let r = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        // Submitted: NO value moved, no fact, watermark untouched, finality "submitted".
        assert_eq!(rail.balance("il"), 0);
        assert_eq!(rail.balance("settle-ptr"), 10_000);
        assert!(rail.ref_target(&r).is_none());
        assert_eq!(rail.finality(&r).unwrap().level, "submitted");
        // Confirm: value moves, fact set.
        rail.confirm(&r);
        assert_eq!(rail.balance("il"), 2_000);
        assert_eq!(rail.balance("settle-ptr"), 6_000);
        let fact = rail.ref_target(&r).unwrap().advanced_channel_meed.unwrap();
        assert_eq!((fact.funded_p, fact.delta), (4_000, 4_000));
        assert_eq!(rail.finality(&r).unwrap().level, "confirmed");
    }

    #[test]
    fn reorg_of_confirmed_advance_reverts_value_and_watermark_conserving() {
        let (rail, addr) = setup(10_000);
        let r = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.confirm(&r);
        assert_eq!(rail.balance("il"), 2_000);
        // Reorg the confirmed (not-yet-finalized) advance: value + watermark fully revert.
        assert!(rail.reorg(&r));
        assert_eq!(rail.balance("il"), 0);
        assert_eq!(rail.balance("wallet"), 0);
        assert_eq!(rail.balance("fund"), 0);
        assert_eq!(
            rail.balance("settle-ptr"),
            10_000,
            "escrow restored — conserves"
        );
        assert!(rail.ref_target(&r).is_none(), "dropped → no target");
        assert!(
            rail.finality(&r).is_none(),
            "dropped → no finality (safe to re-issue)"
        );
        // The watermark was restored: a fresh advance to 4000 re-distributes the full 4000
        // (proving the reorg rolled funded_p back to 0 — NOT a hallucinated 0-delta short).
        let r2 = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.finalize(&r2);
        assert_eq!(rail.balance("il"), 2_000);
        assert_eq!(rail.balance("settle-ptr"), 6_000);
    }

    #[test]
    fn finalized_advance_is_irreversible() {
        let (rail, addr) = setup(10_000);
        let r = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.finalize(&r);
        assert_eq!(rail.finality(&r).unwrap().level, "finalized");
        assert_eq!(rail.balance("il"), 2_000);
        // A finalized tx cannot reorg (the accepted-irreversible level).
        assert!(!rail.reorg(&r));
        assert_eq!(rail.balance("il"), 2_000);
    }

    #[test]
    fn dropped_submitted_advance_moved_nothing() {
        let (rail, addr) = setup(10_000);
        let r = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.drop_tx(&r);
        assert!(rail.ref_target(&r).is_none());
        assert!(rail.finality(&r).is_none());
        assert_eq!(rail.balance("il"), 0);
        assert_eq!(rail.balance("settle-ptr"), 10_000);
    }

    #[test]
    fn advance_idempotent_across_reorg_then_reissue_no_double_pay() {
        // The F6-o shape on the async rail: a first advance confirms then reorgs; a
        // re-issue to the SAME target pays the carve EXACTLY ONCE (never twice, never zero).
        let (rail, addr) = setup(10_000);
        let a = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.confirm(&a);
        rail.reorg(&a); // value reverted
        let b = rail
            .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
            .unwrap();
        rail.finalize(&b);
        // Exactly once: recipients hold 4000 total, escrow debited by exactly 4000.
        assert_eq!(
            rail.balance("il") + rail.balance("wallet") + rail.balance("fund"),
            4_000
        );
        assert_eq!(rail.balance("settle-ptr"), 6_000);
    }

    #[test]
    fn keyed_release_is_idempotent() {
        let (rail, _addr) = setup(10_000);
        let ckpt = [0xcc; 32];
        let r1 = rail
            .release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", 6_000)
            .unwrap();
        // A retry (same CHANNEL_ID + basis) returns the SAME ref — never a second release.
        let r2 = rail
            .release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", 6_000)
            .unwrap();
        assert_eq!(r1, r2);
        rail.finalize(&r1);
        assert_eq!(rail.balance("refund"), 6_000);
        assert_eq!(rail.balance("settle-ptr"), 4_000);
        // A third keyed retry after finality is still the same ref (decided-once).
        let r3 = rail
            .release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", 6_000)
            .unwrap();
        assert_eq!(r1, r3);
        assert_eq!(rail.balance("refund"), 6_000, "no double release");
    }

    #[test]
    fn keyed_release_is_atomic_under_concurrency_no_double_release() {
        // REPRO (the same release_keyed TOCTOU on the ASYNC rail as on VirtualRail). The
        // check and the record must be atomic: N concurrent same-key calls must record EXACTLY
        // ONE `Op::Release`, so at finality the escrow is drained once. Pre-fix the lock was
        // dropped between the key check and the record, so several racers each recorded a release
        // and finalizing them double-drained. `settle-ptr` is seeded with N×amount so every racer
        // that (buggily) records a release has enough escrow to actually DRAIN at finality — the
        // double-release then shows as a clean over-drain, not entangled with the SEPARATE,
        // pre-existing async gap where an insufficiently-covered release still mints at the
        // destination (that gap is out of scope here; see the gate residuals note).
        let ckpt = [0xab; 32];
        let amount = 6_000u128;
        const N: usize = 16;
        for _ in 0..300 {
            let (rail, _addr) = setup(N as u128 * amount);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
            let handles: Vec<_> = (0..N)
                .map(|_| {
                    let rail = rail.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        rail.release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", amount)
                    })
                })
                .collect();
            let refs: Vec<RailRef> = handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap()
                        .expect("keyed release must be idempotent, never error")
                })
                .collect();
            // Finalize every DISTINCT ref the racers returned (value moves at finality). If more
            // than one release was recorded, more than one drains here.
            let mut seen = std::collections::HashSet::new();
            for r in &refs {
                if seen.insert(r.0.clone()) {
                    rail.finalize(r);
                }
            }
            assert_eq!(
                rail.balance("refund"),
                amount,
                "double-release: refund credited more than once for one close key"
            );
            assert_eq!(
                rail.balance("settle-ptr"),
                (N as u128 - 1) * amount,
                "double-release: escrow drained more than once"
            );
            assert!(
                refs.iter().all(|r| *r == refs[0]),
                "keyed release must return the SAME ref for a duplicate key"
            );
        }
    }

    #[test]
    fn settle_idempotent_returns_same_ref_and_applies_once() {
        let rail = AsyncRail::new();
        let transfer = Transfer {
            to: "merchant".into(),
            asset: "virt-usd".into(),
            amount: 1_000,
            kind: TransferKind::Payment,
            memo: None,
        };
        let r1 = rail.settle(transfer.clone(), [0x5e; 32]).unwrap();
        let r2 = rail.settle(transfer, [0x5e; 32]).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(rail.balance("merchant"), 0);
        rail.finalize(&r1);
        assert_eq!(rail.balance("merchant"), 1_000);
        rail.finalize(&r2);
        assert_eq!(rail.balance("merchant"), 1_000);
    }
}
