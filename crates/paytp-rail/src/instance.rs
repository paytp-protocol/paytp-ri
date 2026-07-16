//! The meed-instance contract and its entry state machine (**F4.3/F4.2**).
//!
//! The instance holds meed-only entries and divides each among the
//! establishment-bound meed destinations alone — **no merchant share** (that
//! is what distinguishes it from a split, §5.6). Two record kinds:
//!
//! - **Purchase entries** (Tier 0 two-leg): the full F4.3 state machine
//!   `FUNDED → ATTESTED / CANCELLED / RECLAIM_OPEN → RECLAIMED / LAPSED`, with
//!   atomic funding rejection (duplicate id / past `T_lapse`), all transitions
//!   on the rail's own clock.
//! - **Claim-records** (channel legs, F4.2): windowless, no reclaim, immediately
//!   claimable — the kind exists so a settling debtor cannot fund the aggregate
//!   leg and then reclaim the recipients' money.
//!
//! **The instance DERIVES every record id from the funding parameters** (F4.2/
//! F4-c): a purchase entry's id is `SHA-256(… seed_instance ‖ nonce ‖ AMT ‖
//! T_open ‖ T_lapse ‖ contest)`, a claim-record's is `SHA-256(… seed_instance ‖
//! channel_id ‖ ckpt_ref ‖ P)` — it never trusts a caller-supplied id, so a
//! dust/wrong-deadline funding lands a *different*, orphaned id and can never
//! occupy the honest funder's record. This mirrors the on-chain contract's
//! recompute-and-check.
//!
//! `MeedInstance` is rail-agnostic: each operation returns the [`Payout`]s the
//! rail credits to its ledger (meed distributions and refunds), so the state
//! machine is testable without any ledger.

use num_bigint::BigUint;
use paytp_core::derive::{claim_record_id, entry_id_purchase};
use paytp_core::tier0::attest::{Kind, Signed};
use std::collections::{HashMap, HashSet};

/// One meed destination and its basis points *within the instance* (the sum
/// of the roles naming it). Shares are relative to `bp_total = Σ bp` (100 for
/// schema 0x01), so the instance divides the meed amount pro-rata (F7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeedShare {
    pub dest: String,
    pub bp: u16,
}

/// A credit the rail must apply to its ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    pub dest: String,
    pub amount: u128,
}

/// The observable state of a purchase entry (F4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    Funded,
    Attested,
    Cancelled,
    ReclaimOpen,
    Reclaimed,
    Lapsed,
}

/// Entry-machine rejections (a real rail's revert; F4.3 guards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// Duplicate `entry_id`, or a claim-record key already funded (F4.2/F4.3).
    Duplicate,
    /// Funding whose `T_lapse` is already past (a stillborn entry, F4.3).
    Lapsed,
    /// A zero-amount funding — nothing enters the instance.
    ZeroAmount,
    /// No such entry / claim-record.
    NotFound,
    /// The entry is in a terminal state; terminal is terminal (F4.3).
    Terminal,
    /// A signature (attestation/cancellation) failed against the bound merchant
    /// key, or named the wrong entry/nonce (F4.3).
    BadSignature,
    /// A window guard failed (reclaim opened outside `[T_open, T_lapse]`, or
    /// executed before `T_exec`, F4.3).
    Window,
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for EntryError {}

#[derive(Clone)]
enum State {
    Funded,
    Attested,
    Cancelled,
    ReclaimOpen { opened_at: u64 },
    Reclaimed,
    Lapsed,
}

struct Entry {
    nonce: [u8; 32],
    amount: u128,
    refund_ptr: String,
    t_open: u64,
    t_lapse: u64,
    contest: u64,
    state: State,
}

/// A channel's cumulative meed watermark (Option W, F4.2/F6-o) — the per-channel
/// replacement for the per-round claim-record on the channel path. Mirrors the on-chain
/// `ChannelMeed` account: `funded_p` is the monotone cumulative aggregate meed
/// this channel has funded to the instance, `paid[d]` each **destination's** cumulative
/// share (indexed over the by-destination-aggregated `meed` vector, F7-d/F7.3), and
/// `residue` the carried §10.2 sub-unit dust — **per channel** (the accepted ≤1 µ-unit
/// chain-boundary dust, F6.6, distinct from the instance-wide Tier 0 pool).
#[derive(Clone)]
struct ChannelWatermark {
    funded_p: u128,
    paid: Vec<u128>,
    residue: u128,
}

/// A deployed meed instance (F4.3). All amounts are baseline minimum units.
pub struct MeedInstance {
    merchant_key: [u8; 32],
    /// The `seed_instance` (F4-a) this instance's address derives from — the
    /// preimage the instance recomputes record ids against.
    seed_instance: [u8; 32],
    meed: Vec<MeedShare>,
    bp_total: BigUint,
    entries: HashMap<[u8; 32], Entry>,
    claim_records: HashSet<[u8; 32]>,
    /// The instance-wide running-`V` pool for **Tier 0 purchase entries** (attest /
    /// lapse distribution) — unchanged by Option W, which scopes only the channel path.
    v_received: u128,
    paid: Vec<u128>,
    /// The **per-channel** cumulative meed watermarks (Option W, F4.2/F6-o), keyed by
    /// the signed `CHANNEL_ID` — no lineage/root (that keying is what kills the v2
    /// escrow-strand and forgeable-root). Each channel floors its own carve.
    channel_paid: HashMap<[u8; 8], ChannelWatermark>,
}

impl MeedInstance {
    /// Deploy an instance bound to `merchant_key` with the meed division
    /// `meed`, at the address `seed_instance` derives (F4.1).
    pub fn new(merchant_key: [u8; 32], meed: Vec<MeedShare>, seed_instance: [u8; 32]) -> Self {
        // Aggregate by destination BEFORE storing (F7.3: `bp_d = Σ_r bp_r` per
        // destination, floored ONCE per dest). Two roles naming one dest (e.g. a shared
        // fund) would otherwise each floor independently and strand up to 1 µ-unit per
        // shared dest per round (floor is superadditive: `⌊a⌋ + ⌊b⌋ ≤ ⌊a + b⌋`). The
        // bound `VirtualRail::deploy_instance` feeds the raw per-role vector straight here
        // (from the signed quote's `ADDRESS_INPUTS`), so THIS fold IS the F7.3
        // aggregation; it is idempotent on an already-aggregated vector (the sibling
        // `split_recipients` fold), and brings any directly-constructed instance into F7.3
        // conformance as defense-in-depth. A conforming meed vector's `bp` subtotals stay ≤ MEED_BASE_BP
        // (≤ `u16::MAX`), but `new` is a **public constructor** that must not assume that:
        // the fold **saturates** (`saturating_add`) so a malformed direct construction whose
        // subtotal exceeds `u16::MAX` neither panics (debug) nor wraps to `0` (release — which
        // would zero `bp_total` and strand the payout), it caps at `u16::MAX` and still
        // divides deterministically.
        let mut agg: Vec<MeedShare> = Vec::new();
        for r in meed {
            match agg.iter_mut().find(|a| a.dest == r.dest) {
                Some(a) => a.bp = a.bp.saturating_add(r.bp),
                None => agg.push(r),
            }
        }
        let meed = agg;
        let bp_total: BigUint = meed.iter().map(|r| BigUint::from(r.bp)).sum();
        let n = meed.len();
        MeedInstance {
            merchant_key,
            seed_instance,
            meed,
            bp_total,
            entries: HashMap::new(),
            claim_records: HashSet::new(),
            v_received: 0,
            paid: vec![0u128; n],
            channel_paid: HashMap::new(),
        }
    }

    /// The `seed_instance` this instance's address derives from (F4-a) — the merchant/
    /// wallet bind the `advanced_channel_meed` rail fact against the expected instance.
    pub fn seed_instance(&self) -> [u8; 32] {
        self.seed_instance
    }

    pub fn status(&self, entry_id: &[u8; 32]) -> Option<EntryStatus> {
        self.entries.get(entry_id).map(|e| match e.state {
            State::Funded => EntryStatus::Funded,
            State::Attested => EntryStatus::Attested,
            State::Cancelled => EntryStatus::Cancelled,
            State::ReclaimOpen { .. } => EntryStatus::ReclaimOpen,
            State::Reclaimed => EntryStatus::Reclaimed,
            State::Lapsed => EntryStatus::Lapsed,
        })
    }

    /// F7-d running-V distribution among the meed destinations (no merchant
    /// share). The `V × bp` product is computed in [`BigUint`] (exact, never a wrapping
    /// `u128`); the running `V` accumulator itself **saturates** at the `u128` domain
    /// ceiling (`2¹²⁸ − 1` cumulative µ-units — more than all value that will ever exist,
    /// so unreachable) rather than wrapping. Saturation is the correct cap here: widening
    /// `v_received` to `BigUint` would instead push `entitlement` past `2¹²⁸` and panic the
    /// `u128::try_from` below at that same unreachable ceiling.
    fn distribute(&mut self, amount: u128) -> Vec<Payout> {
        // A degenerate instance with no meed weight (empty/all-zero vector) has no
        // entitled recipients — distribute nothing rather than divide by `bp_total == 0`,
        // which would panic and poison the rail mutex. Mirrors the on-chain
        // `claimable_d` `bp_total == 0 → 0` guard; such a vector is rejected upstream by
        // the meed-vector schema check, so this is defense-in-depth at the rail.
        if self.bp_total == BigUint::from(0u32) {
            return Vec::new();
        }
        self.v_received = self.v_received.saturating_add(amount);
        let v = BigUint::from(self.v_received);
        let mut out = Vec::new();
        for (i, r) in self.meed.iter().enumerate() {
            let ent = (&v * BigUint::from(r.bp)) / &self.bp_total;
            let entitlement = u128::try_from(ent).expect("entitlement <= V < 2^128");
            let claimable = entitlement - self.paid[i];
            if claimable > 0 {
                out.push(Payout {
                    dest: r.dest.clone(),
                    amount: claimable,
                });
                self.paid[i] = entitlement;
            }
        }
        out
    }

    /// Fund a purchase entry (F4.3), **deriving** its `entry_id` from the funding
    /// parameters and the instance seed (F4-c) — a dust/wrong-deadline funding
    /// therefore lands a different, orphaned id. Returns the derived id. Atomic
    /// rejection: duplicate id, a `T_lapse` strictly past, or a zero amount.
    #[allow(clippy::too_many_arguments)]
    pub fn fund_entry(
        &mut self,
        nonce: [u8; 32],
        amount: u128,
        refund_ptr: String,
        t_open: u64,
        t_lapse: u64,
        contest: u64,
        now: u64,
    ) -> Result<[u8; 32], EntryError> {
        if amount == 0 {
            return Err(EntryError::ZeroAmount);
        }
        // F4.3: reject only when T_lapse is ALREADY past (strictly), so t_lapse == now
        // is fundable (lapse is t > T_lapse; reclaim opens through t <= T_lapse).
        if t_lapse < now {
            return Err(EntryError::Lapsed);
        }
        // F4.3: T_open ≤ T_lapse (the on-chain contract enforces this; the host must not
        // drift permissive and accept an inverted window the contract would revert).
        if t_open > t_lapse {
            return Err(EntryError::Window);
        }
        let entry_id = entry_id_purchase(
            &self.seed_instance,
            &nonce,
            amount,
            t_open,
            t_lapse,
            contest,
        );
        if self.entries.contains_key(&entry_id) {
            return Err(EntryError::Duplicate);
        }
        self.entries.insert(
            entry_id,
            Entry {
                nonce,
                amount,
                refund_ptr,
                t_open,
                t_lapse,
                contest,
                state: State::Funded,
            },
        );
        Ok(entry_id)
    }

    fn check_sig(
        &self,
        e: &Entry,
        entry_id: &[u8; 32],
        signed: &Signed,
        kind: Kind,
    ) -> Result<(), EntryError> {
        if signed.kind != kind
            || &signed.entry_id != entry_id
            || signed.nonce != e.nonce
            || !signed.verify(&self.merchant_key)
        {
            return Err(EntryError::BadSignature);
        }
        Ok(())
    }

    /// Post a valid attestation (F4.3): `FUNDED`/`RECLAIM_OPEN` → `ATTESTED`,
    /// terminal, the shares become claimable at once (distributed here).
    pub fn attest(
        &mut self,
        entry_id: [u8; 32],
        signed: &Signed,
    ) -> Result<Vec<Payout>, EntryError> {
        let e = self.entries.get(&entry_id).ok_or(EntryError::NotFound)?;
        match e.state {
            State::Funded | State::ReclaimOpen { .. } => {}
            _ => return Err(EntryError::Terminal),
        }
        self.check_sig(e, &entry_id, signed, Kind::Attestation)?;
        let amount = e.amount;
        self.entries.get_mut(&entry_id).unwrap().state = State::Attested;
        Ok(self.distribute(amount))
    }

    /// Post a valid cancellation (F4.3): `FUNDED`/`RECLAIM_OPEN` → `CANCELLED`,
    /// full refund to the recorded pointer at once, no contest delay.
    pub fn cancel(
        &mut self,
        entry_id: [u8; 32],
        signed: &Signed,
    ) -> Result<Vec<Payout>, EntryError> {
        let e = self.entries.get(&entry_id).ok_or(EntryError::NotFound)?;
        match e.state {
            State::Funded | State::ReclaimOpen { .. } => {}
            _ => return Err(EntryError::Terminal),
        }
        self.check_sig(e, &entry_id, signed, Kind::Cancellation)?;
        let (refund, amount) = (e.refund_ptr.clone(), e.amount);
        self.entries.get_mut(&entry_id).unwrap().state = State::Cancelled;
        Ok(vec![Payout {
            dest: refund,
            amount,
        }])
    }

    /// Open reclaim (F4.3): permissionless, `now ∈ [T_open, T_lapse]`,
    /// `FUNDED` → `RECLAIM_OPEN`.
    pub fn open_reclaim(&mut self, entry_id: [u8; 32], now: u64) -> Result<(), EntryError> {
        let e = self
            .entries
            .get_mut(&entry_id)
            .ok_or(EntryError::NotFound)?;
        if !matches!(e.state, State::Funded) {
            return Err(EntryError::Terminal);
        }
        if now < e.t_open || now > e.t_lapse {
            return Err(EntryError::Window);
        }
        e.state = State::ReclaimOpen { opened_at: now };
        Ok(())
    }

    /// The `T_exec` (reclaim execution gate) of an open reclaim, if open — the
    /// merchant checks enough margin remains before delivering under reclaim (F4.4).
    pub fn reclaim_exec_time(&self, entry_id: &[u8; 32]) -> Option<u64> {
        let e = self.entries.get(entry_id)?;
        match e.state {
            // E4: `saturating_add` mirrors the on-chain contract — a `u64::MAX` contest
            // then saturates so `T_exec` is unreachable (reclaim never fires) instead of
            // overflow-panicking the host under `overflow-checks`.
            State::ReclaimOpen { opened_at } => Some(opened_at.saturating_add(e.contest)),
            _ => None,
        }
    }

    /// Execute reclaim (F4.3): `RECLAIM_OPEN`, rail time strictly `> T_exec`
    /// (`opened_at + contest`), no attestation/cancellation → `RECLAIMED`, refund.
    pub fn execute_reclaim(
        &mut self,
        entry_id: [u8; 32],
        now: u64,
    ) -> Result<Vec<Payout>, EntryError> {
        let e = self.entries.get(&entry_id).ok_or(EntryError::NotFound)?;
        let opened_at = match e.state {
            State::ReclaimOpen { opened_at } => opened_at,
            State::Funded => return Err(EntryError::Window), // reclaim not opened
            _ => return Err(EntryError::Terminal),
        };
        if now <= opened_at.saturating_add(e.contest) {
            return Err(EntryError::Window); // T_exec strictly greater (E4: saturating, no panic)
        }
        let (refund, amount) = (e.refund_ptr.clone(), e.amount);
        self.entries.get_mut(&entry_id).unwrap().state = State::Reclaimed;
        Ok(vec![Payout {
            dest: refund,
            amount,
        }])
    }

    /// Claim a lapsed entry (F4.3): `FUNDED` with rail time `> T_lapse` and no
    /// attestation/cancellation/open reclaim → `LAPSED`, distributed here.
    pub fn claim_lapsed(
        &mut self,
        entry_id: [u8; 32],
        now: u64,
    ) -> Result<Vec<Payout>, EntryError> {
        let e = self.entries.get(&entry_id).ok_or(EntryError::NotFound)?;
        if !matches!(e.state, State::Funded) {
            return Err(EntryError::Terminal);
        }
        if now <= e.t_lapse {
            return Err(EntryError::Window); // not yet lapsed
        }
        let amount = e.amount;
        self.entries.get_mut(&entry_id).unwrap().state = State::Lapsed;
        Ok(self.distribute(amount))
    }

    /// Fund a channel claim-record (F4.2): the key is **derived** from
    /// `(channel_id, ckpt_ref, P)` and the seed — windowless, immediately
    /// claimable, no reclaim path. Atomic-reject on a duplicate key. Returns the
    /// derived key and the distribution.
    pub fn fund_claim_record(
        &mut self,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        amount: u128,
    ) -> Result<([u8; 32], Vec<Payout>), EntryError> {
        if amount == 0 {
            return Err(EntryError::ZeroAmount);
        }
        let key = claim_record_id(&self.seed_instance, &channel_id, &ckpt_ref, amount);
        if !self.claim_records.insert(key) {
            return Err(EntryError::Duplicate);
        }
        Ok((key, self.distribute(amount)))
    }

    /// Whether a claim-record for `(channel_id, ckpt_ref, amount)` already exists — a
    /// **read-only** peek (the key is derived exactly as in [`Self::fund_claim_record`]).
    /// Lets a caller return the idempotent `AlreadyFunded` **before** any escrow debit, so
    /// a retry after a successful draw is not mis-reported as an insufficient-escrow
    /// precondition failure (F6-f).
    pub fn claim_record_funded(
        &self,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        amount: u128,
    ) -> bool {
        let key = claim_record_id(&self.seed_instance, &channel_id, &ckpt_ref, amount);
        self.claim_records.contains(&key)
    }

    /// Advance a channel's cumulative meed watermark to `target_p` (Option W,
    /// F4.2/F6-o) — the per-channel replacement for the per-round [`Self::fund_claim_record`]
    /// on the channel path, mirroring the on-chain `advance_channel_meed`. Distributes
    /// the delta `target_p − funded_p` **per destination** over the **cumulative** target
    /// (`floor(target_p · bp_d / Σbp)` on the by-destination-aggregated `meed` vector,
    /// F7-d/F7.3 — `new()` folds roles sharing a destination so the flooring is once per
    /// dest, never per-role), carries the sub-unit dust as this channel's `residue`, and
    /// advances `funded_p = target_p`. **Idempotent by absolute position:**
    /// `target_p ≤ funded_p` distributes nothing — a drop-then-redraw, a crash retry, or a
    /// stale re-advance is a no-op (the monotone `funded_p` is the exactly-once record that
    /// closes the F6-o cross-checkpoint double-draw by construction). Returns the
    /// `funded_p` AFTER, the aggregate delta distributed, and the per-role payouts the rail
    /// credits.
    pub fn advance_channel_meed(
        &mut self,
        channel_id: [u8; 8],
        target_p: u128,
    ) -> (u128, u128, Vec<Payout>) {
        let n = self.meed.len();
        let (funded_p, mut paid) = match self.channel_paid.get(&channel_id) {
            Some(w) => (w.funded_p, w.paid.clone()),
            None => (0u128, vec![0u128; n]),
        };
        // Idempotent no-op: never move the monotone watermark backward, and a degenerate
        // no-recipient instance (bp_total == 0) distributes nothing (never divide by zero).
        if target_p <= funded_p || self.bp_total == BigUint::from(0u32) {
            return (funded_p, 0, Vec::new());
        }
        let delta = target_p - funded_p;
        // Distribute over the CUMULATIVE target: each DESTINATION floors over `target_p`
        // (`self.meed` was aggregated by destination in `new()`, so this loop is once per
        // dest, `bp_d = Σ_r bp_r`, F7-d/F7.3 — never per-role, which would strand a
        // sub-unit on a shared dest); the remainder carries as this channel's §10.2 `residue`.
        let tv = BigUint::from(target_p);
        let mut out = Vec::new();
        let mut distributed = 0u128;
        for (i, r) in self.meed.iter().enumerate() {
            let ent = (&tv * BigUint::from(r.bp)) / &self.bp_total;
            let entitlement = u128::try_from(ent).expect("entitlement <= target_p < 2^128");
            if entitlement > paid[i] {
                out.push(Payout {
                    dest: r.dest.clone(),
                    amount: entitlement - paid[i],
                });
                paid[i] = entitlement;
            }
            distributed = distributed.saturating_add(paid[i]);
        }
        let residue = target_p.saturating_sub(distributed);
        self.channel_paid.insert(
            channel_id,
            ChannelWatermark {
                funded_p: target_p,
                paid,
                residue,
            },
        );
        (target_p, delta, out)
    }

    /// This channel's cumulative aggregate `funded_p` (0 if never advanced) — the
    /// aggregate the wallet checks against its own-cumulative target (F5-o, Option W:
    /// the per-destination split is the instance's deterministic function, so the wallet
    /// never re-floors — that is what eliminates the v2 floor-desync).
    pub fn channel_funded_p(&self, channel_id: &[u8; 8]) -> u128 {
        self.channel_paid
            .get(channel_id)
            .map(|w| w.funded_p)
            .unwrap_or(0)
    }

    /// This channel's carried §10.2 sub-unit `residue` (0 if never advanced) — the
    /// dust that stays in this channel's record (reverts to merchant/payer at close).
    /// Conservation holds per channel: `Σ paid_r + residue == funded_p`. Used by the
    /// conservation property test and the rail-fact/close accounting.
    pub fn channel_residue(&self, channel_id: &[u8; 8]) -> u128 {
        self.channel_paid
            .get(channel_id)
            .map(|w| w.residue)
            .unwrap_or(0)
    }

    /// Snapshot a channel's watermark (`funded_p`, per-role `paid`, `residue`), or `None`
    /// if the channel has never been advanced. An **async rail** captures this BEFORE an
    /// advance so a reorg can faithfully restore the pre-advance state (post-final
    /// reversal — the mock models the reversal, it does not hallucinate it).
    pub fn channel_watermark_snapshot(
        &self,
        channel_id: &[u8; 8],
    ) -> Option<(u128, Vec<u128>, u128)> {
        self.channel_paid
            .get(channel_id)
            .map(|w| (w.funded_p, w.paid.clone(), w.residue))
    }

    /// Restore a channel's watermark to a prior [`Self::channel_watermark_snapshot`] — the
    /// reorg inverse of [`Self::advance_channel_meed`]. `Some(snap)` rolls the record
    /// back to a prior advance; `None` removes it entirely (reverting the channel's FIRST
    /// ever advance). The rail pairs this with reversing the ledger credits so value
    /// conserves across a reorg.
    pub fn restore_channel_watermark(
        &mut self,
        channel_id: [u8; 8],
        snapshot: Option<(u128, Vec<u128>, u128)>,
    ) {
        match snapshot {
            Some((funded_p, paid, residue)) => {
                self.channel_paid.insert(
                    channel_id,
                    ChannelWatermark {
                        funded_p,
                        paid,
                        residue,
                    },
                );
            }
            None => {
                self.channel_paid.remove(&channel_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::crypto;
    use paytp_core::tier0::attest::{Kind, Signed};

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

    fn instance(mk: [u8; 32]) -> MeedInstance {
        MeedInstance::new(mk, shares(), [0xaa; 32])
    }

    #[test]
    fn fund_derives_id_then_attest_distributes() {
        let sk = [0x55; 32];
        let mk = crypto::ed25519_public(&sk);
        let mut inst = instance(mk);
        let nonce = [0x02; 32];
        let eid = inst
            .fund_entry(nonce, 10_000, "refund".into(), 100, 200, 30, 50)
            .unwrap();
        assert_eq!(inst.status(&eid), Some(EntryStatus::Funded));
        let att = Signed::create(Kind::Attestation, nonce, eid, &sk);
        let payouts = inst.attest(eid, &att).unwrap();
        let get = |d: &str| {
            payouts
                .iter()
                .find(|p| p.dest == d)
                .map(|p| p.amount)
                .unwrap_or(0)
        };
        assert_eq!(get("il"), 5_000);
        assert_eq!(get("wallet"), 3_000);
        assert_eq!(get("fund"), 2_000);
    }

    #[test]
    fn dust_funding_lands_a_different_id() {
        // The mempool-squat closure (F4-c): funding the honest params vs a dust
        // amount derive DIFFERENT ids — the honest id is never occupied by dust.
        let mut inst = instance([0x11; 32]);
        let nonce = [0x02; 32];
        let honest = inst
            .fund_entry(nonce, 10_000, "r".into(), 100, 200, 30, 50)
            .unwrap();
        let dust = inst
            .fund_entry(nonce, 1, "r".into(), 100, 200, 30, 50)
            .unwrap();
        assert_ne!(honest, dust);
        // Both funded (distinct ids); the honest one is untouched.
        assert_eq!(inst.status(&honest), Some(EntryStatus::Funded));
    }

    #[test]
    fn atomic_funding_rejections() {
        let mut inst = instance([0x11; 32]);
        assert_eq!(
            inst.fund_entry([2; 32], 100, "r".into(), 10, 20, 5, 25),
            Err(EntryError::Lapsed) // 20 < 25 (strictly past)
        );
        // t_lapse == now is fundable (not "already past").
        assert!(inst
            .fund_entry([2; 32], 100, "r".into(), 10, 25, 5, 25)
            .is_ok());
        assert_eq!(
            inst.fund_entry([2; 32], 0, "r".into(), 10, 200, 5, 25),
            Err(EntryError::ZeroAmount)
        );
        // Duplicate: funding the same (nonce, amount, windows) twice → same id.
        let mut i2 = instance([0x11; 32]);
        i2.fund_entry([2; 32], 100, "r".into(), 10, 200, 5, 25)
            .unwrap();
        assert_eq!(
            i2.fund_entry([2; 32], 100, "r".into(), 10, 200, 5, 25),
            Err(EntryError::Duplicate)
        );
    }

    #[test]
    fn reclaim_open_execute_windows() {
        let mut inst = instance([0x11; 32]);
        let eid = inst
            .fund_entry([2; 32], 10_000, "refund".into(), 100, 200, 30, 50)
            .unwrap();
        assert_eq!(inst.open_reclaim(eid, 90), Err(EntryError::Window));
        inst.open_reclaim(eid, 150).unwrap();
        assert_eq!(inst.reclaim_exec_time(&eid), Some(180));
        assert_eq!(inst.execute_reclaim(eid, 180), Err(EntryError::Window));
        let payouts = inst.execute_reclaim(eid, 181).unwrap();
        assert_eq!(
            payouts,
            vec![Payout {
                dest: "refund".into(),
                amount: 10_000
            }]
        );
    }

    #[test]
    fn all_zero_meed_vector_distributes_nothing_without_panic() {
        // F7: a non-empty meed vector whose shares are all zero has bp_total == 0;
        // distributing must NOT divide by zero (which would panic and poison the rail
        // mutex). No recipient is entitled, so it yields no payout.
        let sk = [0x55; 32];
        let mk = crypto::ed25519_public(&sk);
        let zero_shares = vec![
            MeedShare {
                dest: "a".into(),
                bp: 0,
            },
            MeedShare {
                dest: "b".into(),
                bp: 0,
            },
        ];
        let mut inst = MeedInstance::new(mk, zero_shares, [0xaa; 32]);
        let nonce = [0x02; 32];
        let eid = inst
            .fund_entry(nonce, 10_000, "refund".into(), 100, 200, 30, 50)
            .unwrap();
        let att = Signed::create(Kind::Attestation, nonce, eid, &sk);
        let payouts = inst.attest(eid, &att).unwrap(); // must not panic
        assert!(payouts.is_empty());
    }

    #[test]
    fn max_contest_saturates_instead_of_panicking() {
        // F7 (E4 host mirror): a u64::MAX contest must not overflow-panic in
        // reclaim_exec_time / execute_reclaim. T_exec saturates to u64::MAX, so reclaim
        // is simply never executable (Window) — never a panic under overflow-checks.
        let mut inst = instance([0x11; 32]);
        let eid = inst
            .fund_entry([2; 32], 10_000, "refund".into(), 100, 200, u64::MAX, 50)
            .unwrap();
        inst.open_reclaim(eid, 150).unwrap();
        assert_eq!(inst.reclaim_exec_time(&eid), Some(u64::MAX)); // saturated, no panic
        assert_eq!(inst.execute_reclaim(eid, u64::MAX), Err(EntryError::Window));
    }

    #[test]
    fn cancel_refunds_and_blocks_attest() {
        let sk = [0x55; 32];
        let mk = crypto::ed25519_public(&sk);
        let mut inst = instance(mk);
        let nonce = [0x02; 32];
        let eid = inst
            .fund_entry(nonce, 10_000, "refund".into(), 100, 200, 30, 50)
            .unwrap();
        let can = Signed::create(Kind::Cancellation, nonce, eid, &sk);
        assert_eq!(
            inst.cancel(eid, &can).unwrap(),
            vec![Payout {
                dest: "refund".into(),
                amount: 10_000
            }]
        );
        let att = Signed::create(Kind::Attestation, nonce, eid, &sk);
        assert_eq!(inst.attest(eid, &att), Err(EntryError::Terminal));
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let sk = [0x55; 32];
        let mk = crypto::ed25519_public(&sk);
        let mut inst = instance(mk);
        let nonce = [0x02; 32];
        let eid = inst
            .fund_entry(nonce, 10_000, "r".into(), 100, 200, 30, 50)
            .unwrap();
        let bad = Signed::create(Kind::Attestation, nonce, eid, &[0x99; 32]);
        assert_eq!(inst.attest(eid, &bad), Err(EntryError::BadSignature));
    }

    #[test]
    fn lapse_distributes_to_recipients() {
        let mut inst = instance([0x11; 32]);
        let eid = inst
            .fund_entry([2; 32], 10_000, "refund".into(), 100, 200, 30, 50)
            .unwrap();
        assert_eq!(inst.claim_lapsed(eid, 200), Err(EntryError::Window));
        let payouts = inst.claim_lapsed(eid, 201).unwrap();
        assert_eq!(payouts.iter().map(|p| p.amount).sum::<u128>(), 10_000);
    }

    #[test]
    fn claim_record_derived_windowless_unreclaimable() {
        let mut inst = instance([0x11; 32]);
        let cid = [0, 0, 0, 0, 0, 0, 0, 1];
        let ckpt = [0xcc; 32];
        let (key, payouts) = inst.fund_claim_record(cid, ckpt, 10_000).unwrap();
        assert_eq!(payouts.iter().map(|p| p.amount).sum::<u128>(), 10_000);
        // Duplicate (same channel/ckpt/P → same derived key) → reject.
        assert_eq!(
            inst.fund_claim_record(cid, ckpt, 10_000),
            Err(EntryError::Duplicate)
        );
        // No reclaim path for a claim-record: the key is not a purchase entry.
        assert_eq!(inst.execute_reclaim(key, 999), Err(EntryError::NotFound));
    }

    #[test]
    fn distribution_exact_for_large_v() {
        // F7-d exactness: V near 2^128 must not overflow u128 in V*bp.
        let mut inst = MeedInstance::new(
            [0x11; 32],
            vec![MeedShare {
                dest: "a".into(),
                bp: 100,
            }],
            [0xaa; 32],
        );
        let big = (1u128 << 120) + 12345;
        let payouts = inst.distribute(big);
        assert_eq!(payouts[0].amount, big); // bp_total = 100, bp = 100 → all of V
    }

    #[test]
    fn distribute_aggregates_shared_destination_before_flooring() {
        // F7.3: `bp_d = Σ_r bp_r` per destination, floored ONCE per dest. Two roles
        // naming one dest must not each floor independently (which strands a sub-unit).
        // Vector [shared:1, shared:1, other:1] (bp_total 3); a P = 2 draw pays the shared
        // dest ⌊2·2/3⌋ = 1 (aggregated), NOT ⌊2/3⌋ + ⌊2/3⌋ = 0 (per-role — the stranding bug).
        let mut inst = MeedInstance::new(
            [0x11; 32],
            vec![
                MeedShare {
                    dest: "shared".into(),
                    bp: 1,
                },
                MeedShare {
                    dest: "shared".into(),
                    bp: 1,
                },
                MeedShare {
                    dest: "other".into(),
                    bp: 1,
                },
            ],
            [0xaa; 32],
        );
        let (_key, payouts) = inst.fund_claim_record([0; 8], [0; 32], 2).unwrap();
        let shared: u128 = payouts
            .iter()
            .filter(|p| p.dest == "shared")
            .map(|p| p.amount)
            .sum();
        assert_eq!(
            shared, 1,
            "shared dest floored once on the aggregated bp (⌊2·2/3⌋ = 1), not per-role (0)"
        );
    }

    #[test]
    fn new_saturates_bp_subtotal_no_overflow_panic_or_zero() {
        // `new` is a public constructor; a malformed direct
        // construction whose same-dest `bp` subtotal exceeds `u16::MAX` must not panic
        // (debug) or wrap to 0 (release — which would zero `bp_total` and strand the payout).
        // The fold saturates at `u16::MAX` and still divides deterministically. (Without the
        // saturating fold, the `65535 + 1` here panics under debug overflow checks.)
        let mut inst = MeedInstance::new(
            [0x11; 32],
            vec![
                MeedShare {
                    dest: "shared".into(),
                    bp: u16::MAX,
                },
                MeedShare {
                    dest: "shared".into(),
                    bp: 1,
                },
            ],
            [0xaa; 32],
        );
        // `bp_total` saturated to `u16::MAX` (NOT 0) → `distribute` divides, no divide-by-zero;
        // the single dest receives all of `P` (⌊P·max/max⌋ = P).
        let (_key, payouts) = inst.fund_claim_record([0; 8], [0; 32], 1_000).unwrap();
        assert_eq!(payouts.iter().map(|p| p.amount).sum::<u128>(), 1_000);
    }

    #[test]
    fn advance_channel_meed_cumulative_and_idempotent() {
        // Option W (F4.2/F6-o): per-channel cumulative watermark. Interim "to 4000" then
        // close "to 10000" distributes only the residual; a re-advance to ≤ funded_p is a
        // no-op (the F6-o anti-double-draw, at the RI layer, mirroring the contract).
        let mut inst = instance([0x11; 32]); // shares [il:50, wallet:30, fund:20], Σ 100
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];
        let (f1, d1, p1) = inst.advance_channel_meed(cid, 4_000);
        assert_eq!((f1, d1), (4_000, 4_000));
        assert_eq!(p1.iter().map(|p| p.amount).sum::<u128>(), 4_000);
        assert_eq!(inst.channel_funded_p(&cid), 4_000);
        // Close draw to 10000 — distributes only the 6000 residual.
        let (f2, d2, p2) = inst.advance_channel_meed(cid, 10_000);
        assert_eq!((f2, d2), (10_000, 6_000));
        assert_eq!(p2.iter().map(|p| p.amount).sum::<u128>(), 6_000);
        // Re-advance to the same (or lower) target — idempotent no-op, no double-pay.
        let (f3, d3, p3) = inst.advance_channel_meed(cid, 10_000);
        assert_eq!((f3, d3), (10_000, 0));
        assert!(p3.is_empty());
        let (f4, d4, p4) = inst.advance_channel_meed(cid, 5_000);
        assert_eq!((f4, d4), (10_000, 0));
        assert!(p4.is_empty());
        // Cumulative shares at 10000: il 5000, wallet 3000, fund 2000.
        let total: u128 = [("il", 5_000u128), ("wallet", 3_000), ("fund", 2_000)]
            .iter()
            .map(|(_, a)| a)
            .sum();
        assert_eq!(total, 10_000);
    }

    #[test]
    fn advance_channel_meed_per_channel_isolation_and_conservation() {
        // Two channels on one instance are independent records (no lineage) and each
        // floors its own carve — the ≤1 µ-unit/role chain-boundary dust (F6.6), which
        // conserves (Σ distributed + residue == funded_p per channel).
        let mut inst = instance([0x22; 32]); // [il:50, wallet:30, fund:20]
        let a = [0xAA; 8];
        let b = [0xBB; 8];
        let (_, _, pa) = inst.advance_channel_meed(a, 55);
        let (_, _, pb) = inst.advance_channel_meed(b, 55);
        // Per-channel: il ⌊55·50/100⌋=27, wallet ⌊55·30/100⌋=16, fund ⌊55·20/100⌋=11 → 54; residue 1.
        assert_eq!(pa.iter().map(|p| p.amount).sum::<u128>(), 54);
        assert_eq!(pb.iter().map(|p| p.amount).sum::<u128>(), 54);
        assert_eq!(inst.channel_funded_p(&a), 55);
        assert_eq!(inst.channel_funded_p(&b), 55);
        // Per-channel conservation: Σ paid_r + residue == funded_p (residue 1 each).
        assert_eq!(
            pa.iter().map(|p| p.amount).sum::<u128>() + inst.channel_residue(&a),
            55
        );
        assert_eq!(
            pb.iter().map(|p| p.amount).sum::<u128>() + inst.channel_residue(&b),
            55
        );
        assert_eq!(inst.channel_residue(&a), 1);
        // Combined distributed (108) is ≤ a single record at 110 (single il ⌊110·50/100⌋=55,
        // wallet 33, fund 22 → 110); the ≤1/role dust reverts as per-channel residue.
        let combined: u128 = pa.iter().chain(pb.iter()).map(|p| p.amount).sum();
        assert_eq!(combined, 108);
        assert!(110 - combined <= 3, "≤1 µ-unit/role hop dust");
    }

    #[test]
    fn advance_channel_meed_aggregates_shared_destination() {
        // The F6-o↔F7-d fix at the RI layer: the channel WATERMARK floors ONCE per
        // destination (`bp_d = Σ_r bp_r`, F7-d/F7.3), matching the on-chain
        // `advance_channel_meed` and the Tier-0 `distribute` path (the sibling
        // `distribute_aggregates_shared_destination_before_flooring`). Three roles
        // (bp 50/30/10) name "dev", one (bp 10) names "other"; `MeedInstance::new` folds
        // them so `bp_dev = 90`, `bp_other = 10`. target 13: dev ⌊13·90/100⌋ = 11 (NOT the
        // per-role ⌊6.5⌋+⌊3.9⌋+⌊1.3⌋ = 10 — the stranding bug), other ⌊13·10/100⌋ = 1,
        // residue 1 (per-role would strand 2).
        let shares = vec![
            MeedShare {
                dest: "dev".into(),
                bp: 50,
            },
            MeedShare {
                dest: "other".into(),
                bp: 10,
            },
            MeedShare {
                dest: "dev".into(),
                bp: 30,
            },
            MeedShare {
                dest: "dev".into(),
                bp: 10,
            },
        ];
        let mut inst = MeedInstance::new([0x11; 32], shares, [0xaa; 32]);
        let cid = [7u8; 8];
        let (funded, delta, payouts) = inst.advance_channel_meed(cid, 13);
        assert_eq!((funded, delta), (13, 13));
        let dev: u128 = payouts
            .iter()
            .filter(|p| p.dest == "dev")
            .map(|p| p.amount)
            .sum();
        let other: u128 = payouts
            .iter()
            .filter(|p| p.dest == "other")
            .map(|p| p.amount)
            .sum();
        assert_eq!(
            dev, 11,
            "shared dest floored once on bp_d=90 (⌊13·90/100⌋=11), not per-role (10)"
        );
        assert_eq!(other, 1);
        assert_eq!(
            inst.channel_residue(&cid),
            1,
            "per-destination residue (per-role would strand 2)"
        );
        // Conservation: Σ payouts + residue == funded_p.
        assert_eq!(
            payouts.iter().map(|p| p.amount).sum::<u128>() + inst.channel_residue(&cid),
            13
        );
    }

    #[test]
    fn watermark_survives_a_snapshot_restore_restart_byte_identically() {
        // Watermark-primitive restart: a merchant that snapshots a channel's watermark,
        // crashes, and restores it into a FRESH instance re-derives BYTE-IDENTICALLY and conserves —
        // no accrual is lost, none double-paid, across the restart. Swept over EVERY restart point of
        // a sequence with sub-unit dust (55), a normal step, an idempotent re-advance, and a jump.
        let cid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let targets = [55u128, 200, 200, 1_000];

        // The no-restart reference end state.
        let mut reference = instance([0x33; 32]);
        for &t in &targets {
            reference.advance_channel_meed(cid, t);
        }
        let ref_state = reference.channel_watermark_snapshot(&cid);

        for k in 0..=targets.len() {
            // Advance [0..k), snapshot, then CRASH — only the durable snapshot survives.
            let mut before = instance([0x33; 32]);
            for &t in &targets[..k] {
                before.advance_channel_meed(cid, t);
            }
            let snap = before.channel_watermark_snapshot(&cid);

            // RESTORE into a fresh instance (same shares) and advance the REST of the sequence.
            let mut after = instance([0x33; 32]);
            after.restore_channel_watermark(cid, snap);
            for &t in &targets[k..] {
                after.advance_channel_meed(cid, t);
            }

            // Byte-identical re-derive: (funded_p, per-role paid, residue) equals the no-restart run.
            assert_eq!(
                after.channel_watermark_snapshot(&cid),
                ref_state,
                "restart at step {k}: the watermark re-derives byte-identically"
            );
            // I1 conservation on the restored end state: funded_p = Σ paid_r + residue.
            let (funded, paid, residue) = after.channel_watermark_snapshot(&cid).expect("advanced");
            assert_eq!(
                funded,
                paid.iter().sum::<u128>() + residue,
                "restart at step {k}: funded_p = Σ paid + residue (nothing minted or lost)"
            );
        }
    }

    #[test]
    fn chain_boundary_dust_is_per_channel_bounded_and_conserves() {
        // each channel PDA floors its OWN carve, so the
        // residue is a per-channel §10.2 non-debt bounded by ≤ 1 µ-unit per role per hop. Across
        // MANY channels the aggregate is O(#channels) — the F6.6 amendment accepts this as bounded
        // dust (each hop costs an open; hop churn is economically bounded), NOT an unbounded loss:
        // EVERY channel conserves `target_p = Σ paid + residue`, and no per-channel residue reaches
        // the role count. (Refutes the "capacity-stall / unbounded accumulation" over-escalation.)
        let mut inst = instance([0x44; 32]); // shares [il:50, wallet:30, fund:20], 3 roles, Σ 100
        let roles = inst.meed.len() as u128;
        let mut total_residue = 0u128;
        for i in 0..64u128 {
            let cid = [i as u8; 8]; // distinct per channel (i < 64)
            let target = 100 * i + 1; // +1 leaves a sub-unit that no role's floor can absorb
            let (funded, delta, payouts) = inst.advance_channel_meed(cid, target);
            let distributed: u128 = payouts.iter().map(|p| p.amount).sum();
            let residue = inst.channel_residue(&cid);
            assert_eq!((funded, delta), (target, target));
            // Per-channel conservation — the cumulative target splits into payouts + residue exactly.
            assert_eq!(
                distributed + residue,
                target,
                "channel {i}: target = Σ paid + residue"
            );
            // Per-channel bound — at most one sub-unit lost per role floor (never the role count).
            assert!(
                residue < roles,
                "channel {i}: residue {residue} < {roles} roles"
            );
            total_residue += residue;
        }
        // The aggregate dust is O(#channels), each bounded — never an unbounded short.
        assert!(
            total_residue < 64 * roles,
            "aggregate dust O(#channels), each ≤ roles"
        );
    }
}
