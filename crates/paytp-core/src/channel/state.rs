//! Channel slice acceptance, the F6.1 lifecycle, and checkpoint supersession
//! (**F6.1/F6.2/F6.3**).
//!
//! The canonical **authenticate-before-state** acceptance order (GAP-FILL F6-b)
//! so multi-fault slices draw deterministic errors and no unauthenticated sender
//! learns channel state, the F6.1 lifecycle (`OPEN ⇄ PAUSED_* → SETTLING →
//! CLOSED`), and the F6.3 supersession rule (`CUM_TOTAL` then the
//! lexicographic-`CKPT_REF` tiebreaker). Balance is the flow-control estimate,
//! never the authoritative settled position (F6-f).

use crate::channel::checkpoint::{Checkpoint, Event, Range};
use crate::slice::Slice;
use crate::transcript;
use num_bigint::BigUint;

/// Channel mode (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `B ∈ [−L_prepay, 0]`, consumption pushes `B` up toward `0`.
    Prepay,
    /// `B ∈ [0, +L_credit]`, consumption pushes `B` up toward `L_credit`.
    Postpay,
}

/// The channel lifecycle state (**F6.1**):
/// `OPEN ⇄ PAUSED_WINDOW / PAUSED_EVIDENCE → SETTLING → CLOSED`. `NEGOTIATING`
/// precedes this type — a [`ChannelState`] exists only once the channel does
/// (the payer holds a valid `CHANNEL_ACK`, §5.4), so it is born `OPEN`. `SETTLING`
/// and `CLOSED` are one-way; the pauses re-enter `OPEN` as bounds release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Slices accepted under F6.2's guards.
    Open,
    /// A slice would breach the mode's balance bound; released by funding or a
    /// completed settlement round re-opening the window (§6.1).
    PausedWindow,
    /// Unevidenced accepted value reached `E`; released by a bilateral checkpoint.
    PausedEvidence,
    /// Terminal-bound: a `CLOSE` or the establishing connection's close (F6-a). No
    /// further slices; the control plane completes what is owed, then `CLOSED`.
    Settling,
    /// Terminal: keys erased (F1.6). No metering.
    Closed,
}

/// The one-way lifecycle phase, held separately from the (independently-releasing)
/// window/evidence pauses so a checkpoint can never clear a window pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Settling,
    Closed,
}

/// Slice-acceptance rejections (F6.8 error mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    /// MAC failed — reject generically, no state answer (F6-b step 3).
    BadMac,
    /// `SEQ` at/below the checkpoint floor or already accounted (`PAYTP_SEQ_INVALID`).
    SeqInvalid,
    /// The amount would push `B` past the mode's bound, or the channel is
    /// window-paused (`PAYTP_WINDOW_EXCEEDED`).
    WindowExceeded,
    /// Unevidenced accepted value would exceed `E` (`PAYTP_EVIDENCE_REQUIRED`).
    EvidenceRequired,
    /// The channel is `SETTLING`/`CLOSED` — no further slices are ever accepted
    /// (F6.1). A slice arriving now meters nothing; the wallet carries the value
    /// into the successor (§5.5).
    NotOpen,
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AcceptError {}

/// Why a chained-successor import (F6.6) was refused — fail-closed, so a
/// `predecessor`-referenced open that cannot import a consistent position never
/// silently opens a fresh zero-state channel (the pre-F6.6 false success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The imported per-role `accruals` did not align 1:1 with the successor's
    /// `vector` (the F6.6 same-instance-inputs prerequisite guarantees they match).
    VectorMismatch,
    /// The imported `B` fell outside the mode's `[bound_lower, bound_upper]` window —
    /// an over-import would bypass the `accept_slice` clamps and let value escape.
    BalanceOutOfBounds,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ImportError {}

/// Per-channel acceptance state (one endpoint's view). Cloneable so a metering
/// batch can validate against a tentative copy and commit whole (F1-j).
#[derive(Clone)]
pub struct ChannelState {
    /// The slice-plane key, or `None` once the channel is `CLOSED` (F1.6 erasure) —
    /// a missing key makes every slice fail at the MAC (`BadMac`), the same generic
    /// answer an unauthenticated slice draws, so no party can forge past it and
    /// `CLOSED` leaks nothing.
    k_session: Option<[u8; 32]>,
    mode: Mode,
    /// The mode's `B` upper bound: `L_credit` (postpay) or `0` (prepay).
    bound_upper: i128,
    /// The mode's `B` lower bound: `0` (postpay funding floor) or `−L_prepay`
    /// (prepay deposit floor). A funding over-transfer clamps here — excess forfeit.
    bound_lower: i128,
    /// The evidence bound `E` (µ-units).
    limit_e: u128,
    /// Per-role basis points (ascending role), for accrual.
    vector: Vec<(u8, u16)>,
    /// Live flow-control estimate `B`.
    balance: i128,
    /// Gross accepted, monotone.
    cum_total: u128,
    /// Per-role accrued numerators (aligned to `vector`).
    accruals: Vec<BigUint>,
    /// Unevidenced accepted value since the last checkpoint.
    unevidenced: u128,
    /// The checkpoint floor: `SEQ` at or below this is invalid (F5-i: floor 0 at birth).
    floor: u64,
    /// Accounted `SEQ`s above the floor.
    accounted: std::collections::BTreeSet<u64>,
    /// This channel's identifier (F5.5 — the checkpoint's `CHANNEL_ID` and the
    /// transcript's `head_0` seed).
    channel_id: [u8; 8],
    /// The transcript head committed at the last checkpoint (`head_0(channel_id)`
    /// before the first) — the chain over all slices at or below the floor (F5-g).
    committed_head: [u8; 32],
    /// Accepted slices since the last checkpoint, keyed by `SEQ` (ascending) so the
    /// transcript is folded in **sequence order** (F5-g — not acceptance order) and
    /// a checkpoint can be recomputed **historically over exactly the named `SEQ`s**
    /// (F6-c): a proposal cut at `last_seq` recomputes over the slices at or below it,
    /// with newer live-window slices excluded — so a slice accepted after the proposal
    /// was cut neither fails a correct proposal (liveness) nor is lost when the
    /// commit retires only that named snapshot (`checkpoint_upto`). The full `Slice` is
    /// retained (not just its bytes) so the historical `CUM_TOTAL`/`ACCRUALS`/`BALANCE`
    /// can subtract the excluded amounts exactly.
    window: std::collections::BTreeMap<u64, Slice>,
    /// The F6.1 lifecycle phase. Born `Open`.
    phase: Phase,
    /// Window pause (F6.1): set on a window breach, a **firm** bar until funding or
    /// a settlement round releases it — a conformant party funds/settles on
    /// `PAYTP_WINDOW_EXCEEDED`, never downsizes into the exhausted window.
    paused_window: bool,
    /// Evidence pause (F6.1): set when *accepted* unevidenced value reaches `E`;
    /// **soft** — the merchant MAY keep accepting within the remaining `E` headroom
    /// while the checkpoint exchange completes (F6.3) — released by a checkpoint.
    paused_evidence: bool,
}

impl ChannelState {
    /// A fresh channel. `limit_l` is `L_credit` (postpay) or `L_prepay` (prepay).
    pub fn new(
        channel_id: [u8; 8],
        k_session: [u8; 32],
        mode: Mode,
        limit_l: u128,
        limit_e: u128,
        vector: Vec<(u8, u16)>,
    ) -> Self {
        // Saturating: `limit_l` is a `u128` off the wire; a value beyond `i128::MAX`
        // must not truncate to a negative bound (which would brick the channel) nor
        // panic on negation (`-i128::MIN`). A channel closes/chains long before such
        // magnitudes (F7-a), so saturating the bound is safe.
        let limit_i = i128::try_from(limit_l).unwrap_or(i128::MAX);
        // F6-g: a fresh (unchained) channel opens at `B = 0` in BOTH modes. `0` is the
        // postpay *lower* bound — fresh postpay has its full `L_credit` of headroom above
        // it — but the prepay *upper* bound, so a fresh prepay channel opens AT its ceiling:
        // no slice is acceptable (a slice adds, pushing `B` past 0) until a confirmed
        // FUNDING_PROOF drives `B` negative (deposit-before-consume), after which
        // consumption pushes `B` back up toward 0. `L_prepay` is the deposit LIMIT, not the
        // opening balance — opening at `−L_prepay` would pre-credit the whole float and let
        // a payer consume `L_prepay` for free (F5).
        let (bound_upper, bound_lower, balance) = match mode {
            Mode::Postpay => (limit_i, 0i128, 0i128),
            Mode::Prepay => (0i128, -limit_i, 0i128),
        };
        let n = vector.len();
        ChannelState {
            k_session: Some(k_session),
            mode,
            bound_upper,
            bound_lower,
            limit_e,
            vector,
            balance,
            cum_total: 0,
            accruals: vec![BigUint::from(0u8); n],
            unevidenced: 0,
            floor: 0,
            accounted: std::collections::BTreeSet::new(),
            channel_id,
            committed_head: transcript::head_0(&channel_id),
            window: std::collections::BTreeMap::new(),
            phase: Phase::Open,
            paused_window: false,
            paused_evidence: false,
        }
    }

    /// A **chained successor** opening at the predecessor's reconciled imported
    /// position (F6.6). Unlike [`ChannelState::new`], it seeds the economic
    /// position — `cum_total`, role-aligned `accruals`, and the canonical imported `B`
    /// (F6-e/F6-g) — so the whole chain's cumulatives advance from there as the successor
    /// accepts its own slices; the slice-plane (id, session key, transcript head, floor,
    /// window) is fresh (a new channel), only the metering POSITION is imported. The
    /// successor's ledger openings (`settled_r`, `net_legs`, `funding`) are seeded
    /// separately at the carriage — F6-f reconciliation reads them alongside these
    /// cumulatives.
    ///
    /// **Fails closed** on an inconsistent import: `imported_accruals` MUST align 1:1
    /// with `vector` (the F6.6 same-instance-inputs prerequisite guarantees the successor's
    /// vector equals the predecessor's), and `imported_balance` MUST fit the mode's
    /// `[bound_lower, bound_upper]` window.
    #[allow(clippy::too_many_arguments)]
    pub fn new_imported(
        channel_id: [u8; 8],
        k_session: [u8; 32],
        mode: Mode,
        limit_l: u128,
        limit_e: u128,
        vector: Vec<(u8, u16)>,
        imported_cum_total: u128,
        imported_accruals: Vec<BigUint>,
        imported_balance: i128,
    ) -> Result<Self, ImportError> {
        if imported_accruals.len() != vector.len() {
            return Err(ImportError::VectorMismatch);
        }
        // Build the fresh slice-plane first (id/session/head/floor/window/bounds), then
        // overwrite ONLY the three economic fields — a partially-initialized state never
        // escapes this constructor.
        let mut state = Self::new(channel_id, k_session, mode, limit_l, limit_e, vector);
        if imported_balance > state.bound_upper || imported_balance < state.bound_lower {
            return Err(ImportError::BalanceOutOfBounds);
        }
        state.cum_total = imported_cum_total;
        state.accruals = imported_accruals;
        state.balance = imported_balance;
        Ok(state)
    }

    /// The current F6.1 lifecycle state, composed from the one-way phase and the
    /// independently-releasing pauses.
    pub fn status(&self) -> Status {
        match self.phase {
            Phase::Settling => Status::Settling,
            Phase::Closed => Status::Closed,
            Phase::Open => {
                if self.paused_window {
                    Status::PausedWindow
                } else if self.paused_evidence {
                    Status::PausedEvidence
                } else {
                    Status::Open
                }
            }
        }
    }

    pub fn balance(&self) -> i128 {
        self.balance
    }
    pub fn cum_total(&self) -> u128 {
        self.cum_total
    }
    /// The mode's window bounds (`[bound_lower, bound_upper]`) — postpay `[0, +L_credit]`,
    /// prepay `[−L_prepay, 0]`. Used to clamp a chained successor's imported `B` (F6-e/F6-g)
    /// to the predecessor's valid range at snapshot time.
    pub fn bound_lower(&self) -> i128 {
        self.bound_lower
    }
    pub fn bound_upper(&self) -> i128 {
        self.bound_upper
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn accruals(&self) -> Vec<(u8, BigUint)> {
        self.vector
            .iter()
            .map(|(r, _)| *r)
            .zip(self.accruals.iter().cloned())
            .collect()
    }

    /// The live gross unsettled DENOM estimate for the F6.4 value trigger — `B`
    /// clamped at `0` (`B` carries both merchant-net and the outstanding meed
    /// carve, §6.2). This is the flow-control *estimate*; the round reconciles the
    /// authoritative position (F6-f). Prepay `B ≤ 0` reads as `0` unsettled here —
    /// the prepay meed is tracked through accruals, not `B` (§6.1).
    pub fn unsettled_estimate(&self) -> u128 {
        self.balance.max(0) as u128
    }

    /// Accept a slice under the canonical F6-b order (authenticate-before-state).
    /// On success the balance, cumulative total, and accrual numerators move and
    /// the `SEQ` is accounted.
    pub fn accept_slice(&mut self, slice: &Slice) -> Result<(), AcceptError> {
        // Step 3: authenticate (MAC) BEFORE any state answer — so an unauthenticated
        // sender (bad MAC) gets an identical `BadMac` whatever the channel's state,
        // never learning that a channel is settling/closed. A `CLOSED` channel has no
        // key; we still run the constant-time verify against a dummy key so the
        // rejection is timing-indistinguishable from a real bad MAC, then reject —
        // unforgeable by anyone (a valid dummy MAC still fails on `is_none`).
        let mac_ok = slice.verify(&self.k_session.unwrap_or([0u8; 32]));
        if self.k_session.is_none() || !mac_ok {
            return Err(AcceptError::BadMac);
        }
        // Only a MAC-holder reaches a state answer. F6.1: a SETTLING/CLOSED channel
        // accepts no further slices, ever.
        if !matches!(self.phase, Phase::Open) {
            return Err(AcceptError::NotOpen);
        }
        // Step 4: SEQ admissible — above the floor and not yet accounted.
        if slice.seq <= self.floor || self.accounted.contains(&slice.seq) {
            return Err(AcceptError::SeqInvalid);
        }
        // A window-paused channel is a firm bar until funding/settlement releases it.
        if self.paused_window {
            return Err(AcceptError::WindowExceeded);
        }
        let amt = slice.amt_micro as u128;
        // Step 5: bounds — window then evidence. `E` rule is *exceed*, never *reach*.
        // Saturating add: `amt` is a `u64` but `balance` can sit near a saturated
        // bound, so a plain `+` could overflow `i128` before the window check.
        let new_balance = self.balance.saturating_add(amt as i128);
        if new_balance > self.bound_upper {
            self.paused_window = true; // F6.1: window breach → firm pause
            return Err(AcceptError::WindowExceeded);
        }
        if self.unevidenced + amt > self.limit_e {
            // Exceeding `E` is rejected but is NOT a reach — the evidence pause is
            // entered only on *accepted* value reaching `E` (below), so a lone
            // oversized slice does not strand an otherwise-empty channel.
            return Err(AcceptError::EvidenceRequired);
        }
        // Accept: move state.
        self.balance = new_balance;
        self.cum_total = self.cum_total.saturating_add(amt);
        let amt_b = BigUint::from(amt);
        for (acc, (_, bp)) in self.accruals.iter_mut().zip(self.vector.iter()) {
            *acc += &amt_b * BigUint::from(*bp);
        }
        self.unevidenced += amt;
        self.accounted.insert(slice.seq);
        // F5-g: retain the slice so the transcript folds in SEQ order at checkpoint
        // time (not acceptance order — reordered arrivals must not fork the head), and
        // so a historical checkpoint can subtract the amounts of slices above a proposal's
        // `last_seq` (F6-c).
        self.window.insert(slice.seq, slice.clone());
        // F6.3: reaching exactly `E` is accepted and pauses the channel pending a
        // checkpoint (the rule is *exceed*, so this slice is accepted first).
        if self.unevidenced >= self.limit_e {
            self.paused_evidence = true;
        }
        Ok(())
    }

    /// Accept all slices of one carriage unit atomically (F1-j / F6.2): they
    /// validate against a tentative copy and commit together — any failure rejects
    /// the whole unit with **nothing accounted** (a partial batch is a divergence
    /// surface). Returns the first failing slice's error.
    pub fn accept_batch(&mut self, slices: &[Slice]) -> Result<(), AcceptError> {
        let mut tentative = self.clone();
        for s in slices {
            if let Err(e) = tentative.accept_slice(s) {
                // Metering rolls back (nothing accounted), but a window breach is a
                // control-state consequence that MUST persist (F6.1) — the batch's
                // demand hit the ceiling, so the real channel firmly pauses;
                // otherwise a payer could wrap slices in a batch to evade the pause
                // and retry a smaller amount without funding/settling.
                if e == AcceptError::WindowExceeded {
                    self.paused_window = true;
                }
                return Err(e);
            }
        }
        *self = tentative;
        Ok(())
    }

    /// A confirmed funding transfer subtracts from `B` — clamped at the mode's
    /// lower bound (`0` postpay, `−L_prepay` prepay): an over-transfer's excess is
    /// forfeit and moves `B` no further (F6.2/F6.4). Confirmed funding re-opens a
    /// window-paused channel (F6.1/F6.4).
    pub fn credit_funding(&mut self, credited: u128) {
        // Saturating throughout: a value beyond `i128::MAX` (the F7-a domain reaches
        // `2¹²⁸−1`) must not wrap on the cast, and `saturating_sub` must not underflow
        // when `balance` is already negative (prepay) — the clamp below runs after.
        self.balance = self
            .balance
            .saturating_sub(i128::try_from(credited).unwrap_or(i128::MAX));
        if self.balance < self.bound_lower {
            self.balance = self.bound_lower;
        }
        // Only an actual funding releases the window — a zero-credit call moves no
        // value and releases nothing.
        if credited > 0 && self.paused_window {
            self.paused_window = false;
        }
    }

    /// A completed postpay settlement round decreases `B` by the gross DENOM value
    /// it settles (F6.2), clamped at the lower bound, and re-opens a window-paused
    /// channel (§6.1) — the window-exhaustion path where the payer elects
    /// settlement over funding. A prepay interim round is meed-only and leaves
    /// `B` unmoved (§6.2); the prepay window re-opens on funding (fresh deposit).
    pub fn apply_settlement_round(&mut self, gross_denom_settled: u128) {
        if self.mode == Mode::Postpay {
            self.balance = self
                .balance
                .saturating_sub(i128::try_from(gross_denom_settled).unwrap_or(i128::MAX));
            if self.balance < self.bound_lower {
                self.balance = self.bound_lower;
            }
            if gross_denom_settled > 0 && self.paused_window {
                self.paused_window = false;
            }
        }
    }

    /// Contiguous runs of the accounted `SEQ`s at or below `cutoff` (F5.5 `RANGES`) —
    /// `u64::MAX` yields every accounted `SEQ`.
    fn ranges_upto(&self, cutoff: u64) -> Vec<Range> {
        let mut ranges = Vec::new();
        let mut it = self.accounted.iter().copied().filter(|s| *s <= cutoff);
        if let Some(first) = it.next() {
            let (mut lo, mut hi) = (first, first);
            for s in it {
                if s == hi + 1 {
                    hi = s;
                } else {
                    ranges.push(Range { lo, hi });
                    lo = s;
                    hi = s;
                }
            }
            ranges.push(Range { lo, hi });
        }
        ranges
    }

    /// Snapshot the current metering as an unsigned [`Checkpoint`] (F5.5): the
    /// running `CUM_TOTAL`/`ACCRUALS` (monotone), `B` (signed), the accepted-`SEQ`
    /// ranges since the last checkpoint, and the transcript head. `events` are the
    /// caller's recorded references (F5.5 `EVENTS`); `timestamp`/`prev_ref` are the
    /// proposer's. The two signature slots are left empty for the caller to sign.
    pub fn build_checkpoint(
        &self,
        timestamp: u64,
        prev_ref: [u8; 32],
        events: Vec<Event>,
    ) -> Checkpoint {
        // The whole current window (the live snapshot) is the historical snapshot with
        // no cutoff.
        self.build_checkpoint_at(u64::MAX, timestamp, prev_ref, events)
    }

    /// Build the checkpoint **as of `cutoff`** — over the accepted slices with
    /// `SEQ ≤ cutoff` only, excluding any newer live-window slice (F6-c). The metering
    /// is the running total minus the excluded slices' amounts (exact — `CUM_TOTAL`,
    /// per-role `ACCRUALS`, and `BALANCE` each moved by an accepted slice's amount, so
    /// undoing the excluded ones reproduces the historical value), the transcript and
    /// `RANGES` cover exactly the included `SEQ`s, and `LAST_SEQ` is the highest included.
    /// `cutoff = u64::MAX` is the whole current window. (This assumes no funding/settlement
    /// event raced the proposal's cut; one that did leaves a legal `PAYTP_STATE_MISMATCH`
    /// round-trip, never a wrong countersignature — §6.3.)
    fn build_checkpoint_at(
        &self,
        cutoff: u64,
        timestamp: u64,
        prev_ref: [u8; 32],
        events: Vec<Event>,
    ) -> Checkpoint {
        // Amounts of the slices strictly above the cutoff — the newer live-window slices
        // this historical snapshot excludes.
        let excluded_amt: u128 = self
            .window
            .iter()
            .filter(|(seq, _)| **seq > cutoff)
            .map(|(_, s)| s.amt_micro as u128)
            .sum();
        let cum = self.cum_total.saturating_sub(excluded_amt);
        // Per-role: subtract `excluded_amt × bp_r` from each running accrual (exact BigUint).
        let excluded_big = BigUint::from(excluded_amt);
        let accruals: Vec<(u8, BigUint)> = self
            .vector
            .iter()
            .zip(self.accruals.iter())
            .map(|((role, bp), acc)| (*role, acc - &excluded_big * BigUint::from(*bp)))
            .collect();
        // Balance moved +amt per accepted slice, so undo the excluded ones.
        let hist_balance = self.balance - excluded_amt as i128;
        let (balance, balance_negative) = if hist_balance < 0 {
            (BigUint::from(hist_balance.unsigned_abs()), true)
        } else {
            (BigUint::from(hist_balance as u128), false)
        };
        let last_seq = self
            .accounted
            .iter()
            .copied()
            .rfind(|s| *s <= cutoff)
            .unwrap_or(self.floor);
        // Transcript over the committed head + the included slices (SEQ order).
        let mut head = self.committed_head;
        for (seq, slice) in self.window.iter() {
            if *seq <= cutoff {
                head = transcript::advance(&head, &slice.encode());
            }
        }
        Checkpoint {
            channel_id: self.channel_id,
            balance,
            balance_negative,
            cum_total: BigUint::from(cum),
            accruals,
            last_seq,
            ranges: self.ranges_upto(cutoff),
            transcript: head,
            events,
            timestamp,
            prev_ref,
            sig_payer: None,
            sig_merchant: None,
        }
    }

    /// The F6-c countersign decision: does a proposed checkpoint recompute to this
    /// endpoint's own metering — `CUM_TOTAL`, `ACCRUALS`, `B`, `LAST_SEQ`, the
    /// `RANGES`, and the transcript head? The proposer's `TIMESTAMP`/`PREV_REF`/
    /// `EVENTS` are its to state (not recomputed). The metering is recomputed
    /// **historically over the named ranges** — the slices at or below the proposal's
    /// `LAST_SEQ` — so a responder that accepted a NEWER slice since the proposal was
    /// cut still countersigns the older true snapshot (§6.3 / F6-c). Equality on
    /// `LAST_SEQ`/`RANGES`/transcript also rejects a proposal that omits an accepted
    /// named slice or names one this endpoint did not accept. The basis is the **prefix
    /// cutoff** (`SEQ ≤ LAST_SEQ`): a proposal naming **non-contiguous** ranges while an
    /// intermediate slice was accepted (`{1,3}` with `2` accepted) fails-closed to a legal
    /// `PAYTP_STATE_MISMATCH` (§6.3 — a round-trip, never value loss), which also keeps the
    /// commit's floor advance (`checkpoint_upto`) a clean prefix (a gap cannot strand a
    /// between-slice below the new floor).
    pub fn recomputes(&self, proposed: &Checkpoint) -> bool {
        let own = self.build_checkpoint_at(
            proposed.last_seq,
            proposed.timestamp,
            proposed.prev_ref,
            proposed.events.clone(),
        );
        own.channel_id == proposed.channel_id
            && own.cum_total == proposed.cum_total
            && own.accruals == proposed.accruals
            && own.balance == proposed.balance
            && own.balance_negative == proposed.balance_negative
            && own.last_seq == proposed.last_seq
            && own.ranges == proposed.ranges
            && own.transcript == proposed.transcript
    }

    /// Commit a bilateral checkpoint over the **whole** current window (up to the
    /// highest accounted `SEQ`, F6.3). A checkpoint that countersigned only a historical
    /// prefix (`recomputes` over a proposal's `LAST_SEQ` while newer slices are live)
    /// commits through [`ChannelState::checkpoint_upto`] instead, so the newer slices are
    /// retained, not lost.
    pub fn checkpoint(&mut self) {
        let hi = self
            .accounted
            .iter()
            .next_back()
            .copied()
            .unwrap_or(self.floor);
        self.checkpoint_upto(hi);
    }

    /// Commit the checkpoint **as of `cutoff`** (F6-c): fold the slices at or below
    /// `cutoff` into the committed transcript head (SEQ order), advance the floor to
    /// `cutoff`, and **retain the newer window slices** (`SEQ > cutoff`) for the next
    /// checkpoint — a slice accepted after the proposal was cut is never dropped from
    /// settlement/chaining (the commit bug). `CUM_TOTAL`/`ACCRUALS` (running, monotone)
    /// are not reset; the checkpoint is a view of the metering, not a counter.
    pub fn checkpoint_upto(&mut self, cutoff: u64) {
        // F5-g: fold only the named (≤ cutoff) slices into the committed head, in SEQ order.
        let mut head = self.committed_head;
        for (seq, slice) in self.window.iter() {
            if *seq <= cutoff {
                head = transcript::advance(&head, &slice.encode());
            }
        }
        self.committed_head = head;
        // Retire only the named snapshot: drop the folded slices, keep the newer ones.
        self.window.retain(|seq, _| *seq > cutoff);
        self.accounted.retain(|seq| *seq > cutoff);
        self.floor = cutoff;
        // Unevidenced now = the retained newer slices' still-unevidenced value (F6.3).
        self.unevidenced = self.window.values().map(|s| s.amt_micro as u128).sum();
        // F6.1: the bilateral checkpoint releases the evidence pause — unless the retained
        // newer value already re-reaches `E`. Never the window pause (only funding/settlement
        // clears that).
        self.paused_evidence = self.unevidenced >= self.limit_e;
    }

    /// Enter `SETTLING` (F6.1/F6-a) — from a `CLOSE` (either side) or the
    /// establishing connection's close. One-way toward `CLOSED`: no further slices
    /// are accepted; the control plane completes what is owed. Idempotent; a
    /// `CLOSED` channel is never revived.
    pub fn begin_settling(&mut self) {
        if self.phase != Phase::Closed {
            self.phase = Phase::Settling;
        }
    }

    /// Move to `CLOSED` (F6.1) once obligations resolve, erasing the session key
    /// (F1.6) so no later slice can ever authenticate. Terminal.
    ///
    /// The key is dropped entirely (`None`): after close every slice fails at the
    /// MAC — unforgeable by *anyone*, a third party or even a peer that knows the old
    /// key — so `CLOSED` leaks nothing. (A public `[0; 32]`, or any deterministic
    /// transform of the shared key, would leave a MAC key someone could forge under
    /// to pass `verify` and observe the `NotOpen` answer.)
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.k_session = None;
    }
}

/// Supersession (F6.3): which of two bilateral checkpoints at the same position
/// is operative — higher `CUM_TOTAL` wins; on equal totals, the lexicographically
/// greater `CKPT_REF` (byte comparison) is the tiebreaker.
pub fn operative<'a>(
    a: (&'a BigUint, &'a [u8; 32]),
    b: (&'a BigUint, &'a [u8; 32]),
) -> &'a [u8; 32] {
    use std::cmp::Ordering;
    match a.0.cmp(b.0) {
        Ordering::Greater => a.1,
        Ordering::Less => b.1,
        Ordering::Equal => {
            if a.1 >= b.1 {
                a.1
            } else {
                b.1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    const TCID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

    fn ks() -> [u8; 32] {
        crypto::k_session(&[1u8; 32], &[2u8; 32], &[0, 0, 0, 0, 0, 0, 0, 1])
    }

    fn vector() -> Vec<(u8, u16)> {
        vec![(0x10, 50), (0x11, 10), (0x12, 30), (0x13, 10)]
    }

    #[test]
    fn accepts_and_accrues() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        let s = Slice::seal(1, 1000, &k).unwrap();
        ch.accept_slice(&s).unwrap();
        assert_eq!(ch.cum_total(), 1000);
        assert_eq!(ch.balance(), 1000);
        assert_eq!(ch.accruals()[0].1, BigUint::from(50_000u32));
    }

    #[test]
    fn bad_mac_before_state() {
        let mut ch = ChannelState::new(TCID, ks(), Mode::Postpay, 1_000_000, 1_000_000, vector());
        let s = Slice::seal(1, 1000, &[9u8; 32]).unwrap();
        assert_eq!(ch.accept_slice(&s), Err(AcceptError::BadMac));
    }

    #[test]
    fn seq_replay_and_floor() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        let s1 = Slice::seal(1, 100, &k).unwrap();
        ch.accept_slice(&s1).unwrap();
        assert_eq!(ch.accept_slice(&s1), Err(AcceptError::SeqInvalid));
        ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()).unwrap();
        ch.checkpoint();
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()),
            Err(AcceptError::SeqInvalid)
        );
        ch.accept_slice(&Slice::seal(3, 100, &k).unwrap()).unwrap();
    }

    #[test]
    fn window_and_evidence_bounds() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 150, 100, vector());
        assert_eq!(
            ch.accept_slice(&Slice::seal(1, 101, &k).unwrap()),
            Err(AcceptError::EvidenceRequired)
        );
        assert_eq!(ch.status(), Status::Open);
        ch.accept_slice(&Slice::seal(1, 100, &k).unwrap()).unwrap();
        assert_eq!(ch.status(), Status::PausedEvidence);
        ch.checkpoint();
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 51, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
    }

    #[test]
    fn funding_reopens_window_and_floors() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1000, 1_000_000, vector());
        ch.accept_slice(&Slice::seal(1, 800, &k).unwrap()).unwrap();
        ch.credit_funding(800);
        assert_eq!(ch.balance(), 0);
        ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()).unwrap();
        ch.credit_funding(500);
        assert_eq!(ch.balance(), 0);
    }

    #[test]
    fn postpay_admits_before_funding() {
        // F6-g postpay half: a fresh postpay channel opens at B = 0 (its LOWER bound) with
        // its full L_credit of headroom above, so it admits slices in arrears with no
        // prior funding — the mirror image of the prepay deposit-before-consume rule.
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1000, 1_000_000, vector());
        assert_eq!(ch.balance(), 0);
        ch.accept_slice(&Slice::seal(1, 800, &k).unwrap()).unwrap();
        assert_eq!(ch.balance(), 800);
        assert_eq!(ch.status(), Status::Open);
    }

    #[test]
    fn prepay_deposit_before_consume_and_floors_at_minus_l() {
        let k = ks();
        // F6-g: a fresh prepay channel opens at B = 0 (its UPPER bound), so no slice is
        // acceptable until a confirmed funding drives B negative (deposit-before-consume).
        let mut ch = ChannelState::new(TCID, k, Mode::Prepay, 1000, 1_000_000, vector());
        assert_eq!(ch.balance(), 0);
        assert_eq!(
            ch.accept_slice(&Slice::seal(1, 400, &k).unwrap()),
            Err(AcceptError::WindowExceeded),
            "a pre-funding prepay slice is rejected (no free consumption)"
        );
        assert_eq!(ch.status(), Status::PausedWindow);
        // A confirmed deposit drives B negative (subtracts) and re-opens the window.
        ch.credit_funding(1000);
        assert_eq!(ch.balance(), -1000);
        assert_eq!(ch.status(), Status::Open);
        // Consumption now pushes B back up toward 0.
        ch.accept_slice(&Slice::seal(1, 400, &k).unwrap()).unwrap();
        assert_eq!(ch.balance(), -600);
        // An over-deposit floors at −L_prepay; the excess is forfeit (F6.2).
        ch.credit_funding(5000);
        assert_eq!(ch.balance(), -1000);
    }

    #[test]
    fn huge_limits_saturate_without_panic() {
        let k = ks();
        // A colossal limit (near the u128 ceiling) must not truncate/negate-panic; the
        // bound saturates and slices accrue normally.
        let mut post = ChannelState::new(TCID, k, Mode::Postpay, u128::MAX, u128::MAX, vector());
        post.accept_slice(&Slice::seal(1, 1_000, &k).unwrap())
            .unwrap();
        assert_eq!(post.balance(), 1_000);
        // Prepay opens at B = 0 (F6-g); the huge `−L_prepay` lower bound is saturated
        // (`−i128::MAX`, no negation panic) but is not the opening balance.
        let pre = ChannelState::new(TCID, k, Mode::Prepay, u128::MAX, u128::MAX, vector());
        assert_eq!(pre.balance(), 0);
    }

    #[test]
    fn huge_funding_saturates_without_panic() {
        let k = ks();
        // Prepay + a colossal funding credit must saturate on the cast AND on the
        // subtraction — never underflow/panic — then clamp at −L_prepay.
        let mut ch = ChannelState::new(TCID, k, Mode::Prepay, 1000, 1_000_000, vector());
        ch.credit_funding(1000); // deposit first (F6-g): B = 0 → −1000
        ch.accept_slice(&Slice::seal(1, 400, &k).unwrap()).unwrap(); // B = −600
        ch.credit_funding(u128::MAX);
        assert_eq!(ch.balance(), -1000);
    }

    #[test]
    fn batch_is_atomic() {
        let k = ks();
        // Large window, E = 150: the 2nd slice exceeds E → the whole batch rejects
        // with NOTHING accounted (evidence exceed does not firm-pause).
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 150, vector());
        let batch = [
            Slice::seal(1, 100, &k).unwrap(),
            Slice::seal(2, 100, &k).unwrap(),
        ];
        assert_eq!(ch.accept_batch(&batch), Err(AcceptError::EvidenceRequired));
        assert_eq!(ch.cum_total(), 0, "a rejected batch accounts nothing");
        assert_eq!(
            ch.status(),
            Status::Open,
            "no pause leaks from a rolled-back batch"
        );
        // A fitting batch commits wholly.
        let ok = [
            Slice::seal(1, 60, &k).unwrap(),
            Slice::seal(2, 60, &k).unwrap(),
        ];
        ch.accept_batch(&ok).unwrap();
        assert_eq!(ch.cum_total(), 120);
    }

    #[test]
    fn batch_window_breach_firm_pauses_the_real_channel() {
        let k = ks();
        // A window breach inside a batch rolls back metering but STILL firm-pauses
        // the real channel — a payer cannot use a batch to evade the pause.
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 150, 1_000_000, vector());
        let batch = [Slice::seal(1, 200, &k).unwrap()];
        assert_eq!(ch.accept_batch(&batch), Err(AcceptError::WindowExceeded));
        assert_eq!(ch.cum_total(), 0);
        assert_eq!(
            ch.status(),
            Status::PausedWindow,
            "batch breach firm-pauses"
        );
        // Firm: a fitting single slice is still barred until funding/settlement.
        assert_eq!(
            ch.accept_slice(&Slice::seal(1, 50, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        ch.credit_funding(1); // an actual funding releases
        assert_eq!(ch.status(), Status::Open);
        ch.accept_slice(&Slice::seal(1, 50, &k).unwrap()).unwrap();
    }

    #[test]
    fn closed_key_erasure_is_unforgeable() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        ch.close();
        // A slice forged under the PUBLIC zero key must NOT authenticate (that would
        // let an attacker distinguish CLOSED from open via the NotOpen answer).
        let forged = Slice::seal(1, 100, &[0u8; 32]).unwrap();
        assert_eq!(ch.accept_slice(&forged), Err(AcceptError::BadMac));
        // Nor under the original key.
        assert_eq!(
            ch.accept_slice(&Slice::seal(1, 100, &k).unwrap()),
            Err(AcceptError::BadMac)
        );
    }

    #[test]
    fn zero_credit_funding_does_not_release_window() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 150, 1_000_000, vector());
        ch.accept_slice(&Slice::seal(1, 100, &k).unwrap()).unwrap();
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        assert_eq!(ch.status(), Status::PausedWindow);
        // A zero-value funding/settlement moves nothing and releases nothing.
        ch.credit_funding(0);
        assert_eq!(ch.status(), Status::PausedWindow);
        ch.apply_settlement_round(0);
        assert_eq!(ch.status(), Status::PausedWindow);
    }

    #[test]
    fn supersession_tiebreaker() {
        let hi = BigUint::from(100u32);
        let lo = BigUint::from(90u32);
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        assert_eq!(operative((&hi, &a), (&lo, &b)), &a);
        assert_eq!(operative((&hi, &a), (&hi, &b)), &b);
    }

    #[test]
    fn lifecycle_pause_window_is_firm_until_release() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1000, 1_000_000, vector());
        assert_eq!(ch.status(), Status::Open);
        ch.accept_slice(&Slice::seal(1, 900, &k).unwrap()).unwrap();
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 200, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        assert_eq!(ch.status(), Status::PausedWindow);
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 50, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        ch.credit_funding(900);
        assert_eq!(ch.status(), Status::Open);
        ch.accept_slice(&Slice::seal(2, 200, &k).unwrap()).unwrap();
        assert_eq!(
            ch.accept_slice(&Slice::seal(3, 900, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        assert_eq!(ch.status(), Status::PausedWindow);
        ch.apply_settlement_round(200);
        assert_eq!(ch.status(), Status::Open);
        assert_eq!(ch.balance(), 0);
    }

    #[test]
    fn lifecycle_checkpoint_does_not_clear_a_window_pause() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1000, 1_000_000, vector());
        ch.accept_slice(&Slice::seal(1, 900, &k).unwrap()).unwrap();
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 200, &k).unwrap()),
            Err(AcceptError::WindowExceeded)
        );
        assert_eq!(ch.status(), Status::PausedWindow);
        ch.checkpoint();
        assert_eq!(ch.status(), Status::PausedWindow);
    }

    #[test]
    fn lifecycle_pause_evidence_and_checkpoint_release() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 100, vector());
        ch.accept_slice(&Slice::seal(1, 100, &k).unwrap()).unwrap();
        assert_eq!(ch.status(), Status::PausedEvidence);
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 1, &k).unwrap()),
            Err(AcceptError::EvidenceRequired)
        );
        assert_eq!(ch.status(), Status::PausedEvidence);
        ch.checkpoint();
        assert_eq!(ch.status(), Status::Open);
    }

    #[test]
    fn lifecycle_settling_and_closed_reject_slices() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        ch.accept_slice(&Slice::seal(1, 100, &k).unwrap()).unwrap();
        ch.begin_settling();
        assert_eq!(ch.status(), Status::Settling);
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()),
            Err(AcceptError::NotOpen)
        );
        ch.close();
        assert_eq!(ch.status(), Status::Closed);
        // After close, the key is erased — a slice now fails at the MAC (BadMac),
        // never reaching a state answer: closing leaks nothing (authenticate-first).
        assert_eq!(
            ch.accept_slice(&Slice::seal(2, 100, &k).unwrap()),
            Err(AcceptError::BadMac)
        );
        ch.begin_settling();
        assert_eq!(ch.status(), Status::Closed);
    }

    #[test]
    fn build_checkpoint_and_recompute() {
        let k = ks();
        let mut ch = ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        let s1 = Slice::seal(1, 10_000, &k).unwrap();
        let s2 = Slice::seal(2, 5_000, &k).unwrap();
        ch.accept_slice(&s1).unwrap();
        ch.accept_slice(&s2).unwrap();

        // The transcript head matches an independent fold of the same slices in the
        // same (ascending-SEQ) order — both parties reproduce it (F5.5/F6.3).
        let cp = ch.build_checkpoint(1_700_000_000, [0u8; 32], vec![]);
        assert_eq!(
            cp.transcript,
            crate::transcript::fold(&TCID, &[s1.encode(), s2.encode()])
        );
        assert_eq!(cp.cum_total, BigUint::from(15_000u32));
        assert_eq!(cp.last_seq, 2);
        assert_eq!(cp.ranges, vec![Range { lo: 1, hi: 2 }]);

        // A counterparty proposing this exact metering is countersignable (F6-c);
        // any metering tamper fails the recompute.
        assert!(ch.recomputes(&cp));
        let mut bad = cp.clone();
        bad.cum_total = BigUint::from(15_001u32);
        assert!(!ch.recomputes(&bad));
        let mut bad_tr = cp.clone();
        bad_tr.transcript = [0xff; 32];
        assert!(!ch.recomputes(&bad_tr));

        // Non-contiguous ranges: a gap (SEQ 4, with 3 missing) splits the run.
        ch.accept_slice(&Slice::seal(4, 1, &k).unwrap()).unwrap();
        let cp2 = ch.build_checkpoint(1_700_000_000, [0u8; 32], vec![]);
        assert_eq!(
            cp2.ranges,
            vec![Range { lo: 1, hi: 2 }, Range { lo: 4, hi: 4 }]
        );
    }

    #[test]
    fn transcript_is_sequence_order_not_acceptance_order() {
        // F5-g: the head folds in SEQ order — accepting out of order yields the SAME
        // head as in-order acceptance, so reordered arrivals never fork the head.
        let k = ks();
        let s1 = Slice::seal(1, 100, &k).unwrap();
        let s2 = Slice::seal(2, 200, &k).unwrap();

        let mut in_order =
            ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        in_order.accept_slice(&s1).unwrap();
        in_order.accept_slice(&s2).unwrap();

        let mut reordered =
            ChannelState::new(TCID, k, Mode::Postpay, 1_000_000, 1_000_000, vector());
        reordered.accept_slice(&s2).unwrap(); // SEQ 2 arrives first
        reordered.accept_slice(&s1).unwrap();

        let a = in_order.build_checkpoint(1, [0u8; 32], vec![]);
        let b = reordered.build_checkpoint(1, [0u8; 32], vec![]);
        assert_eq!(a.transcript, b.transcript);
        assert_eq!(
            a.transcript,
            crate::transcript::fold(&TCID, &[s1.encode(), s2.encode()])
        );
        // The chain continues across a checkpoint in SEQ order too.
        in_order.checkpoint();
        reordered.checkpoint();
        let s3 = Slice::seal(3, 50, &k).unwrap();
        in_order.accept_slice(&s3).unwrap();
        reordered.accept_slice(&s3).unwrap();
        assert_eq!(
            in_order.build_checkpoint(2, [0u8; 32], vec![]).transcript,
            reordered.build_checkpoint(2, [0u8; 32], vec![]).transcript
        );
    }

    #[test]
    fn new_imported_seeds_the_position_and_fails_closed() {
        let cid = [7u8; 8];
        let k = [0x11u8; 32];
        let vector = vec![(0x10u8, 5000u16), (0x11u8, 5000u16)];
        let accruals = vec![BigUint::from(3000u32), BigUint::from(1000u32)];

        // Postpay: imports CUM_TOTAL, per-role accruals, and an in-window B (the
        // successor starts at the predecessor's reconciled position, NOT zero).
        let s = ChannelState::new_imported(
            cid,
            k,
            Mode::Postpay,
            1_000_000,
            500,
            vector.clone(),
            50_000,
            accruals.clone(),
            20_000,
        )
        .unwrap();
        assert_eq!(
            s.cum_total(),
            50_000,
            "imports the predecessor CUM_TOTAL, not zero"
        );
        assert_eq!(s.balance(), 20_000, "opens at the imported B, not 0");
        assert_eq!(
            s.accruals(),
            vec![
                (0x10u8, BigUint::from(3000u32)),
                (0x11u8, BigUint::from(1000u32))
            ],
            "imports per-role accruals — the payer still owes the imported meed"
        );

        // Vector/accruals misalignment → fail-closed (never a silent fresh open).
        assert!(matches!(
            ChannelState::new_imported(
                cid,
                k,
                Mode::Postpay,
                1_000_000,
                500,
                vector.clone(),
                50_000,
                vec![BigUint::from(1u32)],
                0,
            ),
            Err(ImportError::VectorMismatch)
        ));
        // Postpay B above L_credit → outside the window → fail-closed.
        assert!(matches!(
            ChannelState::new_imported(
                cid,
                k,
                Mode::Postpay,
                10_000,
                500,
                vector.clone(),
                50_000,
                accruals.clone(),
                20_000,
            ),
            Err(ImportError::BalanceOutOfBounds)
        ));

        // Prepay imports a NEGATIVE B (−unconsumed deposit) within [−L_prepay, 0].
        let p = ChannelState::new_imported(
            cid,
            k,
            Mode::Prepay,
            1_000_000,
            500,
            vector.clone(),
            30_000,
            accruals.clone(),
            -12_000,
        )
        .unwrap();
        assert_eq!(p.balance(), -12_000);
        // Prepay B below −L_prepay → fail-closed.
        assert!(matches!(
            ChannelState::new_imported(
                cid,
                k,
                Mode::Prepay,
                10_000,
                500,
                vector,
                30_000,
                accruals,
                -20_000,
            ),
            Err(ImportError::BalanceOutOfBounds)
        ));
    }
}
