//! Settlement-round triggers and the prepay meed halt (**F6.4 / §6.4**).
//!
//! The interim-round trigger matrix: a conformant debtor (payer in postpay,
//! merchant in prepay) MUST have begun a settlement round by these points; they
//! are **ceilings, not schedules** — the debtor MAY propose earlier at will. The
//! creditor's remedy against a debtor that does not is the standing one: pause at
//! the window/evidence bound and close from the last bilateral checkpoint (§6.4).
//!
//! These are pure decision functions over an already-reconciled position (F6-f):
//! the caller supplies the unsettled DENOM value and whether it is *settleable*
//! ([`settleable`]); the round arithmetic itself lives in
//! [`crate::channel::settlement`] / [`crate::fee`]. The window-exhaustion and
//! channel-close triggers are lifecycle events (§6.1/§6.4), not threshold reads, so
//! they are the driver's, not here.
//!
//! **In-flight rounds are the caller's to net out.** A round is "begun" the moment
//! the debtor *proposes* it — not when it finalizes on the rail (which can take the
//! whole `SETTLE_TIMEOUT`). So the position these functions judge is always the
//! value **not yet covered by a begun round**, and `last_settle` is the last
//! **begun** round's timestamp. Netting a just-proposed round out of the unsettled
//! value (and advancing `last_settle` to its proposal time) is exactly what makes a
//! halted prepay payer "resume when the merchant runs it" — while *new* value
//! streamed on top still re-triggers and re-halts. The driver tracks that lifecycle
//! state; this module stays a pure read of the residual.

/// Why a settlement round is due (F6.4). `None` means no round is compelled yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Reconciled unsettled value reached `TH_VALUE` (with settleable value).
    Value,
    /// `now − last_settle ≥ TH_TIME` with settleable unsettled value.
    Time,
    /// No round compelled.
    None,
}

/// Whether an unsettled position can actually settle *this* round (F7.3), the gate
/// on both triggers: a **net leg due** (`outstanding_merchant_net > 0`), **or**
/// meed that **extinguishes `E ≥ 1`**. Meed that would pay `P ≥ 1` but
/// extinguish `E = 0` (sub-`P` dust) with no net leg is **unsettleable**: it
/// compels no round and carries (F7.3). `e_extinguished` is the extinguished
/// numerator `Σ E_r` the round would produce over the **outstanding** accruals
/// (`ACCRUALS − opening_settled`; `crate::fee` / the settlement
/// [`crate::channel::Round`]) — **not** the payable carve `P`, which does not
/// distinguish the `E = 0` trap.
pub fn settleable(outstanding_merchant_net: u128, e_extinguished: u128) -> bool {
    outstanding_merchant_net > 0 || e_extinguished >= 1
}

/// Evaluate the F6.4 value/time triggers for the current position.
///
/// - `unsettled_value` — the reconciled `metered − rail-paid` DENOM position (F6-f),
///   **net of any begun (proposed/in-flight) round**. **Postpay:** a party may use
///   its live `B` estimate ([`crate::channel::ChannelState::unsettled_estimate`])
///   less the in-flight value. **Prepay:** `B ≤ 0`, so the value is the outstanding
///   meed carve from reconciliation, never `unsettled_estimate` (which reads `0`
///   while the deposit holds).
/// - `settleable` — [`settleable`] for this residual position; gates **both**
///   triggers, so an unsettleable position (sub-`P` dust, `E = 0`, no net leg)
///   compels no round and can never deadlock a halted payer waiting on a round the
///   debtor cannot run.
/// - `last_settle` — the last **begun** round's timestamp (its proposal), on the
///   party's own clock; before any round it seeds from `CHANNEL_AUTH.TIMESTAMP`
///   (`Established::established_at`), so a fresh channel does not spuriously
///   time-trigger from epoch 0 (F8.4b). Advancing it when a round is proposed is
///   what resets the time trigger for the covered value.
/// - `TH_VALUE = 0` **disables** the value trigger (time-only settlement) and
///   `TH_TIME = 0` **disables** the time trigger (value-only); the window/evidence
///   bound and close remain the backstops, so disabling a trigger defers settlement,
///   never blocks it (F5.2 / F6.5).
pub fn evaluate(
    unsettled_value: u128,
    settleable: bool,
    now: u64,
    last_settle: u64,
    th_value: u128,
    th_time: u64,
) -> Trigger {
    // F6.5/F7.3: an unsettleable position compels no round, whatever its value/age —
    // both threshold triggers gate on settleability.
    if !settleable {
        return Trigger::None;
    }
    // A threshold of 0 disables *that* trigger (F5.2): TH_VALUE=0 → time-only,
    // TH_TIME=0 → value-only.
    if th_value > 0 && unsettled_value >= th_value {
        return Trigger::Value;
    }
    if th_time > 0 && now.saturating_sub(last_settle) >= th_time {
        return Trigger::Time;
    }
    Trigger::None
}

/// The prepay meed halt (§6.4): a conformant payer stops streaming slices once a
/// round is due on the **un-proposed** position and resumes when the merchant runs
/// (proposes) it. Since [`evaluate`] already judges the residual not-yet-begun
/// value with `last_settle` at the last begun round, the halt is simply "a round is
/// due" — proposing the due round nets its value out and advances `last_settle`, so
/// the next call sees no trigger and the payer resumes, while *new* streamed value
/// re-triggers and re-halts. No new message, no new error — the payer's standing
/// right to decide how much to stream.
pub fn prepay_halt(trigger: Trigger) -> bool {
    !matches!(trigger, Trigger::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TH_VALUE: u128 = 10_000;
    const TH_TIME: u64 = 3_600;
    const T0: u64 = 1_700_000_000;

    #[test]
    fn settleable_rule() {
        // A net leg due → settleable, regardless of meed.
        assert!(settleable(1, 0));
        // Meed extinguishing E ≥ 1 → settleable, regardless of net leg.
        assert!(settleable(0, 1));
        // No net leg and E = 0 (the sub-P dust trap) → NOT settleable.
        assert!(!settleable(0, 0));
    }

    #[test]
    fn value_trigger_fires_on_reach_when_settleable() {
        // Below the threshold, not time-due → no round.
        assert_eq!(
            evaluate(9_999, true, T0, T0, TH_VALUE, TH_TIME),
            Trigger::None
        );
        // Reaching TH_VALUE exactly fires (rule is *reach*, so `≥`) — settleable.
        assert_eq!(
            evaluate(10_000, true, T0, T0, TH_VALUE, TH_TIME),
            Trigger::Value
        );
        assert_eq!(
            evaluate(20_000, true, T0, T0, TH_VALUE, TH_TIME),
            Trigger::Value
        );
    }

    #[test]
    fn unsettleable_value_never_triggers() {
        // Value ≥ TH_VALUE but unsettleable (E = 0, no net leg): NO round — this is
        // the dust-deadlock guard (a halted payer would otherwise wait forever).
        assert_eq!(
            evaluate(50_000, false, T0, T0, TH_VALUE, TH_TIME),
            Trigger::None
        );
        // Even with time elapsed, unsettleable → no round.
        assert_eq!(
            evaluate(50_000, false, T0 + TH_TIME, T0, TH_VALUE, TH_TIME),
            Trigger::None
        );
    }

    #[test]
    fn zero_value_threshold_disables_value_trigger() {
        // TH_VALUE = 0 → value trigger off; only the time trigger can fire (F5.2).
        assert_eq!(evaluate(50_000, true, T0, T0, 0, TH_TIME), Trigger::None);
        assert_eq!(
            evaluate(50_000, true, T0 + TH_TIME, T0, 0, TH_TIME),
            Trigger::Time
        );
    }

    #[test]
    fn zero_time_threshold_disables_time_trigger() {
        // TH_TIME = 0 → time trigger off; only the value trigger can fire (F5.2).
        // A huge elapsed does NOT fire the time trigger when TH_TIME is 0.
        assert_eq!(
            evaluate(500, true, T0 + 1_000_000, T0, TH_VALUE, 0),
            Trigger::None
        );
        assert_eq!(
            evaluate(TH_VALUE, true, T0 + 1_000_000, T0, TH_VALUE, 0),
            Trigger::Value
        );
        // Both thresholds 0 → both disabled; settlement defers to window/close backstops.
        assert_eq!(
            evaluate(999_999, true, T0 + 1_000_000, T0, 0, 0),
            Trigger::None
        );
    }

    #[test]
    fn time_trigger_requires_elapsed_and_settleable() {
        // Not yet elapsed, settleable → no round.
        assert_eq!(
            evaluate(500, true, T0 + TH_TIME - 1, T0, TH_VALUE, TH_TIME),
            Trigger::None
        );
        // Elapsed AND settleable → time round.
        assert_eq!(
            evaluate(500, true, T0 + TH_TIME, T0, TH_VALUE, TH_TIME),
            Trigger::Time
        );
    }

    #[test]
    fn value_takes_precedence_over_time() {
        assert_eq!(
            evaluate(10_000, true, T0 + TH_TIME, T0, TH_VALUE, TH_TIME),
            Trigger::Value
        );
    }

    #[test]
    fn prepay_halt_over_the_residual_position() {
        // A due round halts the payer.
        assert!(prepay_halt(Trigger::Value));
        assert!(prepay_halt(Trigger::Time));
        assert!(!prepay_halt(Trigger::None));
        // Resume model: the merchant proposes the due round, netting its value out.
        // The residual position (evaluated on the un-proposed value) no longer
        // triggers, so the payer resumes — WITHOUT a blanket in-flight override.
        let unsettled = 12_000u128;
        assert!(prepay_halt(evaluate(
            unsettled, true, T0, T0, TH_VALUE, TH_TIME
        )));
        let in_flight = 12_000u128; // merchant proposed a round covering it all
        let residual = unsettled - in_flight;
        assert!(!prepay_halt(evaluate(
            residual, false, T0, T0, TH_VALUE, TH_TIME
        )));
        // New value streamed on top of the in-flight round re-halts.
        let new_streamed = 15_000u128; // residual after netting the in-flight round
        assert!(prepay_halt(evaluate(
            new_streamed,
            true,
            T0,
            T0,
            TH_VALUE,
            TH_TIME
        )));
    }
}
