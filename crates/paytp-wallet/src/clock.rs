//! A wallet-owned monotonic clock (C1-9) — the anchor for the F6.5 `TH_TIME`
//! settlement trigger.
//!
//! The wallet reads time from an **injected** clock; the protocol logic never calls
//! the host wall clock directly, so the lib's own tests are deterministic (they inject
//! [`ManualClock`]). The trigger's anchor is ALWAYS the wallet's own local clock —
//! **NEVER** a `Checkpoint.timestamp`, which the wallet does not validate
//! (`checkpoint_basis_ok` ignores it, F5.4) and an untrusted interaction layer or
//! merchant could set to `u64::MAX − th_time` to defer the halt forever
//! (`08-timeouts-clocks.md` names `last_settle` as "the acting party's own wall clock",
//! and here the acting party is the wallet).

/// A source of monotonically-nondecreasing wall-clock seconds. Object-safe, so a channel
/// can hold `&dyn Clock` without threading a type parameter through the whole lifecycle.
pub trait Clock {
    /// The current time in whole seconds. MUST be monotonically nondecreasing across calls
    /// for one channel — the `TH_TIME` deadline arithmetic assumes time never runs backwards
    /// (a backwards jump is defended with `saturating_sub`, never a panic/underflow).
    fn now(&self) -> u64;
}

/// The production clock: the host wall clock in whole seconds since the Unix epoch.
///
/// Reading the host clock lives in the caller's binary, not the protocol logic — the lib
/// never instantiates this itself, so lib tests stay deterministic. A pre-epoch host clock
/// fails **closed** to `0` (the earliest time), which can only make a deadline fire *sooner*,
/// never later — safe for a settlement halt.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A deterministic, manually-advanced clock for tests and reproducible vectors. Interior
/// mutability (a `Cell`) lets a test hold a shared reference the channel borrows while still
/// advancing time between wallet actions.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::cell::Cell<u64>,
}

impl ManualClock {
    /// A clock reading `start` seconds until advanced.
    pub fn new(start: u64) -> Self {
        Self {
            now: std::cell::Cell::new(start),
        }
    }

    /// Advance the clock by `secs` (monotone; saturates rather than wraps).
    pub fn advance(&self, secs: u64) {
        self.now.set(self.now.get().saturating_add(secs));
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_reads_and_advances_monotonically() {
        let c = ManualClock::new(1_000);
        assert_eq!(c.now(), 1_000);
        c.advance(3_600);
        assert_eq!(c.now(), 4_600);
        // Saturates rather than wrapping.
        c.advance(u64::MAX);
        assert_eq!(c.now(), u64::MAX);
    }

    #[test]
    fn system_clock_is_object_safe_and_nonzero() {
        // Object-safety: a `&dyn Clock` is usable (the shape the channel stores).
        let sys = SystemClock;
        let dyn_clock: &dyn Clock = &sys;
        // Any real epoch time is well past 0; the point is that reading it compiles and runs.
        assert!(dyn_clock.now() > 0);
    }
}
