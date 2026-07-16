//! **paytp-f7** — the F7 settlement arithmetic as a `no_std`, fixed-width,
//! heap-free core, shared verbatim by the host reference implementation and the
//! on-chain (SBF) contract kit. One source of the meed division so the two can
//! never diverge (the M5 core-sharing decision).
//!
//! All arithmetic is exact integer — no floating point, no rounding beyond the
//! `floor`s F7 specifies, so every implementation computes bit-identical results
//! (F10 enforces it). Values are fixed-width [`U256`]; the one intermediate that
//! exceeds 256 bits — the per-role attribution `E · N_r` — is computed in
//! [`U512`] and narrowed back under a proven bound. `num-bigint` is retained only
//! as the differential **test oracle** (see `tests`), never shipped.
//!
//! **Width bounds (the overflow proof obligation, enforced by the proptests):**
//! with numerators `N_r < 2¹²⁸` (F7-a), rate `p, q ≤ 2⁶⁴−1` (F3-g), bp ≤ 10⁴, and
//! at most [`MAX_ROLES`] roles: `N = ΣN_r < 2¹³⁴`; `N·p < 2¹⁹⁸` and `P·q·10⁴ <
//! 2²⁰⁶` both fit `U256`; the attribution product `E·N_r < 2²⁶²` needs `U512`, and
//! the quotient `E_r ≤ N_r < 2¹²⁸` narrows back to `U256`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use ruint::aliases::{U256, U512};

/// Basis-point denominator: shares are `bp / 10 000`.
pub const BP_DENOM: u32 = 10_000;

/// The maximum number of meed roles in a division (a hard proof boundary —
/// "short vector" is not a bound). Schema `0x01` uses 4; a
/// vector beyond this is rejected rather than risk an unproven width.
pub const MAX_ROLES: usize = 64;

/// Errors from F7 arithmetic — the two the spec distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F7Error {
    /// An input or output leaves the F7 domain (F7-a/F7.2/F3-g).
    ArithmeticDomain,
    /// The inputs describe an inconsistent/poisoned settlement — rejected, never
    /// repaired (F7.3).
    InconsistentProposal,
}

// `no_std`: `core::error::Error` (stable since Rust 1.81; MSRV 1.85) is the heap-free
// equivalent of `std::error::Error`, so `F7Error` composes as an error on both the host
// and the SBF contract that shares this crate.
impl core::fmt::Display for F7Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for F7Error {}

pub type Result<T> = core::result::Result<T, F7Error>;

#[inline]
fn two_pow_128() -> U256 {
    U256::from(1u8) << 128
}

/// `max(0, a − b)` — the F6-f floor.
#[inline]
fn sat_sub(a: U256, b: U256) -> U256 {
    a.saturating_sub(b)
}

/// Narrow a `U512` **proven** `< 2²⁵⁶` to `U256` (its high four 64-bit limbs are
/// zero). Debug-asserts the bound; callers establish it by the width analysis in
/// the crate docs.
#[inline]
fn narrow(big: U512) -> U256 {
    let l = big.as_limbs();
    // A hard assert (not debug_assert): even though the F7 width analysis proves
    // the high limbs are always zero here, a release-mode silent truncation of
    // financial values must be impossible by construction.
    assert!(
        l[4] == 0 && l[5] == 0 && l[6] == 0 && l[7] == 0,
        "narrow: value exceeds 256 bits"
    );
    U256::from_limbs([l[0], l[1], l[2], l[3]])
}

/// Reject any numerator outside the F7-a domain (`≥ 2¹²⁸`) — the input bound a
/// checkpoint's numerators must satisfy, enforced before any arithmetic so a sum
/// can never saturate and distort the attribution.
#[inline]
fn check_domain(n_r: &[U256]) -> Result<()> {
    if n_r.len() > MAX_ROLES {
        return Err(F7Error::ArithmeticDomain); // width proof boundary
    }
    let two128 = two_pow_128();
    for nr in n_r {
        if *nr >= two128 {
            return Err(F7Error::ArithmeticDomain);
        }
    }
    Ok(())
}

#[inline]
fn sum(values: &[U256]) -> U256 {
    values
        .iter()
        .fold(U256::ZERO, |acc, v| acc.saturating_add(*v))
}

/// A pinned conversion rate `p/q` (F3-c/F7-b): baseline minimum units per one
/// unit of the context's accounting grain. Unity (`p = q = 1`) iff
/// `DENOM = BASELINE_ASSET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    p: u128,
    q: u128,
}

impl Rate {
    /// Validate a rate: non-zero, and `p, q ≤ 2⁶⁴−1` (F3-g, the reduced bound).
    pub fn new(p: u128, q: u128) -> Result<Self> {
        if p == 0 || q == 0 {
            return Err(F7Error::InconsistentProposal); // a zero rate is invalid (F3-c)
        }
        if p > u64::MAX as u128 || q > u64::MAX as u128 {
            return Err(F7Error::ArithmeticDomain);
        }
        Ok(Rate { p, q })
    }

    /// The unity rate, for `DENOM = BASELINE_ASSET`.
    pub fn unity() -> Self {
        Rate { p: 1, q: 1 }
    }

    #[inline]
    fn p_u256(&self) -> U256 {
        U256::from(self.p)
    }
    #[inline]
    fn q_u256(&self) -> U256 {
        U256::from(self.q)
    }
}

// ---------------------------------------------------------------------------
// F7.1 Accrual
// ---------------------------------------------------------------------------

/// Accrue one accepted gross amount into per-role numerators:
/// `accrued_r += amount_µ × bp_r` — exact, no division, no rounding (F7.1).
/// `accrued` and `bp` are aligned per role. Saturating (not wrapping): a
/// pathological accrual that would exceed the type lands out-of-domain and is
/// rejected by [`divide_round`], never silently wrapped.
pub fn accrue(accrued: &mut [U256], bp: &[u16], amount_micro: u128) {
    assert_eq!(accrued.len(), bp.len(), "role alignment");
    let amount = U256::from(amount_micro);
    for (a, &b) in accrued.iter_mut().zip(bp.iter()) {
        *a = a.saturating_add(amount.saturating_mul(U256::from(b)));
    }
}

// ---------------------------------------------------------------------------
// F7.2 Division at settlement
// ---------------------------------------------------------------------------

/// The aggregate leg payment `P = floor(N × p / (q × 10 000))` (F7.2), rejected if
/// `P ≥ 2¹²⁸` (F7.2/F3-g — the output-domain check keeps a 128-bit and a bignum
/// implementation from diverging).
pub fn compute_p(n: &U256, rate: &Rate) -> Result<U256> {
    let numer = n
        .checked_mul(rate.p_u256())
        .ok_or(F7Error::ArithmeticDomain)?;
    let denom = rate.q_u256() * U256::from(BP_DENOM); // ≤ 2⁶⁴·2¹⁴, never overflows
    let p = numer / denom; // floors
    if p >= two_pow_128() {
        return Err(F7Error::ArithmeticDomain); // F7.2: P ≥ 2¹²⁸ invalid
    }
    Ok(p)
}

/// The extinguished total `E = floor(P × q × 10 000 / p)` (F7.3) — the numerator
/// quantity the payment `P` covers, never more (`floor`, not `ceil`).
pub fn compute_e(p_paid: &U256, rate: &Rate) -> Result<U256> {
    let numer = p_paid
        .checked_mul(rate.q_u256())
        .and_then(|x| x.checked_mul(U256::from(BP_DENOM)))
        .ok_or(F7Error::ArithmeticDomain)?;
    Ok(numer / rate.p_u256())
}

/// Whether a round makes **extinguishment progress** (`E ≥ 1`) and therefore
/// carries an aggregate leg (F7.3). Keying on `E ≥ 1` rather than `P ≥ 1` closes
/// the sub-extinguishment infinite-loop trap.
pub fn carries_leg(e: &U256) -> bool {
    !e.is_zero()
}

/// The result of dividing one settlement round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundDivision {
    /// `P`, the aggregate payment (0 iff no leg).
    pub p: U256,
    /// `E`, the total extinguished numerator.
    pub e: U256,
    /// Per-role extinguished numerators `E_r` (aligned to the input `n_r`).
    pub e_r: Vec<U256>,
    /// Whether an aggregate leg is carried (`E ≥ 1`).
    pub leg: bool,
}

/// Divide one round given the outstanding per-role numerators `n_r` (ascending
/// role-id order) and the rate — `P`, `E`, and the canonical per-role attribution
/// (F7.2/F7.3), including the `E ≥ 1` leg rule.
pub fn divide_round(n_r: &[U256], rate: &Rate) -> Result<RoundDivision> {
    check_domain(n_r)?; // MAX_ROLES + F7-a per-numerator bound
    let n = sum(n_r);
    let p = compute_p(&n, rate)?;
    let e = compute_e(&p, rate)?;
    if e > n {
        return Err(F7Error::InconsistentProposal); // E ≤ N by construction
    }
    let e_r = extinguish_per_role(&e, n_r)?;
    Ok(RoundDivision {
        leg: carries_leg(&e),
        p,
        e,
        e_r,
    })
}

/// The canonical per-role attribution (GAP-FILL **F7-c**): `E_r = floor(E×N_r/N)`,
/// then the shortfall `E − Σ E_r` is assigned one unit at a time to roles in
/// ascending role-id order, skipping any role already at its cap `E_r = N_r`.
/// Keeps `E_r ≤ N_r`, so the next round's outstanding never goes negative.
///
/// The product `E · N_r` reaches `2²⁶²` (F7-a domain × [`MAX_ROLES`]), so it is
/// computed in [`U512`] and the quotient — `E_r ≤ N_r < 2¹²⁸` — narrowed back.
pub fn extinguish_per_role(e: &U256, n_r: &[U256]) -> Result<Vec<U256>> {
    check_domain(n_r)?; // MAX_ROLES + F7-a bound, so `sum` cannot saturate
    let n = sum(n_r);
    if n.is_zero() {
        // Nothing accrued: E must be zero and every E_r is zero.
        if !e.is_zero() {
            return Err(F7Error::InconsistentProposal);
        }
        return Ok(n_r.iter().map(|_| U256::ZERO).collect());
    }
    // F7.3: E ≤ N by construction; a direct caller passing E > N is inconsistent
    // and MUST be rejected, never repaired (else the shortfall loop over-caps).
    if *e > n {
        return Err(F7Error::InconsistentProposal);
    }
    let e512 = U512::from(*e);
    let n512 = U512::from(n);
    let mut e_r: Vec<U256> = n_r
        .iter()
        .map(|nr| {
            // E·N_r in 512 bits (can exceed 2²⁵⁶); floor-divide by N; the quotient
            // is ≤ N_r < 2¹²⁸ so it narrows losslessly.
            let prod = e512 * U512::from(*nr);
            narrow(prod / n512)
        })
        .collect();
    let assigned = sum(&e_r);
    let mut shortfall = sat_sub(*e, assigned);
    // Ascending-role-id sweeps, +1 to each non-capped role until placed.
    while !shortfall.is_zero() {
        let mut progressed = false;
        for (er, nr) in e_r.iter_mut().zip(n_r.iter()) {
            if shortfall.is_zero() {
                break;
            }
            if *er < *nr {
                *er += U256::from(1u8);
                shortfall -= U256::from(1u8);
                progressed = true;
            }
        }
        if !progressed {
            // Aggregate spare capacity always covers the shortfall (F7.3), so this
            // is unreachable for consistent inputs; guard rather than loop.
            return Err(F7Error::InconsistentProposal);
        }
    }
    Ok(e_r)
}

// ---------------------------------------------------------------------------
// F7-d instance-side division (claimable_d)
// ---------------------------------------------------------------------------

/// A destination's withdrawable amount (GAP-FILL **F7-d**):
/// `claimable_d = floor(V × bp_d / bp_total) − paid_d`. Sub-unit residue sits in
/// `V` until later legs top it up, and is never a debt (§10.2).
pub fn claimable_d(v_received: &U256, bp_d: u32, bp_total: u32, paid_d: &U256) -> U256 {
    // A malformed share config — no shares, or a role claiming more than the whole
    // (`bp_d > bp_total`, impossible for a well-formed vector) — yields nothing
    // claimable rather than a panic. This also guarantees `entitled ≤ V`, so the
    // `narrow` below can never see a value ≥ 2²⁵⁶.
    if bp_total == 0 || bp_d > bp_total {
        return U256::ZERO;
    }
    // `V · bp_d` can exceed 256 bits for a large running `V`; compute exactly in
    // U512 (not saturating, which would undercount the payout) and narrow the
    // quotient — `entitled = floor(V·bp_d/bp_total) ≤ V < 2²⁵⁶` since `bp_d ≤
    // bp_total`.
    let entitled = narrow(
        U512::from(*v_received) * U512::from(U256::from(bp_d)) / U512::from(U256::from(bp_total)),
    );
    sat_sub(entitled, *paid_d)
}

// ---------------------------------------------------------------------------
// F6-f reconciliation arithmetic
// ---------------------------------------------------------------------------

pub mod reconcile {
    //! The F6-f rail-authoritative settlement reconciliation, as pure formulas.

    use super::*;

    /// The meed carve, computed **once on the cumulative** (F7-d/F6-f):
    /// `floor(Σ ACCRUALS_r / 10 000)`. Per-segment-then-summed undercounts
    /// (`floor(A)+floor(B) ≤ floor(A+B)`).
    pub fn meed_carve(accruals: &[U256]) -> U256 {
        sum(accruals) / U256::from(BP_DENOM)
    }

    /// Outstanding meed per role (F6-f): `accrued_r − Σ E_r(completed rounds)`.
    /// An exact difference (F7.3 keeps `settled_r ≤ accrued_r`); a violation is an
    /// inconsistent history and is rejected, never floored.
    pub fn outstanding_meed_per_role(accrued: &[U256], settled_r: &[U256]) -> Result<Vec<U256>> {
        if accrued.len() != settled_r.len() {
            return Err(F7Error::InconsistentProposal);
        }
        accrued
            .iter()
            .zip(settled_r.iter())
            .map(|(a, s)| {
                if *s > *a {
                    Err(F7Error::InconsistentProposal)
                } else {
                    Ok(*a - *s)
                }
            })
            .collect()
    }

    /// Outstanding merchant-net (F6.4/F6-f):
    /// `max(0, (CUM_TOTAL − meed_carve) − Σ(net legs) − Σ(confirmed funding))`.
    /// The `max(0, …)` floors an over-transfer to 0 (the excess is forfeit), never
    /// a negative net and never a deadlock (the round-18/19 postpay-floor fix).
    pub fn outstanding_merchant_net(
        cum_total: &U256,
        accruals: &[U256],
        net_legs_sum: &U256,
        funding_sum: &U256,
    ) -> U256 {
        let carve = meed_carve(accruals);
        let base = sat_sub(*cum_total, carve);
        let after_legs = sat_sub(base, *net_legs_sum);
        sat_sub(after_legs, *funding_sum)
    }

    /// Prepay unconsumed deposit (F6-f): `Σ funding − CUM_TOTAL`. Consumption never
    /// exceeds the deposit in a prepay channel; a violation is inconsistent and
    /// rejected, not floored.
    pub fn prepay_unconsumed_deposit(funding_sum: &U256, cum_total: &U256) -> Result<U256> {
        if *cum_total > *funding_sum {
            return Err(F7Error::InconsistentProposal);
        }
        Ok(*funding_sum - *cum_total)
    }

    /// The close-time dust reversion credit to the merchant (F7-d/F6-f):
    /// `floor(Σ ACCRUALS / 10 000) − floor(Σ E / 10 000)` — value conserves to the
    /// µ-unit. Rejects the raw inconsistency `ΣE > ΣACCRUALS` (not just the floored
    /// carves), which is impossible under F7.3.
    pub fn close_reversion_credit(accruals: &[U256], extinguished_sum: &U256) -> Result<U256> {
        let total_accrued = sum(accruals);
        if *extinguished_sum > total_accrued {
            return Err(F7Error::InconsistentProposal);
        }
        let accrued_carve = meed_carve(accruals);
        let settled_carve = *extinguished_sum / U256::from(BP_DENOM);
        Ok(accrued_carve - settled_carve)
    }
}

#[cfg(test)]
mod tests;
