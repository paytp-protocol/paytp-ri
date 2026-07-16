//! Property-based value-conservation tests for the settlement arithmetic
//! (F7 / F6-f), now over the shared fixed-width [`paytp_core::fee`] (paytp-f7).
//! This is the executable instrument the frozen F1–F10 campaign called
//! for: the arithmetic is certified by properties that must hold for *every*
//! input, not by a handful of hand cases. (paytp-f7 additionally proves the
//! fixed-width impl equals a BigUint oracle across the domain.)

use paytp_core::fee::{self, reconcile, Rate, U256};
use proptest::prelude::*;

fn u(n: u128) -> U256 {
    U256::from(n)
}
fn sum(v: &[U256]) -> U256 {
    v.iter().fold(U256::ZERO, |a, x| a + *x)
}

proptest! {
    // A single round's division conserves value exactly (F7.2/F7.3).
    #[test]
    fn round_division_conserves_value(
        n_r in prop::collection::vec(0u64..1_000_000_000, 1..6),
        p in 1u128..1_000_000,
        q in 1u128..1_000_000,
    ) {
        let n_r: Vec<U256> = n_r.into_iter().map(|x| u(x as u128)).collect();
        let rate = Rate::new(p, q).unwrap();
        let d = fee::divide_round(&n_r, &rate).unwrap();
        let n = sum(&n_r);

        // E ≤ N.
        prop_assert!(d.e <= n, "E must not exceed N");

        // Σ E_r == E.
        prop_assert_eq!(sum(&d.e_r), d.e, "per-role extinguishment must sum to E");

        // Every E_r ≤ N_r (so next round's outstanding never goes negative).
        for (er, nr) in d.e_r.iter().zip(n_r.iter()) {
            prop_assert!(er <= nr, "E_r must not exceed its own N_r");
        }

        // Residue conservation: Σ(N_r − E_r) == N − E.
        let residue = sum(&n_r.iter().zip(d.e_r.iter()).map(|(nr, er)| *nr - *er).collect::<Vec<_>>());
        prop_assert_eq!(residue, n - d.e, "residue must be N − E and carry");

        // The E ≥ 1 leg rule (NOT P ≥ 1): the leg is carried iff E ≥ 1.
        prop_assert_eq!(d.leg, !d.e.is_zero(), "leg carried iff E ≥ 1");
    }

    // The carve is computed once on the cumulative and never undercounts a
    // per-segment split (F6-f round-7 overcharge closure).
    #[test]
    fn carve_once_never_below_split(a in 0u128..10_000_000, b in 0u128..10_000_000) {
        let once = reconcile::meed_carve(&[u(a + b)]);
        let split = reconcile::meed_carve(&[u(a)]) + reconcile::meed_carve(&[u(b)]);
        prop_assert!(once >= split, "carve-once ≥ carve(a)+carve(b)");
    }

    // Postpay funding credits toward the merchant-net debt and floors at 0 —
    // never a negative position, never a stranded overshoot (F6-f/round-18/19).
    #[test]
    fn postpay_funding_floors_at_zero(
        cum_total in 0u128..10_000_000,
        accrual in 0u128..10_000_000,
        funding in 0u128..20_000_000,
    ) {
        let out = reconcile::outstanding_merchant_net(&u(cum_total), &[u(accrual)], &u(0), &u(funding));
        // Never underflows into a huge value — i.e. it is ≤ the pre-funding debt.
        let debt = reconcile::outstanding_merchant_net(&u(cum_total), &[u(accrual)], &u(0), &u(0));
        prop_assert!(out <= debt, "funding never increases the debt");
        // More funding never yields a larger outstanding.
        let more = reconcile::outstanding_merchant_net(&u(cum_total), &[u(accrual)], &u(0), &u(funding + 1));
        prop_assert!(more <= out, "more funding is monotone non-increasing");
    }

    // claimable_d is monotone non-decreasing in V and never over-pays entitlement.
    #[test]
    fn claimable_monotone(v in 0u128..1_000_000, bp_d in 1u32..10_000) {
        let bp_total = 10_000u32;
        let zero = u(0);
        let c_v = fee::claimable_d(&u(v), bp_d, bp_total, &zero);
        let c_v1 = fee::claimable_d(&u(v + 1), bp_d, bp_total, &zero);
        prop_assert!(c_v1 >= c_v, "claimable non-decreasing in V");
        // Entitlement bound: claimable ≤ floor(V·bp_d/bp_total).
        let entitled = (u(v) * u(bp_d as u128)) / u(bp_total as u128);
        prop_assert!(c_v <= entitled, "never over entitlement");
    }
}
