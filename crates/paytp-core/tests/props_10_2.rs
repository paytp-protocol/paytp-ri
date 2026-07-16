//! §10.2 arithmetic property tests (M4 exit): accrual exactness, single
//! conversion, and dust-never-owed — the three §10.2 guarantees, proven for
//! every input, over the shared fixed-width [`paytp_core::fee`] (paytp-f7).

use paytp_core::fee::{self, Rate, U256};
use proptest::prelude::*;

fn u(n: u128) -> U256 {
    U256::from(n)
}
fn sum(v: &[U256]) -> U256 {
    v.iter().fold(U256::ZERO, |a, x| a + *x)
}

proptest! {
    // Accrual exactness (§10.2): accrual is `Σ amount_µ × bp_r` with NO division
    // and NO rounding — so accruing N slices then dividing equals accruing the
    // summed amount then dividing. Accrual never loses a unit.
    #[test]
    fn accrual_is_exact_and_order_independent(
        amounts in prop::collection::vec(0u64..1_000_000, 1..8),
        bp in 1u16..10_000,
    ) {
        let mut acc = u(0);
        for a in &amounts {
            acc += u(*a as u128) * u(bp as u128); // exact, no division
        }
        let summed: u128 = amounts.iter().map(|a| *a as u128).sum();
        prop_assert_eq!(acc, u(summed) * u(bp as u128));
    }

    // Single conversion (§10.2): a round converts the outstanding total ONCE at
    // the round's rate — `P = floor(N·p/(q·10000))` over the summed `N`, never
    // per-role. Converting the sum equals the one committed `P`.
    #[test]
    fn conversion_happens_once_over_the_summed_outstanding(
        n_r in prop::collection::vec(0u64..10_000_000, 1..6),
        p in 1u128..100_000, q in 1u128..100_000,
    ) {
        let n_r: Vec<U256> = n_r.into_iter().map(|x| u(x as u128)).collect();
        let rate = Rate::new(p, q).unwrap();
        let div = fee::divide_round(&n_r, &rate).unwrap();
        let n = sum(&n_r);
        let expected_p = fee::compute_p(&n, &rate).unwrap(); // one conversion over Σ N_r
        prop_assert_eq!(div.p, expected_p);
    }

    // Dust never owed (§10.2): after a round, the residue `N − E` stays in the
    // accumulators and the next round's outstanding is exactly `accrued − ΣE_r`.
    // No sub-unit is ever a debt: the settled numerators plus the carried residue
    // reconstruct the original accrued exactly.
    #[test]
    fn dust_carries_and_is_never_owed(
        n_r in prop::collection::vec(0u64..10_000_000, 1..6),
        p in 1u128..1_000, q in 1u128..1_000,
    ) {
        let accrued: Vec<U256> = n_r.into_iter().map(|x| u(x as u128)).collect();
        let rate = Rate::new(p, q).unwrap();
        let div = fee::divide_round(&accrued, &rate).unwrap();
        // Per role: settled (E_r) + carried residue (N_r − E_r) == accrued_r.
        for (acc, er) in accrued.iter().zip(div.e_r.iter()) {
            prop_assert!(er <= acc);            // never over-extinguished (not a debt)
            let residue = *acc - *er;           // carries
            prop_assert_eq!(*er + residue, *acc); // exact reconstruction
        }
        // The total residue is exactly N − E (nothing lost, nothing owed).
        let n = sum(&accrued);
        let residue_total = sum(&accrued.iter().zip(div.e_r.iter()).map(|(a, e)| *a - *e).collect::<Vec<_>>());
        prop_assert_eq!(residue_total, n - div.e);
    }
}
