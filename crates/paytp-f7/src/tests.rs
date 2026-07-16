//! paytp-f7 verification: the F10 worked vectors, plus a **differential proptest**
//! proving the fixed-width implementation agrees bit-for-bit with a `num-bigint`
//! oracle across the full F7 domain, plus a **width stress** driving the `E·N_r`
//! intermediate to ~2²⁶² (the `U512` path). The BigUint oracle is test-only.

extern crate std;

use super::reconcile::*;
use super::*;
use num_bigint::BigUint;
use proptest::prelude::*;
use std::prelude::v1::*;

fn u(x: u128) -> U256 {
    U256::from(x)
}
fn us(v: &[u128]) -> Vec<U256> {
    v.iter().map(|&x| u(x)).collect()
}
fn to_big(x: U256) -> BigUint {
    BigUint::from_bytes_le(&x.to_le_bytes::<32>())
}

// ---------------------------------------------------------------------------
// F10 worked vectors (ported from the host oracle — must stay bit-identical)
// ---------------------------------------------------------------------------

#[test]
fn f7_vector_a() {
    // F10.3 A: N=40000, rate 0.3 (3/10), N_r=20000/4000/12000/4000.
    let n_r = us(&[20000, 4000, 12000, 4000]);
    let d = divide_round(&n_r, &Rate::new(3, 10).unwrap()).unwrap();
    assert_eq!(d.p, u(1));
    assert_eq!(d.e, u(33333));
    assert_eq!(d.e_r, us(&[16667, 3334, 9999, 3333]));
    assert!(d.leg);
    let residues: Vec<U256> = n_r
        .iter()
        .zip(d.e_r.iter())
        .map(|(nr, er)| *nr - *er)
        .collect();
    assert_eq!(residues, us(&[3333, 666, 2001, 667]));
    assert_eq!(sum(&residues), u(6667)); // N − E
}

#[test]
fn f7_vector_b() {
    // F10.3 B: N=10000, rate 1.5 (3/2), N_r=4000/6000.
    let n_r = us(&[4000, 6000]);
    let d = divide_round(&n_r, &Rate::new(3, 2).unwrap()).unwrap();
    assert_eq!(d.p, u(1));
    assert_eq!(d.e, u(6666));
    assert_eq!(d.e_r, us(&[2667, 3999]));
}

#[test]
fn f7_sub_extinguishment_trap_carries_no_leg() {
    // F10.3 trap: N=1, rate 15000/1 → P=1 but E=0 → NO leg, N carries.
    let d = divide_round(&us(&[1]), &Rate::new(15000, 1).unwrap()).unwrap();
    assert_eq!(d.p, u(1));
    assert_eq!(d.e, u(0));
    assert!(!d.leg);
    assert_eq!(d.e_r, us(&[0]));
}

#[test]
fn f7_zero_and_unity() {
    let d = divide_round(&us(&[0, 0]), &Rate::unity()).unwrap();
    assert_eq!((d.p, d.e, d.leg), (u(0), u(0), false));
    // Unity: N=25000 → P=floor(25000/10000)=2, E=floor(2*10000/1)=20000.
    let d = divide_round(&us(&[25000]), &Rate::unity()).unwrap();
    assert_eq!(d.p, u(2));
    assert_eq!(d.e, u(20000));
    assert!(d.leg);
}

#[test]
fn f7_domain_rejects() {
    // P ≥ 2^128 → reject on the output domain (F7.2).
    let n_r = vec![u(u128::MAX)];
    assert_eq!(
        divide_round(&n_r, &Rate::new(u64::MAX as u128, 1).unwrap()),
        Err(F7Error::ArithmeticDomain)
    );
    // The public extinguish helper rejects E > N (F7.3, no over-cap).
    assert_eq!(
        extinguish_per_role(&u(2), &us(&[1])),
        Err(F7Error::InconsistentProposal)
    );
    // A rate with p or q > 2^64-1 is rejected; a zero rate too.
    assert_eq!(
        Rate::new((u64::MAX as u128) + 1, 1),
        Err(F7Error::ArithmeticDomain)
    );
    assert_eq!(Rate::new(0, 1), Err(F7Error::InconsistentProposal));
    // Too many roles is rejected (width proof boundary).
    let many = vec![u(1); MAX_ROLES + 1];
    assert_eq!(
        divide_round(&many, &Rate::unity()),
        Err(F7Error::ArithmeticDomain)
    );
}

#[test]
fn claimable_wide_and_zero_total() {
    // V·bp_d exceeds 256 bits — must be EXACT (a saturating impl would undercount).
    let vmax = U256::MAX;
    assert_eq!(claimable_d(&vmax, 10_000, 10_000, &u(0)), vmax); // full share = V
    assert_eq!(
        to_big(claimable_d(&vmax, 5000, 10000, &u(0))),
        oracle::claimable(&to_big(vmax), 5000, 10000, &BigUint::from(0u8))
    );
    // bp_total = 0 → no shares → 0, never a division-by-zero panic.
    assert_eq!(claimable_d(&u(100), 0, 0, &u(0)), u(0));
    // Malformed ratio bp_d > bp_total (share > whole) → 0, never a narrow panic.
    assert_eq!(claimable_d(&U256::MAX, 2, 1, &u(0)), u(0));
}

#[test]
fn extinguish_rejects_out_of_domain() {
    // The public helper enforces F7-a (< 2¹²⁸) and MAX_ROLES, so `sum` cannot
    // saturate and mis-attribute.
    let over = U256::from(1u8) << 128;
    assert_eq!(
        extinguish_per_role(&u(1), &[over]),
        Err(F7Error::ArithmeticDomain)
    );
    // The saturating-sum attack (E=MAX, N_r=[MAX,MAX]) is rejected, not divided
    // into ΣE_r > E.
    assert_eq!(
        extinguish_per_role(&U256::MAX, &[U256::MAX, U256::MAX]),
        Err(F7Error::ArithmeticDomain)
    );
}

#[test]
fn f7_instance_claimable_rule() {
    // F10.3 instance rule: V=1, bp 40/60 → claimable 0/0, residue 1; V=2 → 0/1.
    let z = u(0);
    assert_eq!(claimable_d(&u(1), 40, 100, &z), u(0));
    assert_eq!(claimable_d(&u(1), 60, 100, &z), u(0));
    assert_eq!(claimable_d(&u(2), 40, 100, &z), u(0));
    assert_eq!(claimable_d(&u(2), 60, 100, &z), u(1));
}

#[test]
fn f6f_reconcile_vectors() {
    // carve-once ≥ split-carve (round-7 overcharge closure).
    assert_eq!(meed_carve(&us(&[15000])) + meed_carve(&us(&[16000])), u(2));
    assert_eq!(meed_carve(&us(&[31000])), u(3));
    // outstanding meed: fully settled → zero; settled>accrued → reject.
    assert_eq!(
        outstanding_meed_per_role(&us(&[20000, 4000]), &us(&[20000, 4000])).unwrap(),
        us(&[0, 0])
    );
    assert_eq!(
        outstanding_meed_per_role(&us(&[10]), &us(&[11])),
        Err(F7Error::InconsistentProposal)
    );
    // postpay over-funding floors at 0; partial reduces exactly.
    let (ct, acc, legs) = (u(100_000), us(&[100_000]), u(0));
    assert_eq!(
        outstanding_merchant_net(&ct, &acc, &legs, &u(200_000)),
        u(0)
    );
    assert_eq!(
        outstanding_merchant_net(&ct, &acc, &legs, &u(90_000)),
        u(9_990)
    );
    // prepay unconsumed; over-consumption rejected.
    assert_eq!(
        prepay_unconsumed_deposit(&u(50_000), &u(30_000)).unwrap(),
        u(20_000)
    );
    assert_eq!(
        prepay_unconsumed_deposit(&u(30_000), &u(50_000)),
        Err(F7Error::InconsistentProposal)
    );
    // close reversion = accrued carve − settled carve; raw ΣE>ΣACCRUALS rejected.
    assert_eq!(
        close_reversion_credit(&us(&[31000]), &u(25000)).unwrap(),
        u(1)
    );
    assert_eq!(
        close_reversion_credit(&us(&[15000]), &u(15999)),
        Err(F7Error::InconsistentProposal)
    );
}

/// Width stress: 64 roles each `2¹²⁸−1` at unity drives `N ≈ 2¹³⁴`, `E ≈ 2¹³⁴`,
/// so `E·N_r ≈ 2²⁶²` — the `U512` path. Must complete (no `narrow` panic) and
/// conserve value.
#[test]
fn widest_intermediate_no_panic_and_conserves() {
    let n_r = vec![u(u128::MAX); MAX_ROLES];
    let d = divide_round(&n_r, &Rate::unity()).unwrap();
    // Value conservation: Σ E_r == E, and each E_r ≤ N_r.
    assert_eq!(sum(&d.e_r), d.e);
    for (er, nr) in d.e_r.iter().zip(n_r.iter()) {
        assert!(*er <= *nr);
    }
    // And the fixed-width result equals the BigUint oracle.
    let o =
        oracle::divide_round(&n_r.iter().map(|x| to_big(*x)).collect::<Vec<_>>(), 1, 1).unwrap();
    assert_eq!(to_big(d.p), o.0);
    assert_eq!(to_big(d.e), o.1);
    assert_eq!(d.e_r.iter().map(|x| to_big(*x)).collect::<Vec<_>>(), o.2);
}

// ---------------------------------------------------------------------------
// The BigUint oracle (test-only) — a faithful re-statement of the F7 formulas.
// ---------------------------------------------------------------------------

mod oracle {
    use alloc::vec::Vec;
    use num_bigint::BigUint;
    use num_traits::Zero;

    fn bp() -> BigUint {
        BigUint::from(10_000u32)
    }
    fn two128() -> BigUint {
        BigUint::from(1u8) << 128u32
    }
    fn sat_sub(a: &BigUint, b: &BigUint) -> BigUint {
        if a >= b {
            a - b
        } else {
            BigUint::zero()
        }
    }

    /// Returns `(P, E, E_r)` or `None` if the round is out of domain / inconsistent.
    #[allow(clippy::type_complexity)]
    pub fn divide_round(
        n_r: &[BigUint],
        p: u128,
        q: u128,
    ) -> Option<(BigUint, BigUint, Vec<BigUint>)> {
        let (pp, qq) = (BigUint::from(p), BigUint::from(q));
        for nr in n_r {
            if nr >= &two128() {
                return None;
            }
        }
        let n: BigUint = n_r.iter().sum();
        let big_p = (&n * &pp) / (&qq * bp());
        if big_p >= two128() {
            return None; // P ≥ 2^128
        }
        let e = (&big_p * &qq * bp()) / &pp;
        if e > n {
            return None;
        }
        let e_r = extinguish(&e, n_r)?;
        Some((big_p, e, e_r))
    }

    pub fn extinguish(e: &BigUint, n_r: &[BigUint]) -> Option<Vec<BigUint>> {
        let n: BigUint = n_r.iter().sum();
        if n.is_zero() {
            return if e.is_zero() {
                Some(n_r.iter().map(|_| BigUint::zero()).collect())
            } else {
                None
            };
        }
        if e > &n {
            return None;
        }
        let mut e_r: Vec<BigUint> = n_r.iter().map(|nr| (e * nr) / &n).collect();
        let assigned: BigUint = e_r.iter().sum();
        let mut shortfall = sat_sub(e, &assigned);
        while !shortfall.is_zero() {
            let mut progressed = false;
            for (er, nr) in e_r.iter_mut().zip(n_r.iter()) {
                if shortfall.is_zero() {
                    break;
                }
                if &*er < nr {
                    *er += 1u8;
                    shortfall -= 1u8;
                    progressed = true;
                }
            }
            if !progressed {
                return None;
            }
        }
        Some(e_r)
    }

    pub fn claimable(v: &BigUint, bp_d: u32, bp_total: u32, paid: &BigUint) -> BigUint {
        let entitled = (v * BigUint::from(bp_d)) / BigUint::from(bp_total);
        sat_sub(&entitled, paid)
    }
}

// ---------------------------------------------------------------------------
// Differential proptests: fixed-width == BigUint oracle across the F7 domain.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// `divide_round` agrees with the oracle for random numerators (full u128
    /// domain, i.e. every N_r < 2¹²⁸) and random rate (p, q ∈ [1, 2⁶⁴−1]), across
    /// 1..=MAX_ROLES roles. Agreement includes rejection: both accept or both
    /// reject the same inputs.
    #[test]
    fn divide_round_matches_oracle(
        raw in prop::collection::vec(any::<u128>(), 1..=MAX_ROLES),
        p in 1u64..=u64::MAX,
        q in 1u64..=u64::MAX,
    ) {
        let n_r = us(&raw);
        let n_big: Vec<BigUint> = raw.iter().map(|&x| BigUint::from(x)).collect();
        let got = divide_round(&n_r, &Rate::new(p as u128, q as u128).unwrap());
        let want = oracle::divide_round(&n_big, p as u128, q as u128);
        match (got, want) {
            (Ok(d), Some((op, oe, oer))) => {
                prop_assert_eq!(to_big(d.p), op);
                prop_assert_eq!(to_big(d.e), oe);
                prop_assert_eq!(d.e_r.iter().map(|x| to_big(*x)).collect::<Vec<_>>(), oer);
            }
            (Err(_), None) => {} // both reject — agreement
            (g, w) => prop_assert!(false, "disagree: fixed={:?} oracle_ok={}", g.is_ok(), w.is_some()),
        }
    }

    /// `claimable_d` agrees with the oracle over a WIDE value range — `v` spans the
    /// full 256 bits (built from two u128 halves) so the `V·bp_d` intermediate
    /// exceeds 256 bits, exercising the U512 path (a saturating impl would
    /// undercount here).
    #[test]
    fn claimable_matches_oracle(
        hi in any::<u128>(), lo in any::<u128>(),
        bp_d in 0u32..=10_000,
        paid in any::<u128>(),
    ) {
        let bp_total = 10_000u32;
        let v = (U256::from(hi) << 128) | U256::from(lo);
        let got = claimable_d(&v, bp_d, bp_total, &u(paid));
        let want = oracle::claimable(&to_big(v), bp_d, bp_total, &BigUint::from(paid));
        prop_assert_eq!(to_big(got), want);
    }

    /// The narrowing path is exercised without panic for the widest legal inputs:
    /// many max numerators with a rate that keeps P in domain. Any width bug would
    /// trip `narrow`'s debug assertion here.
    #[test]
    fn wide_inputs_never_panic(
        raw in prop::collection::vec((u128::MAX/2)..=u128::MAX, 2..=MAX_ROLES),
    ) {
        let n_r = us(&raw);
        // Unity keeps P = floor(N/10000) < 2^128 while E ≈ N, maximizing E·N_r.
        let _ = divide_round(&n_r, &Rate::unity()); // must not panic
    }
}
