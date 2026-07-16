//! A channel settlement round (**F5.6/F6.5/F7.2**).
//!
//! A round converts the operative checkpoint's *outstanding* meed numerators
//! (`accrued − Σ settled`, F6-f) at the round's rate into the aggregate `P`,
//! extinguishes `E` (per-role `E_r`), and — iff it makes extinguishment progress
//! (`E ≥ 1`, F7.3) — funds a claim-record `(CHANNEL_ID ‖ CKPT_REF)`. The pure
//! arithmetic is the shared [`crate::fee`] (paytp-f7); this layer applies the
//! F6-f "outstanding = metered − settled" framing and converts the wire
//! [`BigUint`] numerators to fixed-width [`U256`] at the arithmetic boundary.

use crate::error::Result;
use crate::fee::{self, reconcile, Rate, RoundDivision, U256};
use num_bigint::BigUint;

/// A computed settlement round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// The role ids this round settles (ascending), aligned to `division.e_r`.
    pub roles: Vec<u8>,
    /// The F7 division: `P`, `E`, per-role `E_r`, and whether a leg is carried
    /// (fixed-width, from the shared `paytp-f7`).
    pub division: RoundDivision,
}

impl Round {
    /// Compute a round from the checkpoint's per-role **accrued** numerators and
    /// the per-role **already-settled** numerators (F6-f: outstanding =
    /// accrued − settled), at `rate`. Both slices are `(role, numerator)`
    /// ascending and MUST name the same roles. Wire numerators are converted to
    /// [`U256`] here — a numerator outside the F7-a domain is rejected, not
    /// truncated.
    pub fn compute(
        accrued: &[(u8, BigUint)],
        settled: &[(u8, BigUint)],
        rate: &Rate,
    ) -> Result<Round> {
        // Roles MUST align by id (not by slice position, F6-f/F7.1): the settled
        // record names the same roles in the same order as the accruals.
        if accrued.len() != settled.len()
            || accrued
                .iter()
                .zip(settled)
                .any(|((ra, _), (rs, _))| ra != rs)
        {
            return Err(crate::error::Error::InconsistentProposal);
        }
        let roles: Vec<u8> = accrued.iter().map(|(r, _)| *r).collect();
        let accrued_n: Vec<U256> = fee::u256_vec_from_biguints(
            &accrued.iter().map(|(_, n)| n.clone()).collect::<Vec<_>>(),
        )?;
        let settled_n: Vec<U256> = fee::u256_vec_from_biguints(
            &settled.iter().map(|(_, n)| n.clone()).collect::<Vec<_>>(),
        )?;
        // F7-a: a checkpoint naming ANY numerator ≥ 2¹²⁸ is rejected — enforced on
        // the raw accrued/settled numerators, not merely their difference, so a
        // 2¹²⁸+ numerator can never enter the arithmetic even if it cancels.
        let two128 = U256::from(1u8) << 128;
        if accrued_n.iter().chain(&settled_n).any(|v| *v >= two128) {
            return Err(crate::error::Error::ArithmeticDomain);
        }
        // Outstanding per role = accrued − settled (F6-f), rejecting an
        // inconsistent (settled > accrued) history.
        let outstanding = reconcile::outstanding_meed_per_role(&accrued_n, &settled_n)?;
        let division = fee::divide_round(&outstanding, rate)?;
        Ok(Round { roles, division })
    }

    /// Whether this round funds a claim-record (`E ≥ 1`, F7.3).
    pub fn funds_claim_record(&self) -> bool {
        self.division.leg
    }

    /// The aggregate `P` this round pays (0 iff no leg).
    pub fn amount(&self) -> U256 {
        self.division.p
    }

    /// `P` as a wire [`BigUint`] (for TLV / claim-record funding).
    pub fn amount_biguint(&self) -> BigUint {
        fee::biguint_from_u256(self.division.p)
    }

    /// The per-role extinguished numerators `(role, E_r)` this round records in
    /// its signed proposal (F5.6 `EXTINGUISHED`).
    pub fn extinguished(&self) -> Vec<(u8, U256)> {
        self.roles
            .iter()
            .copied()
            .zip(self.division.e_r.iter().copied())
            .collect()
    }

    /// The extinguished numerators as wire `(role, BigUint)` pairs.
    pub fn extinguished_biguint(&self) -> Vec<(u8, BigUint)> {
        self.roles
            .iter()
            .copied()
            .zip(self.division.e_r.iter().map(|e| fee::biguint_from_u256(*e)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tup(v: &[(u8, u128)]) -> Vec<(u8, BigUint)> {
        v.iter().map(|(r, n)| (*r, BigUint::from(*n))).collect()
    }
    fn n(x: u128) -> U256 {
        U256::from(x)
    }

    #[test]
    fn first_round_settles_full_accrued() {
        // F7 vector A shape: accrued 20000/4000/12000/4000, nothing settled, rate 0.3.
        let accrued = tup(&[(0x10, 20000), (0x11, 4000), (0x12, 12000), (0x13, 4000)]);
        let settled = tup(&[(0x10, 0), (0x11, 0), (0x12, 0), (0x13, 0)]);
        let round = Round::compute(&accrued, &settled, &Rate::new(3, 10).unwrap()).unwrap();
        assert!(round.funds_claim_record());
        assert_eq!(round.amount(), n(1)); // P = 1
        assert_eq!(round.division.e, n(33333));
        assert_eq!(
            round.extinguished(),
            vec![
                (0x10, n(16667)),
                (0x11, n(3334)),
                (0x12, n(9999)),
                (0x13, n(3333))
            ]
        );
    }

    #[test]
    fn second_round_settles_only_the_new_outstanding() {
        // After the first round settled 16667/3334/9999/3333, more accrues; the
        // next round settles only the delta — never re-charging settled numerators.
        let accrued = tup(&[(0x10, 40000), (0x11, 8000), (0x12, 24000), (0x13, 8000)]);
        let settled = tup(&[(0x10, 16667), (0x11, 3334), (0x12, 9999), (0x13, 3333)]);
        let round = Round::compute(&accrued, &settled, &Rate::new(3, 10).unwrap()).unwrap();
        // Outstanding = 23333/4666/14001/4667 (sum 46667); P = floor(46667*3/(10*10000)) = 1.
        assert_eq!(round.amount(), n(1));
        // Every E_r ≤ outstanding (never negative next round).
        for (_, er) in round.extinguished() {
            assert!(er <= n(46667));
        }
    }

    #[test]
    fn role_misaligned_settled_rejected() {
        // Settled MUST name the same roles (by id) as accrued — a same-length
        // but different-role vector is rejected, never credited by slice position.
        let accrued = tup(&[(0x10, 20000), (0x12, 12000)]);
        let settled = tup(&[(0x10, 5000), (0x13, 3000)]); // 0x13 ≠ 0x12
        assert!(Round::compute(&accrued, &settled, &Rate::unity()).is_err());
    }

    #[test]
    fn rejects_out_of_domain_numerator() {
        // F7-a: a checkpoint naming a numerator ≥ 2¹²⁸ is rejected even when it
        // cancels against `settled` to a small outstanding (the bound is on the
        // raw numerators, not their difference).
        let big = BigUint::from(1u8) << 128u32; // 2¹²⁸
        let accrued = vec![(0x10u8, big.clone())];
        let settled = vec![(0x10u8, &big - 1u8)];
        assert_eq!(
            Round::compute(&accrued, &settled, &Rate::unity()),
            Err(crate::error::Error::ArithmeticDomain)
        );
    }

    #[test]
    fn sub_extinguishment_trap_funds_no_record() {
        // Channel P>=1/E=0 trap (F7.3): N=1, rate 15000/1 → P=1 but E=0 → no leg.
        let accrued = tup(&[(0x10, 1)]);
        let settled = tup(&[(0x10, 0)]);
        let round = Round::compute(&accrued, &settled, &Rate::new(15000, 1).unwrap()).unwrap();
        assert!(!round.funds_claim_record()); // no claim-record, numerators carry
        assert_eq!(round.division.e, n(0));
    }
}
