//! F7 settlement arithmetic — the host's view of the shared, `no_std`,
//! fixed-width [`paytp_f7`] crate (the M5 core-sharing decision).
//!
//! There is now exactly ONE implementation of the meed division: `paytp-f7`,
//! used verbatim here and by the on-chain (SBF) contract kit, so the two can
//! never diverge. The `num-bigint` version that used to live here is now the
//! differential **test oracle** inside `paytp-f7`.
//!
//! **The wire ↔ arithmetic seam.** The channel wire layer (F5 checkpoints,
//! §11 TLV) legitimately carries arbitrary-width integers as [`BigUint`]; the
//! settlement arithmetic is fixed-width [`U256`]. [`u256_from_biguint`] /
//! [`biguint_from_u256`] convert at that boundary — a numerator wider than the
//! F7-a domain is rejected there or by `divide_round`, never silently truncated.

pub use paytp_f7::{
    accrue, carries_leg, claimable_d, compute_e, compute_p, divide_round, extinguish_per_role,
    reconcile, F7Error, Rate, RoundDivision, BP_DENOM, MAX_ROLES,
};
pub use ruint::aliases::U256;

use crate::error::{Error, Result};
use num_bigint::BigUint;

impl From<F7Error> for Error {
    fn from(e: F7Error) -> Self {
        match e {
            F7Error::ArithmeticDomain => Error::ArithmeticDomain,
            F7Error::InconsistentProposal => Error::InconsistentProposal,
        }
    }
}

/// Convert a wire [`BigUint`] to a fixed-width [`U256`] at the arithmetic
/// boundary. A value that does not fit 256 bits is out of the F7 domain and is
/// rejected (`divide_round` further rejects anything ≥ 2¹²⁸) — never truncated.
pub fn u256_from_biguint(b: &BigUint) -> Result<U256> {
    let le = b.to_bytes_le();
    U256::try_from_le_slice(&le).ok_or(Error::ArithmeticDomain)
}

/// Convert a fixed-width [`U256`] result back to a wire [`BigUint`].
pub fn biguint_from_u256(u: U256) -> BigUint {
    BigUint::from_bytes_le(&u.to_le_bytes::<32>())
}

/// Convert a slice of [`BigUint`] numerators to [`U256`], preserving order.
pub fn u256_vec_from_biguints(items: &[BigUint]) -> Result<Vec<U256>> {
    items.iter().map(u256_from_biguint).collect()
}
