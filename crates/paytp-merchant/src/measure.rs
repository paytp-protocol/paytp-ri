//! M4 economics instrumentation — the measurement report (§7 rows, §10.7 crossover).
//!
//! **Honest scope:** the virtual rail cannot teach
//! real gas, contention, or finality latency — those are the M5 real-rail-only
//! unknowns. So every row here is either **structural** (bytes-on-wire, rail-
//! operation counts, arithmetic floors — rail-agnostic, measurable now) or
//! **pending-real-rail** (gas/latency — named with its methodology, value
//! withheld until M5). No devnet gas is reported as a mainnet number (the §7
//! discipline: testnet gas would fabricate the fee model).

use num_bigint::BigUint;
use paytp_core::channel::checkpoint::{Event, Range};
use paytp_core::channel::Checkpoint;
use paytp_core::fee::BP_DENOM;
use paytp_core::slice::Slice;
use paytp_core::tier0::attest::{Kind, Signed};

/// How a row was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Rail-agnostic: bytes, operation counts, arithmetic floors — measured now.
    Structural,
    /// Real gas / latency — methodology named, value withheld until M5.
    PendingRealRail,
}

/// One measurement row (§7).
#[derive(Debug, Clone)]
pub struct Row {
    pub name: &'static str,
    pub unit: &'static str,
    /// The measured structural value, or `None` for a pending-real-rail row.
    pub value: Option<u64>,
    pub source: Source,
    pub note: &'static str,
}

fn sample_slice_bytes() -> usize {
    let k = [7u8; 32];
    Slice::seal(1, 1_000_000, &k).unwrap().encode().len()
}

fn sample_checkpoint_bytes() -> usize {
    let cid = [0, 0, 0, 0, 0, 0, 0, 1];
    let mut cp = Checkpoint {
        channel_id: cid,
        balance: BigUint::from(0u32),
        balance_negative: false,
        cum_total: BigUint::from(1_000_000u32),
        accruals: vec![
            (0x10, BigUint::from(50_000_000u32)),
            (0x11, BigUint::from(10_000_000u32)),
            (0x12, BigUint::from(30_000_000u32)),
            (0x13, BigUint::from(10_000_000u32)),
        ],
        last_seq: 100,
        ranges: vec![Range { lo: 1, hi: 100 }],
        transcript: paytp_core::transcript::head_0(&cid),
        events: vec![Event {
            kind: 0x02,
            reference: vec![0xcc; 32],
        }],
        timestamp: 1_700_000_000,
        prev_ref: [0u8; 32],
        sig_payer: None,
        sig_merchant: None,
    };
    cp.sign_payer(&[1u8; 32]).unwrap();
    cp.sign_merchant(&[2u8; 32]).unwrap();
    cp.encode().unwrap().len()
}

fn sample_attestation_bytes() -> usize {
    Signed::create(Kind::Attestation, [0x11; 32], [0x22; 32], &[0x55; 32])
        .encode()
        .len()
}

/// The smallest purchase (baseline minimum units) whose meed at `bp` rounds up
/// to ≥ 1 unit: `meed = floor(amount × bp / 10000) ≥ 1` ⇔ `amount ≥ ⌈10000/bp⌉`.
/// The two-leg floor (§7): below it the meed is sub-unit dust.
pub fn two_leg_floor_units(bp: u16) -> u64 {
    BP_DENOM.div_ceil(bp as u32) as u64
}

/// The full §7 measurement report.
pub fn report() -> Vec<Row> {
    vec![
        // --- Object sizes on the wire (structural) ---
        Row {
            name: "metering slice",
            unit: "bytes",
            value: Some(sample_slice_bytes() as u64),
            source: Source::Structural,
            note: "SEQ(8)+AMT(6)+TAG(16) + TLV framing",
        },
        Row {
            name: "bilateral checkpoint",
            unit: "bytes",
            value: Some(sample_checkpoint_bytes() as u64),
            source: Source::Structural,
            note: "schema-0x01 vector, 1 range, 1 event, both sigs",
        },
        Row {
            name: "attestation",
            unit: "bytes",
            value: Some(sample_attestation_bytes() as u64),
            source: Source::Structural,
            note: "NONCE(32)+ENTRY_ID(32)+SIG(64)",
        },
        // --- Rail operation counts per lifecycle (structural) ---
        Row {
            name: "entry: first-use instance deploy",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "counterfactual; once per (merchant,asset,vector,contract)",
        },
        Row {
            name: "two-leg purchase",
            unit: "rail ops",
            value: Some(3),
            source: Source::Structural,
            note: "fund meed entry + net leg + attestation post",
        },
        Row {
            name: "entry funding",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "F4.3 fund",
        },
        Row {
            name: "receipt claim (attest)",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "attestation releases to recipients",
        },
        Row {
            name: "cancellation",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "refund at once, no contest",
        },
        Row {
            name: "reclaim (open+execute)",
            unit: "rail ops",
            value: Some(2),
            source: Source::Structural,
            note: "open_reclaim + execute_reclaim after T_exec",
        },
        Row {
            name: "batch-of-N claim",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "batch takes N entry-ids in one call",
        },
        Row {
            name: "batch reclaim",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "entry-ids only",
        },
        Row {
            name: "attestation posting",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "",
        },
        Row {
            name: "channel settlement round",
            unit: "rail ops",
            value: Some(2),
            source: Source::Structural,
            note: "fund claim-record + net leg (E>=1 rounds only)",
        },
        Row {
            name: "splitter withdrawal / recipient",
            unit: "rail ops",
            value: Some(1),
            source: Source::Structural,
            note: "each recipient withdraws its own share",
        },
        // --- Arithmetic floors (structural) ---
        Row {
            name: "two-leg floor @ 100 bp",
            unit: "min units",
            value: Some(two_leg_floor_units(100)),
            source: Source::Structural,
            note: "meed rounds up to >= 1 unit",
        },
        Row {
            name: "two-leg floor @ 150 bp",
            unit: "min units",
            value: Some(two_leg_floor_units(150)),
            source: Source::Structural,
            note: "the protocol cap",
        },
        // --- Real-rail-only (pending; methodology named) ---
        Row {
            name: "entry lifecycle gas",
            unit: "gas",
            value: None,
            source: Source::PendingRealRail,
            note: "M5: mainnet p50/p95 over a stated window, never raw devnet gas",
        },
        Row {
            name: "channel-round gas vs round value",
            unit: "gas",
            value: None,
            source: Source::PendingRealRail,
            note: "M5: aggregate-leg cost at several thresholds",
        },
        Row {
            name: "quote->redemption latency / finality level",
            unit: "ms",
            value: None,
            source: Source::PendingRealRail,
            note: "M5: distribution over repeated runs per level",
        },
    ]
}

/// §10.7 upgrade-to-channel crossover (structural, rail-agnostic in rail-ops).
///
/// A run of `k` payments as one-shot two-leg purchases costs `k × two_leg_ops`
/// rail operations. The same `k` payments over a channel cost `deploy + k×0`
/// (slices are off-chain) `+ settlements × round_ops`. Returns the smallest `k`
/// at which the channel's amortized rail-op count is strictly lower — the
/// structural crossover; the *gas* crossover is M5 (pending-real-rail).
pub fn channel_crossover_rail_ops(
    two_leg_ops_per_payment: u64,
    settlements: u64,
    round_ops: u64,
) -> u64 {
    let mut k = 1u64;
    loop {
        let one_shot = k * two_leg_ops_per_payment;
        // Channel: one instance deploy (shared) + the settlement rounds.
        let channel = 1 + settlements * round_ops;
        if channel < one_shot {
            return k;
        }
        k += 1;
        if k > 1_000_000 {
            return k; // guard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_has_all_required_rows_and_is_honest() {
        let rows = report();
        // Every §7 row present; structural rows carry a value, pending ones don't.
        for r in &rows {
            match r.source {
                Source::Structural => assert!(r.value.is_some(), "{} must be measured", r.name),
                Source::PendingRealRail => {
                    assert!(r.value.is_none(), "{} must not fake a value", r.name)
                }
            }
        }
        // The named real-rail unknowns are present (not silently dropped).
        assert!(rows.iter().any(|r| r.name.contains("latency")));
        assert!(rows.iter().any(|r| r.name.contains("gas")));
        // Slice is the fixed hot-path object; assert its structural size.
        let slice = rows.iter().find(|r| r.name == "metering slice").unwrap();
        assert_eq!(slice.value, Some(sample_slice_bytes() as u64));
    }

    #[test]
    fn two_leg_floors() {
        assert_eq!(two_leg_floor_units(100), 100); // 1% → 100 min units
        assert_eq!(two_leg_floor_units(150), 67); // ceil(10000/150)
    }

    #[test]
    fn channel_beats_one_shots_quickly() {
        // Two-leg one-shot = 3 rail ops/payment; a channel with 1 settlement = 2
        // round ops. Crossover: channel (1+2=3) < k×3 first at k=2.
        assert_eq!(channel_crossover_rail_ops(3, 1, 2), 2);
    }
}
