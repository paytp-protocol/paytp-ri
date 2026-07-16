//! External/runtime drift — executable repros for the AsyncRail-mock
//! drifts found by an independent adversarial review, 2026-07-15.
//!
//! These are LATENT, async-layer (ASYNC-1) hazards: the shipped v0.1 settles on the
//! synchronous `VirtualRail` (submit == final, no reorg), so none is exploitable today.
//! They matter when the real async adapter is built to the F8.1 model the `AsyncRail`
//! mock stands in for — each is a place the mock DIVERGES from a contract a real
//! adapter (or its consumers) would rely on. Each test ASSERTS THE DRIFT (the current
//! wrong behavior) so it fails RED the day the mock is fixed to the contract.
//!
//! Run: `cargo test -p paytp-rail --test consistency_c3_async`

use paytp_rail::{AsyncRail, MeedShare, RailAdapter, Transfer, TransferKind};

const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

// Bring the test-only deploy helper into scope via the crate feature the workspace
// dev-build enables for tests.
fn setup(deposit: u128) -> (AsyncRail, String) {
    let rail = AsyncRail::new();
    let addr = rail.deploy_instance_unchecked(
        &[0x77; 32],
        [0x88; 32],
        vec![
            MeedShare {
                dest: "il".into(),
                bp: 50,
            },
            MeedShare {
                dest: "wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: "fund".into(),
                bp: 20,
            },
        ],
    );
    let f = rail
        .submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: deposit,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
    rail.finalize(&f);
    (rail, addr)
}

/// The distribution fact `advanced_channel_meed` is exposed at CONFIRMED
/// (reversible), contradicting the adapter.rs trait doc: "On the async rail it is `Some`
/// only once the advance FINALIZED (the value moved)."
#[test]
fn fact_exposed_at_confirmed_not_finalized() {
    let (rail, addr) = setup(10_000);
    let r = rail
        .advance_channel_meed(Some("settle-ptr"), &addr, CID, 4_000, "virt-usd".into())
        .unwrap();
    rail.confirm(&r); // CONFIRMED, not finalized — a reorg can still revert it.
    let fin = rail.finality(&r).unwrap();
    assert_eq!(
        fin.level, "confirmed",
        "the advance is at a REVERSIBLE level"
    );

    // DRIFT: the fact is Some at the reversible 'confirmed' level. The adapter.rs
    // contract says it is Some only once FINALIZED. A consumer that reads the fact
    // WITHOUT independently gating on finality().level == the irreversible level would
    // credit/fold a reversible advance. (The settlement-verify consumer DOES gate —
    // carriage.rs:1405 finality_reached(fin_meed); the fold-poll consumer,
    // carriage.rs:2187, reads the fact with no finalized-level check in that block.)
    let fact = rail.ref_target(&r).and_then(|i| i.advanced_channel_meed);
    assert!(
        fact.is_some(),
        "REPRO: advanced_channel_meed is Some at 'confirmed' — the trait doc says \
         it should be None until 'finalized'"
    );
}

/// `finality().time` returns the CURRENT clock, not the fixed time the tx
/// reached that level. The trait doc (adapter.rs `Finality`): "the on-chain time it was
/// reached." `VirtualRail` returns the fixed `submit + delay`; `AsyncRail` returns the
/// moving clock — so the honor rule `t_fin <= exp+grace` would false-reject an on-time
/// payment queried late, if any honor-window consumer ran on the async rail.
#[test]
fn finality_time_is_current_clock_not_reach_time() {
    let (rail, _addr) = setup(10_000);
    let p = rail
        .submit(Transfer {
            to: "eoa".into(),
            asset: "virt-usd".into(),
            amount: 10,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
    rail.finalize(&p);
    let t_reach = rail.finality(&p).unwrap().time; // "reached" time as observed now
    rail.advance_clock(1_000); // a delayed merchant poll
    let t_late = rail.finality(&p).unwrap().time;

    // DRIFT: the reported finality time MOVED with the clock (t_late == t_reach + 1000),
    // although the tx reached 'finalized' once and never changed. A fixed-reach-time
    // adapter (VirtualRail) reports the same value on both reads.
    assert_ne!(
        t_reach, t_late,
        "REPRO: AsyncRail.finality().time tracks the current clock, not the reach time"
    );
    assert_eq!(t_late, t_reach + 1_000);
}

/// `release_keyed` strands a refund after a reorg: the keyed cache pins the
/// FIRST ref forever, so a post-reorg retry returns the now-Dropped ref and never
/// re-submits. The adapter.rs doc promises "a retry after an outage/reorg/restart
/// re-submits the SAME reference the rail dedups" — but a Dropped ref moves nothing, so
/// the refund deadlocks. (The advance path is reorg-safe by watermark position; this
/// keyed-release path is NOT.)
#[test]
fn release_keyed_strands_refund_after_reorg() {
    let (rail, _addr) = setup(10_000);
    let ckpt = [0xcc; 32];
    let r1 = rail
        .release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", 6_000)
        .unwrap();
    rail.confirm(&r1);
    assert_eq!(rail.balance("refund"), 6_000, "confirmed release credited");

    // Reorg the confirmed-not-finalized release: value reverts, ref becomes Dropped.
    assert!(rail.reorg(&r1));
    assert_eq!(rail.balance("refund"), 0, "reorg reverted the refund");
    assert!(rail.finality(&r1).is_none(), "dropped → no finality");

    // The merchant, seeing no finality, retries the keyed release.
    let r2 = rail
        .release_keyed(CID, ckpt, "settle-ptr", "refund", "virt-usd", 6_000)
        .unwrap();
    assert_eq!(r1, r2, "the cache returned the SAME (dropped) ref");

    // DRIFT: finalizing the retry moves nothing — the ref is permanently Dropped — so the
    // refund is stranded. finalize() is a no-op on a Dropped ref.
    rail.finalize(&r2);
    assert_eq!(
        rail.balance("refund"),
        0,
        "REPRO: the refund is stranded — the keyed cache pinned a dropped ref, so no \
         retry can ever re-submit it"
    );
    assert_eq!(
        rail.balance("settle-ptr"),
        10_000,
        "deposit never left escrow"
    );
}
