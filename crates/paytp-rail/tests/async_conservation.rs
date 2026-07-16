//! **The conservation certification for the Option W watermark on the async, reorg-capable
//! rail (F8.1).** Exhaustive over every rail-event interleaving (submit → {finalize, confirm,
//! confirm-then-reorg, drop} → …) across a sequence of monotone advances that includes a
//! sub-unit-dust target, an idempotent re-advance, and a large jump. The invariant asserted
//! after EVERY step, for all 4⁴ = 256 interleavings:
//!
//! - **I1 conservation** — nothing is minted or lost: the initial deposit splits exactly into
//!   (remaining deposit) + (Σ recipient credits) + (instance residue). A reorg reverts the
//!   value AND the watermark exactly, so no dust leaks and the enablers are never over- or
//!   under-paid.
//! - **watermark identity** — the deposit is debited exactly by `funded_p`, and `funded_p =
//!   distributed + residue` (each accrual's carve reaches the enablers **exactly once**; a
//!   drop/reorg-then-reissue never double-pays — the F6-o closure, on-rail).
//! - **deterministic re-derivation** — replaying the same event sequence reaches the identical
//!   final watermark (the primitive-level restart-identity; the full durable-store restart is
//!   the merchant-plane follow-on).
//!
//! This is the "executable proof, not model opinion" the meta-caveat requires for the
//! settlement arithmetic.

use paytp_rail::{AsyncRail, MeedShare, RailAdapter, Transfer, TransferKind};

const DEPOSIT: u128 = 1_000_000;
const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const SETTLE: &str = "settle-ptr";
const ASSET: &str = "virt-usd";

fn shares() -> Vec<MeedShare> {
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
    ]
}

fn setup() -> (AsyncRail, String) {
    let rail = AsyncRail::new();
    let addr = rail.deploy_instance_unchecked(&[0x77; 32], [0x88; 32], shares());
    let f = rail
        .submit(Transfer {
            to: SETTLE.into(),
            asset: ASSET.into(),
            amount: DEPOSIT,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
    rail.finalize(&f);
    (rail, addr)
}

fn recipient_total(rail: &AsyncRail) -> u128 {
    rail.balance("il") + rail.balance("wallet") + rail.balance("fund")
}

/// Assert the conservation + watermark identities hold in the current state.
fn assert_conserves(rail: &AsyncRail, addr: &str, ctx: &str) {
    let deposit = rail.balance(SETTLE);
    let recipients = recipient_total(rail);
    let funded = rail.channel_funded_p(addr, &CID);
    let residue = rail.channel_residue(addr, &CID);
    // I1: nothing minted or lost — the deposit splits into recipients + instance residue.
    assert_eq!(
        DEPOSIT,
        deposit + recipients + residue,
        "conservation [{ctx}]: deposit {deposit} + recipients {recipients} + residue {residue}"
    );
    // The deposit is debited exactly by the watermark, distributed once each (+ carried dust).
    assert_eq!(
        DEPOSIT - deposit,
        funded,
        "deposit debited by funded_p [{ctx}]"
    );
    assert_eq!(
        funded,
        recipients + residue,
        "funded_p = distributed + residue [{ctx}]"
    );
}

#[derive(Clone, Copy, Debug)]
enum Event {
    Finalize,
    ConfirmThenFinalize,
    ConfirmReorg,
    Drop,
}

/// Run the target sequence under an event pattern, asserting conservation after every step.
/// Returns the final `funded_p` for the deterministic-re-derivation cross-check.
fn run(pattern: &[Event; 4]) -> u128 {
    // dust (199 → residue 2) + normal + idempotent-if-committed + a large jump.
    let targets = [199u128, 1000, 1000, 3000];
    let (rail, addr) = setup();
    for (i, &target) in targets.iter().enumerate() {
        let r = rail
            .advance_channel_meed(Some(SETTLE), &addr, CID, target, ASSET.into())
            .unwrap();
        // Submitted: no value has moved yet (async) — conservation holds at the prior state.
        assert_conserves(&rail, &addr, "post-submit");
        match pattern[i] {
            Event::Finalize => rail.finalize(&r),
            Event::ConfirmThenFinalize => {
                rail.confirm(&r);
                assert_conserves(&rail, &addr, "post-confirm");
                rail.finalize(&r);
            }
            Event::ConfirmReorg => {
                rail.confirm(&r);
                assert_conserves(&rail, &addr, "post-confirm");
                assert!(
                    rail.reorg(&r),
                    "a confirmed (not-yet-final) advance can reorg"
                );
            }
            Event::Drop => rail.drop_tx(&r),
        }
        assert_conserves(&rail, &addr, "post-event");
    }
    rail.channel_funded_p(&addr, &CID)
}

#[test]
fn watermark_conserves_across_all_rail_event_interleavings() {
    use Event::*;
    let events = [Finalize, ConfirmThenFinalize, ConfirmReorg, Drop];
    let mut count = 0u32;
    // Exhaustive over 4⁴ = 256 interleavings of the rail lifecycle across the 4 advances.
    for &e0 in &events {
        for &e1 in &events {
            for &e2 in &events {
                for &e3 in &events {
                    let pat = [e0, e1, e2, e3];
                    let f1 = run(&pat);
                    // Restart / determinism: replaying the SAME events re-derives the identical
                    // final watermark (no dependence on anything but the events themselves).
                    let f2 = run(&pat);
                    assert_eq!(
                        f1, f2,
                        "deterministic re-derivation (restart identity) for {pat:?}"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 256, "exhaustive over all interleavings");
}

#[test]
fn all_finalize_reaches_the_max_target_distributed_once() {
    use Event::Finalize;
    // The happy path end-state: every advance finalizes → the watermark is the max target,
    // distributed exactly once, the deposit debited by exactly it.
    let _ = run(&[Finalize, Finalize, Finalize, Finalize]);
    let (rail, addr) = setup();
    for &t in &[199u128, 1000, 1000, 3000] {
        let r = rail
            .advance_channel_meed(Some(SETTLE), &addr, CID, t, ASSET.into())
            .unwrap();
        rail.finalize(&r);
    }
    assert_eq!(
        rail.channel_funded_p(&addr, &CID),
        3000,
        "reached the max cumulative target"
    );
    // 3000: il 1500, wallet 900, fund 600 → 3000 distributed, residue 0.
    assert_eq!(recipient_total(&rail), 3000);
    assert_eq!(
        rail.balance(SETTLE),
        DEPOSIT - 3000,
        "deposit debited by exactly the watermark"
    );
}
