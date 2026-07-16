//! M3 channel settlement — the value-conservation certification (F5/F6/F7/F6-f).
//!
//! Drives a channel lifecycle on the virtual rail: accrue (metering) → bilateral
//! checkpoint → settlement round (compute `P`/`E` → fund the claim-record, which
//! distributes to recipients) → net leg → close reconciliation. Asserts value
//! conserves to the µ-unit — the "settlement math certified by tests, not prose"
//! mandate. A failing assertion here would be a spec bug, per the brief.

use num_bigint::BigUint;
use paytp_core::channel::checkpoint::{Event, Range};
use paytp_core::channel::{Checkpoint, Round};
use paytp_core::fee::{self, reconcile, Rate, U256};
use paytp_rail::{MeedShare, RailAdapter, Transfer, TransferKind, VirtualRail};

/// Convert wire `(role, BigUint)` numerators to fixed-width U256 for reconcile.
fn u256s(acc: &[(u8, BigUint)]) -> Vec<U256> {
    acc.iter()
        .map(|(_, n)| fee::u256_from_biguint(n).unwrap())
        .collect()
}
/// Σ of per-role extinguished numerators (U256).
fn e_sum(e_r: &[U256]) -> U256 {
    e_r.iter().fold(U256::ZERO, |a, x| a + *x)
}

const IL: &str = "il";
const WALLET: &str = "wallet";
const FUND: &str = "fund";
const MERCHANT: &str = "merchant";
const CHANNEL_ID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];

/// Schema-0x01 meed shares within the instance (bp_total = 100).
fn shares() -> Vec<MeedShare> {
    vec![
        MeedShare {
            dest: IL.into(),
            bp: 50,
        },
        MeedShare {
            dest: WALLET.into(),
            bp: 30,
        },
        MeedShare {
            dest: FUND.into(),
            bp: 20,
        }, // OS 10 + dev fund 10
    ]
}

/// Per-role accrued numerators for a gross amount (µ-units × bp), roles 0x10..0x13.
fn accruals(gross: u128) -> Vec<(u8, BigUint)> {
    vec![
        (0x10, BigUint::from(gross * 50)),
        (0x11, BigUint::from(gross * 10)),
        (0x12, BigUint::from(gross * 30)),
        (0x13, BigUint::from(gross * 10)),
    ]
}

fn zero_settled() -> Vec<(u8, BigUint)> {
    vec![
        (0x10, BigUint::from(0u32)),
        (0x11, BigUint::from(0u32)),
        (0x12, BigUint::from(0u32)),
        (0x13, BigUint::from(0u32)),
    ]
}

/// Build a bilateral checkpoint carrying the metering, return its reference.
fn bilateral_checkpoint(cum_total: u128, acc: &[(u8, BigUint)], last_seq: u64) -> [u8; 32] {
    let mut cp = Checkpoint {
        channel_id: CHANNEL_ID,
        balance: BigUint::from(0u32),
        balance_negative: false,
        cum_total: BigUint::from(cum_total),
        accruals: acc.to_vec(),
        last_seq,
        ranges: vec![Range {
            lo: 1,
            hi: last_seq,
        }],
        transcript: paytp_core::transcript::head_0(&CHANNEL_ID),
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
    cp.reference().unwrap()
}

#[test]
fn deterministic_round_conserves_value_to_the_micro_unit() {
    // Postpay, DENOM = BASELINE_ASSET (unity rate) — a deterministic round.
    let gross: u128 = 1_000_000;
    let rail = VirtualRail::new(1);
    let seed = [0x33u8; 32];
    let instance = rail.deploy_instance_unchecked(&seed, [0x55; 32], shares());

    let acc = accruals(gross);
    let ckpt_ref = bilateral_checkpoint(gross, &acc, 100);

    // The round settles the full accrued at unity rate.
    let round = Round::compute(&acc, &zero_settled(), &Rate::unity()).unwrap();
    assert!(round.funds_claim_record());
    let p = u128::try_from(round.amount()).unwrap();
    assert_eq!(p, 10_000); // 1% of gross in baseline units

    // Fund the claim-record with P → distributes among meed dests.
    rail.fund_claim_record(&instance, CHANNEL_ID, ckpt_ref, p, "baseline".into())
        .unwrap();
    assert_eq!(rail.balance(IL), 5_000);
    assert_eq!(rail.balance(WALLET), 3_000);
    assert_eq!(rail.balance(FUND), 2_000);

    // Merchant-net (postpay): max(0, (CUM_TOTAL − carve) − net legs − funding).
    let acc_n = u256s(&acc);
    let carve = reconcile::meed_carve(&acc_n);
    assert_eq!(carve, U256::from(10_000u32)); // the 1% meed in µ-units
    let merchant_net_before = reconcile::outstanding_merchant_net(
        &U256::from(gross),
        &acc_n,
        &U256::from(0u32),
        &U256::from(0u32),
    );
    assert_eq!(merchant_net_before, U256::from(990_000u32));

    // Pay the net leg (990_000 to the merchant), then reconcile → 0 outstanding.
    let net = u128::try_from(merchant_net_before).unwrap();
    rail.submit(Transfer {
        to: MERCHANT.into(),
        asset: "baseline".into(),
        amount: net,
        kind: TransferKind::Payment,
        memo: None,
    })
    .unwrap();
    let merchant_net_after = reconcile::outstanding_merchant_net(
        &U256::from(gross),
        &acc_n,
        &U256::from(net),
        &U256::from(0u32),
    );
    assert_eq!(merchant_net_after, U256::from(0u32));

    // Close dust reversion: full extinguishment → no dust.
    let e_total = e_sum(&round.division.e_r);
    let reversion = reconcile::close_reversion_credit(&acc_n, &e_total).unwrap();
    assert_eq!(reversion, U256::from(0u32));

    // VALUE CONSERVATION: gross in = merchant net + meed payouts, exactly.
    let total_out =
        rail.balance(MERCHANT) + rail.balance(IL) + rail.balance(WALLET) + rail.balance(FUND);
    assert_eq!(total_out, gross);
}

#[test]
fn cross_currency_round_extinguishes_and_conserves() {
    // DENOM ≠ BASELINE: rate 0.3 (F7 vector A shape). The round extinguishes only
    // the payable part; the sub-P residue carries (dust), reverting to the merchant.
    let acc = vec![
        (0x10, BigUint::from(20000u32)),
        (0x11, BigUint::from(4000u32)),
        (0x12, BigUint::from(12000u32)),
        (0x13, BigUint::from(4000u32)),
    ];
    let round = Round::compute(&acc, &zero_settled(), &Rate::new(3, 10).unwrap()).unwrap();
    // P = 1, E = 33333 (< N = 40000). Residue 6667 carries.
    assert_eq!(round.amount(), U256::from(1u32));
    assert_eq!(round.division.e, U256::from(33333u32));
    let acc_n = u256s(&acc);
    // Close dust reversion = accrued_carve − settled_carve = floor(40000/10000) −
    // floor(33333/10000) = 4 − 3 = 1 µ-unit reverts to the merchant.
    let e_total = e_sum(&round.division.e_r);
    assert_eq!(
        reconcile::close_reversion_credit(&acc_n, &e_total).unwrap(),
        U256::from(1u32)
    );
}

#[test]
fn two_rounds_never_re_charge_settled_numerators() {
    // Two settlement rounds; the second settles only the new outstanding. Value
    // conserves: the claim-records' total meed == Σ P, never double-counted.
    let rail = VirtualRail::new(1);
    let instance = rail.deploy_instance_unchecked(&[0x44u8; 32], [0x55; 32], shares());

    // Round 1 over gross 1_000_000.
    let acc1 = accruals(1_000_000);
    let ref1 = bilateral_checkpoint(1_000_000, &acc1, 100);
    let r1 = Round::compute(&acc1, &zero_settled(), &Rate::unity()).unwrap();
    let p1 = u128::try_from(r1.amount()).unwrap();
    rail.fund_claim_record(&instance, CHANNEL_ID, ref1, p1, "b".into())
        .unwrap();

    // Round 2 over cumulative gross 2_000_000, settled = round 1's E_r.
    let acc2 = accruals(2_000_000);
    let settled = r1.extinguished_biguint(); // wire form → next round's `settled`
    let ref2 = bilateral_checkpoint(2_000_000, &acc2, 200);
    let r2 = Round::compute(&acc2, &settled, &Rate::unity()).unwrap();
    let p2 = u128::try_from(r2.amount()).unwrap();
    rail.fund_claim_record(&instance, CHANNEL_ID, ref2, p2, "b".into())
        .unwrap();

    // Total meed distributed == carve of the whole-chain cumulative (carve-once).
    let acc2_n = u256s(&acc2);
    let carve_total = u128::try_from(reconcile::meed_carve(&acc2_n)).unwrap();
    assert_eq!(p1 + p2, carve_total); // 10000 + 10000 = 20000 = 1% of 2_000_000
    assert_eq!(
        rail.balance(IL) + rail.balance(WALLET) + rail.balance(FUND),
        carve_total
    );
    // The two claim-records have distinct ids (distinct CKPT_REF) — no double-fund.
    assert_ne!(ref1, ref2);
    // Re-funding a round's claim-record (same CHANNEL_ID ‖ CKPT_REF ‖ P) is
    // atomically refused (F4.2/F4.3) — a round funds exactly once, never twice.
    assert!(rail
        .fund_claim_record(&instance, CHANNEL_ID, ref1, p1, "b".into())
        .is_err());
}

#[test]
fn sub_extinguishment_round_funds_no_claim_record() {
    // F7.3: a P>=1/E=0 round funds NO claim-record on the rail (no zero-progress
    // on-chain post; the numerators carry). The driver skips funding when !leg.
    let rail = VirtualRail::new(1);
    let instance = rail.deploy_instance_unchecked(&[0x66u8; 32], [0x55; 32], shares());
    // N=1, rate 15000/1 → P=1 but E=0.
    let acc = vec![(0x10, BigUint::from(1u32))];
    let round = Round::compute(
        &acc,
        &[(0x10, BigUint::from(0u32))],
        &Rate::new(15000, 1).unwrap(),
    )
    .unwrap();
    assert!(!round.funds_claim_record());
    // A conformant driver funds nothing → no meed distributed.
    if round.funds_claim_record() {
        let p = u128::try_from(round.amount()).unwrap();
        rail.fund_claim_record(&instance, CHANNEL_ID, [0xcc; 32], p, "b".into())
            .unwrap();
    }
    assert_eq!(
        rail.balance(IL) + rail.balance(WALLET) + rail.balance(FUND),
        0
    );
}

/// F6.4 interim-round triggers (value/time) and the prepay meed halt, wired to
/// the REAL reconciliation: `settleable` uses the round's extinguished `E` (F7.3,
/// not the payable carve `P`), and the unsettled value comes from the channel's
/// live estimate (postpay) or the meed carve (prepay).
#[test]
fn interim_round_triggers_and_prepay_halt() {
    use paytp_core::channel::state::{ChannelState, Mode};
    use paytp_core::channel::trigger::{self, Trigger};
    use paytp_core::slice::Slice;

    let k = paytp_core::crypto::k_session(&[1u8; 32], &[2u8; 32], &CHANNEL_ID);
    let vector = vec![(0x10, 50u16), (0x11, 10), (0x12, 30), (0x13, 10)];
    let th_value: u128 = 5_000;
    let th_time: u64 = 3_600;
    let t0: u64 = 1_700_000_000;

    // Σ E_r the deterministic round would extinguish (F7.3), from the real math.
    // These channels have no prior settled round, so `opening_settled = zero_settled`
    // and the outstanding accruals ARE the full accruals (a channel WITH history
    // would pass its cumulative settled here).
    let e_extinguished = |st: &ChannelState| -> u128 {
        let round = Round::compute(&st.accruals(), &zero_settled(), &Rate::unity()).unwrap();
        u128::try_from(e_sum(&round.division.e_r)).unwrap()
    };
    // Settleable per F6-f/F7.3: a merchant-net due, or meed extinguishing E ≥ 1.
    let is_settleable = |st: &ChannelState, net: u128, fund: u128| -> bool {
        let acc = u256s(&st.accruals());
        let mnet = reconcile::outstanding_merchant_net(
            &U256::from(st.cum_total()),
            &acc,
            &U256::from(net),
            &U256::from(fund),
        );
        trigger::settleable(u128::try_from(mnet).unwrap(), e_extinguished(st))
    };

    // --- Postpay VALUE trigger: fires when the live estimate reaches TH_VALUE. ---
    let mut st = ChannelState::new(
        CHANNEL_ID,
        k,
        Mode::Postpay,
        10_000_000,
        10_000_000,
        vector.clone(),
    );
    st.accept_slice(&Slice::seal(1, 4_000, &k).unwrap())
        .unwrap(); // B = 4_000 < 5_000
    assert_eq!(
        trigger::evaluate(
            st.unsettled_estimate(),
            is_settleable(&st, 0, 0),
            t0,
            t0,
            th_value,
            th_time
        ),
        Trigger::None
    );
    st.accept_slice(&Slice::seal(2, 2_000, &k).unwrap())
        .unwrap(); // B = 6_000 ≥ 5_000
    assert_eq!(
        trigger::evaluate(
            st.unsettled_estimate(),
            is_settleable(&st, 0, 0),
            t0,
            t0,
            th_value,
            th_time
        ),
        Trigger::Value
    );

    // --- Postpay TIME trigger: small value below TH_VALUE, elapsed + settleable. ---
    let mut lo = ChannelState::new(
        CHANNEL_ID,
        k,
        Mode::Postpay,
        10_000_000,
        10_000_000,
        vector.clone(),
    );
    lo.accept_slice(&Slice::seal(1, 500, &k).unwrap()).unwrap(); // B = 500 < 5_000
    assert_eq!(
        trigger::evaluate(
            lo.unsettled_estimate(),
            is_settleable(&lo, 0, 0),
            t0,
            t0,
            th_value,
            th_time
        ),
        Trigger::None // not yet elapsed
    );
    assert_eq!(
        trigger::evaluate(
            lo.unsettled_estimate(),
            is_settleable(&lo, 0, 0),
            t0 + th_time,
            t0,
            th_value,
            th_time
        ),
        Trigger::Time
    );

    // --- Prepay HALT: meed owed (B ≤ 0, so the value is the carve). A due round
    //     halts the payer; the merchant proposing it nets the value out of the
    //     un-proposed position → the payer resumes; NEW value re-halts (F6.4/§6.4). ---
    let mut pre = ChannelState::new(CHANNEL_ID, k, Mode::Prepay, 10_000_000, 10_000_000, vector);
    pre.credit_funding(10_000); // F6-g: a prepay channel deposits before it can consume (B: 0 → −10_000)
    pre.accept_slice(&Slice::seal(1, 4_000, &k).unwrap())
        .unwrap();
    let meed_val = u128::try_from(reconcile::meed_carve(&u256s(&pre.accruals()))).unwrap();
    let due = trigger::evaluate(
        meed_val,
        is_settleable(&pre, 0, 0),
        t0 + th_time,
        t0,
        th_value,
        th_time,
    );
    assert_eq!(due, Trigger::Time);
    assert!(
        trigger::prepay_halt(due),
        "a due prepay meed round halts the payer"
    );
    // Merchant proposes the round: its value is netted out (un-proposed residual = 0)
    // and last_settle advances to the proposal → no trigger → payer resumes.
    let resumed = trigger::evaluate(0, false, t0 + th_time, t0 + th_time, th_value, th_time);
    assert!(
        !trigger::prepay_halt(resumed),
        "payer resumes once the merchant proposes"
    );
}

/// F6.6 chaining — value conservation across a generation hand-off. A successor
/// imports the predecessor's opening cumulatives (settled meed + net legs) and
/// settles on the WHOLE-CHAIN cumulative, so the meed carve is taken ONCE on the
/// cumulative ACCRUALS (F6-f/F7-d): a naive per-generation carve undercounts (floor
/// is non-distributive), the cumulative-delta credits it exactly, and total gross in
/// equals total merchant-net + total meed to the µ-unit.
#[test]
fn chained_channel_conserves_value_across_generations() {
    let g1: u128 = 150;
    let g2: u128 = 150;
    let acc1 = accruals(g1);
    let acc2 = accruals(g2);
    let acc_whole: Vec<(u8, BigUint)> = acc1
        .iter()
        .zip(acc2.iter())
        .map(|((r, a), (_, b))| (*r, a + b))
        .collect();

    let a1 = u256s(&acc1);
    let a_whole = u256s(&acc_whole);

    // Meed: carve-once on the cumulative, credited as the generational delta.
    let carve1 = reconcile::meed_carve(&a1);
    let carve_whole = reconcile::meed_carve(&a_whole);
    let carve_naive_g2 = reconcile::meed_carve(&u256s(&acc2));
    assert_eq!(u128::try_from(carve1).unwrap(), 1);
    assert_eq!(u128::try_from(carve_whole).unwrap(), 3);
    assert!(
        carve_whole > carve1 + carve_naive_g2,
        "cumulative carve recovers the lost unit"
    );
    let gen2_meed = carve_whole - carve1;
    assert_eq!(
        carve1 + gen2_meed,
        carve_whole,
        "chain meed sums to the cumulative carve"
    );

    // Merchant-net: whole-chain cumulative with the imported opening net leg.
    let cum_whole = U256::from(g1 + g2);
    let zero = U256::ZERO;
    let net1 = reconcile::outstanding_merchant_net(&U256::from(g1), &a1, &zero, &zero);
    let net2 = reconcile::outstanding_merchant_net(&cum_whole, &a_whole, &net1, &zero);
    let total_net = net1 + net2;

    assert_eq!(
        reconcile::outstanding_merchant_net(&cum_whole, &a_whole, &total_net, &zero),
        zero,
        "chain fully settled → 0 outstanding merchant-net"
    );

    // VALUE CONSERVATION across the chain: gross in = merchant-net + meed, exactly.
    assert_eq!(
        total_net + carve_whole,
        cum_whole,
        "chain conserves value to the µ-unit"
    );

    // Full extinguishment leaves no close-time dust to revert.
    let e_whole: U256 = a_whole.iter().fold(U256::ZERO, |acc, x| acc + *x);
    assert_eq!(
        reconcile::close_reversion_credit(&a_whole, &e_whole).unwrap(),
        zero
    );
}

#[test]
fn prepay_close_refund_conserves_deposit_to_the_micro_unit() {
    // End-to-end under the corrected model (C1 release + C2 draw + the close
    // arithmetic C3 wires): a prepay deposit FUNDS the meed (drawn from the deposit,
    // never minted), the unconsumed remainder REFUNDS to the payer at close, and value
    // conserves to the µ-unit. Drives the rail primitives + F7 helpers directly — the
    // settlement/close reconciliation the production path orchestrates.
    let rail = VirtualRail::new(0);
    let instance = rail.deploy_instance_unchecked(&[0x23u8; 32], [0x55; 32], shares());
    const SETTLE_PTR: &str = "settle-ptr"; // the prepay deposit escrow (merchant pointer)
    const REFUND_PTR: &str = "payer-refund";

    // 1. Fund: the payer deposits D at settle_ptr (F6.2 — funding lands there).
    let d: u128 = 1_000_000;
    rail.submit(Transfer {
        to: SETTLE_PTR.into(),
        asset: "baseline".into(),
        amount: d,
        kind: TransferKind::Payment,
        memo: None,
    })
    .unwrap();

    // 2. Consume gross C; accrue the per-role meed numerators.
    let c: u128 = 400_000;
    let acc = accruals(c);
    let acc_n = u256s(&acc);
    let ckpt_ref = bilateral_checkpoint(c, &acc, 100);

    // 3. Interim meed round: extinguish the accrued meed P, DRAWN from the deposit
    //    (C2) — the merchant is the prepay debtor (F6-f).
    let round = Round::compute(&acc, &zero_settled(), &Rate::unity()).unwrap();
    let p = u128::try_from(round.amount()).unwrap();
    assert_eq!(p, 4_000); // 1% of gross C
    rail.draw_claim_record(
        SETTLE_PTR,
        &instance,
        CHANNEL_ID,
        ckpt_ref,
        p,
        "baseline".into(),
    )
    .unwrap();
    assert_eq!(
        rail.balance(IL) + rail.balance(WALLET) + rail.balance(FUND),
        p
    ); // recipients paid P
    assert_eq!(rail.balance(SETTLE_PTR), d - p); // escrow debited by P (not minted)

    // 4. Close: refund the unconsumed deposit to the payer (C1 release); the close-time
    //    reversion (0 on full extinguishment) reverts to the merchant.
    let refund = reconcile::prepay_unconsumed_deposit(&U256::from(d), &U256::from(c)).unwrap();
    assert_eq!(refund, U256::from(d - c));
    rail.release(
        SETTLE_PTR,
        REFUND_PTR,
        "baseline",
        u128::try_from(refund).unwrap(),
    )
    .unwrap();
    let e_total = e_sum(&round.division.e_r);
    assert_eq!(
        reconcile::close_reversion_credit(&acc_n, &e_total).unwrap(),
        U256::ZERO
    ); // full extinguishment → no dust; the merchant keeps settle_ptr

    // 5. CONSERVATION: D in = recipients (P) + payer refund (D−C) + merchant remainder.
    let recipients = rail.balance(IL) + rail.balance(WALLET) + rail.balance(FUND);
    let merchant = rail.balance(SETTLE_PTR);
    assert_eq!(rail.balance(REFUND_PTR), d - c); // 600_000 returned to the payer
    assert_eq!(merchant, c - p); // 396_000 net kept by the merchant
    assert_eq!(recipients + rail.balance(REFUND_PTR) + merchant, d); // = D, exactly
                                                                     // The payer's net cost is exactly the gross consumed — no overpay, no double-pay.
    assert_eq!(d - rail.balance(REFUND_PTR), c);
}
