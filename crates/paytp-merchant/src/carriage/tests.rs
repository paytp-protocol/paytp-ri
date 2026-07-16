//! Carriage dispatch tests (F5.1/F5-a/F5-b/F5-c): type-octet routing on `/channel`,
//! `/ack`-only retrieval, `/batch` framing + atomic metering, and the misroute/
//! unknown-octet rejections.

use super::{Carriage, CarriageError, Response};
use crate::channel::ChannelDriver;
use num_bigint::BigUint;
use paytp_core::channel::checkpoint::{Checkpoint, CheckpointRequest};
use paytp_core::channel::establish::{
    ChannelAuth, ChannelOpen, Close, FundingProof, MODE_POSTPAY, MODE_PREPAY,
};
use paytp_core::channel::settle_msg::{
    InstanceLeg, Output, PrepayDrawCompleted, SettlementProof, SettlementPropose, TxRef,
};
use paytp_core::channel::state::Status;
use paytp_core::channel::{AckRequest, ChannelAck, VectorEntry};
use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::derive::{claim_record_id, settlement_net_memo, AddressInputs, MeedVectorEntry};
use paytp_core::fee::{self, Rate, U256};
use paytp_core::tlv::{self, Field, Object};
use paytp_core::{crypto, slice::Slice};
use paytp_rail::{MeedShare, RailAdapter, Transfer, TransferKind, VirtualRail};
use std::sync::Arc;

const PAYER_SK: [u8; 32] = [1u8; 32];
const MERCH_SK: [u8; 32] = [2u8; 32];
const ENC_SEED: [u8; 32] = [7u8; 32];
const CID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];
const NOW: u64 = 1_700_000_000;

fn carriage() -> Carriage {
    Carriage::demo(ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle"))
}

fn payer_open(merchant_key: [u8; 32], enc_key: [u8; 32], s: [u8; 32]) -> ChannelOpen {
    let mut auth = ChannelAuth {
        payer_key: crypto::ed25519_public(&PAYER_SK),
        channel_id: CID,
        merchant_key,
        denom: "solana:dev/usdc".into(),
        mode: MODE_POSTPAY,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: None,
        baseline_net: "solana:dev".into(),
        rate_source: None,
        rate_dev: None,
        schema: 1,
        vector: vec![
            VectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            VectorEntry {
                role: 0x11,
                bp: 10,
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            VectorEntry {
                role: 0x12,
                bp: 30,
                dest: "solana:dev:wallet".into(),
            },
            VectorEntry {
                role: 0x13,
                bp: 10,
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ],
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor: None,
        timestamp: NOW,
        baseline_asset: "solana:dev/usdc".into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    };
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc_key, &s).unwrap()
}

/// A **chained-successor** open (F6.6): a fresh `channel_id` naming a
/// `predecessor`, with the SAME economic terms as `payer_open` (so the F6.6 clause-(c)
/// fingerprint matches its predecessor).
fn payer_open_chained(
    merchant_key: [u8; 32],
    enc_key: [u8; 32],
    s: [u8; 32],
    channel_id: [u8; 8],
    predecessor: ([u8; 8], [u8; 32]),
) -> ChannelOpen {
    // Round-trip a base `payer_open` auth to inherit its exact terms, then re-target it.
    let base = payer_open(merchant_key, enc_key, [0x11; 32]);
    let mut auth = base.auth;
    auth.channel_id = channel_id;
    auth.predecessor = Some(predecessor);
    auth.hs = crypto::h_commit(&s);
    auth.sig = None;
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc_key, &s).unwrap()
}

/// A postpay open with a chosen meed/net finality (for the fold-at-irreversible guard test).
fn open_with_finality(
    mkey: [u8; 32],
    enc: [u8; 32],
    s: [u8; 32],
    fin_meed: &str,
    fin_denom: &str,
) -> ChannelOpen {
    let mut auth = payer_open(mkey, enc, s).auth;
    auth.fin_meed = fin_meed.into();
    auth.fin_denom = fin_denom.into();
    auth.sig = None;
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc, &s).unwrap()
}

#[test]
fn reorgable_finality_channel_refused_on_a_rail() {
    // Build gate R1-1 (fold-at-irreversible, F8.1): a channel naming a REORG-ABLE meed or net
    // finality — weaker than the rail's strongest, irreversible level — is refused at OPEN. Else the
    // merchant folds `settled_r` / clears a draw / refunds at a level a reorg reverts, stranding the
    // enablers. VirtualRail levels = ["pending", "final"]; strongest = "final".
    let mut c = carriage().with_rail(Box::new(VirtualRail::new(FINALITY_DELAY)));
    let (mkey, enc, s) = (c.merchant_key(), c.enc_key(), [0x5a; 32]);
    for (fr, fd) in [
        ("pending", "final"),
        ("final", "pending"),
        ("pending", "pending"),
    ] {
        let bad = open_with_finality(mkey, enc, s, fr, fd);
        assert_eq!(
            c.channel(&framed_msg(0x01, &bad.encode().unwrap()), NOW),
            Err(CarriageError::Rejected),
            "a reorg-able finality ({fr}/{fd}) is refused at open"
        );
    }
    // The strongest (irreversible) level opens the channel normally.
    let good = open_with_finality(mkey, enc, s, "final", "final");
    assert!(
        matches!(
            c.channel(&framed_msg(0x01, &good.encode().unwrap()), NOW)
                .unwrap(),
            Response::Message(_)
        ),
        "the strongest (irreversible) finality opens the channel"
    );
}

/// A **prepay** open: MODE_PREPAY + a refund pointer (required for prepay, §5.4). The
/// deposit funds consumption in advance; at close the unconsumed remainder returns to
/// `refund_ptr` (F6-f).
fn prepay_open(merchant_key: [u8; 32], enc_key: [u8; 32], s: [u8; 32]) -> ChannelOpen {
    let mut auth = ChannelAuth {
        payer_key: crypto::ed25519_public(&PAYER_SK),
        channel_id: CID,
        merchant_key,
        denom: "solana:dev/usdc".into(),
        mode: MODE_PREPAY,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: Some("solana:dev:refund".into()),
        baseline_net: "solana:dev".into(),
        rate_source: None,
        rate_dev: None,
        schema: 1,
        vector: vec![
            VectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            VectorEntry {
                role: 0x11,
                bp: 10,
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            VectorEntry {
                role: 0x12,
                bp: 30,
                dest: "solana:dev:wallet".into(),
            },
            VectorEntry {
                role: 0x13,
                bp: 10,
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ],
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor: None,
        timestamp: NOW,
        baseline_asset: "solana:dev/usdc".into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    };
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc_key, &s).unwrap()
}

fn framed_msg(octet: u8, obj: &[u8]) -> Vec<u8> {
    let mut v = vec![octet];
    v.extend_from_slice(obj);
    v
}

fn k_session(merchant_key: [u8; 32], s: [u8; 32]) -> [u8; 32] {
    crypto::k_session(
        &s,
        &crypto::bind_salt(&crypto::ed25519_public(&PAYER_SK), &merchant_key),
        &CID,
    )
}

fn batch_body(cid: [u8; 8], slices: &[Slice]) -> Vec<u8> {
    let head = Object::from_fields(vec![Field::new(0x00, false, cid.to_vec())])
        .unwrap()
        .encode();
    let mut frames = vec![head];
    frames.extend(slices.iter().map(|s| s.encode()));
    tlv::frame_objects(&frames)
}

/// Open a channel through the carriage and return `(carriage, k_session, auth_hash)`.
fn opened() -> (Carriage, [u8; 32], [u8; 32]) {
    open_on(carriage())
}

/// Open a channel through a (possibly store-backed) carriage — the body of [`opened`], factored so
/// a test can attach a durable store first (e.g. a failing store, C1-3).
fn open_on(mut c: Carriage) -> (Carriage, [u8; 32], [u8; 32]) {
    let mkey = c.merchant_key();
    let enc = c.enc_key();
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s);
    let resp = c
        .channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let auth_hash = match resp {
        Response::Message(m) => {
            assert_eq!(m[0], 0x02, "response is a CHANNEL_ACK (0x02)");
            let ack = ChannelAck::parse(&m[1..]).unwrap();
            assert!(ack.verify(&mkey).is_ok());
            assert_eq!(ack.auth_hash, open.auth.auth_hash().unwrap());
            ack.auth_hash
        }
        _ => panic!("open must return an ACK message"),
    };
    assert_eq!(c.state(&CID).unwrap().status(), Status::Open);
    (c, k_session(mkey, s), auth_hash)
}

#[test]
fn open_then_batch_meters() {
    let (mut c, k, _ah) = opened();
    let s1 = Slice::seal(1, 10_000, &k).unwrap();
    let s2 = Slice::seal(2, 5_000, &k).unwrap();
    assert_eq!(c.batch(&batch_body(CID, &[s1, s2])), Ok(Response::Accepted));
    assert_eq!(c.state(&CID).unwrap().cum_total(), 15_000);
}

fn signed_funding(auth_hash: [u8; 32], tx_ref: &str, amount: u128) -> Vec<u8> {
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: tx_ref.into(),
        amount,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    framed_msg(0x05, &fp.encode().unwrap())
}

#[test]
fn funding_credits_and_reopens() {
    let (mut c, k, ah) = opened();
    // Drive the balance up, then a FUNDING_PROOF credits it back down.
    c.batch(&batch_body(CID, &[Slice::seal(1, 20_000, &k).unwrap()]))
        .unwrap();
    assert_eq!(
        c.channel(&signed_funding(ah, "sig1", 20_000), NOW),
        Ok(Response::Accepted)
    );
    // Credited-not-raw (F6.4): gross 20_000 at 100 bp → meed carve 200, merchant-net
    // 19_800. A 20_000 funding credits only the 19_800 owed to the merchant; the 200
    // excess is forfeit, and `B` floors at the outstanding meed carve (owed to the
    // instance, not the merchant pointer), NOT at 0.
    assert_eq!(c.state(&CID).unwrap().balance(), 200);
}

#[test]
fn funding_with_a_failing_durable_store_rejects_and_leaves_the_ref_creditable() {
    // C1-3: a durable one-decision store that FAILS to persist the consume must NOT be conflated
    // with an already-consumed ref. On the funding CREDIT path the old masking (a failed write
    // reported as `AlreadyDecided`) made the merchant ack `Accepted` and burn the ref WITHOUT
    // crediting `B` — the payer's on-rail deposit stranded. Correct: reject (retryable — the
    // transfer is on-rail), consume NOTHING, so a retry against a recovered store credits once.
    use crate::one_decision::WalOneDecision;
    let path = one_decision_wal_path("funding-fail");
    // A store whose every append fails (read-only fd) — the deterministic storage-failure case.
    let store = Arc::new(WalOneDecision::read_only_for_test(&path).unwrap());
    let (mut c, k, ah) = open_on(carriage().with_decisions(store));
    // Meter value so the window is open and a funding proof would credit it. No rail is attached, so
    // on_funding takes the signature-only interim path whose canonical ref is the tx_ref ("sig1").
    c.batch(&batch_body(CID, &[Slice::seal(1, 20_000, &k).unwrap()]))
        .unwrap();
    let before = c.state(&CID).unwrap().balance();
    assert_eq!(
        c.channel(&signed_funding(ah, "sig1", 20_000), NOW),
        Err(CarriageError::Rejected),
        "a storage failure on the funding credit path rejects (retryable) — never a phantom Accepted"
    );
    assert_eq!(
        c.state(&CID).unwrap().balance(),
        before,
        "B was NOT credited under the failed store (the deposit is not silently absorbed)"
    );
    assert!(
        !c.ref_consumed("sig1"),
        "the ref was NOT burned in-memory — a retry against a recovered store can still credit it"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn funding_replay_is_refused() {
    let (mut c, k, ah) = opened();
    c.batch(&batch_body(CID, &[Slice::seal(1, 40_000, &k).unwrap()]))
        .unwrap();
    // First funding credits; a byte-identical replay (same rail+tx_ref) is refused —
    // a rail transaction is creditable once (§5.4).
    assert_eq!(
        c.channel(&signed_funding(ah, "sig1", 20_000), NOW),
        Ok(Response::Accepted)
    );
    assert_eq!(
        c.channel(&signed_funding(ah, "sig1", 20_000), NOW),
        Err(CarriageError::Rejected)
    );
    assert_eq!(
        c.state(&CID).unwrap().balance(),
        20_000,
        "replay did not double-credit"
    );
    // A FUNDING_PROOF bound to a different channel (wrong AUTH_HASH) is refused.
    assert_eq!(
        c.channel(&signed_funding([0; 32], "sig2", 20_000), NOW),
        Err(CarriageError::Rejected)
    );
}

#[test]
fn ack_retrieval_only_on_ack_resource() {
    let (mut c, _k, _ah) = opened();
    let mut req = AckRequest {
        channel_id: CID,
        timestamp: NOW,
        sig: None,
    };
    req.sign(&PAYER_SK).unwrap();
    let body = framed_msg(0x0A, &req.encode().unwrap());
    // On /ack: returns the CHANNEL_ACK.
    match c.ack(&body, NOW).unwrap() {
        Response::Message(m) => assert_eq!(m[0], 0x02),
        _ => panic!("ack retrieval returns a message"),
    }
    // On /channel: retrieval is misrouted (F5.1 — /ack only).
    assert_eq!(c.channel(&body, NOW), Err(CarriageError::Misrouted));
}

#[test]
fn close_moves_to_settling_and_bars_slices() {
    let (mut c, k, _ah) = opened();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: [0xcc; 32],
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap(); // payer-signed → chain intent honored
    assert_eq!(
        c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    assert_eq!(c.state(&CID).unwrap().status(), Status::Settling);
    // A SETTLING channel meters no further slices (F6.1) — a MAC-valid slice draws
    // the specific Closed outcome (the sender is authenticated, so no leak).
    assert_eq!(
        c.batch(&batch_body(CID, &[Slice::seal(1, 100, &k).unwrap()])),
        Err(CarriageError::Closed)
    );
}

#[test]
fn chained_successor_imports_the_reconciled_position_and_conserves() {
    // End-to-end (F6.6): a predecessor meters real value, closes with chain_intent
    // (the float is NOT refunded), the carriage snapshots its reconciled position,
    // and a chained successor OPENS AT it — importing CUM_TOTAL and the per-role accruals,
    // NOT a fresh zero state. Value carries across the boundary; the payer still owes the
    // imported meed (accruals), and the successor's window continues from the imported B.
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 40_000, &k).unwrap(),
            Slice::seal(2, 20_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    assert_eq!(c.state(&CID).unwrap().cum_total(), 60_000);
    let pred_accruals = c.state(&CID).unwrap().accruals();
    assert!(
        pred_accruals
            .iter()
            .any(|(_, a)| *a > num_bigint::BigUint::from(0u8)),
        "the predecessor accrued meed to import"
    );

    // Cut the bilateral checkpoint at 60_000 — the successor chains from THIS named anchor
    // (F6.6 clause (b) / F3: a successor imports the NAMED checkpoint, never live
    // state; a channel that metered value must checkpoint before it can chain).
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    // Close CID naming the operative checkpoint, with chain_intent.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );

    // Open a chained successor naming (CID, ckpt) — it imports the reconciled position.
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 11];
    let succ = payer_open_chained(
        c.merchant_key(),
        c.enc_key(),
        [0x8c; 32],
        succ_id,
        (CID, ckpt),
    );
    assert!(matches!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    let ss = c.state(&succ_id).unwrap();
    assert_eq!(
        ss.cum_total(),
        60_000,
        "the successor imports the predecessor CUM_TOTAL, not zero (the fix)"
    );
    assert_eq!(
        ss.accruals(),
        pred_accruals,
        "the successor imports the per-role accruals — the payer still owes the meed"
    );
    // Postpay imported B = CUM_TOTAL − funding − net_legs − floor(Σ E / 10000) = 60_000
    // (nothing settled/funded on the predecessor), so the window continues from there.
    assert_eq!(ss.balance(), 60_000);
    // And the successor keeps metering from the imported position: another 10_000 lands.
    let k2 = crypto::k_session(
        &[0x8c; 32],
        &crypto::bind_salt(&crypto::ed25519_public(&PAYER_SK), &c.merchant_key()),
        &succ_id,
    );
    c.batch(&batch_body(
        succ_id,
        &[Slice::seal(1, 10_000, &k2).unwrap()],
    ))
    .unwrap();
    assert_eq!(
        c.state(&succ_id).unwrap().cum_total(),
        70_000,
        "the whole-chain CUM_TOTAL advances (imported 60_000 + own 10_000)"
    );
}

#[test]
fn late_predecessor_funding_credits_the_successor() {
    // F6-f — the imported-predecessor credit path. After a chain_intent
    // close AND a successor import, a FUNDING_PROOF still bound to the PREDECESSOR (its rail
    // transfer memo carries the predecessor AUTH_HASH) is NOT lost: the revocable model keeps
    // the predecessor creditable and routes the leg to the live successor (`resolve_chain_tip`),
    // verifying it against the predecessor it names. The OLD freeze REJECTED such a leg,
    // over-collecting (postpay) / short-refunding (prepay). Spec §6.2: a proof bound to a
    // predecessor is "credited in the first checkpoint of a successor."
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ah, ckpt_ref) = opened_ckpt_with_ah(rail); // postpay, cum 15_000, checkpointed
                                                           // Chain-close the predecessor (Pending), then a successor imports the position (Committed).
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 13];
    let succ = payer_open_chained(
        c.merchant_key(),
        c.enc_key(),
        [0x8c; 32],
        succ_id,
        (CID, ckpt_ref),
    );
    assert!(matches!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    let owed_before = c.state(&succ_id).unwrap().balance();
    // A late funding transfer bound to the PREDECESSOR (memo = predecessor AUTH_HASH).
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 5_000,
            kind: TransferKind::Payment,
            memo: Some(ah),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut fp = FundingProof {
        channel_id: CID, // names the PREDECESSOR
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: 5_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    // Accepted — and credited to the SUCCESSOR (the tip), not the frozen predecessor.
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    let owed_after = c.state(&succ_id).unwrap().balance();
    assert!(
        owed_after <= owed_before - 5_000,
        "late predecessor funding 5000 not credited to the successor (owed {owed_before} -> {owed_after})"
    );
    // The predecessor's own ledger did NOT move (the credit went to the successor).
    assert_eq!(c.state(&CID).unwrap().cum_total(), 15_000);
}

/// The deterministic F6-e synthetic-checkpoint reference of a **funded-but-unmetered** birth
/// channel (`cum_total = 0`), computed exactly as the carriage recomputes it at import.
fn birth_synthetic_ref(channel_id: [u8; 8], prepay: bool, funding: u128) -> [u8; 32] {
    let accruals: Vec<(u8, BigUint)> = [0x10u8, 0x11, 0x12, 0x13]
        .iter()
        .map(|r| (*r, BigUint::from(0u8)))
        .collect();
    let still = paytp_core::channel::checkpoint::StillbornState {
        channel_id,
        prepay,
        cum_total: BigUint::from(0u8),
        accruals,
        settled_sum: BigUint::from(0u8),
        net_legs_sum: BigUint::from(0u8),
        funding_sum: BigUint::from(funding),
        timestamp: NOW,
        prev_ref: [0u8; 32],
    };
    still
        .synthetic_checkpoint()
        .unwrap()
        .synthetic_reference()
        .unwrap()
}

/// A prepay chained open naming `predecessor`, re-targeting a prepay base auth. `hs_secret`
/// lets a test build a DELIBERATELY BROKEN open (seal a secret whose `H(s)` ≠ the committed
/// `hs`) that fails establishment AFTER the carriage has recorded the chain snapshot.
fn prepay_open_chained(
    merchant_key: [u8; 32],
    enc_key: [u8; 32],
    s: [u8; 32],
    channel_id: [u8; 8],
    predecessor: ([u8; 8], [u8; 32]),
    hs_secret: [u8; 32],
) -> ChannelOpen {
    let mut auth = prepay_open(merchant_key, enc_key, [0x11; 32]).auth;
    auth.channel_id = channel_id;
    auth.predecessor = Some(predecessor);
    auth.hs = crypto::h_commit(&hs_secret);
    auth.sig = None;
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc_key, &s).unwrap()
}

#[test]
fn stale_snapshot_not_imported_after_synthetic_ref_moves() {
    // DEFECT this test pins: a chain snapshot from a FAILED successor open
    // must not be importable after the predecessor's deterministic synthetic reference moves.
    // A birth prepay float, a failed open that records a snapshot at the old ref, then a late
    // funding that changes the ref — a successor naming the OLD ref must be REJECTED, never
    // import the stale pre-funding position (which would strand the late deposit).
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let mk = d.key();
    let ek = d.enc_key();
    let open = prepay_open(mk, ek, [0x5a; 32]);
    let ah = open.auth.auth_hash().unwrap();
    let (rail, tx1) = rail_with_funding(ah, 100_000, None);
    let handle = rail.clone();
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    // Fund F1 = 100_000, then chain-close (Pending). No slices → a birth (cum_total 0) float.
    let mut fp1 = FundingProof {
        channel_id: CID,
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: tx1,
        amount: 100_000,
        sig: None,
    };
    fp1.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp1.encode().unwrap()), NOW)
        .unwrap();
    let r1 = birth_synthetic_ref(CID, true, 100_000);
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: r1,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    // A FAILED successor open naming (CID, r1): the carriage records the snapshot, then
    // establishment fails on H(s) mismatch — leaving a stale snapshot under (CID, r1).
    let bad = prepay_open_chained(
        mk,
        ek,
        [0x88; 32],
        [0, 0, 0, 0, 0, 0, 0, 21],
        (CID, r1),
        [0x99; 32],
    );
    assert_eq!(
        c.channel(&framed_msg(0x01, &bad.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
    // Late funding F2 = 50_000 lands on the Pending predecessor → synthetic ref moves to r2.
    let tx2 = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 50_000,
            kind: TransferKind::Payment,
            memo: Some(ah),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut fp2 = FundingProof {
        channel_id: CID,
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: tx2.0,
        amount: 50_000,
        sig: None,
    };
    fp2.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp2.encode().unwrap()), NOW)
        .unwrap();
    // A successor naming the OLD ref r1 MUST be rejected — the stale snapshot is cleared, and
    // a recompute at the current funding yields r2 ≠ r1. It never imports the stale float.
    let succ = prepay_open_chained(
        mk,
        ek,
        [0x8c; 32],
        [0, 0, 0, 0, 0, 0, 0, 22],
        (CID, r1),
        [0x8c; 32],
    );
    assert_eq!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
    // A successor naming the CURRENT ref r2 imports the FULL float (100_000 + 50_000).
    let r2 = birth_synthetic_ref(CID, true, 150_000);
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 23];
    let good = prepay_open_chained(mk, ek, [0x7d; 32], succ_id, (CID, r2), [0x7d; 32]);
    assert!(matches!(
        c.channel(&framed_msg(0x01, &good.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    assert_eq!(
        c.state(&succ_id).unwrap().balance(),
        -150_000,
        "the successor imports the full post-funding prepay float"
    );
}

#[test]
fn redirected_funding_to_a_reconciled_postpay_tip_is_credited() {
    // Mode-aware admissibility: a late predecessor-bound funding leg redirected to a
    // tip that has itself plain-closed (`Reconciled`) is credited iff the tip is **postpay** —
    // funding pays down its standing merchant-net (floored at 0), never stranded (there is no
    // refund flow to a dead channel). (A **prepay** Reconciled tip would reject — its deposit is
    // already reconciled; covered by the conservation property test.) The earlier
    // guard rejected BOTH modes over-broadly; `funding_admissible` narrows it correctly.
    // Predecessor chains into a POSTPAY successor; the successor plain-closes; a late funding
    // naming the predecessor resolves to the tip and is credited.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ah, ckpt_ref) = opened_ckpt_with_ah(rail); // postpay, cum 15_000, checkpointed
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 24];
    let succ = payer_open_chained(
        c.merchant_key(),
        c.enc_key(),
        [0x8c; 32],
        succ_id,
        (CID, ckpt_ref),
    );
    c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW)
        .unwrap();
    // The successor (the live tip) plain-closes → its durable disposition is `Reconciled`.
    let mut succ_close = Close {
        channel_id: succ_id,
        ckpt_ref: [0u8; 32],
        chain_intent: false,
        sig: None,
    };
    succ_close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &succ_close.encode().unwrap()), NOW)
        .unwrap();
    // A late funding bound to the PREDECESSOR resolves to the reconciled POSTPAY tip → credited
    // (pays down the tip's standing merchant-net, floored — the postpay strand fix).
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 5_000,
            kind: TransferKind::Payment,
            memo: Some(ah),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: 5_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "a late funding to a reconciled POSTPAY tip is credited (pays standing merchant-net)"
    );
}

#[test]
fn chain_intent_close_rejected_while_a_round_is_in_flight() {
    // F6.6 quiescence (round-2 gate fix): a `chain_intent` close is REJECTED while an
    // unconfirmed settlement round is in flight. The round's rail legs are bound to THIS
    // channel's `(CHANNEL_ID, CKPT_REF)` memo (F6-h), so they cannot settle the successor;
    // folding after the snapshot would strand the paid legs AND import the full obligation
    // (double-pay). The payer completes/lapses the round, then chains. A NON-chain close is
    // unaffected.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    // Propose a round → an unconfirmed RoundDecision in `self.rounds` (not yet proven).
    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    // A chain_intent close is rejected — the channel is not quiescent.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
    // A NON-chain close of the same in-flight channel is accepted (reconciles normally).
    let mut close2 = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: false,
        sig: None,
    };
    close2.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close2.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
}

#[test]
fn prepay_close_refunds_unconsumed_deposit() {
    // At close a prepay channel returns Σ funding − CUM_TOTAL to the
    // payer's refund pointer via the escrow-release primitive. The meed is drawn
    // FROM the deposit during settlement (prepay merchant is the debtor), so this
    // refund cannot double-pay it.
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let deposit = 1_000_000u128;
    let (rail, tx_ref) = rail_with_funding(auth_hash, deposit, None);
    let rail_handle = rail.clone();

    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();

    // Prepay deposits BEFORE it consumes: fund the full deposit, then meter C = 400_000.
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: deposit,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 400_000, &k).unwrap()]))
        .unwrap();
    // Checkpoint the consumption: F6-k/F6-f reconcile the refund against the NAMED checkpoint's
    // CUM_TOTAL, so consumed value must be checkpointed to be deducted (uncheckpointed value is
    // the merchant's E-risk, eaten at close — see `close_refund_reads_named_not_live_checkpoint`).
    let (req, ckpt_ref) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    assert_eq!(rail_handle.balance("solana:dev:settle"), deposit); // deposit sits at settle_ptr

    // Close with no chain intent → refund D − C = 600_000 to the refund pointer.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    assert_eq!(rail_handle.balance("solana:dev:refund"), 600_000);
    // C stays at settle_ptr — the merchant's net plus the still-owed meed obligation.
    assert_eq!(rail_handle.balance("solana:dev:settle"), 400_000);
}

#[test]
fn prepay_chained_close_rolls_forward_without_refund() {
    // A payer that chains in its CLOSE keeps the float for the successor — no refund
    // (§6.2: a deposit paid out is a checkpoint no successor can import).
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let rail_handle = rail.clone();
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();

    let mut close = Close {
        channel_id: CID,
        ckpt_ref: [0u8; 32],
        chain_intent: true, // roll the deposit forward
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(rail_handle.balance("solana:dev:refund"), 0); // no refund
    assert_eq!(rail_handle.balance("solana:dev:settle"), 1_000_000); // float stays for the successor
}

#[test]
fn prepay_replayed_close_does_not_double_refund() {
    // Idempotency (gate CRITICAL): a replayed CLOSE must NOT release the refund again.
    // settle_ptr is seeded with OTHER channels' commingled deposits so a second release
    // WOULD succeed without the guard — the test proves it does not fire.
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let rail_handle = rail.clone();
    // Other channels' deposits sitting at the shared settle_ptr (the pool).
    rail_handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 2_000_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();

    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();

    let mut close = Close {
        channel_id: CID,
        ckpt_ref: [0u8; 32],
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    let framed = framed_msg(0x09, &close.encode().unwrap());
    // First close → refund D − C = 1_000_000 (no metering). Pool: 3M − 1M = 2M left.
    assert_eq!(c.channel(&framed, NOW), Ok(Response::Accepted));
    assert_eq!(rail_handle.balance("solana:dev:refund"), 1_000_000);
    assert_eq!(rail_handle.balance("solana:dev:settle"), 2_000_000);
    // REPLAY the identical close → accepted idempotently, but NO second release: the
    // other channels' 2_000_000 is untouched, and the refund is not doubled.
    assert_eq!(c.channel(&framed, NOW), Ok(Response::Accepted));
    assert_eq!(rail_handle.balance("solana:dev:refund"), 1_000_000);
    assert_eq!(rail_handle.balance("solana:dev:settle"), 2_000_000);
}

#[test]
fn imported_successor_plain_close_refunds_against_imported_cum() {
    // A chained successor imports a nonzero CONSUMED position but
    // signs NO operative checkpoint of its own, so it lives in no `operative` entry. Its
    // plain-close refund MUST deduct the IMPORTED consumption — an imported successor is not a
    // fresh birth. Without the `imported_cum` basis the refund reads `0` and returns the WHOLE
    // deposit, losing the imported consumption (merchant out the consumed value).
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let (mk, ek) = (d.key(), d.enc_key());
    let open = prepay_open(mk, ek, [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let rail_handle = rail.clone();
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    // Predecessor: fund the full deposit, consume 60_000, checkpoint it, chain-close (float rolls
    // forward — Pending).
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(mk, [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 60_000, &k).unwrap()]))
        .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();

    // Successor imports cum_total = 60_000 and opening_funding = 1_000_000; it signs NO checkpoint.
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 21];
    let succ = prepay_open_chained(mk, ek, [0x8c; 32], succ_id, (CID, ckpt), [0x8c; 32]);
    assert!(matches!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    assert_eq!(
        c.state(&succ_id).unwrap().cum_total(),
        60_000,
        "the successor imported the consumed position"
    );

    // Plain-close the successor → refund = funding (1_000_000) − imported cum (60_000) = 940_000,
    // NOT the whole 1_000_000 (which the missing `imported_cum` basis would have returned).
    let mut sclose = Close {
        channel_id: succ_id,
        ckpt_ref: [0u8; 32], // the successor signed no checkpoint of its own
        chain_intent: false,
        sig: None,
    };
    sclose.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &sclose.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    assert_eq!(
        rail_handle.balance("solana:dev:refund"),
        940_000,
        "imported-successor refund must deduct the imported consumption (60_000), not read 0"
    );
}

#[test]
fn imported_stillborn_chain_close_rejected_fail_fast() {
    // A chained successor that imports a NONZERO position
    // but signs no own checkpoint cannot be chained ONWARD (F5-a — its final checkpoint would be
    // an F6-e synthetic one over nonzero imported state, deferred). Its `chain_intent` close is
    // rejected FAIL-FAST (the payer plain-closes instead), never recorded as a `Pending` intent no
    // successor can consume.
    let (mut c, k, _ah) = opened(); // postpay
    c.batch(&batch_body(CID, &[Slice::seal(1, 60_000, &k).unwrap()]))
        .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    // Successor imports 60_000, signs no own checkpoint.
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 22];
    let succ = payer_open_chained(
        c.merchant_key(),
        c.enc_key(),
        [0x8c; 32],
        succ_id,
        (CID, ckpt),
    );
    assert!(matches!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    assert_eq!(c.state(&succ_id).unwrap().cum_total(), 60_000);
    // The successor's chain_intent close is REJECTED (no own checkpoint + nonzero imported position).
    let mut sclose = Close {
        channel_id: succ_id,
        ckpt_ref: [0u8; 32],
        chain_intent: true,
        sig: None,
    };
    sclose.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &sclose.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "an imported nonzero stillborn cannot chain onward — reject fail-fast (F5-a)"
    );
    // A PLAIN close of the same successor is accepted (postpay: the imported debt stands as a
    // §6.4 standing obligation, not stranded in a dead Pending).
    let mut pclose = Close {
        channel_id: succ_id,
        ckpt_ref: [0u8; 32],
        chain_intent: false,
        sig: None,
    };
    pclose.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &pclose.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
}

#[test]
fn batch_bound_errors_are_specific_post_mac() {
    let (mut c, k, _ah) = opened();
    // A MAC-valid slice past the window bound (limit_l = 1_000_000) → WindowExceeded.
    assert_eq!(
        c.batch(&batch_body(CID, &[Slice::seal(1, 2_000_000, &k).unwrap()])),
        Err(CarriageError::WindowExceeded)
    );
    // A slice under a WRONG key fails the MAC → the generic pre-auth rejection.
    let wrong = Slice::seal(1, 100, &[0x99; 32]).unwrap();
    assert_eq!(
        c.batch(&batch_body(CID, &[wrong])),
        Err(CarriageError::Rejected)
    );
}

/// The payer's `CHECKPOINT_REQUEST` (F5.5): build a proposal from the (identical)
/// metering, sign the payer slot (the inner half-signed checkpoint), and wrap it in
/// the `PayTPv1-ckpt-req` two-label construction.
fn payer_checkpoint_request(c: &Carriage) -> (Vec<u8>, [u8; 32]) {
    let mut cp = c
        .state(&CID)
        .unwrap()
        .build_checkpoint(NOW, [0u8; 32], vec![]);
    cp.sign_payer(&PAYER_SK).unwrap();
    // The bilateral reference the merchant will produce (payer + merchant sigs); the
    // merchant signs with MERCH_SK, so reproduce that here for the CLOSE ckpt_ref.
    let mut bilateral = cp.clone();
    bilateral.sign_merchant(&MERCH_SK).unwrap();
    // F5.5 wrapper: {0x00 PROPOSED (half-signed ckpt), 0x70 SIG (ckpt-req)}.
    let mut req = CheckpointRequest::proposing(cp);
    req.sign(&PAYER_SK).unwrap();
    (
        framed_msg(0x03, &req.encode().unwrap()),
        bilateral.reference().unwrap(),
    )
}

#[test]
fn checkpoint_countersign_and_close_anchors_to_it() {
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let mkey = c.merchant_key();
    let pkey = crypto::ed25519_public(&PAYER_SK);

    // CHECKPOINT_REQUEST → the merchant recomputes, countersigns, returns 0x04.
    let (req, expected_ref) = payer_checkpoint_request(&c);
    let bilateral = match c.channel(&req, NOW).unwrap() {
        Response::Message(m) => {
            assert_eq!(m[0], 0x04);
            let cp = Checkpoint::parse(&m[1..]).unwrap();
            cp.verify_bilateral(&pkey, &mkey).unwrap();
            cp
        }
        _ => panic!("checkpoint request returns a bilateral CHECKPOINT"),
    };
    assert_eq!(bilateral.reference().unwrap(), expected_ref);

    // C44b: a CLOSE must now name the operative checkpoint. A wrong ref is refused;
    // the right one settles.
    let mut wrong = Close {
        channel_id: CID,
        ckpt_ref: [0xab; 32],
        chain_intent: false,
        sig: None,
    };
    wrong.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &wrong.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
    let mut right = Close {
        channel_id: CID,
        ckpt_ref: expected_ref,
        chain_intent: false,
        sig: None,
    };
    right.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &right.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    assert_eq!(c.state(&CID).unwrap().status(), Status::Settling);
}

#[test]
fn checkpoint_request_bare_form_rejected_wrapped_accepted() {
    // F5.5: the merchant's checkpoint-request handler now expects the two-label
    // wrapper. A BARE `0x03 ‖ <half-signed checkpoint>` (the pre-fix RI form, and a
    // conformant peer's rejected input) is MALFORMED; the F5.5-wrapped request is accepted
    // and countersigned into a bilateral CHECKPOINT (0x04).
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(CID, &[Slice::seal(1, 10_000, &k).unwrap()]))
        .unwrap();
    // Bare form (no wrapper) → Malformed.
    let mut bare = c
        .state(&CID)
        .unwrap()
        .build_checkpoint(NOW, [0u8; 32], vec![]);
    bare.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x03, &bare.encode().unwrap()), NOW),
        Err(CarriageError::Malformed)
    );
    // F5.5-wrapped request → accepted (countersigned 0x04).
    let (req, _ref) = payer_checkpoint_request(&c);
    assert!(matches!(c.channel(&req, NOW), Ok(Response::Message(m)) if m[0] == 0x04));
}

#[test]
fn checkpoint_mismatch_is_rejected() {
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(CID, &[Slice::seal(1, 10_000, &k).unwrap()]))
        .unwrap();
    // A proposal whose metering does not recompute (inflated CUM_TOTAL) is a mismatch.
    // The wire form is the F5.5 wrapper: the sigs verify (the inflated value is signed),
    // but the recompute fails → StateMismatch (not a signature/parse rejection).
    let mut cp = c
        .state(&CID)
        .unwrap()
        .build_checkpoint(NOW, [0u8; 32], vec![]);
    cp.cum_total = num_bigint::BigUint::from(999_999u32);
    cp.sign_payer(&PAYER_SK).unwrap();
    let mut req = CheckpointRequest::proposing(cp);
    req.sign(&PAYER_SK).unwrap();
    assert!(matches!(
        c.channel(&framed_msg(0x03, &req.encode().unwrap()), NOW),
        Err(CarriageError::StateMismatch(_))
    ));
}

#[test]
fn checkpoint_releases_evidence_pause() {
    // E = 10_000: a slice reaching E pauses on evidence; the countersigned checkpoint
    // releases it (F6.3).
    let mut c = carriage();
    let mkey = c.merchant_key();
    let enc = c.enc_key();
    let s = [0x5a; 32];
    // Re-open with a small E by building the auth directly (payer_open uses E=500_000).
    let mut auth = ChannelAuth {
        payer_key: crypto::ed25519_public(&PAYER_SK),
        channel_id: CID,
        merchant_key: mkey,
        denom: "solana:dev/usdc".into(),
        mode: MODE_POSTPAY,
        limit_l: 1_000_000,
        limit_e: 10_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: None,
        baseline_net: "solana:dev".into(),
        rate_source: None,
        rate_dev: None,
        schema: 1,
        vector: vec![
            VectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            VectorEntry {
                role: 0x11,
                bp: 10,
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            VectorEntry {
                role: 0x12,
                bp: 30,
                dest: "solana:dev:wallet".into(),
            },
            VectorEntry {
                role: 0x13,
                bp: 10,
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ],
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor: None,
        timestamp: NOW,
        baseline_asset: "solana:dev/usdc".into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    };
    auth.sign(&PAYER_SK).unwrap();
    let open = ChannelOpen::build(auth, &enc, &s).unwrap();
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(mkey, s);

    c.batch(&batch_body(CID, &[Slice::seal(1, 10_000, &k).unwrap()]))
        .unwrap();
    assert_eq!(c.state(&CID).unwrap().status(), Status::PausedEvidence);
    let (req, _r) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    assert_eq!(c.state(&CID).unwrap().status(), Status::Open);
}

/// Open, meter, and checkpoint — returns `(carriage, operative ckpt_ref)`.
fn opened_and_checkpointed() -> (Carriage, [u8; 32]) {
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req, ckpt_ref) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    (c, ckpt_ref)
}

// The metering `opened_and_checkpointed` produces: gross 15_000, schema-0x01 roles
// 0x10/0x11/0x12/0x13 @ 50/10/30/10 bp → per-role accruals
// 750_000/150_000/450_000/150_000. The recomputed deterministic round is therefore
// P=150, E_r=750_000/150_000/450_000/150_000, net=14_850 (= gross − carve 150). These
// are derived below via the same public math the carriage uses, not hard-coded.
const GROSS: u128 = 15_000;

/// The correctly-recomputed deterministic round for the standard metering.
fn correct_round() -> (u128, Vec<(u8, BigUint)>, u128) {
    let n_r = vec![
        fee::u256_from_biguint(&BigUint::from(750_000u32)).unwrap(),
        fee::u256_from_biguint(&BigUint::from(150_000u32)).unwrap(),
        fee::u256_from_biguint(&BigUint::from(450_000u32)).unwrap(),
        fee::u256_from_biguint(&BigUint::from(150_000u32)).unwrap(),
    ];
    let div = fee::divide_round(&n_r, &Rate::new(1, 1).unwrap()).unwrap();
    let p = u128::try_from(fee::biguint_from_u256(div.p)).unwrap();
    let e_r: Vec<(u8, BigUint)> = [0x10u8, 0x11, 0x12, 0x13]
        .iter()
        .zip(div.e_r.iter())
        .map(|(r, u)| (*r, fee::biguint_from_u256(*u)))
        .collect();
    let owed = fee::reconcile::outstanding_merchant_net(
        &U256::from(GROSS),
        &n_r,
        &U256::ZERO,
        &U256::ZERO,
    );
    (
        p,
        e_r,
        u128::try_from(fee::biguint_from_u256(owed)).unwrap(),
    )
}

/// A deterministic proposal matching the recomputed round; `net_override`/`p_override`
/// let a test propose an *understated* round to prove the economic check rejects it.
fn propose_round(
    ckpt_ref: [u8; 32],
    net_override: Option<u128>,
    p_override: Option<u128>,
) -> SettlementPropose {
    let (p, e_r, net) = correct_round();
    let mut sp = SettlementPropose {
        channel_id: CID,
        ckpt_ref,
        outputs: vec![Output {
            amount: BigUint::from(net_override.unwrap_or(net)),
            asset: "solana:dev/usdc".into(),
            dest: "solana:dev:settle".into(),
        }],
        instance_leg: Some(InstanceLeg {
            amount: BigUint::from(p_override.unwrap_or(p)),
            credited: vec![],
            extinguished: e_r,
        }),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    sp.sign_payer(&PAYER_SK).unwrap();
    sp
}

/// Round economics for a total metering of `cum` µ-units under the schema-01 vector
/// (roles 0x10:50 / 0x11:10 / 0x12:30 / 0x13:10) against a fresh ledger — `(P, E_r, net)`.
/// Generalizes `correct_round()` (which is `round_for(15_000)`).
fn round_for(cum: u128) -> (u128, Vec<(u8, BigUint)>, u128) {
    let bps = [(0x10u8, 50u128), (0x11, 10), (0x12, 30), (0x13, 10)];
    let n_r: Vec<U256> = bps
        .iter()
        .map(|(_, bp)| fee::u256_from_biguint(&BigUint::from(cum * bp)).unwrap())
        .collect();
    let div = fee::divide_round(&n_r, &Rate::new(1, 1).unwrap()).unwrap();
    let p = u128::try_from(fee::biguint_from_u256(div.p)).unwrap();
    let e_r = bps
        .iter()
        .map(|(r, _)| *r)
        .zip(div.e_r.iter().map(|u| fee::biguint_from_u256(*u)))
        .collect();
    let owed =
        fee::reconcile::outstanding_merchant_net(&U256::from(cum), &n_r, &U256::ZERO, &U256::ZERO);
    (
        p,
        e_r,
        u128::try_from(fee::biguint_from_u256(owed)).unwrap(),
    )
}

/// A deterministic proposal for a `cum`-µ-unit position against `ckpt_ref`.
fn propose_round_for(ckpt_ref: [u8; 32], cum: u128) -> SettlementPropose {
    let (p, e_r, net) = round_for(cum);
    let mut sp = SettlementPropose {
        channel_id: CID,
        ckpt_ref,
        outputs: vec![Output {
            amount: BigUint::from(net),
            asset: "solana:dev/usdc".into(),
            dest: "solana:dev:settle".into(),
        }],
        instance_leg: Some(InstanceLeg {
            amount: BigUint::from(p),
            credited: vec![],
            extinguished: e_r,
        }),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    sp.sign_payer(&PAYER_SK).unwrap();
    sp
}

/// The instance address the meed leg pays (F4.1), derived exactly as the carriage.
fn seed_instance() -> [u8; 32] {
    AddressInputs {
        merchant_key: crypto::ed25519_public(&MERCH_SK),
        asset: "solana:dev/usdc".into(),
        schema: 1,
        vector: vec![
            MeedVectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            MeedVectorEntry {
                role: 0x11,
                bp: 10,
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            MeedVectorEntry {
                role: 0x12,
                bp: 30,
                dest: "solana:dev:wallet".into(),
            },
            MeedVectorEntry {
                role: 0x13,
                bp: 10,
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ],
        contract: 1,
        merchant_net: None,
    }
    .seed_instance()
    .unwrap()
}

/// The conformant schema-0x01 meed vector (IL/OS/WALLET/DEV @ 50/10/30/10 bp).
fn schema01_vector() -> Vec<VectorEntry> {
    vec![
        VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "solana:dev:il".into(),
        },
        VectorEntry {
            role: 0x11,
            bp: 10,
            dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        VectorEntry {
            role: 0x12,
            bp: 30,
            dest: "solana:dev:wallet".into(),
        },
        VectorEntry {
            role: 0x13,
            bp: 10,
            dest: DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

/// An OFF-BASELINE payer open: DENOM ≠ BASELINE_ASSET, so the channel requires a rate and its
/// settlement rounds carry a CONVERSION (F5.6). Otherwise identical to `payer_open`.
fn payer_open_off_baseline(merchant_key: [u8; 32], enc_key: [u8; 32], s: [u8; 32]) -> ChannelOpen {
    let mut auth = ChannelAuth {
        payer_key: crypto::ed25519_public(&PAYER_SK),
        channel_id: CID,
        merchant_key,
        denom: "solana:dev/eur".into(), // ≠ baseline_asset → off-baseline
        mode: MODE_POSTPAY,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: None,
        baseline_net: "solana:dev".into(),
        rate_source: Some("solana:dev:oracle".into()), // required off-baseline
        rate_dev: Some(50),                            // required off-baseline
        schema: 1,
        vector: schema01_vector(),
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor: None,
        timestamp: NOW,
        baseline_asset: "solana:dev/usdc".into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    };
    auth.sign(&PAYER_SK).unwrap();
    ChannelOpen::build(auth, &enc_key, &s).unwrap()
}

#[test]
fn off_baseline_open_is_fail_closed() {
    // (2026-07-10): an off-baseline channel (DENOM ≠ BASELINE_ASSET) is now rejected AT
    // OPEN, not merely at settlement. This RI defers off-baseline wholesale — a converted round
    // needs the rate oracle, and an off-baseline chain is rejected (`chained_import`) — so such a
    // channel could only *carry* metered value it can never settle or chain out, stranding it.
    // Fail-closing at establishment keeps value off an unsettleable channel. (Spec-permitted
    // off-baseline, F5.6/F6.5, is an RI conformance-scope deferral.)
    let mut c = carriage();
    let (mkey, enc) = (c.merchant_key(), c.enc_key());
    let open = payer_open_off_baseline(mkey, enc, [0x5a; 32]);
    // The driver returns `OffBaselineUnsupported`, mapped to the uniform carriage rejection.
    assert_eq!(
        c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
}

#[test]
fn checkpoint_retry_returns_countersigned_idempotently() {
    // F6: after the first CHECKPOINT_REQUEST is countersigned, state.checkpoint() advances
    // the floor, so an identical retry no longer recomputes(). The merchant must still recover
    // the receipt for the payer (e.g. after a lost response) by re-returning the SAME
    // countersigned checkpoint, not a PAYTP_STATE_MISMATCH stall (liveness — CUM_TOTAL/ACCRUALS
    // live on the operative + F6-f ledger regardless of the receipt).
    let (mut c, k, _ah) = opened();
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req, _ckpt_ref) = payer_checkpoint_request(&c);
    let first = c.channel(&req, NOW);
    assert!(matches!(&first, Ok(Response::Message(_))));
    // The identical retry returns the SAME countersigned checkpoint (idempotent), where the
    // merchant previously answered Err(StateMismatch(None)).
    assert_eq!(c.channel(&req, NOW), first);
}

#[test]
fn settlement_propose_verifies_economics_against_checkpoint() {
    let (mut c, ckpt_ref) = opened_and_checkpointed();
    // The correctly-recomputed round is accepted (no rail → CONFIRMED deferred).
    assert_eq!(
        c.channel(
            &framed_msg(0x06, &propose_round(ckpt_ref, None, None).encode().unwrap()),
            NOW
        ),
        Ok(Response::Accepted)
    );
    // An identical-terms retry is accepted (F6.5).
    assert_eq!(
        c.channel(
            &framed_msg(0x06, &propose_round(ckpt_ref, None, None).encode().unwrap()),
            NOW
        ),
        Ok(Response::Accepted)
    );
}

#[test]
fn settlement_understated_round_rejected() {
    // The core of the F6-f recompute: a debtor proposing LESS net than the checkpoint
    // owes (14_850) — here net=1 — is rejected, and so is an understated meed P.
    let (mut c, ckpt_ref) = opened_and_checkpointed();
    assert_eq!(
        c.channel(
            &framed_msg(
                0x06,
                &propose_round(ckpt_ref, Some(1), None).encode().unwrap()
            ),
            NOW
        ),
        Err(CarriageError::Rejected)
    );
    let (mut c2, ck2) = opened_and_checkpointed();
    assert_eq!(
        c2.channel(
            &framed_msg(0x06, &propose_round(ck2, None, Some(1)).encode().unwrap()),
            NOW
        ),
        Err(CarriageError::Rejected)
    );
}

#[test]
fn settlement_propose_with_extra_sig_merchant_rejected() {
    // F5.6 / F5-h: a deterministic (baseline-denominated) round is single-signed —
    // only the debtor's slot present. An OTHERWISE-VALID proposal (correct economics + correct
    // payer sig) that ALSO carries a `SIG_MERCHANT` slot is rejected on the deterministic round
    // the RI settles (default-deny). Without the reject, the merchant would process it and
    // `proposal_hash()` would bind the non-canonical both-signed bytes.
    let (mut c, ckpt_ref) = opened_and_checkpointed();
    let mut both_signed = propose_round(ckpt_ref, None, None); // valid, payer-signed
    both_signed.sign_merchant(&MERCH_SK).unwrap(); // illegal extra slot (even a valid one)
    assert!(both_signed.sig_merchant.is_some());
    assert_eq!(
        c.channel(&framed_msg(0x06, &both_signed.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
    // Control: the SAME round single-signed (the canonical deterministic form) is accepted —
    // proving the rejection is the extra slot, not the round economics.
    assert!(c
        .channel(
            &framed_msg(0x06, &propose_round(ckpt_ref, None, None).encode().unwrap()),
            NOW
        )
        .is_ok());
}

#[test]
fn settlement_propose_rejections() {
    let (mut c, ckpt_ref) = opened_and_checkpointed();

    // Wrong CKPT_REF (not the operative checkpoint) → rejected.
    assert_eq!(
        c.channel(
            &framed_msg(
                0x06,
                &propose_round([0xab; 32], None, None).encode().unwrap()
            ),
            NOW
        ),
        Err(CarriageError::Rejected)
    );

    // An OUTPUTS destination not bound at establishment → rejected.
    let mut unbound = propose_round(ckpt_ref, None, None);
    unbound.outputs[0].dest = "solana:dev:attacker".into();
    unbound.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x06, &unbound.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );

    // A substituted (non-DENOM) asset → rejected (F5.6).
    let mut wrong_asset = propose_round(ckpt_ref, None, None);
    wrong_asset.outputs[0].asset = "solana:dev/attacoin".into();
    wrong_asset.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x06, &wrong_asset.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );

    // CONVERSION present on a baseline-denominated channel → malformed (F5.6 presence).
    let mut with_conv = propose_round(ckpt_ref, None, None);
    with_conv.conversion = Some(paytp_core::channel::settle_msg::Conversion {
        rate: "1".into(),
        rate_time: NOW,
        rate_exp: NOW + 3600,
        rate_grace: 60,
    });
    with_conv.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x06, &with_conv.encode().unwrap()), NOW),
        Err(CarriageError::Malformed)
    );

    // A PROOF naming a round the merchant never countersigned → rejected.
    let mut orphan = SettlementProof {
        channel_id: CID,
        proposal_hash: [0x99; 32],
        tx_refs: vec![TxRef {
            leg: 0x01,
            reference: "x".into(),
            finality: "final".into(),
        }],
        sig_payer: None,
        sig_merchant: None,
    };
    orphan.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x07, &orphan.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
}

#[test]
fn malformed_slice_is_channel_independent() {
    // A corrupt slice frame is Malformed whether or not the channel exists — the
    // structural parse happens before the channel lookup, so it is not a pre-auth
    // existence oracle (F6-b).
    let (mut c, _k, _ah) = opened();
    let head = Object::from_fields(vec![Field::new(0x00, false, CID.to_vec())])
        .unwrap()
        .encode();
    let garbage = vec![0xffu8, 0x01, 0x02]; // not a valid slice object
    let body_known = tlv::frame_objects(&[head.clone(), garbage.clone()]);
    // Known channel + corrupt slice.
    assert_eq!(c.batch(&body_known), Err(CarriageError::Malformed));
    // Unknown channel + corrupt slice → the SAME error (no oracle).
    let other_head = Object::from_fields(vec![Field::new(0x00, false, vec![9u8; 8])])
        .unwrap()
        .encode();
    let body_unknown = tlv::frame_objects(&[other_head, garbage]);
    assert_eq!(c.batch(&body_unknown), Err(CarriageError::Malformed));
}

#[test]
fn routing_rejections() {
    let mut c = carriage();
    // Empty body → UnknownType.
    assert_eq!(c.channel(&[], NOW), Err(CarriageError::UnknownType));
    // An octet outside 0x01..=0x0A.
    assert_eq!(
        c.channel(&framed_msg(0xff, b"x"), NOW),
        Err(CarriageError::UnknownType)
    );
    // A recognized-but-inbound-unsupported control object: SETTLEMENT_CONFIRMED
    // (0x08) is creditor-outbound in postpay, never received here.
    assert_eq!(
        c.channel(&framed_msg(0x08, b"x"), NOW),
        Err(CarriageError::Unsupported)
    );
    // A /channel control object misrouted to /ack.
    assert_eq!(
        c.ack(&framed_msg(0x01, b"x"), NOW),
        Err(CarriageError::Misrouted)
    );
    // A FUNDING_PROOF for a channel this merchant does not hold → the uniform
    // pre-auth rejection (no UnknownChannel oracle, F6-b).
    assert_eq!(
        c.channel(&signed_funding_other([9; 8]), NOW),
        Err(CarriageError::Rejected)
    );
}

fn signed_funding_other(cid: [u8; 8]) -> Vec<u8> {
    let mut fp = FundingProof {
        channel_id: cid,
        auth_hash: [0; 32],
        rail: "solana:dev".into(), // F9.1 rail id (was "r": now rejected at parse)
        tx_ref: "t".into(),
        amount: 1,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    framed_msg(0x05, &fp.encode().unwrap())
}

#[test]
fn retransmit_open_does_not_reset_meter() {
    // Build the OPEN once and keep its exact bytes — a real network retransmit
    // resends the identical object (the HPKE seal is randomized, so re-sealing would
    // be a different object and correctly trip the chosen-secret replay bar).
    let mut c = carriage();
    let mkey = c.merchant_key();
    let enc = c.enc_key();
    let open_bytes = framed_msg(0x01, &payer_open(mkey, enc, [0x5a; 32]).encode().unwrap());

    c.channel(&open_bytes, NOW).unwrap();
    let k = k_session(mkey, [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 30_000, &k).unwrap()]))
        .unwrap();
    assert_eq!(c.state(&CID).unwrap().cum_total(), 30_000);

    // A byte-identical retransmit returns the stored ACK, never re-initializing the
    // metering state (F5-m — no slice-plane reset).
    match c.channel(&open_bytes, NOW).unwrap() {
        Response::Message(m) => assert_eq!(m[0], 0x02),
        _ => panic!("retransmit returns the stored ACK"),
    }
    assert_eq!(
        c.state(&CID).unwrap().cum_total(),
        30_000,
        "meter not reset"
    );
}

// --- Rail-adapter verification (F6.4/F6.5) ---

const FINALITY_DELAY: u64 = 100;

/// A rail with one funding transfer to the settlement pointer already final, its
/// memo bound to `auth_hash` (the interim channel binding). Returns `(rail,
/// tx_ref)`.
fn rail_with_funding(
    auth_hash: [u8; 32],
    amount: u128,
    memo: Option<[u8; 32]>,
) -> (VirtualRail, String) {
    let rail = VirtualRail::new(FINALITY_DELAY);
    let r = rail
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount,
            kind: TransferKind::Payment,
            memo: memo.or(Some(auth_hash)),
        })
        .unwrap();
    rail.advance_clock(FINALITY_DELAY); // reach `final`
    (rail, r.0)
}

/// Open a channel on a carriage backed by `rail`. Returns `(carriage, auth_hash)`.
fn opened_with_rail(rail: VirtualRail) -> (Carriage, [u8; 32]) {
    let mut c = Carriage::demo(ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle"))
        .with_rail(Box::new(rail));
    let mkey = c.merchant_key();
    let enc = c.enc_key();
    let open = payer_open(mkey, enc, [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    (c, auth_hash)
}

#[test]
fn rail_funding_verified_and_credited() {
    // Build the auth first to bind the funding tx's memo to its AUTH_HASH.
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = payer_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 20_000, None);

    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 20_000, &k).unwrap()]))
        .unwrap();

    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 20_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    // Credited-not-raw (F6.4): gross 20_000 at 100 bp → merchant-net 19_800 credited,
    // `B` floors at the 200 outstanding meed carve (see funding_credits_and_reopens).
    assert_eq!(c.state(&CID).unwrap().balance(), 200);
}

#[test]
fn rail_funding_wrong_memo_or_unfinalized_rejected() {
    // A funding tx whose memo names a DIFFERENT channel (attacker's) is refused — the
    // memo binds the tx to one channel (interim).
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = payer_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 20_000, Some([0xbe; 32])); // wrong memo

    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 20_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );

    // A funding tx that has NOT reached finality is refused.
    let rail2 = VirtualRail::new(FINALITY_DELAY);
    let r = rail2
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 20_000,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    // no advance_clock → still "pending"
    let d2 = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open2 = payer_open(d2.key(), d2.enc_key(), [0x5a; 32]);
    let mut c2 = Carriage::demo(d2).with_rail(Box::new(rail2));
    c2.channel(&framed_msg(0x01, &open2.encode().unwrap()), NOW)
        .unwrap();
    let mut fp2 = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: r.0,
        amount: 20_000,
        sig: None,
    };
    fp2.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c2.channel(&framed_msg(0x05, &fp2.encode().unwrap()), NOW),
        Err(CarriageError::Rejected)
    );
}

#[test]
fn rail_settlement_full_correlation_confirms() {
    // The full F6-f CONFIRMED: the rail carries the round's REAL legs — the meed
    // leg pays P to the DERIVED instance address in BASELINE_ASSET with its memo
    // binding the exact (CHANNEL_ID, CKPT_REF, P) claim record, and the net leg pays
    // the recomputed merchant-net to the settlement pointer — both final, meed
    // first. The creditor correlates them and signs SETTLEMENT_CONFIRMED.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone(); // shares state — submit legs after we know CKPT_REF
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    let mkey = c.merchant_key();
    let (p, _e_r, net) = correct_round();

    // Propose the correctly-recomputed round (verified against the checkpoint).
    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );

    // Lay the round's real legs on the shared rail. The meed leg is executed through the
    // REAL primitive (Option W, F6-o): deploy the instance (F4.1), then advance_channel_meed
    // moves the per-channel watermark to the round's own-cumulative target (single round:
    // target_P == P), runs the F7.3 distribution, and stamps the ref with the
    // `advanced_channel_meed` fact — so the proof correlates a genuinely-distributing advance,
    // not a hand-forged memo (F6-m: the flagship meed path proven advance → proof → CONFIRMED).
    let seed = seed_instance();
    let inst = handle.deploy_instance_unchecked(
        &seed,
        crypto::ed25519_public(&MERCH_SK),
        vec![
            MeedShare {
                dest: "solana:dev:il".into(),
                bp: 50,
            },
            MeedShare {
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
            MeedShare {
                dest: "solana:dev:wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
        ],
    );
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();
    // The F7-d meed distribution ran through the real primitive — all four schema-0x01
    // recipients are credited their governed share of P (50/10/30/10 bp) on the rail. This
    // is the "governed meed on the wire" actually reaching every recipient, end-to-end —
    // including the OS and Dev-Fund roles a non-conformant vector would have starved.
    let (b_il, b_os, b_wallet, b_dev) = (
        handle.balance("solana:dev:il"),
        handle.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER),
        handle.balance("solana:dev:wallet"),
        handle.balance(DEV_FUND_DEST_PLACEHOLDER),
    );
    assert!(b_il > 0 && b_os > 0 && b_wallet > 0 && b_dev > 0);
    assert_eq!(b_os, b_dev); // 10 bp each
    assert!(b_il > b_wallet && b_wallet > b_os); // 50 > 30 > 10 bp
    assert_eq!(b_il + b_os + b_wallet + b_dev, p); // the whole pool P reaches the recipients
    let net_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            // F6-h: the net leg names its round on the rail — memo binds (CHANNEL_ID, CKPT_REF).
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);

    let mut proof = SettlementProof {
        channel_id: CID,
        proposal_hash: prop.proposal_hash().unwrap(),
        tx_refs: vec![
            TxRef {
                leg: 0x01,
                reference: meed.0,
                finality: "final".into(),
            },
            TxRef {
                leg: 0x02,
                reference: net_ref.0.clone(),
                finality: "final".into(),
            },
        ],
        sig_payer: None,
        sig_merchant: None,
    };
    proof.sign_payer(&PAYER_SK).unwrap();
    match c
        .channel(&framed_msg(0x07, &proof.encode().unwrap()), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("a fully-correlated PROOF returns a signed CONFIRMED"),
    }

    // The completed round decreased the live `B` by the gross DENOM it settled (F6.2):
    // metered 15_000 = merchant-net 14_850 + settled carve 150 (floor(1_500_000/10_000)),
    // so `B` goes to 0 and a window pause would re-open (§6.1).
    assert_eq!(
        c.state(&CID).unwrap().balance(),
        0,
        "settlement round did not decrease B"
    );

    // Defect B — idempotent re-proof: the debtor may have lost the first CONFIRMED, so
    // re-submitting the SAME proof re-emits the SAME signed CONFIRMED (never re-folding
    // the ledger), rather than an empty Accepted the debtor cannot act on.
    match c
        .channel(&framed_msg(0x07, &proof.encode().unwrap()), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("a re-proof of a confirmed round re-emits the CONFIRMED receipt"),
    }
    // The idempotent re-emit must NOT double-decrement `B` (no re-fold).
    assert_eq!(
        c.state(&CID).unwrap().balance(),
        0,
        "re-proof double-decremented B"
    );

    // F6-m — a proof carrying ONLY the meed leg folds the meed INDEPENDENTLY (F6-f:
    // "the meed is credited independently of the net leg") and returns `Accepted`, NOT a
    // CONFIRMED receipt: the net leg is still owed (the debtor cannot evade it — no CONFIRMED
    // is emitted), but the finalized meed is credited NOW rather than re-charged at the
    // next checkpoint (the double-charge). A CONFIRMED comes only once the net completes.
    let rail2 = VirtualRail::new(FINALITY_DELAY);
    let h2 = rail2.clone();
    let (mut c2, ck2) = opened_and_checkpointed_on(rail2);
    c2.channel(
        &framed_msg(0x06, &propose_round(ck2, None, None).encode().unwrap()),
        NOW,
    )
    .unwrap();
    // Fund the meed leg through the REAL primitive on rail2 (a non-distributing plain
    // transfer is itself rejected by F6-m), then present ONLY the meed leg.
    let inst2 = deploy_schema01_instance(&h2);
    let roy2 = h2
        .advance_channel_meed(None, &inst2, CID, p, "solana:dev/usdc".into())
        .unwrap();
    h2.advance_clock(FINALITY_DELAY);
    let mut only_meed = SettlementProof {
        channel_id: CID,
        proposal_hash: propose_round(ck2, None, None).proposal_hash().unwrap(),
        tx_refs: vec![TxRef {
            leg: 0x01,
            reference: roy2.0,
            finality: "final".into(),
        }],
        sig_payer: None,
        sig_merchant: None,
    };
    only_meed.sign_payer(&PAYER_SK).unwrap();
    // Meed folds independently → Accepted (no CONFIRMED): the net is still owed.
    assert_eq!(
        c2.channel(&framed_msg(0x07, &only_meed.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
}

#[test]
fn net_leg_hijack_foreign_round_memo_rejected_then_bound_confirms() {
    // F6-h — the net-leg hijack bar. A fully-correlated round whose net transfer
    // carries a DIFFERENT channel's round memo (the shape of a debtor claiming a victim's
    // transfer to the SHARED settlement pointer as its own leg) is REJECTED; the SAME
    // round with the correct (CHANNEL_ID, CKPT_REF) memo CONFIRMS — so the round memo is
    // the decisive factor, and a transfer bound to another channel's round can never
    // settle this one.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    let mkey = c.merchant_key();
    let (p, _e_r, net) = correct_round();

    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );

    // Fund the meed leg through the real primitive (so ONLY the net leg is in question).
    let seed = seed_instance();
    let inst = handle.deploy_instance_unchecked(
        &seed,
        crypto::ed25519_public(&MERCH_SK),
        vec![
            MeedShare {
                dest: "solana:dev:il".into(),
                bp: 50,
            },
            MeedShare {
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
            MeedShare {
                dest: "solana:dev:wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
        ],
    );
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();

    // The hijack shape: a net transfer bound to a DIFFERENT channel's round.
    const VICTIM_CID: [u8; 8] = [0x99; 8];
    assert_ne!(VICTIM_CID, CID);
    let foreign = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&VICTIM_CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let build = |net_ref: String| {
        let mut proof = SettlementProof {
            channel_id: CID,
            proposal_hash: prop.proposal_hash().unwrap(),
            tx_refs: vec![
                TxRef {
                    leg: 0x01,
                    reference: meed.0.clone(),
                    finality: "final".into(),
                },
                TxRef {
                    leg: 0x02,
                    reference: net_ref,
                    finality: "final".into(),
                },
            ],
            sig_payer: None,
            sig_merchant: None,
        };
        proof.sign_payer(&PAYER_SK).unwrap();
        proof.encode().unwrap()
    };
    // Foreign-round memo → the leg does not name THIS round → rejected (never committed,
    // so neither the meed nor the foreign net ref is consumed).
    assert_eq!(
        c.channel(&framed_msg(0x07, &build(foreign.0)), NOW),
        Err(CarriageError::Rejected)
    );

    // The SAME round, net transfer correctly bound to (CID, ckpt_ref) → CONFIRMED.
    let bound = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    match c.channel(&framed_msg(0x07, &build(bound.0)), NOW).unwrap() {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("the correctly round-bound net leg must CONFIRM"),
    }
}

#[test]
fn meed_leg_credited_independently_of_delayed_net() {
    // F6-m — the meed is credited INDEPENDENTLY of the net leg (F6-f). A deterministic
    // round funds meed first (F5-h); if the net leg lags (a slow/failed rail), a proof
    // carrying ONLY the finalized meed leg MUST credit it NOW — else the meed is
    // orphaned and re-charged at close/next settlement (the double-charge). Before the
    // fix the meed-only proof was REJECTED (an owed OUTPUT unmatched), so this asserts
    // the spec-correct outcome and FAILS RED on the pre-fix code.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    let mkey = c.merchant_key();
    let (p, _e_r, net) = correct_round();
    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    let ph = prop.proposal_hash().unwrap();

    // Execute the meed leg through the REAL distributing primitive (enablers paid P).
    let inst = deploy_schema01_instance(&handle);
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    // A MEED-ONLY proof (the net leg has not finalized yet).
    let mut roy_proof = SettlementProof {
        channel_id: CID,
        proposal_hash: ph,
        tx_refs: vec![TxRef {
            leg: 0x01,
            reference: meed.0,
            finality: "final".into(),
        }],
        sig_payer: None,
        sig_merchant: None,
    };
    roy_proof.sign_payer(&PAYER_SK).unwrap();
    // The finalized meed is credited NOW → Accepted (NOT yet CONFIRMED — the net is owed).
    assert_eq!(
        c.channel(&framed_msg(0x07, &roy_proof.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "F6-m: a finalized meed leg must be credited independently of the delayed net leg"
    );
    assert_eq!(
        instance_recipient_total(&handle),
        p,
        "the enablers received the carve P once (on funding)"
    );

    // The net leg finalizes late; a NET-ONLY proof now completes the round → CONFIRMED,
    // WITHOUT re-folding the already-credited meed (the once-guard).
    let net_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut net_proof = SettlementProof {
        channel_id: CID,
        proposal_hash: ph,
        tx_refs: vec![TxRef {
            leg: 0x02,
            reference: net_ref.0,
            finality: "final".into(),
        }],
        sig_payer: None,
        sig_merchant: None,
    };
    net_proof.sign_payer(&PAYER_SK).unwrap();
    match c
        .channel(&framed_msg(0x07, &net_proof.encode().unwrap()), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("F6-m: the net leg completing a meed-folded round must CONFIRM"),
    }
    // The meed was distributed EXACTLY ONCE — completing the net did not re-charge it.
    assert_eq!(
        instance_recipient_total(&handle),
        p,
        "F6-m: the meed must not be double-charged when the net leg completes the round"
    );
    // The window fell to 0 (net 14_850 + settled carve 150 = the metered 15_000), exactly as
    // the all-in-one CONFIRMED does — the split fold conserves the same total.
    assert_eq!(
        c.state(&CID).unwrap().balance(),
        0,
        "split fold moved B by the full gross once"
    );
}

#[test]
fn zero_owed_round_confirms_not_bricked() {
    // Regression: a zero-owed deterministic round (E = 0,
    // net = 0) proposed against a zero-outstanding checkpoint must CONFIRM on an empty proof,
    // NOT wedge. The split-fold "no progress" guard originally rejected it (it folds nothing),
    // leaving it stored-unconfirmed → F6-l then bars every future round + F6-i bars chain-close
    // → the channel bricks on a fully-conformant message. The guard now admits a round that
    // CONFIRMS with zero legs (restoring the pre-split behavior).
    let rail = VirtualRail::new(FINALITY_DELAY);
    let (mut c, _ah) = opened_with_rail(rail); // fresh postpay channel, cum_total = 0
    let (req, ckpt_ref) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    // A zero-owed round: no meed (E = 0), no net output.
    let mut zero = SettlementPropose {
        channel_id: CID,
        ckpt_ref,
        outputs: vec![],
        instance_leg: None,
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    zero.sign_payer(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x06, &zero.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "a zero-owed round is a valid proposal"
    );
    // An empty proof (zero legs owed) must CONFIRM the round — not be rejected into a wedge.
    let mut proof = SettlementProof {
        channel_id: CID,
        proposal_hash: zero.proposal_hash().unwrap(),
        tx_refs: vec![],
        sig_payer: None,
        sig_merchant: None,
    };
    proof.sign_payer(&PAYER_SK).unwrap();
    match c
        .channel(&framed_msg(0x07, &proof.encode().unwrap()), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08, "zero-owed round CONFIRMs on an empty proof")
        }
        other => panic!("F6-m: a zero-owed round must CONFIRM, not wedge: {other:?}"),
    }
}

/// Like `opened_and_checkpointed` but on a rail-backed carriage (same metering).
fn opened_and_checkpointed_on(rail: VirtualRail) -> (Carriage, [u8; 32]) {
    let (mut c, _ah) = opened_with_rail(rail);
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req, ckpt_ref) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    (c, ckpt_ref)
}

// ===================================================================================
// REPRO PROBES. Each asserts the SPEC-CORRECT outcome, so a
// RED failure confirms the finding is real and a GREEN pass would expose a false
// positive. Verification probes, not committed regression tests.
// ===================================================================================

/// Like `opened_and_checkpointed_on` but keeps the AUTH_HASH (for a mid-round funding).
fn opened_ckpt_with_ah(rail: VirtualRail) -> (Carriage, [u8; 32], [u8; 32]) {
    let (mut c, ah) = opened_with_rail(rail);
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req, ckpt_ref) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    (c, ah, ckpt_ref)
}

#[test]
// FIXED (F1) — funding no longer bumps the ledger version, so a round whose legs the
// payer finalized on-rail is no longer stranded by a concurrent funding credit.
fn funding_race_strands_finalized_net_leg() {
    // Propose a deterministic round, execute BOTH rail legs
    // (meed + net, memo-bound to this CKPT_REF), then — before the proof — a funding
    // credit bumps `ledger.version`. The proof is rejected as stale, and the finalized net
    // leg has no credit path. Spec (§6.4): "any output of a round that did not complete ...
    // is credited, never paid twice, in any later proposal, settlement, or close."
    // SPEC-CORRECT: after the payer paid the net leg on-rail, the owed balance reflects it.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ah, ckpt_ref) = opened_ckpt_with_ah(rail);
    let (p, _e_r, net) = correct_round();
    let owed_before = c.state(&CID).unwrap().balance();

    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    let seed = seed_instance();
    let inst = handle.deploy_instance_unchecked(
        &seed,
        crypto::ed25519_public(&MERCH_SK),
        vec![
            MeedShare {
                dest: "solana:dev:il".into(),
                bp: 50,
            },
            MeedShare {
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
            MeedShare {
                dest: "solana:dev:wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
        ],
    );
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();
    let net_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);

    // RACE: a small funding credit lands before the proof, bumping ledger.version.
    let fund_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 1_000,
            kind: TransferKind::Payment,
            memo: Some(ah),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: fund_ref.0.clone(),
        amount: 1_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "funding should credit"
    );

    let mut proof = SettlementProof {
        channel_id: CID,
        proposal_hash: prop.proposal_hash().unwrap(),
        tx_refs: vec![
            TxRef {
                leg: 0x01,
                reference: meed.0,
                finality: "final".into(),
            },
            TxRef {
                leg: 0x02,
                reference: net_ref.0.clone(),
                finality: "final".into(),
            },
        ],
        sig_payer: None,
        sig_merchant: None,
    };
    proof.sign_payer(&PAYER_SK).unwrap();
    let _ = c.channel(&framed_msg(0x07, &proof.encode().unwrap()), NOW);

    let owed_after = c.state(&CID).unwrap().balance();
    assert!(
        owed_after <= owed_before - (net as i128),
        "STRAND: paid net leg {net} on-rail but owed only fell from {owed_before} to \
         {owed_after} — the finalized net leg was not credited"
    );
}

#[test]
// FIXED (F6-f) — a chain_intent close is revocable: with no successor, a later plain
// CLOSE reclaims the deposit ("chain intent is not a waiver").
fn chain_intent_close_without_successor_traps_deposit() {
    // A prepay `chain_intent` close freezes the predecessor (snapshot +
    // chain_closed + Settling) WITHOUT refunding, assuming a successor will consume it. If
    // none comes, a later non-chain close cannot refund (`already_closing`). Spec (§6.4):
    // "Chain intent is not a waiver: until a successor is accepted the payer may demand the
    // return at any time." SPEC-CORRECT: the payer recovers the unconsumed deposit.
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let rail_handle = rail.clone();
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();

    // Payer chain-closes (intent). No successor ever opens.
    let mut close1 = Close {
        channel_id: CID,
        ckpt_ref: [0u8; 32],
        chain_intent: true,
        sig: None,
    };
    close1.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close1.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(rail_handle.balance("solana:dev:refund"), 0); // not yet refunded (rolled forward)

    // Payer demands the return (no successor came) via a non-chain close.
    let mut close2 = Close {
        channel_id: CID,
        ckpt_ref: [0u8; 32],
        chain_intent: false,
        sig: None,
    };
    close2.sign(&PAYER_SK).unwrap();
    let _ = c.channel(&framed_msg(0x09, &close2.encode().unwrap()), NOW);

    assert!(
        rail_handle.balance("solana:dev:refund") > 0,
        "TRAP: prepay chain-intent close with no successor never refunded the deposit"
    );
}

#[test]
// Checkpoint-before-chain (F6-k): a `chain_intent` close is REJECTED while
// live metering exceeds the named final checkpoint (accepted-but-uncheckpointed slices). The
// parties checkpoint the outstanding slices first, then chain — importing the FULL position, not
// the stale checkpoint. Importing the checkpoint while dropping uncheckpointed value would
// (prepay) re-credit consumed float / (postpay) lose the debt, amplified per hop → E defeated.
fn chain_close_requires_checkpoint_before_chain() {
    let rail = VirtualRail::new(FINALITY_DELAY);
    let (mut c, _ah, ckpt_ref) = opened_ckpt_with_ah(rail);
    let checkpoint_cum = c.state(&CID).unwrap().cum_total(); // named checkpoint == 15_000

    // Meter MORE slices without a new checkpoint (live now exceeds the checkpoint).
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(3, 4_000, &k).unwrap()]))
        .unwrap();
    let live_cum = c.state(&CID).unwrap().cum_total(); // 19_000
    assert!(
        live_cum > checkpoint_cum,
        "precondition: uncheckpointed slices"
    );

    // A chain-close naming the (stale) checkpoint is REJECTED — uncheckpointed value stands.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "chain-close must reject while live > checkpoint (F6-k)"
    );

    // Checkpoint the outstanding slices → new operative at the full 19_000 position.
    let (req2, ckpt_ref2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();
    assert_eq!(c.state(&CID).unwrap().cum_total(), live_cum);

    // Now the chain-close naming the NEW final checkpoint is accepted, and the successor imports
    // the full 19_000 (nothing dropped).
    let mut close2 = Close {
        channel_id: CID,
        ckpt_ref: ckpt_ref2,
        chain_intent: true,
        sig: None,
    };
    close2.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x09, &close2.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 12];
    let succ = payer_open_chained(
        c.merchant_key(),
        c.enc_key(),
        [0x8c; 32],
        succ_id,
        (CID, ckpt_ref2),
    );
    assert!(matches!(
        c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW),
        Ok(Response::Message(_))
    ));
    assert_eq!(
        c.state(&succ_id).unwrap().cum_total(),
        live_cum, // the full 19_000 — checkpoint-first captured the 4_000, nothing dropped
        "successor must import the full checkpointed position"
    );
}

#[test]
// The prepay plain-close refund (F6-f / F6-k) reconciles against the NAMED
// (operative) checkpoint's CUM_TOTAL, never live — the merchant bears any uncheckpointed ≤ E as
// its own risk (and refunding against live would let it, holding the symmetric slice key, forge
// slices to short the deposit). 300_000 is checkpointed, 100_000 is not → refund 1_000_000 −
// 300_000 = 700_000 (the merchant eats the uncheckpointed 100_000).
fn close_refund_reads_named_not_live_checkpoint() {
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(d.key(), d.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let rail_handle = rail.clone();
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    // Meter 300_000 and CHECKPOINT it (the evidenced consumption).
    c.batch(&batch_body(CID, &[Slice::seal(1, 300_000, &k).unwrap()]))
        .unwrap();
    let (req, _ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    // Meter 100_000 MORE without checkpointing (unevidenced, at the merchant's E-risk).
    c.batch(&batch_body(CID, &[Slice::seal(2, 100_000, &k).unwrap()]))
        .unwrap();
    // Plain close → refund uses the checkpoint cum (300_000): 1_000_000 − 300_000 = 700_000.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: _ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        rail_handle.balance("solana:dev:refund"),
        700_000,
        "refund must be against the checkpoint (300_000), the merchant eating the uncheckpointed 100_000"
    );
}

#[test]
// Resolved by serialization (F6-l): the overlapping-round state the strand needed cannot
// form. Propose round A (unconfirmed); a NEW round B on a DIFFERENT checkpoint is REJECTED while A
// is in flight (only A's retry is admitted). So no round is ever staled → no finalized net leg is
// stranded-then-rebilled, no stale meed double-charged. A conformant debtor settles
// sequentially: complete (or lapse) A, then propose B.
fn serialized_second_round_rejected_while_first_in_flight() {
    let rail = VirtualRail::new(FINALITY_DELAY);
    let (mut c, _ah) = opened_with_rail(rail);
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    // Meter 15_000 → checkpoint A.
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(1, 10_000, &k).unwrap(),
            Slice::seal(2, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req_a, ckpt_a) = payer_checkpoint_request(&c);
    c.channel(&req_a, NOW).unwrap();
    // Propose round A (unconfirmed, in flight).
    let prop_a = propose_round(ckpt_a, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop_a.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    // A's RETRY (same CKPT_REF, identical terms) is still admitted (F6.5).
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop_a.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "a retry of the in-flight round (same ckpt) is admitted"
    );
    // Meter more → checkpoint B (a different, later checkpoint).
    c.batch(&batch_body(
        CID,
        &[
            Slice::seal(3, 10_000, &k).unwrap(),
            Slice::seal(4, 5_000, &k).unwrap(),
        ],
    ))
    .unwrap();
    let (req_b, ckpt_b) = payer_checkpoint_request(&c);
    c.channel(&req_b, NOW).unwrap();
    // A NEW round B on a DIFFERENT checkpoint, while A is still unconfirmed, is REJECTED (F6-l) —
    // the overlapping-round state that the strand needed never forms.
    let prop_b = propose_round_for(ckpt_b, 30_000);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop_b.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "a second round while the first is unconfirmed must be rejected (serialization)"
    );
}

#[test]
// (FIXED): a plain-closed (`Reconciled`) channel MUST still admit its FINAL settlement
// round (F6.5 "a round MUST begin at close") — the old `chain_state.contains_key` guard barred it,
// stranding the postpay final round / prepay carve. `bars_new_round` now bars only the chaining
// dispositions (Pending/Committed), so a plain close admits the round.
fn plain_close_admits_final_settlement_round() {
    let rail = VirtualRail::new(FINALITY_DELAY);
    let (mut c, _ah, ckpt_ref) = opened_ckpt_with_ah(rail); // postpay, cum 15_000, checkpointed
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: false, // plain close → Reconciled
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    // The final round is now proposable (was `Err(Rejected)` — the lockout).
    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "a plain-closed channel must ADMIT its final settlement round"
    );
}

// ===========================================================================================
// Close-plane value-conservation certification. The close-plane analogue of the
// F10 vectors: drive the terminal events through the carriage and assert the conservation
// invariant — deposit = payer refund + enablers' carve + merchant net (prepay); paid ≤ owed and
// the late funding credited (postpay) — plus the retryable draw and the historical recompute.
// ===========================================================================================

/// Deploy the schema-0x01 meed instance (IL/OS/WALLET/DEV @ 50/10/30/10 bp) so a prepay close
/// draw distributes `P` to the recipients (mirrors `rail_settlement_full_correlation_confirms`).
fn deploy_schema01_instance(rail: &VirtualRail) -> String {
    rail.deploy_instance_unchecked(
        &seed_instance(),
        crypto::ed25519_public(&MERCH_SK),
        vec![
            MeedShare {
                dest: "solana:dev:il".into(),
                bp: 50,
            },
            MeedShare {
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
            MeedShare {
                dest: "solana:dev:wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
        ],
    )
}

/// Sum of the four schema-0x01 meed recipients' rail balances — what the enablers received.
fn instance_recipient_total(rail: &VirtualRail) -> u128 {
    rail.balance("solana:dev:il")
        + rail.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER)
        + rail.balance("solana:dev:wallet")
        + rail.balance(DEV_FUND_DEST_PLACEHOLDER)
}

/// Drive a PREPAY channel through open → fund `deposit` → meter+checkpoint `consumed` → plain
/// CLOSE, on `rail`. The instance is deployed iff `deploy`. Returns the shared rail handle for
/// terminal-ledger assertions. `[0x5a; 32]` is the session secret (matches `prepay_open`).
fn drive_prepay_plain_close(deposit: u128, consumed: u128, deploy: bool) -> VirtualRail {
    let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(dch.key(), dch.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    if deploy {
        deploy_schema01_instance(&handle);
    }
    // Fund the deposit at settle_ptr, capturing its ref for the FUNDING_PROOF.
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: deposit,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut c = Carriage::demo(dch).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: deposit,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[Slice::seal(1, consumed as u64, &k).unwrap()],
    ))
    .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    handle
}

#[test]
fn prepay_close_draws_the_carve_to_the_instance() {
    // The prepay conservation fix: at a plain close the merchant DRAWS the outstanding meed
    // carve from the deposit to the enablers' instance — it does NOT keep it. Conserves exactly.
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100; // vector bp sum = 100 → 1% → 1_000
    let rail = drive_prepay_plain_close(deposit, consumed, true);

    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - consumed,
        "payer refunded the unconsumed deposit"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "the enablers' carve reached the instance (the prepay conservation fix)"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        consumed - carve,
        "merchant keeps its net, NOT the enablers' carve"
    );
    assert_eq!(
        rail.balance("solana:dev:refund")
            + instance_recipient_total(&rail)
            + rail.balance("solana:dev:settle"),
        deposit,
        "conservation: nothing minted or lost"
    );
}

#[test]
fn prepay_close_conservation_sweep() {
    // The close-plane analogue of the F10 vectors: for a range of (deposit, consumed) — including
    // dust boundaries and a zero carve — the plain-close terminal ledger conserves EXACTLY and the
    // enablers' carve reaches the instance in every reachable path.
    for &(deposit, consumed) in &[
        (1_000_000u128, 100_000u128), // clean 1% → carve 1_000
        (500_000, 250_000),           // carve 2_500
        (1_000_000, 99_999),          // dust: carve floor(99_999/100) = 999
        (1_000_000, 1),               // sub-P: carve 0 — nothing to draw, still conserves
        (600_000, 400_000),           // carve 4_000
    ] {
        let carve = consumed / 100; // the drawn P = floor(Σaccruals/10000), vector bp sum = 100
                                    // The F7-d floor distribution to the enablers (relative shares 50/10/30/10; sub-unit dust
                                    // stays as instance residue — claimable, never with the merchant).
        let er = carve * 50 / 100 + carve * 10 / 100 + carve * 30 / 100 + carve * 10 / 100;
        let rail = drive_prepay_plain_close(deposit, consumed, true);
        let refund = rail.balance("solana:dev:refund");
        let recipients = instance_recipient_total(&rail);
        let settle = rail.balance("solana:dev:settle");
        // The two EXACT ledger invariants that prove the fix: the payer is refunded the
        // unconsumed deposit, and the carve LEFT the merchant's escrow (settle_ptr) — the merchant
        // keeps only its net, never the enablers' carve.
        assert_eq!(
            refund,
            deposit - consumed,
            "refund (d={deposit}, c={consumed})"
        );
        assert_eq!(
            settle,
            consumed - carve,
            "merchant net (d={deposit}, c={consumed})"
        );
        // Conservation: deposit = payer refund + carve (to enablers) + merchant net.
        assert_eq!(
            refund + carve + settle,
            deposit,
            "conservation (d={deposit}, c={consumed})"
        );
        // The carve reached the enablers via the F7-d distribution (dust residue held by the instance).
        assert_eq!(
            recipients, er,
            "enablers received the floor-distributed carve"
        );
        if carve > 0 {
            assert!(
                recipients > 0,
                "a nonzero carve reaches the enablers, never the merchant"
            );
        }
    }
}

#[test]
fn prepay_close_draw_is_retryable_after_transient_failure() {
    // The prepay carve draw is RETRYABLE, never a terminal silent leak (the risk being a
    // terminal-failure carve leak). A transient failure — here the instance not yet deployed
    // (`NoSuchAccount`) — leaves the draw PENDING; a replay close re-attempts and completes it, with
    // NO double-refund. The claim record's idempotency backs exactly-once.
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100;
    let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(dch.key(), dch.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    // NOTE: the instance is deliberately NOT deployed yet — the first draw fails NoSuchAccount.
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: deposit,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut c = Carriage::demo(dch).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: deposit,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[Slice::seal(1, consumed as u64, &k).unwrap()],
    ))
    .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    // First close: refund succeeds, the draw fails (no instance) → carve PENDING, not lost.
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        handle.balance("solana:dev:refund"),
        deposit - consumed,
        "refund done on the first close"
    );
    assert_eq!(
        instance_recipient_total(&handle),
        0,
        "the carve draw is PENDING after a transient failure, not lost"
    );
    assert_eq!(
        handle.balance("solana:dev:settle"),
        consumed,
        "the carve has NOT left settle_ptr yet (draw pending)"
    );
    // The transient condition clears (deploy the instance); REPLAY the close → the draw retries.
    deploy_schema01_instance(&handle);
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        handle.balance("solana:dev:refund"),
        deposit - consumed,
        "no double-refund on the replay close"
    );
    assert_eq!(
        instance_recipient_total(&handle),
        carve,
        "the retry drew the carve to the enablers — RETRYABLE, never a terminal leak"
    );
    assert_eq!(
        handle.balance("solana:dev:settle"),
        consumed - carve,
        "settle_ptr debited by the carve on the retry"
    );
}

#[test]
fn postpay_late_funding_after_plain_close_is_credited() {
    // Postpay strand fix (direct, non-chained): a late funding racing a plain close credits the
    // standing merchant-net (floored), never stranded — the old `Refunded`/`contains_key` guard
    // rejected it, stranding an on-rail transfer.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ah, ckpt_ref) = opened_ckpt_with_ah(rail); // postpay, cum 15_000, checkpointed
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    // A late funding to the shared settle_ptr, memo-bound to this channel's AUTH_HASH.
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 5_000,
            kind: TransferKind::Payment,
            memo: Some(ah),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash: ah,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: 5_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "postpay late funding after a plain close is credited (strand fix), not stranded"
    );
}

#[test]
fn newer_slice_does_not_fail_a_correct_checkpoint_and_is_not_lost() {
    // F6-c: a CHECKPOINT_REQUEST cut at seq1 must STILL countersign after the merchant accepts a
    // newer seq2 (F6-c: recompute HISTORICALLY over the named ranges, not live — was StateMismatch)
    // AND the commit must retire ONLY the named snapshot, so seq2 survives into the next checkpoint.
    let (mut c, k, _ah) = opened(); // postpay
    c.batch(&batch_body(CID, &[Slice::seal(1, 10_000, &k).unwrap()]))
        .unwrap();
    // Cut the payer's request at seq1.
    let (req1, _ref1) = payer_checkpoint_request(&c);
    // A newer slice (seq2) arrives before the merchant processes req1.
    c.batch(&batch_body(CID, &[Slice::seal(2, 5_000, &k).unwrap()]))
        .unwrap();
    // The seq1 request still countersigns, over its named (historical) range.
    let bilateral1 = match c.channel(&req1, NOW).unwrap() {
        Response::Message(m) => {
            assert_eq!(m[0], 0x04);
            Checkpoint::parse(&m[1..]).unwrap()
        }
        _ => panic!("F6-c: a correct seq1 checkpoint must countersign despite a newer live slice"),
    };
    assert_eq!(
        bilateral1.cum_total,
        num_bigint::BigUint::from(10_000u32),
        "the countersigned snapshot is historical — seq1 only, excluding the newer seq2"
    );
    assert_eq!(bilateral1.last_seq, 1);
    // seq2 is NOT lost: a second checkpoint captures it (running total now 15_000).
    let (req2, _ref2) = payer_checkpoint_request(&c);
    let bilateral2 = match c.channel(&req2, NOW).unwrap() {
        Response::Message(m) => {
            assert_eq!(m[0], 0x04);
            Checkpoint::parse(&m[1..]).unwrap()
        }
        _ => panic!("F6-c commit: seq2 must survive into the next checkpoint, not be dropped"),
    };
    assert_eq!(
        bilateral2.cum_total,
        num_bigint::BigUint::from(15_000u32),
        "seq2 retained by the commit — the next checkpoint includes it"
    );
    assert_eq!(bilateral2.last_seq, 2);
}

#[test]
fn imported_prepay_successor_plain_close_draws_the_imported_carve() {
    // A chained PREPAY successor imports outstanding meed but signs no
    // own checkpoint; its plain close refunds against the imported consumption AND MUST draw the
    // imported carve to the instance — never leave it with the merchant. The draw uses the IMPORTED
    // basis (predecessor's final checkpoint ref + imported accruals), pinned at close.
    let d = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let (mk, ek) = (d.key(), d.enc_key());
    let open = prepay_open(mk, ek, [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let (rail, tx_ref) = rail_with_funding(auth_hash, 1_000_000, None);
    let handle = rail.clone();
    deploy_schema01_instance(&handle);
    let mut c = Carriage::demo(d).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    // Predecessor: fund 1_000_000, consume 60_000 (carve = 600), checkpoint, chain-close (Pending —
    // the outstanding meed rolls forward to the successor, NOT drawn here).
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(mk, [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 60_000, &k).unwrap()]))
        .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    // Successor imports cum=60_000, funding=1_000_000, the outstanding carve 600; signs NO checkpoint.
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 22];
    let succ = prepay_open_chained(mk, ek, [0x8c; 32], succ_id, (CID, ckpt), [0x8c; 32]);
    c.channel(&framed_msg(0x01, &succ.encode().unwrap()), NOW)
        .unwrap();
    // Plain-close the successor → refund 940_000 AND draw the imported carve 600 to the instance.
    let mut sclose = Close {
        channel_id: succ_id,
        ckpt_ref: [0u8; 32], // no own checkpoint
        chain_intent: false,
        sig: None,
    };
    sclose.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &sclose.encode().unwrap()), NOW)
        .unwrap();

    let carve = 600u128; // 60_000 / 100
    assert_eq!(
        handle.balance("solana:dev:refund"),
        940_000,
        "imported-successor refund = deposit - imported consumption"
    );
    assert_eq!(
        instance_recipient_total(&handle),
        carve,
        "the IMPORTED carve reaches the instance — never pocketed by the merchant"
    );
    assert_eq!(
        handle.balance("solana:dev:settle"),
        60_000 - carve,
        "merchant keeps only its net of the imported consumption"
    );
    // Conservation: deposit = payer refund + carve to enablers + merchant net.
    assert_eq!(940_000 + carve + (60_000 - carve), 1_000_000);
}

#[test]
fn prepay_close_draw_is_pinned_against_a_later_operative_advance() {
    // The draw is PINNED at first close to (CKPT_REF, P). A checkpoint
    // completing later in Settling advances `self.operative`, but the retry MUST draw the pinned
    // amount for the CLOSE basis — NOT a higher P against the advanced checkpoint (a double-draw /
    // over-draw shorting the merchant's net).
    let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(dch.key(), dch.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    // Instance NOT deployed yet — the first draw fails (NoSuchAccount) → pinned draw stays pending.
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut c = Carriage::demo(dch).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    // Meter C1 = 100_000 (carve P1 = 1_000) and checkpoint it (ckpt_1).
    c.batch(&batch_body(CID, &[Slice::seal(1, 100_000, &k).unwrap()]))
        .unwrap();
    let (req1, ckpt_1) = payer_checkpoint_request(&c);
    c.channel(&req1, NOW).unwrap();
    // Meter C2 = 50_000 MORE, uncheckpointed (live cum 150_000; would be P2 = 1_500).
    c.batch(&batch_body(CID, &[Slice::seal(2, 50_000, &k).unwrap()]))
        .unwrap();
    // Plain close against ckpt_1 → refund vs 100_000, PIN the draw to (ckpt_1, 1_000). Draw fails
    // (no instance) → pending.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt_1,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        instance_recipient_total(&handle),
        0,
        "draw pending (no instance yet)"
    );
    // A checkpoint of the C2 slice completes in Settling → operative ADVANCES to ckpt_2 (cum 150_000).
    let (req2, _ckpt_2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();
    // Deploy the instance and REPLAY the EXACT ORIGINAL close (naming ckpt_1, now STALE vs the
    // advanced operative ckpt_2). The replay-retry fix accepts a `Reconciled` replay
    // regardless of the operative ref and re-attempts the PINNED draw (ckpt_1, 1_000) — NOT a fresh
    // 1_500 against the advanced checkpoint, and NOT a rejection at the operative-ref freshness check.
    deploy_schema01_instance(&handle);
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        instance_recipient_total(&handle),
        1_000,
        "the PINNED carve (1_000) is drawn on an EXACT replay — not 1_500, not rejected as stale"
    );
    // Refund was against the close basis (100_000): 1_000_000 - 100_000 = 900_000, once.
    assert_eq!(
        handle.balance("solana:dev:refund"),
        900_000,
        "refund once, against the close basis"
    );
    assert_eq!(
        handle.balance("solana:dev:settle"),
        100_000 - 1_000,
        "settle_ptr debited by the refund + the pinned carve only"
    );
}

#[test]
fn prepay_settlement_propose_is_barred() {
    // A PREPAY channel is never settled via a payer-proposed round — the merchant
    // is the prepay meed debtor and DRAWS the carve. `on_settlement_propose` rejects prepay,
    // foreclosing a payer racing a redundant meed round against the merchant's pinned close draw.
    let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(dch.key(), dch.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut c = Carriage::demo(dch).with_rail(Box::new(rail));
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: 1_000_000,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(1, 100_000, &k).unwrap()]))
        .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    // A payer-proposed round on a prepay channel is rejected (prepay settlement is merchant-driven).
    let prop = propose_round(ckpt, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "a prepay channel does not settle via a payer-proposed round"
    );
}

#[test]
fn meed_leg_confirms_on_plain_transfer_without_distribution() {
    // F6-m — the non-distributing-leg forge. The settlement `0x01` meed leg is credited
    // against the rail's DISTRIBUTION fact (`advanced_channel_meed`), NOT the caller-settable
    // memo: a plain transfer to the instance address carrying the (rail-public) claim key advances
    // no watermark and distributes NOTHING, so it MUST be rejected; the enablers receive the carve
    // only via a genuine `advance_channel_meed`. Two phases on ONE round prove the fix
    // DISCRIMINATES: the forge is rejected (enablers 0), then the honest distributing advance
    // confirms the same round (enablers P) — not a blunt "reject every meed leg".
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    let mkey = c.merchant_key();
    let (p, _e_r, net) = correct_round();
    let prop = propose_round(ckpt_ref, None, None);
    c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW)
        .unwrap();
    let inst = deploy_schema01_instance(&handle);
    let claim = claim_record_id(&seed_instance(), &CID, &ckpt_ref, p);
    let build = |roy_ref: String, net_ref: String| {
        let mut proof = SettlementProof {
            channel_id: CID,
            proposal_hash: prop.proposal_hash().unwrap(),
            tx_refs: vec![
                TxRef {
                    leg: 0x01,
                    reference: roy_ref,
                    finality: "final".into(),
                },
                TxRef {
                    leg: 0x02,
                    reference: net_ref,
                    finality: "final".into(),
                },
            ],
            sig_payer: None,
            sig_merchant: None,
        };
        proof.sign_payer(&PAYER_SK).unwrap();
        proof.encode().unwrap()
    };

    // PHASE 1 — ATTACK: a PLAIN submit to the instance address with the forged claim-record memo
    // (NOT `advance_channel_meed`). It credits the instance address's balance but runs no F7.3
    // division and advances no watermark, so the ref carries `advanced_channel_meed = None`.
    let forged = handle
        .submit(Transfer {
            to: inst.clone(),
            asset: "solana:dev/usdc".into(),
            amount: p,
            kind: TransferKind::Payment,
            memo: Some(claim),
        })
        .unwrap();
    let net_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    // The forged (non-distributing) meed leg is rejected; the `0x01` check fails on the missing
    // `advanced_channel_meed` fact before any commit, so nothing folds and no TX_REF is consumed.
    assert_eq!(
        c.channel(&framed_msg(0x07, &build(forged.0, net_ref.0.clone())), NOW),
        Err(CarriageError::Rejected),
        "F6-m: a non-distributing meed leg (plain transfer) must be rejected"
    );
    // The forge distributed nothing to the enablers — exactly why it must be rejected.
    assert_eq!(
        instance_recipient_total(&handle),
        0,
        "F6-m: a plain transfer to the instance address distributes nothing to the enablers"
    );

    // PHASE 2 — HONEST: the SAME round settled through the real primitive. `advance_channel_meed`
    // moves the per-channel watermark to target_P (single round: == P), runs the F7.3 division to the
    // recipients, and the rail stamps the ref with the `advanced_channel_meed` distribution fact. A
    // fresh net leg is laid at the same clock so the meed finalizes no later than the net (F6.4).
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();
    let net_ref2 = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    match c
        .channel(&framed_msg(0x07, &build(meed.0, net_ref2.0)), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("F6-m: the genuine distributing meed leg must CONFIRM the round"),
    }
    // The enablers receive the full carve P — through the honest path, exactly once.
    assert_eq!(
        instance_recipient_total(&handle),
        p,
        "F6-m: the enablers must receive the carve P via the distributing leg"
    );
}

#[test]
fn o27c_imported_balance_preserves_small_diff_between_huge_operands() {
    // F6-o: `imported_balance_f6e` must compute `cum − paid` in u128
    // FIRST, then narrow — NOT clamp the operands first (which erases a small delta between
    // two ≥ 2¹²⁷ operands to 0, under-reporting the imported balance and letting a successor
    // over-accept). Postpay: paid = funding + net_legs + settled_carve. cum = 2¹²⁷ + 100,
    // funding = 2¹²⁷ → true B = 100 (the successor opens AT its ceiling and rejects new slices).
    let m = 1u128 << 127;
    let b = super::imported_balance_f6e(
        paytp_core::channel::state::Mode::Postpay,
        m + 100, // cum
        &[],     // settled_r (settled_carve = 0)
        0,       // net_legs
        m,       // funding
        i128::MIN,
        i128::MAX,
    );
    assert_eq!(
        b, 100,
        "small delta between two >= 2^127 operands preserved (not clamped to 0)"
    );
}

// --- F6-n: the prepay interim meed draw (F6-o) ---

/// Drive a PREPAY channel through open → fund `deposit` → meter `consumed` (one slice, SEQ 1) →
/// bilateral checkpoint, WITHOUT closing — leaving the channel LIVE with an operative checkpoint
/// carrying the accrued meed. Returns (live Carriage, rail handle, operative ckpt_ref). The
/// instance is deployed iff `deploy`.
fn drive_prepay_to_operative(
    deposit: u128,
    consumed: u128,
    deploy: bool,
) -> (Carriage, VirtualRail, [u8; 32]) {
    drive_prepay_inner(deposit, consumed, deploy, None)
}

/// As [`drive_prepay_to_operative`], but optionally installs a durable one-decision `store` (its
/// funding credit + any close then route through the store) — for the restart tests.
fn drive_prepay_inner(
    deposit: u128,
    consumed: u128,
    deploy: bool,
    store: Option<std::sync::Arc<dyn crate::one_decision::OneDecisionStore>>,
) -> (Carriage, VirtualRail, [u8; 32]) {
    let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let open = prepay_open(dch.key(), dch.enc_key(), [0x5a; 32]);
    let auth_hash = open.auth.auth_hash().unwrap();
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    if deploy {
        deploy_schema01_instance(&handle);
    }
    let fref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: deposit,
            kind: TransferKind::Payment,
            memo: Some(auth_hash),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut c = Carriage::demo(dch).with_rail(Box::new(rail));
    if let Some(store) = store {
        c = c.with_decisions(store);
    }
    c.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
        .unwrap();
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash,
        rail: "solana:dev".into(),
        tx_ref: fref.0,
        amount: deposit,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW)
        .unwrap();
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[Slice::seal(1, consumed as u64, &k).unwrap()],
    ))
    .unwrap();
    let (req, ckpt) = payer_checkpoint_request(&c);
    c.channel(&req, NOW).unwrap();
    (c, handle, ckpt)
}

/// Run the interim draw to COMPLETION: the first call submits the draw (finality pending under
/// FINALITY_DELAY), the second — after the clock advances to finality — folds and returns the
/// signed receipt.
fn complete_interim_draw(c: &mut Carriage, rail: &VirtualRail) -> PrepayDrawCompleted {
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "draw submitted; finality pending on the first call (FINALITY_DELAY)"
    );
    rail.advance_clock(FINALITY_DELAY);
    c.run_prepay_interim_draw(&CID)
        .expect("the receipt is emitted once the draw reaches FIN_MEED")
}

/// A unique scratch WAL path (no `tempfile` dep) for a durable-store test.
fn one_decision_wal_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "paytp-carriage-{}-{}-{}.wal",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn durable_one_decision_store_replays_the_guards_across_a_restart() {
    // The durable store persists the channel-plane exactly-once decisions — a consumed
    // funding reference (F6-d global once) and a channel's TERMINAL close disposition — so a merchant
    // rebuilt from it (a restart / a second replica) refuses a replayed funding credit and never
    // re-refunds or re-imports a channel it already disposed. A prior process's decisions sit in the
    // WAL; a fresh Carriage restored from it must show the guards.
    use crate::one_decision::{Decision, OneDecisionStore, WalOneDecision};
    let path = one_decision_wal_path("restart");

    // A prior process recorded: funding ref "canon-1" consumed, and channel CID RECONCILED with a
    // pinned carve draw still owed — the exact shapes on_funding / on_close write to the store.
    {
        let store = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            store.decide(&super::fund_key("canon-1"), b""),
            Decision::Fresh
        );
        let disp = super::ChainState::Reconciled {
            pending_draw: Some(([9u8; 32], 150)),
        };
        assert_eq!(
            store.decide(&super::disp_key(&CID), &super::encode_disp(&disp)),
            Decision::Fresh
        );
    } // drop → the process exits; only the WAL persists

    // RESTART: a fresh Carriage replays the durable log into its working guard maps.
    let store2 = Arc::new(WalOneDecision::open(&path).unwrap());
    let c = Carriage::demo(ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle"))
        .with_decisions(store2);

    // The consumed funding reference survived → a replay of that credit is refused (no double-credit).
    assert!(
        c.ref_consumed("canon-1"),
        "the consumed funding ref replayed across the restart"
    );
    assert!(
        !c.ref_consumed("canon-2"),
        "an unrelated reference is still fresh"
    );

    // The terminal disposition survived byte-identically (Reconciled + its pinned carve draw) → the
    // channel is treated as already-closed, so on_close's `first_close` is false and never re-refunds.
    assert_eq!(
        c.chain_state.get(&CID),
        Some(&super::ChainState::Reconciled {
            pending_draw: Some(([9u8; 32], 150))
        }),
        "the close disposition (and its pinned carve draw) replayed byte-identically"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn prepay_close_records_the_disposition_durably_and_the_refund_is_idempotent() {
    // End-to-end: a prepay close through a Carriage backed by a durable store
    // RECORDS the terminal Reconciled disposition to the store (a restart replays it → no re-refund),
    // and the keyed release makes the refund idempotent (a retry returns the same ref, value once).
    use crate::one_decision::WalOneDecision;
    let path = one_decision_wal_path("close");
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let store = Arc::new(WalOneDecision::open(&path).unwrap());
    let (mut c, rail, ckpt) = drive_prepay_inner(deposit, consumed, true, Some(store));

    // Plain close → refund the unconsumed deposit + reconcile (through the store-backed carriage).
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - consumed,
        "the unconsumed deposit was refunded once"
    );

    // The WIRING recorded the terminal disposition durably: a fresh Carriage rebuilt from the SAME WAL
    // sees the channel RECONCILED (so a post-restart replay close is first_close=false → no re-refund).
    let c2 = Carriage::demo(ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle"))
        .with_decisions(Arc::new(WalOneDecision::open(&path).unwrap()));
    assert!(
        matches!(
            c2.chain_state.get(&CID),
            Some(super::ChainState::Reconciled { .. })
        ),
        "on_close recorded the Reconciled disposition durably — a restart replays it"
    );

    // Idempotent keyed release: a retry of the SAME (channel, basis) refund returns the same ref and
    // moves NOTHING — the refund balance is unchanged (no double-release across a replay / restart).
    let before = rail.balance("solana:dev:refund");
    rail.release_keyed(
        CID,
        ckpt,
        "solana:dev:settle",
        "solana:dev:refund",
        "solana:dev/usdc",
        deposit - consumed,
    )
    .unwrap();
    assert_eq!(
        rail.balance("solana:dev:refund"),
        before,
        "the keyed release is idempotent — the refund never double-releases"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn shared_store_gates_the_one_decision_across_replicas() {
    // The durable store is the AUTHORITATIVE cross-replica CAS gate, not
    // a side log. Two merchant replicas sharing ONE store (an Arc) cannot both consume the same
    // funding reference — the second's consume_ref returns false (no double-credit), despite its own
    // fresh in-memory `consumed_funding` set. The terminal close disposition is likewise authoritative.
    let shared: Arc<dyn crate::one_decision::OneDecisionStore> =
        Arc::new(crate::one_decision::InMemoryOneDecision::new());
    let mut a = carriage().with_decisions(shared.clone());
    let mut b = carriage().with_decisions(shared.clone());
    assert_eq!(
        a.consume_ref("canon-R".into()),
        super::ConsumeOutcome::First,
        "replica A is the first to consume the funding ref"
    );
    assert_eq!(
        b.consume_ref("canon-R".into()),
        super::ConsumeOutcome::Duplicate,
        "replica B refuses the already-consumed ref — the store gates the credit (no double-credit)"
    );
    // The terminal disposition is authoritative in the shared store too (refund XOR import, once).
    let _ = a.record_disposition(&CID, &super::ChainState::Reconciled { pending_draw: None });
    assert_eq!(
        shared
            .get(&super::disp_key(&CID))
            .and_then(|v| super::decode_disp(&v)),
        Some(super::ChainState::Reconciled { pending_draw: None }),
        "the terminal disposition is durable + authoritative across replicas"
    );
}

#[test]
fn close_refund_reserves_before_submit_and_is_crash_idempotent() {
    // Refund crash-safety: the close refund is RESERVED in the durable store BEFORE the
    // release submits, and the canonical ref is persisted — so a restart re-derives the reserve and
    // re-attempts the SAME keyed release (the rail dedups), never a lost or doubled refund.
    let path = one_decision_wal_path("refund");
    let store: Arc<dyn crate::one_decision::OneDecisionStore> =
        Arc::new(crate::one_decision::WalOneDecision::open(&path).unwrap());
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let (mut c, rail, ckpt) = drive_prepay_inner(deposit, consumed, true, Some(store.clone()));

    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - consumed,
        "the unconsumed deposit was refunded once"
    );
    // The durable store recorded the refund RESERVE (before the submit) AND the canonical ref — the
    // restart-recovery handles: a rebuilt merchant re-derives the pending reserve and polls the ref.
    assert!(
        store.get(&super::refund_reserve_key(&CID, &ckpt)).is_some(),
        "the refund is reserved durably (before the release submits)"
    );
    let persisted_ref = store
        .get(&super::refund_ref_key(&CID, &ckpt))
        .expect("the canonical release ref is persisted");

    // Restart re-attempt (recover the reserve → re-issue the SAME keyed release): the rail dedups to
    // the persisted ref and moves NOTHING — the refund lands EXACTLY ONCE across the crash.
    let before = rail.balance("solana:dev:refund");
    let reref = rail
        .release_keyed(
            CID,
            ckpt,
            "solana:dev:settle",
            "solana:dev:refund",
            "solana:dev/usdc",
            deposit - consumed,
        )
        .unwrap();
    assert_eq!(
        reref.0.as_bytes(),
        persisted_ref.as_slice(),
        "the restart re-attempt recovers the SAME persisted release ref"
    );
    assert_eq!(
        rail.balance("solana:dev:refund"),
        before,
        "no double-release on the crash-restart re-attempt"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn reconciliation_dust_is_zero_for_a_first_generation_channel() {
    // Reconcile-only: the merchant surfaces the bounded reconciliation dust
    // so its books tie out — a first-generation channel (no imported settled meed) leaks ZERO,
    // because its whole-chain carve reservation and its per-channel watermark coincide exactly. The
    // dust is non-zero ONLY for a chained successor that settled meed before chaining, and is
    // then bounded to ≤1µ/hop (the pure-arithmetic bound is asserted separately below).
    let (c, _ckpt) = opened_and_checkpointed();
    assert_eq!(
        c.reconciliation_dust(&CID),
        0,
        "a first-generation channel leaks no reconciliation dust"
    );
}

#[test]
fn reconciliation_dust_formula_is_bounded_by_one_per_hop() {
    // The reconciliation dust `floor(Σwhole/1e4) − floor(Σimported/1e4) − floor((Σwhole−Σimported)
    // /1e4)` is 0 or 1 for ANY `whole ≥ imported`, by floor superadditivity — the ≤1µ/hop §10.2
    // bound the merchant records (and the reason the total leak is O(#hops), never unbounded).
    let carve = |x: u128| x / 10_000;
    for &(whole, imported) in &[
        (2_500_000u128, 0u128), // first-gen: dust 0
        (1_511_000, 755_000),   // the settled-predecessor example: dust 1
        (2_500_000, 1_500_000), // exact boundary: dust 0
        (1_000_005, 500_004),   // arbitrary split
        (9_999, 5_000),         // sub-carve operands
        (u32::MAX as u128, u32::MAX as u128 / 3),
    ] {
        let dust = carve(whole)
            .saturating_sub(carve(imported))
            .saturating_sub(carve(whole - imported));
        assert!(
            dust <= 1,
            "dust {dust} exceeds 1µ for whole={whole} imported={imported}"
        );
    }
}

#[test]
fn interim_draw_settles_carve_keeps_channel_live_and_folds() {
    // F6-n happy path: a live prepay channel draws its accrued meed to the instance WITHOUT
    // closing; the carve reaches the enablers, the merchant-signed receipt binds the round to the
    // rail facts, the channel stays live, and settled_r folds so a second draw is a no-op.
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100; // vector bp sum = 100 → 1%
    let (mut c, rail, ckpt) = drive_prepay_to_operative(deposit, consumed, true);

    // The draw distributes the carve to the enablers on submit (before finality).
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "finality pending on the first call"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "the carve reached the enablers on submit"
    );

    // On finality the receipt is emitted, binding the round to the rail facts.
    rail.advance_clock(FINALITY_DELAY);
    let receipt = c
        .run_prepay_interim_draw(&CID)
        .expect("receipt on finality");
    assert_eq!(receipt.channel_id, CID);
    assert_eq!(receipt.ckpt_ref, ckpt);
    assert_eq!(receipt.amount, BigUint::from(carve));
    receipt
        .verify_merchant(&crypto::ed25519_public(&MERCH_SK))
        .expect("merchant-signed under PayTPv1-prepay-draw");
    assert_eq!(
        receipt.claim_record,
        claim_record_id(&seed_instance(), &CID, &ckpt, carve),
        "the receipt names THIS round's claim record (binds P + ckpt)"
    );
    assert_eq!(
        receipt.rail, "solana:dev",
        "F5-o/F9.1 0x05 RAIL is the CAIP-2 baseline network (BASELINE_NET), \
         not the CAIP-19 baseline_asset (solana:dev/usdc)"
    );

    // The channel is STILL LIVE (not closed/settling) — the persistent-metering value prop.
    assert!(
        matches!(
            c.state(&CID).unwrap().status(),
            Status::Open | Status::PausedWindow | Status::PausedEvidence
        ),
        "the channel keeps metering after an interim draw — it did not close"
    );

    // settled_r folded ⇒ a second call on the SAME operative checkpoint RE-EMITS the notice
    // idempotently (one round per CKPT_REF — no second DRAW), never a double-draw (F5-o liveness).
    let reemit = c
        .run_prepay_interim_draw(&CID)
        .expect("a completed round re-emits its notice, not a second draw");
    assert_eq!(reemit.ckpt_ref, ckpt, "re-emit names the same round");
    assert_eq!(reemit.amount, BigUint::from(carve));
    assert_eq!(
        reemit.rail, "solana:dev",
        "re-emit carries the same CAIP-2 RAIL"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "no double-draw of the carve"
    );
}

#[test]
fn interim_draw_is_locked_before_the_rail_and_retryable() {
    // F6-n(a): the round is LOCKED before the rail draw; a transient failure (the instance not yet
    // deployed → the draw fails) leaves it locked and UNDRAWN; a retry executes the LOCKED params —
    // even after accruals GROW — so the deposit is never over-drawn (the crash-retry over-draw
    // this guards: a recompute after later accrual would fund a second, larger claim record).
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100;
    let (mut c, rail, ckpt) = drive_prepay_to_operative(deposit, consumed, false); // instance ABSENT

    // First attempt: the draw fails → the round is locked, undrawn, no receipt, nothing distributed.
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "the draw fails transiently (instance absent) → round locked"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        0,
        "nothing drawn on a failed attempt"
    );

    // Accruals GROW before the retry (a second slice + checkpoint) — the classic over-draw setup.
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(
        CID,
        &[Slice::seal(2, consumed as u64, &k).unwrap()],
    ))
    .unwrap();
    let (req2, _ckpt2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();

    // Deploy + retry: the LOCKED round (ckpt1, carve1) settles — NOT the grown operative's 2×carve.
    deploy_schema01_instance(&rail);
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "retry submits the locked round; finality pending"
    );
    rail.advance_clock(FINALITY_DELAY);
    let receipt = c
        .run_prepay_interim_draw(&CID)
        .expect("the locked round completes on finality");
    assert_eq!(
        receipt.ckpt_ref, ckpt,
        "retry settled the LOCKED ckpt1, not the grown operative"
    );
    assert_eq!(
        receipt.amount,
        BigUint::from(carve),
        "retry drew the LOCKED P (carve1) — never a recompute-up"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "exactly carve1 reached the enablers — the deposit is not over-drawn"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        deposit - carve,
        "the deposit is debited by P exactly once"
    );
}

#[test]
fn interim_draws_across_checkpoints_conserve() {
    // The persistent-metering value prop: two interim rounds across two checkpoints each settle
    // their delta carve, conserving on the whole-chain cumulative (one round per CKPT_REF).
    let deposit = 1_000_000u128;
    let c1 = 100_000u128;
    let c2 = 150_000u128;
    let (mut c, rail, _ckpt1) = drive_prepay_to_operative(deposit, c1, true);

    // Round 1: settle c1's carve.
    let r1 = complete_interim_draw(&mut c, &rail);
    assert_eq!(r1.amount, BigUint::from(c1 / 100));
    assert_eq!(instance_recipient_total(&rail), c1 / 100);

    // Meter c2 more + a NEW checkpoint → the operative advances (a fresh CKPT_REF).
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(2, c2 as u64, &k).unwrap()]))
        .unwrap();
    let (req2, ckpt2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();

    // Round 2 on the new checkpoint advances the per-channel watermark to the CUMULATIVE carve
    // (Option W): the receipt names `target_P` (the position), while the advance distributes only
    // the delta `ΔP = target_P − funded_p` to the enablers — closing the #1 double-draw.
    let r2 = complete_interim_draw(&mut c, &rail);
    assert_eq!(r2.ckpt_ref, ckpt2, "round 2 anchors the fresh checkpoint");
    assert_eq!(
        r2.amount,
        BigUint::from((c1 + c2) / 100),
        "round 2 names the CUMULATIVE watermark target (not the per-round delta)"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        (c1 + c2) / 100,
        "the enablers received the whole-chain carve across two rounds, once each (delta distributed)"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        deposit - (c1 + c2) / 100,
        "the deposit is debited by the total carve"
    );
}

#[test]
fn interim_draw_conservation_sweep() {
    // The interim analogue of the close conservation sweep: over a range of (deposit, consumed),
    // the drawn P leaves the deposit exactly once and the enablers receive the floor-distributed
    // carve (sub-unit dust stays as instance residue, never with the merchant).
    for &(deposit, consumed) in &[
        (1_000_000u128, 100_000u128),
        (500_000, 250_000),
        (1_000_000, 99_999), // dust: carve floor(99_999/100) = 999
        (600_000, 400_000),
    ] {
        let carve = consumed / 100;
        let er = carve * 50 / 100 + carve * 10 / 100 + carve * 30 / 100 + carve * 10 / 100;
        let (mut c, rail, _ckpt) = drive_prepay_to_operative(deposit, consumed, true);
        let _r = complete_interim_draw(&mut c, &rail);
        assert_eq!(
            rail.balance("solana:dev:settle"),
            deposit - carve,
            "the full carve P left the deposit (d={deposit}, c={consumed})"
        );
        assert_eq!(
            instance_recipient_total(&rail),
            er,
            "enablers received the floor-distributed carve (d={deposit}, c={consumed})"
        );
    }
}

#[test]
fn interim_draw_in_flight_then_close_no_double_draw() {
    // F6-n(d): a plain close DRAINS an in-flight interim round before pinning the close carve. Here
    // the interim draw failed transiently (instance absent) → the round is locked+undrawn; the
    // close removes it and draws the FULL carve ONCE (never twice). Conserves exactly.
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100;
    let (mut c, rail, ckpt) = drive_prepay_to_operative(deposit, consumed, false); // instance ABSENT

    assert!(c.run_prepay_interim_draw(&CID).is_none()); // round locked, undrawn
    assert_eq!(instance_recipient_total(&rail), 0);

    deploy_schema01_instance(&rail);
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();

    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "the carve reached the enablers exactly once (the drained round did not double it)"
    );
    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - consumed,
        "payer refunded the unconsumed deposit"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        consumed - carve,
        "merchant keeps only its net"
    );
    assert_eq!(
        rail.balance("solana:dev:refund")
            + instance_recipient_total(&rail)
            + rail.balance("solana:dev:settle"),
        deposit,
        "conservation: exactly once, nothing minted or lost"
    );
}

#[test]
fn completed_interim_then_close_draws_only_residual() {
    // A COMPLETED interim round folds settled_r; a later plain close draws only the RESIDUAL carve
    // (here 0 — the interim already drew it), never re-drawing. Conserves.
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100;
    let (mut c, rail, ckpt) = drive_prepay_to_operative(deposit, consumed, true);
    let _r = complete_interim_draw(&mut c, &rail);
    assert_eq!(instance_recipient_total(&rail), carve);

    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "the close drew no residual — no double-draw"
    );
    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - consumed,
        "unconsumed deposit refunded"
    );
    assert_eq!(
        rail.balance("solana:dev:refund")
            + instance_recipient_total(&rail)
            + rail.balance("solana:dev:settle"),
        deposit,
        "conservation"
    );
}

#[test]
fn interim_draw_barred_after_close_and_when_in_flight_bars_chain_close() {
    // Guards + F6-i: no interim draw on a terminal (Settling) channel; and an in-flight interim
    // round (registered in self.rounds) bars a chain-intent close (F6-i quiescence).
    let (mut c, rail, ckpt) = drive_prepay_to_operative(1_000_000, 100_000, false); // draw fails → locked in-flight
    assert!(c.run_prepay_interim_draw(&CID).is_none());
    let mut chain_close = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    chain_close.sign(&PAYER_SK).unwrap();
    assert!(
        c.channel(&framed_msg(0x09, &chain_close.encode().unwrap()), NOW)
            .is_err(),
        "a chain-intent close is barred while an interim round is in flight (F6-i)"
    );

    // After a plain close (→ Settling), no interim draw runs.
    let mut plain = Close {
        channel_id: CID,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    plain.sign(&PAYER_SK).unwrap();
    deploy_schema01_instance(&rail); // so the close draw itself can complete
    c.channel(&framed_msg(0x09, &plain.encode().unwrap()), NOW)
        .unwrap();
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "no interim draw on a terminal (Settling) channel"
    );
}

#[test]
fn postpay_in_flight_round_survives_a_plain_close() {
    // The plain-close drain is scoped to PREPAY interim rounds. A POSTPAY
    // in-flight settlement round (proposed, funded on-rail, not yet proved) MUST survive a plain
    // close and still CONFIRM — draining it (postpay rounds also have `draw_ref = None`) would
    // strand the funded legs and double-pay the round.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ckpt_ref) = opened_and_checkpointed_on(rail);
    let mkey = c.merchant_key();
    let (p, _e_r, net) = correct_round();

    // Propose the round → locked in the merchant's in-flight state.
    let prop = propose_round(ckpt_ref, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );

    // A PLAIN close arrives BEFORE the proof (the drain must not touch this postpay round).
    let mut close = Close {
        channel_id: CID,
        ckpt_ref,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();

    // Lay the round's real legs + prove → the round SURVIVED the close and CONFIRMS.
    let seed = seed_instance();
    let inst = handle.deploy_instance_unchecked(
        &seed,
        crypto::ed25519_public(&MERCH_SK),
        vec![
            MeedShare {
                dest: "solana:dev:il".into(),
                bp: 50,
            },
            MeedShare {
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
            MeedShare {
                dest: "solana:dev:wallet".into(),
                bp: 30,
            },
            MeedShare {
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                bp: 10,
            },
        ],
    );
    let meed = handle
        .advance_channel_meed(None, &inst, CID, p, "solana:dev/usdc".into())
        .unwrap();
    let net_ref = handle
        .submit(Transfer {
            to: "solana:dev:settle".into(),
            asset: "solana:dev/usdc".into(),
            amount: net,
            kind: TransferKind::Payment,
            memo: Some(settlement_net_memo(&CID, &ckpt_ref)),
        })
        .unwrap();
    handle.advance_clock(FINALITY_DELAY);
    let mut proof = SettlementProof {
        channel_id: CID,
        proposal_hash: prop.proposal_hash().unwrap(),
        tx_refs: vec![
            TxRef {
                leg: 0x01,
                reference: meed.0,
                finality: "final".into(),
            },
            TxRef {
                leg: 0x02,
                reference: net_ref.0.clone(),
                finality: "final".into(),
            },
        ],
        sig_payer: None,
        sig_merchant: None,
    };
    proof.sign_payer(&PAYER_SK).unwrap();
    match c
        .channel(&framed_msg(0x07, &proof.encode().unwrap()), NOW)
        .unwrap()
    {
        Response::Message(m) => {
            assert_eq!(m[0], 0x08);
            paytp_core::channel::settle_msg::SettlementConfirmed::parse(&m[1..])
                .unwrap()
                .verify_merchant(&mkey)
                .unwrap();
        }
        _ => panic!("the postpay round must survive the plain close and CONFIRM — not be drained"),
    }
}

#[test]
fn interim_submitted_then_checkpoint_then_close_draws_carve_once() {
    // A possible async-rail double-draw: an interim draw submitted-but-not-final,
    // then a checkpoint advance + plain close. On the SYNCHRONOUS VirtualRail the draw's `funds_claim`
    // is set at submit, so the rail-authoritative drain FOLDS it and the close draws only the RESIDUAL
    // — the carve is drawn EXACTLY ONCE (conservation holds). This repro asserts the spec-correct
    // outcome; its green confirms the double-draw is a real-async-rail concern (funds_claim only at
    // finality → drain removes → close re-draws → both land), the tracked real-rail deferral — NOT a
    // VirtualRail value loss.
    let deposit = 1_000_000u128;
    let c1 = 100_000u128;
    let c2 = 150_000u128;
    let (mut c, rail, _ckpt1) = drive_prepay_to_operative(deposit, c1, true);

    // Interim draw: submit tx1 for ckpt1 (funds_claim set at submit), finality PENDING → None, unfolded.
    assert!(
        c.run_prepay_interim_draw(&CID).is_none(),
        "submitted; finality pending"
    );
    assert_eq!(
        instance_recipient_total(&rail),
        c1 / 100,
        "P1 distributed at submit"
    );

    // Advance the checkpoint (new accruals) WITHOUT completing the interim round's finality.
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(2, c2 as u64, &k).unwrap()]))
        .unwrap();
    let (req2, ckpt2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();

    // Plain close: the drain folds the submitted ckpt1 round (funds_claim set), the close draws the residual.
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: ckpt2,
        chain_intent: false,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    c.channel(&framed_msg(0x09, &close.encode().unwrap()), NOW)
        .unwrap();

    // The carve is drawn EXACTLY ONCE across the interim submit + the close residual — no double-draw.
    let total_carve = (c1 + c2) / 100;
    assert_eq!(
        instance_recipient_total(&rail),
        total_carve,
        "carve reached the enablers exactly once"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        (c1 + c2) - total_carve,
        "merchant keeps only its net (consumed − carve) — the carve left the deposit ONCE, no double-draw"
    );
    assert_eq!(
        rail.balance("solana:dev:refund"),
        deposit - (c1 + c2),
        "payer refunded the unconsumed deposit"
    );
    assert_eq!(
        rail.balance("solana:dev:settle")
            + instance_recipient_total(&rail)
            + rail.balance("solana:dev:refund"),
        deposit,
        "conservation: nothing minted or lost"
    );
}

/// Round 2's economics against a ledger that already folded round 1's `prev_e_r` (into `settled_r`)
/// and `prev_net` (into `net_legs_sum`), now at cumulative gross `cum2` — returns the OWN-CUMULATIVE
/// watermark target `target_P2`, the INCREMENTAL per-role `E_r2`, and the INCREMENTAL merchant net,
/// each via the SAME public F7 math the merchant's `recompute_round` / `cumulative_target_p` use (so
/// a matching proposal is accepted). Schema-01 vector (roles 0x10:50 / 0x11:10 / 0x12:30 / 0x13:10).
fn second_round(
    cum2: u128,
    prev_e_r: &[(u8, BigUint)],
    prev_net: u128,
) -> (u128, Vec<(u8, BigUint)>, u128) {
    let bps = [(0x10u8, 50u128), (0x11, 10), (0x12, 30), (0x13, 10)];
    let accrued: Vec<U256> = bps
        .iter()
        .map(|(_, bp)| fee::u256_from_biguint(&BigUint::from(cum2 * bp)).unwrap())
        .collect();
    let settled: Vec<U256> = bps
        .iter()
        .map(|(r, _)| {
            let s = prev_e_r
                .iter()
                .find(|(rr, _)| rr == r)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            fee::u256_from_biguint(&s).unwrap()
        })
        .collect();
    // Incremental per-round `E_r2` (recompute_round): outstanding = accrued − settled, then divide.
    let outstanding = fee::reconcile::outstanding_meed_per_role(&accrued, &settled).unwrap();
    let div = fee::divide_round(&outstanding, &Rate::new(1, 1).unwrap()).unwrap();
    let e_r2: Vec<(u8, BigUint)> = bps
        .iter()
        .map(|(r, _)| *r)
        .zip(div.e_r.iter().map(|u| fee::biguint_from_u256(*u)))
        .collect();
    // OWN-CUMULATIVE watermark target `target_P2` (cumulative_target_p): imported_settled = 0 for a
    // first-generation channel → subtract nothing → floor(Σaccrued / 1e4).
    let zeros = vec![U256::ZERO; bps.len()];
    let cum_outstanding = fee::reconcile::outstanding_meed_per_role(&accrued, &zeros).unwrap();
    let cum_div = fee::divide_round(&cum_outstanding, &Rate::new(1, 1).unwrap()).unwrap();
    let target_p2 = u128::try_from(fee::biguint_from_u256(cum_div.p)).unwrap();
    // Incremental merchant net (outstanding_merchant_net with round 1's net already paid).
    let net = fee::reconcile::outstanding_merchant_net(
        &U256::from(cum2),
        &accrued,
        &U256::from(prev_net),
        &U256::ZERO,
    );
    (
        target_p2,
        e_r2,
        u128::try_from(fee::biguint_from_u256(net)).unwrap(),
    )
}

#[test]
fn postpay_settlement_across_checkpoints_advances_watermark_once() {
    // Option W closure (POSTPAY). Two settlement rounds across two checkpoints on ONE channel each
    // settle the channel's OWN-CUMULATIVE target on the SAME per-channel watermark. Round 2's 0x01
    // advance to target_P2 ≥ target_P1 moves ONLY the residual ΔP = target_P2 − target_P1, so the
    // enablers receive the cumulative carve EXACTLY ONCE (monotone funded_p) — the cross-checkpoint
    // double-settle the F6-o finding raised closes by construction. The merchant binds the advance
    // fact (`advanced_channel_meed`), not a per-round claim record, so it is checkpoint-agnostic.
    let rail = VirtualRail::new(FINALITY_DELAY);
    let handle = rail.clone();
    let (mut c, ckpt1) = opened_and_checkpointed_on(rail); // postpay, cum 15_000
    let inst = deploy_schema01_instance(&handle);

    let build_proof = |ph: [u8; 32], roy: String, net: String| {
        let mut proof = SettlementProof {
            channel_id: CID,
            proposal_hash: ph,
            tx_refs: vec![
                TxRef {
                    leg: 0x01,
                    reference: roy,
                    finality: "final".into(),
                },
                TxRef {
                    leg: 0x02,
                    reference: net,
                    finality: "final".into(),
                },
            ],
            sig_payer: None,
            sig_merchant: None,
        };
        proof.sign_payer(&PAYER_SK).unwrap();
        proof.encode().unwrap()
    };
    let lay_net = |ckpt: [u8; 32], amount: u128| {
        handle
            .submit(Transfer {
                to: "solana:dev:settle".into(),
                asset: "solana:dev/usdc".into(),
                amount,
                kind: TransferKind::Payment,
                memo: Some(settlement_net_memo(&CID, &ckpt)),
            })
            .unwrap()
    };

    // ---- ROUND 1 (cum 15_000, fresh ledger → target_P1 == per-round P1 == 150) ----
    let (p1, _e_r1, net1) = correct_round();
    let prop1 = propose_round(ckpt1, None, None);
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop1.encode().unwrap()), NOW),
        Ok(Response::Accepted)
    );
    // Payer ADVANCES the watermark 0 → target_P1 and lays the net leg (meed finalizes first).
    let roy1 = handle
        .advance_channel_meed(None, &inst, CID, p1, "solana:dev/usdc".into())
        .unwrap();
    let net1_ref = lay_net(ckpt1, net1);
    handle.advance_clock(FINALITY_DELAY);
    match c
        .channel(
            &framed_msg(
                0x07,
                &build_proof(prop1.proposal_hash().unwrap(), roy1.0, net1_ref.0),
            ),
            NOW,
        )
        .unwrap()
    {
        Response::Message(m) => assert_eq!(m[0], 0x08, "round 1 CONFIRMS"),
        _ => panic!("round 1 must CONFIRM"),
    }
    assert_eq!(
        instance_recipient_total(&handle),
        p1,
        "round 1: the enablers received target_P1"
    );

    // ---- meter a third slice (+10_000) + CHECKPOINT 2 (cum 25_000) ----
    let k = k_session(c.merchant_key(), [0x5a; 32]);
    c.batch(&batch_body(CID, &[Slice::seal(3, 10_000, &k).unwrap()]))
        .unwrap();
    let (req2, ckpt2) = payer_checkpoint_request(&c);
    c.channel(&req2, NOW).unwrap();

    // ---- ROUND 2 (cum 25_000; ledger folded round 1's e_r1 = correct_round().1 and net1) ----
    let (target_p2, e_r2, net2) = second_round(25_000, &correct_round().1, net1);
    assert_eq!(
        target_p2, 250,
        "cumulative target = floor(25_000 * 100 / 1e4)"
    );
    let mut prop2 = SettlementPropose {
        channel_id: CID,
        ckpt_ref: ckpt2,
        outputs: vec![Output {
            amount: BigUint::from(net2),
            asset: "solana:dev/usdc".into(),
            dest: "solana:dev:settle".into(),
        }],
        instance_leg: Some(InstanceLeg {
            amount: BigUint::from(target_p2), // OWN-CUMULATIVE, not the per-round delta
            credited: vec![],
            extinguished: e_r2,
        }),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    prop2.sign_payer(&PAYER_SK).unwrap();
    // Acceptance PROVES the round-2 economics matched the merchant's recompute (INSTANCE_LEG.amount ==
    // target_P2 own-cumulative, EXTINGUISHED == incremental E_r2, OUTPUTS == incremental net).
    assert_eq!(
        c.channel(&framed_msg(0x06, &prop2.encode().unwrap()), NOW),
        Ok(Response::Accepted),
        "round 2's own-cumulative target_P2 + incremental E_r2 verify against the checkpoint"
    );
    // Payer ADVANCES the watermark target_P1 → target_P2 — distributes ONLY the residual ΔP.
    let roy2 = handle
        .advance_channel_meed(None, &inst, CID, target_p2, "solana:dev/usdc".into())
        .unwrap();
    let net2_ref = lay_net(ckpt2, net2);
    handle.advance_clock(FINALITY_DELAY);
    match c
        .channel(
            &framed_msg(
                0x07,
                &build_proof(prop2.proposal_hash().unwrap(), roy2.0.clone(), net2_ref.0),
            ),
            NOW,
        )
        .unwrap()
    {
        Response::Message(m) => assert_eq!(m[0], 0x08, "round 2 CONFIRMS"),
        _ => panic!("round 2 must CONFIRM against the advanced watermark"),
    }

    // ---- #1 CLOSURE: the enablers received the CUMULATIVE target_P2 EXACTLY ONCE ----
    assert_eq!(
        instance_recipient_total(&handle),
        target_p2,
        "enablers paid the cumulative target_P2 ONCE — not target_P1 + target_P2 (no cross-checkpoint double)"
    );
    let adv2 = handle
        .ref_target(&roy2)
        .unwrap()
        .advanced_channel_meed
        .unwrap();
    assert_eq!(
        adv2.funded_p, target_p2,
        "watermark reached the cumulative target"
    );
    assert_eq!(
        adv2.delta,
        target_p2 - p1,
        "round 2's advance distributed ONLY the residual ΔP = target_P2 − target_P1"
    );
}

#[test]
fn completed_interim_draw_receipt_is_reemitted_idempotently() {
    // Liveness: a completed interim draw's signed notice, if its
    // delivery is lost, MUST be re-servable — a retry re-emits the SAME PREPAY_DRAW_COMPLETED
    // (reconstructed from the confirmed round + rail facts), NEVER re-drawing, so the halted payer is
    // not stranded (the postpay CONFIRMED re-emit analogue).
    let deposit = 1_000_000u128;
    let consumed = 100_000u128;
    let carve = consumed / 100;
    let (mut c, rail, ckpt) = drive_prepay_to_operative(deposit, consumed, true);
    let first = complete_interim_draw(&mut c, &rail);

    // The delivery is "lost" → a retry re-emits the identical signed notice, no second draw.
    let reemit = c
        .run_prepay_interim_draw(&CID)
        .expect("a completed round re-emits its notice (liveness)");
    assert_eq!(reemit.ckpt_ref, ckpt);
    assert_eq!(reemit.ckpt_ref, first.ckpt_ref);
    assert_eq!(reemit.amount, first.amount);
    assert_eq!(reemit.claim_record, first.claim_record);
    assert_eq!(reemit.tx_ref, first.tx_ref);
    reemit
        .verify_merchant(&crypto::ed25519_public(&MERCH_SK))
        .expect("the re-emitted notice is merchant-signed");
    // No double-draw — the carve reached the enablers exactly once.
    assert_eq!(
        instance_recipient_total(&rail),
        carve,
        "re-emit does not re-draw the carve"
    );
    assert_eq!(
        rail.balance("solana:dev:settle"),
        deposit - carve,
        "the deposit is debited by the carve exactly once (no close/refund in this test)"
    );
}

// ---------------------------------------------------------------------------
// F5-m — proof-profile construction + restart tests (durable state mandatory)
// ---------------------------------------------------------------------------

/// Build a proof carriage on a WAL at `path` (the SAME store backs the driver's F5-m tombstones and
/// the carriage guards — `Carriage::proof` installs one `Arc` into both).
fn proof_carriage(path: &std::path::Path) -> (Carriage, VirtualRail) {
    use crate::one_decision::WalOneDecision;
    let store = Arc::new(WalOneDecision::open(path).unwrap());
    let rail = VirtualRail::new(FINALITY_DELAY);
    let driver = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let c = Carriage::proof(driver, Box::new(rail.clone()), store).expect("proof carriage builds");
    (c, rail)
}

#[test]
fn proof_carriage_tombstones_a_channel_open_across_restart() {
    // F5-m (boundary: AFTER channel open). A proof carriage durably records the channel-open
    // acceptance. After a restart — a FRESH proof carriage on the SAME durable log — a replay of the
    // captured CHANNEL_OPEN is REJECTED (the tombstone): never a fresh Established channel (which
    // would reset the slice plane and re-bill captured slices), and never an ACK retransmit into an
    // unservable channel.
    let path = one_decision_wal_path("o30-f5m");
    let s = [0x5au8; 32];
    let open = {
        let (mut c, _rail) = proof_carriage(&path);
        let open = payer_open(c.merchant_key(), c.enc_key(), s);
        // A fresh open succeeds (ACK returned).
        let resp = c
            .channel(&framed_msg(0x01, &open.encode().unwrap()), NOW)
            .expect("fresh open");
        assert!(matches!(resp, Response::Message(_)), "fresh open ACKs");
        open
    }; // drop → crash / restart

    // RESTART: a fresh proof carriage on the SAME log restores the tombstone.
    let (mut c2, _rail2) = proof_carriage(&path);
    // A replay of the captured CHANNEL_OPEN is refused — the tombstone, not a fresh channel.
    assert_eq!(
        c2.channel(&framed_msg(0x01, &open.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "a replayed CHANNEL_OPEN after restart is tombstone-rejected, never re-established"
    );
    // And a FUNDING_PROOF for that id is refused too (the live channel is gone — the deposit before
    // any durable funding decision is a bounded-trust strand, recoverable evidentiary, ASYNC-1).
    let mut fp = FundingProof {
        channel_id: CID,
        auth_hash: [0u8; 32],
        rail: "solana:dev".into(),
        tx_ref: "whatever".into(),
        amount: 1,
        sig: None,
    };
    fp.sign(&PAYER_SK).unwrap();
    assert_eq!(
        c2.channel(&framed_msg(0x05, &fp.encode().unwrap()), NOW),
        Err(CarriageError::Rejected),
        "funding for a tombstoned (post-restart, unservable) channel is refused, never minted"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn proof_carriage_replays_the_funding_and_disposition_guards_across_restart() {
    // Boundaries: AFTER funding consume + AFTER close disposition — via the PROOF constructor's own
    // strict replay (`replay_guards`). A prior life recorded a consumed funding ref and a terminal
    // Reconciled disposition; a fresh proof carriage rebuilt from the SAME log shows both, so a
    // replayed funding credit is refused and a replayed close never re-refunds.
    use crate::one_decision::{Decision, OneDecisionStore, WalOneDecision};
    let path = one_decision_wal_path("o30-guards");
    {
        let store = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            store.decide(&super::fund_key("canon-Z"), b""),
            Decision::Fresh
        );
        let disp = super::ChainState::Reconciled { pending_draw: None };
        assert_eq!(
            store.decide(&super::disp_key(&CID), &super::encode_disp(&disp)),
            Decision::Fresh
        );
    } // crash

    let (c, _rail) = proof_carriage(&path);
    assert!(
        c.ref_consumed("canon-Z"),
        "the consumed funding ref replayed into the proof carriage (no double-credit)"
    );
    assert_eq!(
        c.chain_state.get(&CID),
        Some(&super::ChainState::Reconciled { pending_draw: None }),
        "the terminal close disposition replayed (no re-refund / re-import)"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn proof_construction_fails_closed_on_a_corrupt_durable_log() {
    // A proof carriage MUST fail closed on a complete-but-corrupt durable record,
    // never silently forget a decision. Seed a `disp:` record with an undecodable value.
    use crate::one_decision::{Decision, OneDecisionStore, WalOneDecision};
    let path = one_decision_wal_path("o30-corrupt");
    {
        let store = WalOneDecision::open(&path).unwrap();
        // A disposition value that `decode_disp` rejects (unknown tag byte).
        assert_eq!(
            store.decide(&super::disp_key(&CID), &[0xFF]),
            Decision::Fresh
        );
    }
    let store2 = Arc::new(WalOneDecision::open(&path).unwrap());
    let driver = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    let built = Carriage::proof(driver, Box::new(VirtualRail::new(FINALITY_DELAY)), store2);
    assert!(
        matches!(built, Err(super::ConfigError::DecisionLog)),
        "a corrupt disposition record fails the proof construction closed, never silently skipped"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn proof_construction_fails_closed_on_a_padded_disposition() {
    // decode_disp EXACT length: a valid tag 0x02 with TRAILING garbage must
    // NOT decode as Reconciled{None} (which would lose a pending prepay carve draw) — it fails the
    // proof construction closed, never silently accepts a truncated/padded value.
    use crate::one_decision::{Decision, OneDecisionStore, WalOneDecision};
    let path = one_decision_wal_path("o30-pad");
    {
        let store = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            store.decide(&super::disp_key(&CID), &[0x02, 0xFF]),
            Decision::Fresh
        );
    }
    let store2 = Arc::new(WalOneDecision::open(&path).unwrap());
    let driver = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    assert!(
        matches!(
            Carriage::proof(driver, Box::new(VirtualRail::new(FINALITY_DELAY)), store2),
            Err(super::ConfigError::DecisionLog)
        ),
        "a padded disposition record fails the proof construction closed"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn proof_construction_fails_closed_on_a_nonempty_fund_value() {
    // A `fund:` record's value is ALWAYS empty (the canonical ref is the key). A non-empty value is
    // corruption → fail the proof construction closed, never silently consume the ref.
    use crate::one_decision::{Decision, OneDecisionStore, WalOneDecision};
    let path = one_decision_wal_path("o30-fundval");
    {
        let store = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            store.decide(&super::fund_key("canon-x"), b"garbage"),
            Decision::Fresh
        );
    }
    let store2 = Arc::new(WalOneDecision::open(&path).unwrap());
    let driver = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
    assert!(
        matches!(
            Carriage::proof(driver, Box::new(VirtualRail::new(FINALITY_DELAY)), store2),
            Err(super::ConfigError::DecisionLog)
        ),
        "a fund: record with a non-empty value fails the proof construction closed"
    );
    let _ = std::fs::remove_file(&path);
}
