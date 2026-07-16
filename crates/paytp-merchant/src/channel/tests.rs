//! Establishment driver tests (F5.2–F5.4 / F5-m / F6.1 / F6.6) — the Change A
//! flip: a reverse-proxy terminator is now a POSITIVE capability, replay is barred
//! by the F5-m channel-id record instead of a TLS exporter, and both ends derive
//! `K_session` from the public `BindSalt`.

use super::*;
use paytp_core::channel::establish::MODE_POSTPAY;
use paytp_core::channel::{AckRequest, ChannelAuth, ChannelOpen, VectorEntry};
use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::crypto;
use paytp_core::slice::Slice;

const PAYER_SK: [u8; 32] = [1u8; 32];
const MERCH_SK: [u8; 32] = [2u8; 32];
const ENC_SEED: [u8; 32] = [7u8; 32];
const CID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];
const NOW: u64 = 1_700_000_000;

fn driver() -> ChannelDriver {
    ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle")
}

/// Unwrap a fresh establishment, panicking on a retransmit.
fn established(out: Result<OpenOutcome, ChannelError>) -> Established {
    match out.unwrap() {
        OpenOutcome::Established(e) => *e,
        OpenOutcome::Retransmit(_) => panic!("expected a fresh establishment, got a retransmit"),
    }
}

/// The conformant schema-0x01 meed vector every well-formed channel carries
/// (§10.1: IL/OS/WALLET/DEV @ 50/10/30/10 bp, CAIP dests).
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

/// Payer side: build a signed baseline-denominated postpay `CHANNEL_AUTH` and seal
/// `s` to the merchant's `ENC_KEY`. `channel_id`/`timestamp`/`predecessor` vary.
fn payer_open(
    merchant_key: [u8; 32],
    enc_key: [u8; 32],
    s: [u8; 32],
    channel_id: [u8; 8],
    timestamp: u64,
    predecessor: Option<([u8; 8], [u8; 32])>,
) -> ChannelOpen {
    payer_open_vec(
        merchant_key,
        enc_key,
        s,
        channel_id,
        timestamp,
        predecessor,
        schema01_vector(),
    )
}

/// As [`payer_open`], but with a caller-supplied meed vector — the rejection test
/// passes a non-conformant one. The payer signature is valid, so the merchant reaches the
/// meed-vector conformance check only after `verify()` passes.
fn payer_open_vec(
    merchant_key: [u8; 32],
    enc_key: [u8; 32],
    s: [u8; 32],
    channel_id: [u8; 8],
    timestamp: u64,
    predecessor: Option<([u8; 8], [u8; 32])>,
    vector: Vec<VectorEntry>,
) -> ChannelOpen {
    let payer_key = crypto::ed25519_public(&PAYER_SK);
    let mut auth = ChannelAuth {
        payer_key,
        channel_id,
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
        vector,
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor,
        timestamp,
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
fn happy_path_handshake_and_slices() {
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s, CID, NOW, None);

    let est = established(d.open_channel(&open, NOW));
    // The ACK verifies under the merchant identity and answers this auth.
    est.ack.verify(&mkey).unwrap();
    assert_eq!(est.ack.auth_hash, open.auth.auth_hash().unwrap());

    // Both ends derive the same K_session from the public BindSalt.
    let salt = crypto::bind_salt(&open.auth.payer_key, &mkey);
    let payer_ks = crypto::k_session(&s, &salt, &CID);
    assert_eq!(est.k_session, payer_ks);

    // The settlement-threshold terms survive the handoff (F8.4b), not dropped.
    assert_eq!(est.th_value, 100_000);
    assert_eq!(est.th_time, 3600);
    assert_eq!(est.established_at, NOW);

    // A payer-sealed slice verifies + is accepted by the merchant's channel state.
    let mut state = est.state;
    let slice = Slice::seal(1, 10_000, &payer_ks).unwrap();
    assert!(slice.verify(&est.k_session));
    state.accept_slice(&slice).unwrap();
    assert_eq!(state.cum_total(), 10_000);
}

#[test]
fn open_rejects_nonconformant_meed_vector() {
    // A channel whose CHANNEL_AUTH understates the governed meed — here a 2-role
    // [IL=50, WALLET=50] vector that starves OS and the Dev-Fund — is refused at open even
    // though the payer signature verifies. The merchant re-checks the vector, so a rogue
    // interaction layer cannot strip the OS / Dev-Fund shares off the wire.
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];
    let bad = vec![
        VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "solana:dev:il".into(),
        },
        VectorEntry {
            role: 0x12,
            bp: 50,
            dest: "solana:dev:wallet".into(),
        },
    ];
    let open = payer_open_vec(mkey, enc, s, CID, NOW, None, bad);
    // The payer signature verifies — the rejection is the meed-vector conformance check,
    // not a bad signature.
    open.auth.verify().unwrap();
    assert!(matches!(
        d.open_channel(&open, NOW),
        Err(ChannelError::BadAuth)
    ));
}

#[test]
fn reverse_proxy_positive() {
    // A terminator fronts the origin. The merchant signs an artifact naming the
    // TERMINATOR's cert + the origin's ENC_KEY; the payer verifies it against the
    // cert it saw on the connection (the terminator's) and seals s to the origin.
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let term_cert = [0xcc; 32];
    let art = d.issue_artifact("api.example.com", term_cert, NOW - 100, NOW + 100);

    // Payer accepts the artifact for the connection it actually sees.
    art.accept(&mkey, &term_cert, "api.example.com", NOW)
        .unwrap();

    // Channel forms end-to-end; the origin (not the terminator) unseals.
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s, CID, NOW, None);
    let est = established(d.open_channel(&open, NOW));
    est.ack.verify(&mkey).unwrap();

    // The terminator, holding a different X25519 secret, cannot unseal s.
    let (term_secret, _term_pub) = crypto::x25519_keypair_from_seed(&[0x99; 32]);
    assert!(crypto::open_session_secret(
        &term_secret,
        &open.seal,
        &open.auth.canonical_content().unwrap()
    )
    .is_err());
}

#[test]
fn unauthorized_terminator_negative() {
    // The merchant authorized an artifact for cert C_auth only. An unauthorized
    // terminator presents C_evil; the payer's artifact acceptance refuses, so no
    // CHANNEL_OPEN is ever built.
    let d = driver();
    let mkey = d.key();
    let c_auth = [0xcc; 32];
    let c_evil = [0xee; 32];
    let art = d.issue_artifact("api.example.com", c_auth, NOW - 100, NOW + 100);
    assert!(art.accept(&mkey, &c_evil, "api.example.com", NOW).is_err());
    // Even a forged artifact fails: the terminator cannot sign as the merchant.
    let mut forged = art.clone();
    forged.cert_hash = c_evil;
    forged.sig = None;
    forged.sign(&[0x33; 32]).unwrap(); // terminator's own key, not the merchant's
    assert!(forged
        .accept(&mkey, &c_evil, "api.example.com", NOW)
        .is_err());
}

#[test]
fn f5m_replay_suppression() {
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s, CID, NOW, None);

    let first = established(d.open_channel(&open, NOW));

    // A byte-identical retransmission returns ONLY the stored ACK — never a fresh
    // Established (which would reset the metering state and let captured slices
    // re-bill from SEQ=1).
    match d.open_channel(&open, NOW).unwrap() {
        OpenOutcome::Retransmit(ack) => {
            assert_eq!(ack.encode().unwrap(), first.ack.encode().unwrap())
        }
        OpenOutcome::Established(_) => panic!("retransmit must NOT re-initialize the channel"),
    }

    // Chosen-secret replay: SAME signed CHANNEL_AUTH, a DIFFERENT (re-sealed) SEAL.
    // AUTH_HASH matches but the OPEN is not byte-identical, so it is rejected — the
    // attacker never gets the merchant to derive a K_session from its own s'.
    let resealed = ChannelOpen::build(open.auth.clone(), &enc, &[0xab; 32]).unwrap();
    assert!(matches!(
        d.open_channel(&resealed, NOW),
        Err(ChannelError::ChannelReplay)
    ));

    // A different auth reusing the same CHANNEL_ID (different terms → different
    // AUTH_HASH) is rejected as a replay.
    let s2 = [0x6b; 32];
    let open2 = payer_open(mkey, enc, s2, CID, NOW, None);
    assert!(matches!(
        d.open_channel(&open2, NOW),
        Err(ChannelError::ChannelReplay)
    ));

    // A terminated channel is never re-initialized, not even by an identical OPEN.
    d.terminate(&CID);
    assert!(matches!(
        d.open_channel(&open, NOW),
        Err(ChannelError::ChannelReplay)
    ));
}

#[test]
fn rejects_bad_inputs() {
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];

    // Timestamp outside the ±600 s window.
    let stale = payer_open(mkey, enc, s, CID, NOW - 10_000, None);
    assert!(matches!(
        d.open_channel(&stale, NOW),
        Err(ChannelError::TimestampOutOfWindow)
    ));

    // Auth naming a different merchant key.
    let wrong_m = payer_open([0x44; 32], enc, s, [0, 0, 0, 0, 0, 0, 0, 8], NOW, None);
    assert!(matches!(
        d.open_channel(&wrong_m, NOW),
        Err(ChannelError::WrongMerchant)
    ));

    // A tampered seal will not open.
    let mut bad_seal = payer_open(mkey, enc, s, [0, 0, 0, 0, 0, 0, 0, 9], NOW, None);
    bad_seal.seal[79] ^= 0xff;
    assert!(matches!(
        d.open_channel(&bad_seal, NOW),
        Err(ChannelError::SealInvalid)
    ));

    // HS commitment ≠ H(s): seal a *different* secret than HS commits to.
    let hs_bad0 = payer_open(mkey, enc, s, [0, 0, 0, 0, 0, 0, 0, 10], NOW, None);
    // Re-seal the object's auth (with its HS = H(s)) around a different secret s'.
    let s_prime = [0x77; 32];
    let hs_bad = ChannelOpen::build(hs_bad0.auth, &enc, &s_prime).unwrap();
    assert!(matches!(
        d.open_channel(&hs_bad, NOW),
        Err(ChannelError::HsMismatch)
    ));
}

#[test]
fn chained_successor_establishes_f6_6() {
    // F6.6: after the predecessor terminates, a chained successor with a FRESH
    // CHANNEL_ID and a PREDECESSOR reference establishes cleanly.
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];

    let open = payer_open(mkey, enc, s, CID, NOW, None);
    let pred = established(d.open_channel(&open, NOW));
    d.terminate(&CID);
    // A chain_intent close records the predecessor's reconciled position (here a fresh,
    // un-metered zero position) keyed by its final checkpoint reference.
    let pred_ref = pred.auth_hash;
    record_zero_snapshot(&mut d, CID, pred_ref);

    // PREDECESSOR = prior CHANNEL_ID (8) ‖ final checkpoint reference (32).
    let succ_id = [0, 0, 0, 0, 0, 0, 0, 11];
    let succ = payer_open(mkey, enc, [0x8c; 32], succ_id, NOW, Some((CID, pred_ref)));
    let est = established(d.open_channel(&succ, NOW));
    est.ack.verify(&mkey).unwrap();
    assert_eq!(est.channel_id, succ_id);
    assert_eq!(est.ack.auth_hash, succ.auth.auth_hash().unwrap());
    // It IMPORTED the predecessor's position (F6.6) — a fresh predecessor imports zero,
    // and the successor carries the ledger openings for the carriage to seed.
    assert_eq!(est.state.cum_total(), 0);
    assert_eq!(est.state.balance(), 0);
    assert!(
        est.ledger_openings.is_some(),
        "a chained open carries ledger openings"
    );
    // Inherits the predecessor's established_at (no TH_TIME clock reset across the chain).
    assert_eq!(est.established_at, NOW);

    // WITHOUT a recorded snapshot the chain fails CLOSED — never a silent fresh open.
    let orphan = payer_open(
        mkey,
        enc,
        [0x8d; 32],
        [0, 0, 0, 0, 0, 0, 0, 12],
        NOW,
        Some((CID, [0xde; 32])),
    );
    assert!(matches!(
        d.open_channel(&orphan, NOW),
        Err(ChannelError::ChainRejected)
    ));
}

/// Establish a channel `id` (fresh, no predecessor) and immediately terminate it —
/// modelling a closed predecessor a successor can chain from (same payer, §5.4).
fn establish_and_terminate(d: &mut ChannelDriver, id: [u8; 8], s: [u8; 32]) {
    established(d.open_channel(&payer_open(d.key(), d.enc_key(), s, id, NOW, None), NOW));
    d.terminate(&id);
}

/// Record a **zero-position** chain snapshot for an established predecessor `id` under
/// key `(id, final_ref)` — modelling a `chain_intent` close of a fresh (un-metered)
/// predecessor (F6.6). A real close computes this in the carriage from the
/// predecessor's ledger; a driver-only test records it directly. The `terms_fingerprint`
/// is over the predecessor's own established terms, so a same-terms successor validates.
fn record_zero_snapshot(d: &mut ChannelDriver, id: [u8; 8], final_ref: [u8; 32]) {
    let payer_key = crypto::ed25519_public(&PAYER_SK);
    let t = d
        .settlement_terms(&id)
        .expect("predecessor established")
        .clone();
    let terms_fingerprint = chain_terms_fingerprint(
        Mode::Postpay,
        &t.seed_instance,
        &t.denom,
        &t.baseline_net,
        &t.fin_meed,
        &t.fin_denom,
        t.th_value,
        t.th_time,
    );
    let accruals = schema01_vector()
        .iter()
        .map(|v| (v.role, num_bigint::BigUint::from(0u8)))
        .collect();
    d.record_chain_snapshot(
        (id, final_ref),
        ChainSnapshot {
            cum_total: 0,
            accruals,
            opening_settled_r: vec![],
            opening_net_legs: 0,
            opening_funding: 0,
            imported_balance: 0,
            payer_key,
            mode: Mode::Postpay,
            terms_fingerprint,
            established_at: NOW,
        },
    );
}

#[test]
fn chain_fingerprint_covers_baseline_net() {
    // F6.6(c) "baseline network identical": a successor differing ONLY in
    // BASELINE_NET must NOT match its predecessor's terms fingerprint. The instance seed
    // commits BASELINE_ASSET (not the network), so the network is pinned by the fingerprint.
    let seed = [7u8; 32];
    let a = chain_terms_fingerprint(
        Mode::Postpay,
        &seed,
        "solana:dev/usdc",
        "solana:dev",
        "final",
        "final",
        1,
        2,
    );
    let b = chain_terms_fingerprint(
        Mode::Postpay,
        &seed,
        "solana:dev/usdc",
        "eip155:1", // only BASELINE_NET differs
        "final",
        "final",
        1,
        2,
    );
    assert_ne!(
        a, b,
        "differing BASELINE_NET must change the terms fingerprint"
    );
}

#[test]
fn stillborn_passthrough_a_to_b_to_c_conserves_value() {
    // §5.4/F6-e: the deterministic SYNTHETIC checkpoint a stillborn B presents carries the
    // predecessor A's metering (a stillborn accepts no slices) plus B's own accepted
    // funding — value is conserved through the stillborn and B's synthetic reference never
    // collides with a real checkpoint. **v1 scope:** chaining THROUGH a stillborn —
    // importing its synthetic position at a successor's open — is DEFERRED (the snapshot
    // import serves a `chain_intent`-closed predecessor, and a stillborn never closes), so
    // a successor naming the stillborn's synthetic reference fails CLOSED. The synthetic
    // checkpoint's conservation (the bytes below) is validated independently of the import.
    use num_bigint::BigUint;
    use paytp_core::channel::checkpoint::StillbornState;

    let mut d = driver();
    let (mkey, enc) = (d.key(), d.enc_key());

    // A's final imported cumulatives (as from A's bilateral checkpoint), carried into B.
    let a_ref = [0xa1; 32];
    let a_cum = BigUint::from(40000u32);
    let a_acc = vec![
        (0x10, BigUint::from(25000u32)),
        (0x12, BigUint::from(15000u32)),
    ];
    let (a_settled, a_net, a_funding) = (
        BigUint::from(33333u32),
        BigUint::from(10000u32),
        BigUint::from(5000u32),
    );

    // B is stillborn but WAS funded before its connection dropped (+2000): its cumulative
    // funding = A.opening_funding + B's own. Metering / settled / net legs pass through.
    let b_id = [0, 0, 0, 0, 0, 0, 0, 11];
    let b_own_funding = BigUint::from(2000u32);
    let b = StillbornState {
        channel_id: b_id,
        prepay: false,
        cum_total: a_cum.clone(),
        accruals: a_acc.clone(),
        settled_sum: a_settled.clone(),
        net_legs_sum: a_net.clone(),
        funding_sum: &a_funding + &b_own_funding,
        timestamp: NOW,
        prev_ref: a_ref,
    };
    let b_synth = b.synthetic_checkpoint().unwrap();
    let b_ref = b_synth.synthetic_reference().unwrap();

    // v1: chaining THROUGH the stillborn B fails CLOSED — B never went through a
    // `chain_intent` close, so no snapshot exists for (b_id, b_ref). Never a silent fresh
    // open dropping the carried position; the synthetic-import path is deferred past v1.
    let c_id = [0, 0, 0, 0, 0, 0, 0, 13];
    assert!(matches!(
        d.open_channel(
            &payer_open(mkey, enc, [0x9e; 32], c_id, NOW, Some((b_id, b_ref))),
            NOW,
        ),
        Err(ChannelError::ChainRejected)
    ));

    // Value conservation through B's synthetic checkpoint: metering + accruals pass
    // through, funding accumulates (not lost or double-counted), and B's synthetic
    // reference cannot collide with A's real checkpoint reference (F6-e).
    assert_eq!(
        b_synth.cum_total, a_cum,
        "metering conserved through the stillborn"
    );
    assert_eq!(
        b_synth.accruals, a_acc,
        "accruals conserved through the stillborn"
    );
    assert_eq!(
        b.funding_sum,
        &a_funding + &b_own_funding,
        "deposit accumulates, never stranded"
    );
    assert_ne!(
        b_ref, a_ref,
        "synthetic reference never collides with the import"
    );
}

#[test]
fn chaining_reference_consumed_once_keyed_by_channel_and_checkpoint() {
    // §5.4: a predecessor checkpoint is imported by AT MOST ONE successor. The key is
    // (channel id, checkpoint) — never the id alone — so a chain passes through a
    // stillborn: the predecessor's checkpoint and this channel's own final checkpoint
    // are distinct keys, so nothing strands and nothing double-consumes.
    let mut d = driver();
    let (mkey, enc) = (d.key(), d.enc_key());
    let (a_id, a_ref) = (CID, [0xa1; 32]);
    establish_and_terminate(&mut d, a_id, [0x5a; 32]); // A: a real, closed predecessor.
    record_zero_snapshot(&mut d, a_id, a_ref); // A chain_intent-closed → importable.

    // B imports (a_id, a_ref) — succeeds and consumes it; B is then chain_intent-closed.
    let b_id = [0, 0, 0, 0, 0, 0, 0, 11];
    established(d.open_channel(
        &payer_open(mkey, enc, [0x8c; 32], b_id, NOW, Some((a_id, a_ref))),
        NOW,
    ));
    d.terminate(&b_id);

    // A SECOND successor B' naming the SAME predecessor reference is rejected (one-decision).
    let b2_id = [0, 0, 0, 0, 0, 0, 0, 12];
    assert!(matches!(
        d.open_channel(
            &payer_open(mkey, enc, [0x8d; 32], b2_id, NOW, Some((a_id, a_ref))),
            NOW
        ),
        Err(ChannelError::ChainReplay)
    ));

    // C imports B's OWN final checkpoint (b_id, ref_b) — a DISTINCT key — and succeeds.
    let ref_b = [0xb2; 32];
    record_zero_snapshot(&mut d, b_id, ref_b); // B chain_intent-closed → importable.
    let c_id = [0, 0, 0, 0, 0, 0, 0, 13];
    established(d.open_channel(
        &payer_open(mkey, enc, [0x9e; 32], c_id, NOW, Some((b_id, ref_b))),
        NOW,
    ));

    // Re-importing (b_id, ref_b) is now also barred — consumed exactly once.
    let c2_id = [0, 0, 0, 0, 0, 0, 0, 14];
    assert!(matches!(
        d.open_channel(
            &payer_open(mkey, enc, [0x9f; 32], c2_id, NOW, Some((b_id, ref_b))),
            NOW
        ),
        Err(ChannelError::ChainReplay)
    ));
}

#[test]
fn chaining_consumes_nothing_for_unvalidated_or_failed_predecessor() {
    // The one-decision bar consumes ONLY a real, closed, same-payer predecessor — so an
    // invalid decision can never strand a valid one (the poisoning guard).
    let mut d = driver();
    let (mkey, enc) = (d.key(), d.enc_key());
    let (a_id, a_ref) = (CID, [0xa1; 32]);
    establish_and_terminate(&mut d, a_id, [0x5a; 32]);
    record_zero_snapshot(&mut d, a_id, a_ref); // A chain_intent-closed → importable.

    // (i) A CHANNEL_OPEN chaining from a real closed A but that FAILS unseal (H(s)
    //     mismatch) consumes nothing — a later valid successor is not stranded. (H(s) is
    //     checked before the import, so this rejects `HsMismatch`, and no import runs.)
    let bad_id = [0, 0, 0, 0, 0, 0, 0, 30];
    let good = payer_open(mkey, enc, [0x8c; 32], bad_id, NOW, Some((a_id, a_ref)));
    let bad = ChannelOpen::build(good.auth.clone(), &enc, &[0x77; 32]).unwrap(); // re-seal ≠ HS
    assert!(matches!(
        d.open_channel(&bad, NOW),
        Err(ChannelError::HsMismatch)
    ));

    // (ii) A CHANNEL_OPEN naming an UNKNOWN predecessor (no recorded snapshot) is now
    //      REJECTED **fail-closed** — never a silent fresh open that drops the
    //      predecessor's position — and consumes nothing, so it cannot strand a real chain.
    let u_id = [0, 0, 0, 0, 0, 0, 0, 31];
    assert!(matches!(
        d.open_channel(
            &payer_open(
                mkey,
                enc,
                [0x42; 32],
                u_id,
                NOW,
                Some(([9, 9, 9, 9, 9, 9, 9, 9], [0xee; 32])),
            ),
            NOW,
        ),
        Err(ChannelError::ChainRejected)
    ));

    // (iii) The valid successor B chaining from (a_id, a_ref) still establishes — neither
    //       the failed open nor the fail-closed unknown-predecessor open consumed A's reference.
    let b_id = [0, 0, 0, 0, 0, 0, 0, 11];
    established(d.open_channel(
        &payer_open(mkey, enc, [0x8c; 32], b_id, NOW, Some((a_id, a_ref))),
        NOW,
    ));
}

#[test]
fn lost_ack_reconnect_recovery_forces_no_settlement() {
    // The mobile-churn case relies on: a chaining CHANNEL_ACK is lost mid-handshake.
    // Recovery is pure control-plane — no settlement is forced — via two mechanisms:
    // (1) a byte-identical retransmit returns the SAME stored ACK and does NOT
    //     re-initialize or re-consume; (2) the ACK is retrievable from the control
    //     endpoint against a payer-signed request, on any connection (§5.4).
    use paytp_core::channel::state::Status;

    let mut d = driver();
    let (mkey, enc) = (d.key(), d.enc_key());
    let (a_id, a_ref) = (CID, [0xa1; 32]);
    establish_and_terminate(&mut d, a_id, [0x5a; 32]);
    record_zero_snapshot(&mut d, a_id, a_ref); // A chain_intent-closed → B can import it.
    let b_id = [0, 0, 0, 0, 0, 0, 0, 11];
    let openb = payer_open(mkey, enc, [0x8c; 32], b_id, NOW, Some((a_id, a_ref)));
    let est = established(d.open_channel(&openb, NOW));
    assert_eq!(
        est.state.status(),
        Status::Open,
        "establishment forces no settlement"
    );

    // (1) Lost ACK → byte-identical retransmit returns the SAME ACK, no re-establishment.
    match d.open_channel(&openb, NOW).unwrap() {
        OpenOutcome::Retransmit(ack) => {
            assert_eq!(ack.encode().unwrap(), est.ack.encode().unwrap());
        }
        OpenOutcome::Established(_) => panic!("a retransmit must not re-establish the channel"),
    }
    // The retransmit did NOT release the predecessor reference: a fresh successor from the
    // same (a_id, a_ref) is still barred (consumed exactly once by B, not twice).
    let x_id = [0, 0, 0, 0, 0, 0, 0, 20];
    assert!(matches!(
        d.open_channel(
            &payer_open(mkey, enc, [0x77; 32], x_id, NOW, Some((a_id, a_ref))),
            NOW
        ),
        Err(ChannelError::ChainReplay)
    ));

    // (2) Recovery on a DIFFERENT connection: the ACK is served against a payer-signed
    //     request — the wallet that signed CHANNEL_AUTH can always learn the outcome.
    let mut req = AckRequest {
        channel_id: b_id,
        timestamp: NOW,
        sig: None,
    };
    req.sign(&PAYER_SK).unwrap();
    let got = d
        .serve_ack_request(&req, NOW)
        .expect("ACK retrievable on any connection");
    assert_eq!(got.encode().unwrap(), est.ack.encode().unwrap());
}

#[test]
fn ack_request_retrieval_is_authenticated() {
    // F5.3: retrieval returns the CHANNEL_ACK only for a request signed by *that
    // channel's* payer key within the F8.2 window — nobody else learns the terms.
    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s, CID, NOW, None);
    let est = established(d.open_channel(&open, NOW));

    // A valid, fresh, payer-signed request retrieves the stored ACK.
    let mut req = AckRequest {
        channel_id: CID,
        timestamp: NOW,
        sig: None,
    };
    req.sign(&PAYER_SK).unwrap();
    let got = d
        .serve_ack_request(&req, NOW)
        .expect("valid request served");
    assert_eq!(got.encode().unwrap(), est.ack.encode().unwrap());

    // A wrong-key signature is refused (an intermediary knowing only CHANNEL_ID).
    let mut forged = AckRequest {
        channel_id: CID,
        timestamp: NOW,
        sig: None,
    };
    forged.sign(&[0x55; 32]).unwrap();
    assert!(d.serve_ack_request(&forged, NOW).is_none());

    // A stale timestamp is refused.
    assert!(d.serve_ack_request(&req, NOW + 10_000).is_none());

    // An unknown channel id is refused.
    let mut other = AckRequest {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 99],
        timestamp: NOW,
        sig: None,
    };
    other.sign(&PAYER_SK).unwrap();
    assert!(d.serve_ack_request(&other, NOW).is_none());
}

#[test]
fn close_path_settles_and_bars_reuse() {
    // The full close wiring: establish → meter a slice → payer CLOSE verified →
    // channel enters SETTLING (no more slices) + F5-m bars re-init → CLOSED.
    use paytp_core::channel::state::Status;
    use paytp_core::channel::Close;
    use paytp_core::slice::Slice;

    let mut d = driver();
    let mkey = d.key();
    let enc = d.enc_key();
    let s = [0x5a; 32];
    let open = payer_open(mkey, enc, s, CID, NOW, None);
    let mut est = established(d.open_channel(&open, NOW));
    let payer_key = crypto::ed25519_public(&PAYER_SK);

    est.state
        .accept_slice(&Slice::seal(1, 1_000, &est.k_session).unwrap())
        .unwrap();
    assert_eq!(est.state.status(), Status::Open);

    // The payer sends a CLOSE (naming the final checkpoint, chain intent set).
    let mut close = Close {
        channel_id: CID,
        ckpt_ref: est.auth_hash,
        chain_intent: true,
        sig: None,
    };
    close.sign(&PAYER_SK).unwrap();
    let decision = close.accept(&CID, &payer_key, &mkey).unwrap();
    assert!(decision.by_payer && decision.chain_intent);

    // Wire it: the endpoint enters SETTLING and the F5-m record is terminated.
    est.state.begin_settling();
    d.terminate(&CID);
    assert_eq!(est.state.status(), Status::Settling);

    // No further slices are accepted, and the channel id can never re-open.
    assert!(est
        .state
        .accept_slice(&Slice::seal(2, 1_000, &est.k_session).unwrap())
        .is_err());
    assert!(matches!(
        d.open_channel(&open, NOW),
        Err(ChannelError::ChannelReplay)
    ));

    // Obligations resolved → CLOSED (keys erased).
    est.state.close();
    assert_eq!(est.state.status(), Status::Closed);
}
