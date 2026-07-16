//! M2 two-leg Tier 0 end-to-end (virtual rail).
//!
//! Meed-first-means-final funding, the entry state machine, and the merchant
//! entry order (F4.4/F4.5): quote → fund meed entry → (finality) → net leg →
//! (finality) → redeem → receipt + posted attestation releasing the meed.

use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::tier0::quote::MeedEntry;
use paytp_merchant::{InMemoryStore, Merchant, RedeemError, TwoLegParams};
use paytp_rail::{EntryStatus, RailAdapter, RailRef, Transfer, TransferKind, VirtualRail};

const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";
const REFUND: &str = "eip155:1:0xPayerRefund";
const RESOURCE: &str = "https://api.example/premium";
const BASELINE_ASSET: &str = "eip155:1/native";
const NET_ASSET: &str = "eip155:137/usdc";

fn vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: IL_DEST.into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            // Absent/unlisted OS → the independent open-source fund (§10.1/F9.4 step 2).
            dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: WALLET_DEST.into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

fn params<'a>(nonce: [u8; 32]) -> TwoLegParams<'a> {
    TwoLegParams {
        resource: RESOURCE,
        nonce,
        exp: 1_000_000_500,
        idem: b"idem-2leg".to_vec(),
        registry_version: 5,
        net_network: "eip155:137",
        net_asset: NET_ASSET,
        net_amount: 990_000,
        baseline_network: "eip155:1",
        baseline_asset: BASELINE_ASSET,
        meed_amount: 10_000,
        rate: "1",
        rate_source: "coinbase-spot",
        reclaim: 3_600,
        contest: 600,
        grace: 300,
        retry: 600,
        fin_meed: "final",
        fin_net: "final",
        vector: vector(),
    }
}

/// A PayTP-aware two-leg wallet: meed FIRST (and final), then the net leg.
fn wallet_two_leg(
    rail: &VirtualRail,
    tlq: &paytp_merchant::TwoLegQuote,
    merchant_net_payout: &str,
) -> (RailRef, RailRef) {
    let q = &tlq.quote;
    // 1. Fund the meed entry at the instance (F4.5 — meed first). The
    //    instance derives the entry_id; it MUST equal the merchant's derived id.
    let (meed_ref, funded_id) = rail
        .fund_entry(
            &tlq.instance_address,
            q.nonce,
            10_000,
            REFUND.into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            BASELINE_ASSET.into(),
        )
        .expect("fund meed entry");
    assert_eq!(funded_id, tlq.entry_id, "derived id matches the quote");
    rail.advance_clock(2); // wait meed finality BEFORE the net leg (first-means-final)
                           // 2. Net leg to the merchant on the net rail.
    let net_ref = rail
        .submit(Transfer {
            to: merchant_net_payout.to_string(),
            asset: NET_ASSET.into(),
            amount: 990_000,
            kind: TransferKind::Payment,
            memo: Some(q.nonce),
        })
        .expect("net leg");
    rail.advance_clock(2); // net finality
    (meed_ref, net_ref)
}

#[test]
fn two_leg_happy_path() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();

    let tlq = merchant.build_two_leg_quote(&rail, params([0x21; 32]));
    assert!(rail.has_instance(&tlq.instance_address));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);

    // The entry is FUNDED before redemption; recipients not yet paid.
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::Funded)
    );
    assert_eq!(rail.balance(IL_DEST), 0);

    let receipt = merchant
        .redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, 1_000_000_006)
        .expect("redeem two-leg");

    // Receipt: meed then net, with the entry id.
    assert_eq!(receipt.paid.len(), 2);
    assert_eq!(receipt.paid[0].leg, "meed");
    assert_eq!(receipt.paid[1].leg, "net");
    assert_eq!(receipt.entry, Some(tlq.entry_id));
    let rjson = String::from_utf8(receipt.to_json()).unwrap();
    assert!(paytp_core::tier0::Receipt::parse_verify(&rjson, &merchant.key).is_ok());

    // The attestation was posted → entry ATTESTED, meed distributed (10000):
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::Attested)
    );
    assert_eq!(rail.balance(IL_DEST), 5_000);
    assert_eq!(rail.balance(WALLET_DEST), 3_000);
    // 0x11 OS → independent OS fund; 0x13 Dev Fund → Dev Fund (distinct seats).
    assert_eq!(rail.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER), 1_000);
    assert_eq!(rail.balance(DEV_FUND_DEST_PLACEHOLDER), 1_000);
    // Net leg reached the merchant.
    assert_eq!(rail.balance("merchant-net-payout"), 990_000);
}

#[test]
fn two_leg_idempotent_redeem() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x22; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);
    let r1 = merchant
        .redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, 1_000_000_006)
        .unwrap();
    let r2 = merchant
        .redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, 1_000_000_006)
        .unwrap();
    assert_eq!(r1.to_json(), r2.to_json());
    // Meed distributed exactly once (idempotent attestation).
    assert_eq!(rail.balance(IL_DEST), 5_000);
}

#[test]
fn redeem_retry_after_attest_before_nonce_consume_completes() {
    // C1-4: the crash-atomicity window. `redeem_two_leg` posts the attestation (rail, durable) BEFORE
    // consuming the nonce (merchant store). A crash in between leaves the entry ATTESTED with the
    // nonce still FRESH. On retry the nonce peek does NOT short-circuit (fresh), so the flow re-checks
    // the entry — which is now Attested. The old entry-status match rejected anything but
    // Funded/ReclaimOpen, so the payer was left paid on both legs with NO delivery and NO receipt.
    // Correct: an already-attested entry is idempotent success — redeem completes and returns a receipt.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x2b; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);

    // Reproduce the post-crash state: the attestation landed on the rail (entry ATTESTED, meed
    // distributed) but the nonce was never consumed (the store is untouched — fresh).
    let att = merchant.make_attestation(tlq.quote.nonce, tlq.entry_id);
    rail.attest_entry(&tlq.instance_address, tlq.entry_id, &att)
        .expect("out-of-band attest simulates the pre-crash attestation");
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::Attested),
        "entry attested, but the nonce store is still fresh (the crash window)"
    );
    assert_eq!(
        rail.balance(IL_DEST),
        5_000,
        "meed already distributed once"
    );

    // The retry must COMPLETE (deliver + receipt), not reject — and must not re-distribute the meed.
    let receipt = merchant
        .redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, 1_000_000_006)
        .expect("retry against an attested entry completes idempotently");
    assert_eq!(receipt.entry, Some(tlq.entry_id));
    let rjson = String::from_utf8(receipt.to_json()).unwrap();
    assert!(paytp_core::tier0::Receipt::parse_verify(&rjson, &merchant.key).is_ok());
    assert_eq!(
        rail.balance(IL_DEST),
        5_000,
        "meed distributed exactly once — the idempotent retry did not double-pay recipients"
    );
}

#[test]
fn reclaim_then_attest_on_the_entry() {
    // F4.3: the payer opens reclaim; a valid attestation before execution wins.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x23; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);
    // Payer opens reclaim inside [T_open, T_lapse].
    rail.advance_clock((tlq.t_open + 1).saturating_sub(rail.chain_time()));
    rail.open_reclaim(&tlq.instance_address, tlq.entry_id)
        .expect("open reclaim");
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::ReclaimOpen)
    );
    // Merchant redeems (delivery) and posts the attestation → ATTESTED, reclaim cancelled.
    let now = tlq.t_open + 2;
    // The quote is past exp here, but both legs reached finality within exp+grace,
    // so the honor rule still applies. (finality times were ~1e9+2/4 < exp+grace.)
    let r = merchant.redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, now);
    assert!(
        r.is_ok(),
        "redeem should honor legs final within the window"
    );
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::Attested)
    );
    assert_eq!(rail.balance(IL_DEST), 5_000);
}

#[test]
fn reclaim_open_redeem_requires_f8f_inclusion_margin() {
    // F8-f: delivering under a reclaim-open entry requires TWICE the adapter's
    // declared inclusion latency of remaining margin before T_exec. The same redeem that
    // succeeds on a synchronous rail (reclaim_then_attest_on_the_entry, latency 0) is
    // refused when the adapter declares a latency large enough that the attestation could
    // be front-run by a permissionless execute_reclaim.
    let rail = VirtualRail::new(2).with_inclusion_latency(300);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x24; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);
    rail.advance_clock((tlq.t_open + 1).saturating_sub(rail.chain_time()));
    rail.open_reclaim(&tlq.instance_address, tlq.entry_id)
        .expect("open reclaim");
    // now=t_open+2: T_exec = opened_at(t_open+1)+contest(600); remaining margin 599 < 2*300.
    let now = tlq.t_open + 2;
    let r = merchant.redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, now);
    assert!(
        matches!(r, Err(RedeemError::PaymentUnverified)),
        "redeem must be refused without 2x inclusion-latency margin to T_exec"
    );
}

#[test]
fn delivered_two_leg_reclaim_fails_because_attested() {
    // (F7-d): a DELIVERED two-leg purchase is ATTESTED before any reclaim
    // can execute, so a payer who then tries to open+execute reclaim to claw the
    // meed back FAILS — the strip is barred. Complements
    // `reclaim_then_attest_on_the_entry` (attestation wins mid-reclaim); this locks
    // the guarantee from the *delivered-then-reclaim* direction.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x2a; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let (rmeed, rnet) = wallet_two_leg(&rail, &tlq, &merchant.payout);

    // Merchant delivers: posts the attestation before delivery → ATTESTED, meed
    // distributed to the recipients.
    let r = merchant.redeem_two_leg(&json, RESOURCE, &rmeed, &rnet, &rail, &store, 1_000_000_006);
    assert!(
        r.is_ok(),
        "delivery honors both legs final within the window"
    );
    assert_eq!(
        rail.entry_status(&tlq.instance_address, &tlq.entry_id),
        Some(EntryStatus::Attested)
    );
    assert_eq!(rail.balance(IL_DEST), 5_000);

    // The payer now tries to strip the meed via reclaim, inside [T_open, T_lapse].
    rail.advance_clock((tlq.t_open + 1).saturating_sub(rail.chain_time()));
    assert!(
        rail.open_reclaim(&tlq.instance_address, tlq.entry_id)
            .is_err(),
        "cannot open reclaim on a delivered (attested) entry"
    );
    // And execution is barred too (the entry is terminal, not RECLAIM_OPEN).
    assert!(
        rail.execute_reclaim(&tlq.instance_address, tlq.entry_id)
            .is_err(),
        "cannot execute reclaim on a delivered entry"
    );
    // The meed stays with the recipients — never clawed back.
    assert_eq!(rail.balance(IL_DEST), 5_000, "meed not stripped");
}

#[test]
fn net_leg_to_wrong_address_rejected() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x24; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    // Meed funded correctly...
    let (meed_ref, _) = rail
        .fund_entry(
            &tlq.instance_address,
            tlq.quote.nonce,
            10_000,
            REFUND.into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            BASELINE_ASSET.into(),
        )
        .unwrap();
    rail.advance_clock(2);
    // ...but the net leg goes to an attacker address.
    let bad_net = rail
        .submit(Transfer {
            to: "attacker".into(),
            asset: NET_ASSET.into(),
            amount: 990_000,
            kind: TransferKind::Payment,
            memo: Some(tlq.quote.nonce),
        })
        .unwrap();
    rail.advance_clock(2);
    assert_eq!(
        merchant.redeem_two_leg(
            &json,
            RESOURCE,
            &meed_ref,
            &bad_net,
            &rail,
            &store,
            1_000_000_006
        ),
        Err(RedeemError::PaymentUnverified)
    );
}

#[test]
fn dust_meed_funding_does_not_satisfy_redeem() {
    // C1 closure (F4-c): funding the entry with a DUST amount lands a DIFFERENT
    // derived id, so the merchant's honest derived id is never FUNDED → reject.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x28; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    // Wallet funds a DUST amount (1) instead of the quoted 10_000.
    let (dust_ref, dust_id) = rail
        .fund_entry(
            &tlq.instance_address,
            tlq.quote.nonce,
            1,
            REFUND.into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            BASELINE_ASSET.into(),
        )
        .unwrap();
    assert_ne!(dust_id, tlq.entry_id, "dust funds a different, orphaned id");
    rail.advance_clock(2);
    let net_ref = rail
        .submit(Transfer {
            to: merchant.payout.clone(),
            asset: NET_ASSET.into(),
            amount: 990_000,
            kind: TransferKind::Payment,
            memo: Some(tlq.quote.nonce),
        })
        .unwrap();
    rail.advance_clock(2);
    assert_eq!(
        merchant.redeem_two_leg(
            &json,
            RESOURCE,
            &dust_ref,
            &net_ref,
            &rail,
            &store,
            1_000_000_006
        ),
        Err(RedeemError::PaymentUnverified)
    );
}

#[test]
fn building_second_quote_does_not_wipe_instance() {
    // C3 closure: two quotes with the same merchant/asset/vector/contract share
    // one instance; building the second MUST NOT wipe the first's funded entry.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let a = merchant.build_two_leg_quote(&rail, params([0x30; 32]));
    let (_, a_id) = rail
        .fund_entry(
            &a.instance_address,
            a.quote.nonce,
            10_000,
            REFUND.into(),
            a.t_open,
            a.t_lapse,
            600,
            BASELINE_ASSET.into(),
        )
        .unwrap();
    // Build a second quote (same inputs → same instance address).
    let b = merchant.build_two_leg_quote(&rail, params([0x31; 32]));
    assert_eq!(a.instance_address, b.instance_address);
    // The first entry survives (deploy_instance is idempotent).
    assert_eq!(
        rail.entry_status(&a.instance_address, &a_id),
        Some(EntryStatus::Funded)
    );
}

#[test]
fn missing_meed_entry_rejected() {
    // Net leg present and final, but the meed entry was never funded.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let tlq = merchant.build_two_leg_quote(&rail, params([0x25; 32]));
    let json = String::from_utf8(tlq.quote.to_json()).unwrap();
    let net_ref = rail
        .submit(Transfer {
            to: merchant.payout.clone(),
            asset: NET_ASSET.into(),
            amount: 990_000,
            kind: TransferKind::Payment,
            memo: Some(tlq.quote.nonce),
        })
        .unwrap();
    rail.advance_clock(2);
    // Fabricate a meed ref that didn't fund the entry (a net payment, say).
    let fake_meed = rail
        .submit(Transfer {
            to: tlq.instance_address.clone(),
            asset: BASELINE_ASSET.into(),
            amount: 10_000,
            kind: TransferKind::Payment,
            memo: Some(tlq.quote.nonce),
        })
        .unwrap();
    rail.advance_clock(2);
    assert_eq!(
        merchant.redeem_two_leg(
            &json,
            RESOURCE,
            &fake_meed,
            &net_ref,
            &rail,
            &store,
            1_000_000_006
        ),
        Err(RedeemError::PaymentUnverified) // entry not FUNDED at the derived id
    );
}
