//! M1 baseline Tier 0 end-to-end (virtual rail).
//!
//! Drives the full §5.6 baseline flow — quote → validate → split payTo → pay →
//! redeem (settlement-precedes-delivery) → receipt — plus the properties M1's
//! exit names: correct split division, nonce idempotency, proof-replay
//! rejection, plain-x402 completion, and the expiry/honor rule.

use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::tier0::quote::{MeedEntry, Quote};
use paytp_core::x402::PaymentRequirements;
use paytp_merchant::{BaselineParams, InMemoryStore, Merchant, RedeemError};
use paytp_rail::{RailAdapter, Transfer, TransferKind, VirtualRail};

const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";

fn schema01_vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: IL_DEST.into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            // Absent/unlisted OS → the independent open-source fund (§10.1/F9.4 step 2),
            // NOT the Development Fund.
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

fn params<'a>(nonce: [u8; 32], amount: u128) -> BaselineParams<'a> {
    BaselineParams {
        resource: "https://api.example/data",
        nonce,
        exp: 1_000_000_500,
        idem: b"idem-1".to_vec(),
        registry_version: 5,
        baseline_network: "eip155:8453",
        asset: "eip155:1/native",
        amount,
        finality: "final",
        grace: 300,
        retry: 600,
        max_timeout_seconds: 60,
        extra: None,
        vector: schema01_vector(),
    }
}

#[derive(Clone)]
struct PresentedPayment {
    transfer: Transfer,
    settle_id: [u8; 32],
}

/// A minimal PayTP-aware wallet/client: validates the quote and prepares the
/// payer's signed-payment stand-in for the merchant to settle.
fn wallet_prepares(
    rail: &VirtualRail,
    quote: &Quote,
    merchant_key: &[u8; 32],
    settle_id: [u8; 32],
) -> PresentedPayment {
    // Client validation before paying (§5.4/§5.6): the governed meed vector AND every
    // offer's `accept.network` as CAIP-2 (F3-c — a sentinel network is invalid). This wallet holds
    // no registry, so it accepts the OS share only at the independent-fund fallback (fail-closed).
    quote
        .validate_tier0(paytp_core::registry::SnapshotStore::empty_ref())
        .expect("tier0 quote ok");
    let offer = &quote.offers[0];
    let pay_to = match &offer.accept {
        paytp_core::jcs::StrictValue::Object(m) => m
            .iter()
            .find(|(k, _)| k == "payTo")
            .and_then(|(_, v)| match v {
                paytp_core::jcs::StrictValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap(),
        _ => panic!("accept object"),
    };
    // Re-derive the split from the signed quote and refuse a payTo mismatch (the
    // split commits the offer's signed net destination `merchantNet`).
    let merchant_net = quote
        .offers
        .iter()
        .find(|o| o.two_leg.is_none())
        .and_then(|o| o.merchant_net.as_deref())
        .expect("baseline offer merchantNet");
    quote
        .verify_split_pay_to(
            merchant_key,
            "eip155:1/native",
            merchant_net,
            &pay_to,
            |seed| rail.derive_address(seed),
        )
        .expect("payTo matches re-derivation");
    PresentedPayment {
        transfer: Transfer {
            to: pay_to,
            asset: "eip155:1/native".into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: None,
        },
        settle_id,
    }
}

const RESOURCE: &str = "https://api.example/data";

#[test]
fn baseline_happy_path_divides_and_receipts() {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();

    let bq = merchant.build_baseline_quote(&rail, params([0x01; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();

    // Client validates + pays the split.
    let reparsed = Quote::parse_verify(&json, &merchant.key).unwrap();
    let payment = wallet_prepares(&rail, &reparsed, &merchant.key, [0xA1; 32]);

    // Redeem: settlement precedes delivery; receipt signed & verifiable.
    let receipt = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_003,
        )
        .expect("redeem");
    let receipt_json = String::from_utf8(receipt.to_json()).unwrap();
    let verified = paytp_core::tier0::Receipt::parse_verify(&receipt_json, &merchant.key).unwrap();
    assert_eq!(verified.nonce, [0x01; 32]);
    assert_eq!(verified.paid.len(), 1);
    assert_eq!(verified.paid[0].leg, "split");

    // Split divided correctly (99% merchant, 1% meed) when the merchant settled
    // the presented payment.
    assert_eq!(rail.balance("merchant-payout"), 990_000);
    assert_eq!(rail.balance(IL_DEST), 5_000);
    assert_eq!(rail.balance(WALLET_DEST), 3_000);
    // 0x11 OS (10 bp) → independent OS fund; 0x13 Dev Fund (10 bp) → Dev Fund — distinct seats now.
    assert_eq!(rail.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER), 1_000);
    assert_eq!(rail.balance(DEV_FUND_DEST_PLACEHOLDER), 1_000);
}

#[test]
fn nonce_idempotency_and_replay() {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(&rail, params([0x02; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let payment = wallet_prepares(&rail, &bq.quote, &merchant.key, [0xA2; 32]);

    let r1 = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .unwrap();
    let merchant_after_first = rail.balance("merchant-payout");
    // Same nonce + same payment authorization → idempotent, identical receipt, no second charge.
    let r2 = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .unwrap();
    assert_eq!(r1.to_json(), r2.to_json());
    assert_eq!(rail.balance("merchant-payout"), merchant_after_first);

    // A different nonce reusing the SAME canonical settlement ref is rejected by
    // the durable used_refs arbiter.
    let bq2 = merchant.build_baseline_quote(&rail, params([0x03; 32], 1_000_000));
    let json2 = String::from_utf8(bq2.quote.to_json()).unwrap();
    assert_eq!(
        merchant.redeem_baseline(
            &json2,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        ),
        Err(RedeemError::Replayed)
    );
}

#[test]
fn design_a_rejects_cross_payer_hijack_via_used_refs() {
    // The CRITICAL Design A closure: once P's presented payment authorization
    // settles to a canonical ref and consumes P's nonce, an observer cannot redeem
    // their own fresh quote against that same settlement, even though the split is
    // shared across the merchant's quotes.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();

    let payer = merchant.build_baseline_quote(&rail, params([0x07; 32], 1_000_000));
    let payer_json = String::from_utf8(payer.quote.to_json()).unwrap();
    let payer_payment = wallet_prepares(&rail, &payer.quote, &merchant.key, [0xA7; 32]);
    assert!(merchant
        .redeem_baseline(
            &payer_json,
            RESOURCE,
            payer_payment.transfer.clone(),
            payer_payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .is_ok());

    let observer = merchant.build_baseline_quote(&rail, params([0x08; 32], 1_000_000));
    let observer_json = String::from_utf8(observer.quote.to_json()).unwrap();
    assert_eq!(
        merchant.redeem_baseline(
            &observer_json,
            RESOURCE,
            payer_payment.transfer.clone(),
            payer_payment.settle_id,
            &rail,
            &store,
            1_000_000_003,
        ),
        Err(RedeemError::Replayed)
    );

    // The observer can still complete by presenting their own fresh payment
    // authorization; that is payment, not hijack.
    let observer_payment = wallet_prepares(&rail, &observer.quote, &merchant.key, [0xA8; 32]);
    assert!(merchant
        .redeem_baseline(
            &observer_json,
            RESOURCE,
            observer_payment.transfer.clone(),
            observer_payment.settle_id,
            &rail,
            &store,
            1_000_000_004,
        )
        .is_ok());
}

#[test]
fn mismatched_presented_payment_rejected_before_settle() {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(&rail, params([0x09; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();

    // A wrong-asset presented payment (right split, right amount) is not payment (F4.4).
    let wrong_asset = Transfer {
        to: bq.split_address.clone(),
        asset: "eip155:1/OTHER".into(),
        amount: 1_000_000,
        kind: TransferKind::Payment,
        memo: None,
    };
    assert_eq!(
        merchant.redeem_baseline(
            &json,
            RESOURCE,
            wrong_asset,
            [0xA9; 32],
            &rail,
            &store,
            1_000_000_003,
        ),
        Err(RedeemError::PaymentUnverified)
    );
    assert_eq!(rail.balance("merchant-payout"), 0);
}

#[test]
fn unaware_style_client_presents_payment_and_completes_without_memo() {
    // An unaware-style x402 client only presents the exact transfer it authorized;
    // the merchant settles it under Design A, so redemption succeeds without a
    // PayTP memo.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(&rail, params([0x04; 32], 500_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let payment = PresentedPayment {
        transfer: Transfer {
            to: bq.split_address.clone(),
            asset: "eip155:1/native".into(),
            amount: 500_000,
            kind: TransferKind::Payment,
            memo: None,
        },
        settle_id: [0xA4; 32],
    };
    let receipt = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .expect("merchant settles the presented payment");
    assert_eq!(receipt.nonce, [0x04; 32]);
    assert_eq!(rail.balance("merchant-payout"), 495_000); // 99%
    assert_eq!(rail.balance(IL_DEST), 2_500); // 0.5%
}

#[test]
fn baseline_quote_omits_extra_memo_and_retries_without_second_mint() {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let mut extra = serde_json::Map::new();
    extra.insert("feePayer".into(), serde_json::json!("payer111"));
    let bq = merchant.build_baseline_quote(
        &rail,
        BaselineParams {
            extra: Some(extra),
            ..params([0x14; 32], 500_000)
        },
    );
    let mirror = PaymentRequirements::from_strict(&bq.quote.offers[0].accept).unwrap();
    assert_eq!(
        mirror.extra.as_ref().and_then(|m| m.get("feePayer")),
        Some(&serde_json::json!("payer111"))
    );
    assert!(
        !mirror
            .extra
            .as_ref()
            .is_some_and(|m| m.contains_key("memo")),
        "baseline mirror must not advertise exact-svm extra.memo"
    );

    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let payment = PresentedPayment {
        transfer: Transfer {
            to: bq.split_address.clone(),
            asset: "eip155:1/native".into(),
            amount: 500_000,
            kind: TransferKind::Payment,
            memo: None,
        },
        settle_id: [0xB4; 32],
    };
    let first = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .expect("first redeem");
    let merchant_after_first = rail.balance("merchant-payout");
    let retry = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer,
            payment.settle_id,
            &rail,
            &store,
            1_000_000_003,
        )
        .expect("retry returns stored receipt");
    assert_eq!(first.to_json(), retry.to_json());
    assert_eq!(rail.balance("merchant-payout"), merchant_after_first);
}

#[test]
fn expired_quote_rejected() {
    // The payment reaches finality only AFTER exp+grace (1_000_000_800): the
    // honor rule does NOT apply, so redemption is expired. (A leg final *within*
    // the window MUST be honored regardless of wall-clock — see the happy path.)
    let rail = VirtualRail::new(1500); // fin.time = 1_000_000_000 + 1500 = 1_000_001_500
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(&rail, params([0x05; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let payment = wallet_prepares(&rail, &bq.quote, &merchant.key, [0xA5; 32]);
    assert_eq!(
        merchant.redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_000,
        ),
        Err(RedeemError::PaymentUnverified)
    );
    rail.advance_clock(1500);
    assert_eq!(
        merchant.redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer,
            payment.settle_id,
            &rail,
            &store,
            1_000_001_500,
        ),
        Err(RedeemError::Expired)
    );
}

#[test]
fn tampered_quote_rejected() {
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(&rail, params([0x06; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let tampered = json.replace(IL_DEST, "eip155:1:0xEVILdestination");
    let payment = wallet_prepares(&rail, &bq.quote, &merchant.key, [0xA6; 32]);
    assert_eq!(
        merchant.redeem_baseline(
            &tampered,
            RESOURCE,
            payment.transfer,
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        ),
        Err(RedeemError::QuoteInvalid)
    );
    assert_eq!(rail.balance("merchant-payout"), 0);
}

/// A unique scratch WAL path (no `tempfile` dep).
fn wal_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "paytp-baseline-{}-{}-{}.wal",
        tag,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn durable_store_replay_refuses_a_replayed_proof_after_a_restart() {
    // Boundary: AFTER nonce write. With the DURABLE `WalMerchantStore`, a redemption's
    // consumed-nonce record survives a merchant restart, so a replayed payment proof after the
    // restart returns the STORED receipt (idempotent) instead of re-verifying and delivering a
    // second time. Proves the receipt round-trips faithfully through the real `redeem_baseline`
    // path (build → to_json → WAL → parse_verify → returned).
    use paytp_merchant::WalMerchantStore;
    let path = wal_path("s1");
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");

    let bq = merchant.build_baseline_quote(&rail, params([0xA1; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let reparsed = Quote::parse_verify(&json, &merchant.key).unwrap();
    let payment = wallet_prepares(&rail, &reparsed, &merchant.key, [0xC1; 32]);

    // First redemption through a durable store → consumed-nonce record persisted.
    let first = {
        let store = WalMerchantStore::open(&path, merchant.key).unwrap();
        merchant
            .redeem_baseline(
                &json,
                RESOURCE,
                payment.transfer.clone(),
                payment.settle_id,
                &rail,
                &store,
                1_000_000_003,
            )
            .expect("first redeem")
    }; // drop the store → crash / restart

    // RESTART: a fresh store over the SAME log replays the consumed nonce. A replay of the same
    // proof returns the STORED receipt (no second delivery) — byte-identical to the first.
    let store2 = WalMerchantStore::open(&path, merchant.key).unwrap();
    let replay = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer,
            payment.settle_id,
            &rail,
            &store2,
            1_000_000_009,
        )
        .expect("replay returns the stored receipt, not a re-delivery");
    assert_eq!(
        first.to_json(),
        replay.to_json(),
        "the durable store returns the SAME receipt across a restart — no double delivery"
    );
    let _ = std::fs::remove_file(&path);
}
