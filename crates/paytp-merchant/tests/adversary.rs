//! M7 adversary suite.
//!
//! Executable attacks that MUST FAIL against PayTP's design. Each doubles as
//! proof the PayTP profile closes what base x402 leaves to the implementation
//! (ch 3 §3.6): the merchant-signed quote binds payment to one resource/vector,
//! and the consumed nonce/ref record is an atomic check-and-set **at the merchant
//! before delivery** (not at a facilitator), and settlement precedes delivery.
//!
//! The x402 classes are drawn from the 2026 analyses (arXiv 2605.11781 "Five
//! Attacks on x402"; 2605.30998 "Free-Riding in the AI Economy") — re-verified
//! live 2026-07-09. Their four flaw classes — cross-resource substitution,
//! duplicate-settlement race, allowance overdraft, denial of settlement — plus
//! leaked-token resubmission each become a must-FAIL test here.

use std::sync::atomic::{AtomicUsize, Ordering};

use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::registry::{Kind, Snapshot, SnapshotStore};
use paytp_core::tier0::quote::{MeedEntry, Quote};
use paytp_merchant::{
    BaselineParams, InMemoryStore, Merchant, MerchantStore, NonceRecord, RedeemError,
};
use paytp_rail::{RailAdapter, RailRef, Transfer, TransferKind, VirtualRail};

const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";
const ASSET: &str = "eip155:1/native";
const TWOLEG_REFUND: &str = "eip155:1:0xPayerRefund";
const TWOLEG_BASELINE_ASSET: &str = "eip155:1/native";
const TWOLEG_NET_ASSET: &str = "eip155:137/usdc";

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

fn params<'a>(nonce: [u8; 32], resource: &'a str, amount: u128) -> BaselineParams<'a> {
    BaselineParams {
        resource,
        nonce,
        exp: 1_000_000_500,
        idem: b"idem".to_vec(),
        registry_version: 5,
        baseline_network: "eip155:8453", // a baseline offer's network must map to an x402 name (F3-j)
        asset: ASSET,
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

/// Prepare the split payment re-derived from a signed quote. The payer keeps the
/// `settle_id` private until presenting it to the merchant.
fn prepare_split(
    rail: &VirtualRail,
    merchant: &Merchant,
    quote: &Quote,
    settle_id: [u8; 32],
) -> PresentedPayment {
    let seed = quote
        .address_inputs(&merchant.key, ASSET, Some(merchant.payout.as_str()))
        .seed_split()
        .unwrap();
    let split = rail.derive_address(&seed);
    PresentedPayment {
        transfer: Transfer {
            to: split,
            asset: ASSET.into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: None,
        },
        settle_id,
    }
}

// ---- x402: cross-resource substitution (Context Binding violation) ----

#[test]
fn cross_resource_substitution_is_refused() {
    // Attack: a valid payment proof for resource A (same price) transplanted onto a
    // request for resource B. In x402 the signature binds only ⟨merchant, amount,
    // nonce⟩, not the resource — PayTP's merchant-signed quote binds BOTH the
    // resource and the nonce, so the transplant draws no delivery.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();

    let qa = merchant.build_baseline_quote(
        &rail,
        params([0x0A; 32], "https://api/resource-A", 1_000_000),
    );
    let json_a = String::from_utf8(qa.quote.to_json()).unwrap();
    let payment = prepare_split(&rail, &merchant, &qa.quote, [0xAA; 32]);

    // The honest A redemption succeeds first; from here on the canonical settlement ref is used.
    assert!(merchant
        .redeem_baseline(
            &json_a,
            "https://api/resource-A",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002
        )
        .is_ok());

    // The DIRECT context-binding attack: transplant the valid A quote + A payment
    // onto the resource-B endpoint. The merchant serves resource B, so it redeems
    // with `expected_resource = resource-B`; the signed quote says resource A, so
    // the F3.4 resource binding refuses it (`QuoteInvalid`) — the proof is bound to
    // its resource, unlike x402 where the signature ignores the resource id.
    assert_eq!(
        merchant.redeem_baseline(
            &json_a,
            "https://api/resource-B", // the endpoint the attacker replays to
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_003
        ),
        Err(RedeemError::QuoteInvalid)
    );

    // And a fresh equal-priced quote for B cannot be satisfied by A's payment
    // either: the canonical settlement ref is already bound to A's nonce in used_refs.
    let qb = merchant.build_baseline_quote(
        &rail,
        params([0x0B; 32], "https://api/resource-B", 1_000_000),
    );
    let json_b = String::from_utf8(qb.quote.to_json()).unwrap();
    assert_eq!(
        merchant.redeem_baseline(
            &json_b,
            "https://api/resource-B",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_004
        ),
        Err(RedeemError::Replayed)
    );
}

// ---- x402: duplicate-settlement race (Authorization Uniqueness violation) ----

#[test]
fn duplicate_settlement_race_consumes_the_nonce_exactly_once() {
    // Attack: concurrent requests exploit the verify↔settle race so one nonce yields
    // many deliveries. PayTP closes it with an atomic check-and-set BEFORE delivery.
    // Here N threads race the store's consume_nonce on ONE nonce; the delivery
    // (the build closure) MUST run exactly once, and every racer gets the same
    // receipt — no second charge, no second delivery.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let seed_store = InMemoryStore::new();
    let q = merchant.build_baseline_quote(&rail, params([0x0C; 32], "https://api/x", 1_000_000));
    let json = String::from_utf8(q.quote.to_json()).unwrap();
    let payment = prepare_split(&rail, &merchant, &q.quote, [0xAC; 32]);
    // One honest redemption to obtain a real receipt to hand the racing closure.
    let receipt = merchant
        .redeem_baseline(
            &json,
            "https://api/x",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &seed_store,
            1_000_000_002,
        )
        .unwrap();
    let pay_ref = rail
        .settle(payment.transfer.clone(), payment.settle_id)
        .expect("settle cache returns first ref");

    let store = InMemoryStore::new();
    let record = NonceRecord {
        payment_ref: pay_ref.0.clone(),
        idem: q.quote.idem.clone(),
        resource: "https://api/x".into(),
        quote_sig: q.quote.signature.unwrap(),
    };
    let deliveries = AtomicUsize::new(0);
    let nonce = [0x0C; 32];

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..32 {
            let store = &store;
            let record = &record;
            let receipt = &receipt;
            let deliveries = &deliveries;
            handles.push(scope.spawn(move || {
                store.consume_nonce(nonce, record, &mut || {
                    deliveries.fetch_add(1, Ordering::SeqCst); // the delivery side-effect
                    receipt.clone()
                })
            }));
        }
        for h in handles {
            assert!(
                h.join().unwrap().is_ok(),
                "every racer resolves to the one receipt"
            );
        }
    });

    // The whole point: 32 concurrent settlements delivered exactly once.
    assert_eq!(
        deliveries.load(Ordering::SeqCst),
        1,
        "exactly-once delivery under a 32-way race"
    );
}

/// A `MerchantStore` that counts how many times the delivery/receipt-build closure
/// actually runs — so the full-redeem race can assert the delivery happens exactly
/// once, not merely that the returned receipts are byte-identical.
struct CountingStore {
    inner: InMemoryStore,
    builds: AtomicUsize,
}
impl MerchantStore for CountingStore {
    fn peek(&self, nonce: [u8; 32], record: &NonceRecord) -> paytp_merchant::Peek {
        self.inner.peek(nonce, record)
    }
    fn consume_nonce(
        &self,
        nonce: [u8; 32],
        record: &NonceRecord,
        build: &mut dyn FnMut() -> paytp_core::tier0::Receipt,
    ) -> Result<paytp_core::tier0::Receipt, paytp_merchant::StoreError> {
        self.inner.consume_nonce(nonce, record, &mut || {
            self.builds.fetch_add(1, Ordering::SeqCst);
            build()
        })
    }
}

#[test]
fn duplicate_settlement_race_through_full_redeem_delivers_once() {
    // The end-to-end form: race the FULL `merchant.redeem_baseline` (not just the
    // store helper) 32 ways against a shared merchant/store/rail. Every racer must
    // resolve to the SAME receipt AND the delivery (receipt-build) closure must run
    // exactly once through the full redeem path — a counting store observes it.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = CountingStore {
        inner: InMemoryStore::new(),
        builds: AtomicUsize::new(0),
    };
    let q = merchant.build_baseline_quote(&rail, params([0x1C; 32], "https://api/x", 1_000_000));
    let json = String::from_utf8(q.quote.to_json()).unwrap();
    let payment = prepare_split(&rail, &merchant, &q.quote, [0xBC; 32]);

    let receipts: Vec<Vec<u8>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let (merchant, store, rail, json, payment) =
                    (&merchant, &store, &rail, &json, &payment);
                scope.spawn(move || {
                    merchant
                        .redeem_baseline(
                            json,
                            "https://api/x",
                            payment.transfer.clone(),
                            payment.settle_id,
                            rail,
                            store,
                            1_000_000_002,
                        )
                        .expect("each racer redeems idempotently")
                        .to_json()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // All 32 concurrent redemptions produced the byte-identical receipt...
    assert!(receipts.windows(2).all(|w| w[0] == w[1]));
    // ...the delivery (receipt build) ran EXACTLY ONCE through the full redeem
    // path (observed, not inferred)...
    assert_eq!(store.builds.load(Ordering::SeqCst), 1);
    // ...and the split moved exactly once (one payment), not 32×.
    assert_eq!(rail.balance("merchant-payout"), 990_000);
}

// ---- x402: leaked-token resubmission ----

#[test]
fn leaked_token_resubmission_is_refused() {
    // Attack: a captured payment authorization replayed. Replaying the SAME nonce
    // is an idempotent retry (one delivery); replaying the payment ref under a
    // FRESH nonce is refused (bound to the original nonce).
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let q = merchant.build_baseline_quote(&rail, params([0x0D; 32], "https://api/x", 1_000_000));
    let json = String::from_utf8(q.quote.to_json()).unwrap();
    let payment = prepare_split(&rail, &merchant, &q.quote, [0xAD; 32]);

    let r1 = merchant
        .redeem_baseline(
            &json,
            "https://api/x",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .unwrap();
    // Same nonce + ref → idempotent (identical receipt, no second charge).
    let r2 = merchant
        .redeem_baseline(
            &json,
            "https://api/x",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .unwrap();
    assert_eq!(r1.to_json(), r2.to_json());

    // The leaked ref replayed under a fresh quote/nonce → refused.
    let q2 = merchant.build_baseline_quote(&rail, params([0x0E; 32], "https://api/x", 1_000_000));
    let json2 = String::from_utf8(q2.quote.to_json()).unwrap();
    assert_eq!(
        merchant.redeem_baseline(
            &json2,
            "https://api/x",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_003
        ),
        Err(RedeemError::Replayed)
    );
}

// ---- x402: denial of settlement / deliver-before-settle ----

#[test]
fn delivery_requires_settlement_first() {
    // Attack: flood past a settlement rate-limit so the service delivers before the
    // payment finalizes. PayTP redeems (delivers) only after the payment reaches the
    // quoted finality — a not-yet-final payment is refused, so there is no
    // deliver-without-settle window.
    let rail = VirtualRail::new(5); // finality only after 5 ticks
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let q = merchant.build_baseline_quote(&rail, params([0x0F; 32], "https://api/x", 1_000_000));
    let json = String::from_utf8(q.quote.to_json()).unwrap();
    let payment = prepare_split(&rail, &merchant, &q.quote, [0xAF; 32]);
    // Not advanced to finality yet → redemption refused (no delivery).
    assert!(merchant
        .redeem_baseline(
            &json,
            "https://api/x",
            payment.transfer.clone(),
            payment.settle_id,
            &rail,
            &store,
            1_000_000_001
        )
        .is_err());
    // After finality, it delivers.
    rail.advance_clock(5);
    assert!(merchant
        .redeem_baseline(
            &json,
            "https://api/x",
            payment.transfer,
            payment.settle_id,
            &rail,
            &store,
            1_000_000_006
        )
        .is_ok());
}

// ---- x402: allowance overdraft — PayTP binds exact amounts, no "upto" ----

#[test]
fn underpayment_is_refused_no_upto_allowance() {
    // The allowance-overdraft class rides x402's "upto" dynamic-price allowances.
    // PayTP quotes an EXACT amount; a payment below it is not payment.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let q = merchant.build_baseline_quote(&rail, params([0x11; 32], "https://api/x", 1_000_000));
    let json = String::from_utf8(q.quote.to_json()).unwrap();
    let seed = q
        .quote
        .address_inputs(&merchant.key, ASSET, Some(merchant.payout.as_str()))
        .seed_split()
        .unwrap();
    let split = rail.derive_address(&seed);
    let under = Transfer {
        to: split,
        asset: ASSET.into(),
        amount: 999_999, // one micro-unit short
        kind: TransferKind::Payment,
        memo: None,
    };
    assert_eq!(
        merchant.redeem_baseline(
            &json,
            "https://api/x",
            under,
            [0xB1; 32],
            &rail,
            &store,
            1_000_000_002
        ),
        Err(RedeemError::PaymentUnverified)
    );
}

// ---- registry attacks (§5.4): rogue OS, invalid vector, stale snapshot ----

fn signed_snapshot(kind: Kind) -> Snapshot {
    let mut s = Snapshot {
        version: 5,
        kind,
        issued: 1_700_000_000,
        window_floor: 3,
        os_recipients: vec![
            ("apple".into(), "eip155:1:0xApple".into()),
            ("google".into(), "eip155:1:0xGoogle".into()),
        ],
        revoked: if kind == Kind::Revocation {
            vec![4]
        } else {
            vec![]
        },
        rate_sources: vec![("coinbase".into(), "https://api/rates".into())],
        sig: [0u8; 64],
    };
    s.sign(&[0x99; 32]).unwrap();
    s
}

#[test]
fn rogue_os_assertion_cannot_move_value_to_the_asserter() {
    // Attack: a false OS assertion to capture the 10 bp OS share. A rogue/unlisted
    // OS id resolves to the independent open-source fund fallback (§10.1),
    // NOT the asserter — the assertion can deny an OS its share but never redirect
    // value, and routing the fallback to a Foundation-independent fund keeps the
    // deny-to-enrich surface at zero.
    let mut store = SnapshotStore::new();
    store.insert(signed_snapshot(Kind::Rotation));
    // An unlisted (rogue) OS id → the independent open-source fund, not the attacker.
    assert_eq!(
        store
            .resolve_os_destination(5, Some("os.attacker.evil"))
            .unwrap(),
        INDEPENDENT_OS_FUND_DEST_PLACEHOLDER
    );
    // A listed OS resolves to its pinned canonical destination.
    assert_eq!(
        store.resolve_os_destination(5, Some("apple")).unwrap(),
        "eip155:1:0xApple"
    );
}

#[test]
fn invalid_meed_vector_is_refused() {
    // Attack: a malicious merchant serves a quote whose vector does not total 100 bp
    // / has wrong cardinality (skimming a role). The client validates the vector
    // before paying (§5.4) and MUST reject it. Built as a raw quote because an
    // honest merchant's builder never emits a non-conformant vector.
    let bad_vector = vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: IL_DEST.into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: DEV_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: WALLET_DEST.into(),
        },
        // role 0x13 (10 bp) omitted → totals 90 bp, cardinality wrong
    ];
    let q = Quote {
        v: "1".into(),
        resource: "https://api/x".into(),
        nonce: [0x21; 32],
        exp: 1_000_000_500,
        idem: b"idem".to_vec(),
        schema: 1,
        contract: 1,
        registry: 5,
        baseline: "eip155:8453".into(),
        grace: 300,
        retry: 600,
        vector: bad_vector,
        offers: vec![],
        signature: None,
    };
    // The governed validator's shape stage rejects the wrong cardinality before any registry
    // lookup, so an empty store suffices here (no context-free validator remains).
    assert!(q.validate_vector_governed(&SnapshotStore::new()).is_err());
}

#[test]
fn stale_or_revoked_registry_version_is_refused() {
    // Attack: get a wallet to accept a stale/revoked registry snapshot (e.g. one
    // with a since-revoked OS destination). A version outside the acceptance window
    // or in a revoked list is refused.
    let mut store = SnapshotStore::new();
    store.insert(signed_snapshot(Kind::Rotation)); // version 5, window_floor 3
                                                   // Below the window floor → not accepted.
    assert!(!store.version_accepted(2));
    assert!(store.resolve_os_destination(2, Some("apple")).is_err());
    // A revocation snapshot withdraws version 4.
    store.insert(signed_snapshot(Kind::Revocation));
    assert!(!store.version_accepted(4));
    assert!(store.resolve_os_destination(4, Some("apple")).is_err());
}

// ---- entry-machine attacks: nonce-desync, zero-contest-window ----

#[test]
fn nonce_desync_funds_an_orphan_the_merchant_never_quoted() {
    // Attack (nonce-desync, from M0's formal rules): a payer funds an entry the
    // merchant never quoted — a different amount/deadline derives a DIFFERENT
    // entry_id, so the merchant's re-derivation from its own quote never finds it,
    // and the honest entry is never dup-blocked.
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x31; 32]));
    // Fund with a DIFFERENT meed amount than the merchant quoted (a desync).
    let (_r, desynced_id) = rail
        .fund_entry(
            &tlq.instance_address,
            [0x31; 32],
            9_999, // merchant quoted 10_000
            "eip155:1:0xRefund".into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            "eip155:1/native".into(),
        )
        .unwrap();
    // The desynced funding lands a DIFFERENT id — never the merchant's quoted entry.
    assert_ne!(desynced_id, tlq.entry_id);
    // And it does NOT block the honest entry: the merchant's own quoted entry_id is
    // still fundable (the desync stranded only the attacker's own money, F4-c).
    let (_r2, honest_id) = rail
        .fund_entry(
            &tlq.instance_address,
            [0x31; 32],
            10_000, // the amount the merchant actually quoted
            "eip155:1:0xRefund".into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            "eip155:1/native".into(),
        )
        .expect("the honest entry is still fundable after the desync");
    assert_eq!(honest_id, tlq.entry_id);
}

fn fund_twoleg_meed(rail: &VirtualRail, tlq: &paytp_merchant::TwoLegQuote) -> RailRef {
    let (meed_ref, funded_id) = rail
        .fund_entry(
            &tlq.instance_address,
            tlq.quote.nonce,
            10_000,
            TWOLEG_REFUND.into(),
            tlq.t_open,
            tlq.t_lapse,
            600,
            TWOLEG_BASELINE_ASSET.into(),
        )
        .expect("fund meed entry");
    assert_eq!(funded_id, tlq.entry_id);
    meed_ref
}

fn submit_twoleg_net(
    rail: &VirtualRail,
    tlq: &paytp_merchant::TwoLegQuote,
    merchant_payout: &str,
) -> RailRef {
    rail.submit(Transfer {
        to: merchant_payout.to_string(),
        asset: TWOLEG_NET_ASSET.into(),
        amount: 990_000,
        kind: TransferKind::Payment,
        memo: Some(tlq.quote.nonce),
    })
    .expect("net leg")
}

fn wallet_funds_twoleg(
    rail: &VirtualRail,
    tlq: &paytp_merchant::TwoLegQuote,
    merchant_payout: &str,
) -> (RailRef, RailRef) {
    let meed_ref = fund_twoleg_meed(rail, tlq);
    rail.advance_clock(2);
    let net_ref = submit_twoleg_net(rail, tlq, merchant_payout);
    rail.advance_clock(2);
    (meed_ref, net_ref)
}

#[test]
fn two_leg_staple_attack_rejects_foreign_net_memo() {
    // Staple attack: the hostile IL funds only its cheap quote-B meed leg, then tries to
    // staple the victim's quote-A net leg to buy B. The net-leg memo check is load-bearing:
    // B requires nonce_B, while the victim net ref carries nonce_A.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let qa = merchant.build_two_leg_quote(&rail, twoleg_params([0x41; 32]));
    let qb = merchant.build_two_leg_quote(&rail, twoleg_params([0x42; 32]));
    let json_a = String::from_utf8(qa.quote.to_json()).unwrap();
    let json_b = String::from_utf8(qb.quote.to_json()).unwrap();

    let (meed_a, net_a) = wallet_funds_twoleg(&rail, &qa, &merchant.payout);
    let meed_b = fund_twoleg_meed(&rail, &qb);
    rail.advance_clock(2);

    assert_eq!(
        merchant.redeem_two_leg(
            &json_b,
            "https://api/premium",
            &meed_b,
            &net_a,
            &rail,
            &store,
            1_000_000_010,
        ),
        Err(RedeemError::PaymentUnverified),
        "twoleg.rs net-leg memo check is load-bearing for P3: nonce_A net cannot satisfy quote B"
    );

    let receipt_a = merchant
        .redeem_two_leg(
            &json_a,
            "https://api/premium",
            &meed_a,
            &net_a,
            &rail,
            &store,
            1_000_000_011,
        )
        .expect("the victim's honest quote still redeems once");
    assert_eq!(receipt_a.entry, Some(qa.entry_id));
    assert_eq!(
        merchant.redeem_two_leg(
            &json_b,
            "https://api/premium",
            &meed_b,
            &net_a,
            &rail,
            &store,
            1_000_000_012,
        ),
        Err(RedeemError::Replayed),
        "after A redeems, the independent net-ref dedup also bars B from consuming net_A"
    );
    assert_eq!(rail.balance("merchant-net-payout"), 990_000);
}

#[test]
fn two_leg_reusing_one_net_ref_across_combined_keys_is_replayed() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let qa = merchant.build_two_leg_quote(&rail, twoleg_params([0x43; 32]));
    let qb = merchant.build_two_leg_quote(&rail, twoleg_params([0x44; 32]));
    let json_a = String::from_utf8(qa.quote.to_json()).unwrap();
    let json_b = String::from_utf8(qb.quote.to_json()).unwrap();
    let (meed_a, net_a) = wallet_funds_twoleg(&rail, &qa, &merchant.payout);
    merchant
        .redeem_two_leg(
            &json_a,
            "https://api/premium",
            &meed_a,
            &net_a,
            &rail,
            &store,
            1_000_000_010,
        )
        .expect("first redemption consumes net_A");

    let meed_b = fund_twoleg_meed(&rail, &qb);
    rail.advance_clock(2);
    assert_eq!(
        merchant.redeem_two_leg(
            &json_b,
            "https://api/premium",
            &meed_b,
            &net_a,
            &rail,
            &store,
            1_000_000_011,
        ),
        Err(RedeemError::Replayed),
        "net_A is consumed independently of the combined meed|net key"
    );
}

#[test]
fn two_leg_same_split_redirect_attack_c_is_closed() {
    // Attack C on the secure two-leg: an in-path party cannot apply the victim's
    // funding for quote A to a different quote B. B derives a different entry id
    // and the victim net leg carries nonce_A, not nonce_B.
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let store = InMemoryStore::new();
    let qa = merchant.build_two_leg_quote(&rail, twoleg_params([0x45; 32]));
    let qb = merchant.build_two_leg_quote(&rail, twoleg_params([0x46; 32]));
    assert_ne!(qa.entry_id, qb.entry_id);
    let (meed_a, net_a) = wallet_funds_twoleg(&rail, &qa, &merchant.payout);
    let net_info = rail.ref_target(&net_a).unwrap();
    assert_eq!(net_info.memo, Some(qa.quote.nonce));
    assert_ne!(net_info.memo, Some(qb.quote.nonce));

    let json_a = String::from_utf8(qa.quote.to_json()).unwrap();
    let json_b = String::from_utf8(qb.quote.to_json()).unwrap();
    assert_eq!(
        merchant.redeem_two_leg(
            &json_b,
            "https://api/premium",
            &meed_a,
            &net_a,
            &rail,
            &store,
            1_000_000_010,
        ),
        Err(RedeemError::PaymentUnverified)
    );
    assert!(merchant
        .redeem_two_leg(
            &json_a,
            "https://api/premium",
            &meed_a,
            &net_a,
            &rail,
            &store,
            1_000_000_011,
        )
        .is_ok());
}

#[test]
fn compat_single_leg_same_split_redirect_residual() {
    // Compat single-leg is P1+P2, not P3: shipped x402 carries no quote nonce on-chain.
    // A hostile in-path party holding same-split quote B can first-consume the victim's
    // payment authorization for quote A. This is the documented residual: accounting is
    // safe (one settlement, one delivery, meed divides, merchant is paid), but the funding
    // payer's intended resource is not on-chain bound. Native two-leg is the closure.
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let qa = merchant.build_baseline_quote(
        &rail,
        params([0x47; 32], "https://api/resource-A", 1_000_000),
    );
    let qb = merchant.build_baseline_quote(
        &rail,
        params([0x48; 32], "https://api/resource-B", 1_000_000),
    );
    assert_eq!(qa.split_address, qb.split_address);
    let json_a = String::from_utf8(qa.quote.to_json()).unwrap();
    let json_b = String::from_utf8(qb.quote.to_json()).unwrap();
    let victim_payment = prepare_split(&rail, &merchant, &qa.quote, [0xC7; 32]);

    let delivered_b = merchant
        .redeem_baseline(
            &json_b,
            "https://api/resource-B",
            victim_payment.transfer.clone(),
            victim_payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .expect("compat residual: B can first-consume A's same-split payment");
    assert_eq!(delivered_b.resource, "https://api/resource-B");
    assert_eq!(
        merchant.redeem_baseline(
            &json_a,
            "https://api/resource-A",
            victim_payment.transfer,
            victim_payment.settle_id,
            &rail,
            &store,
            1_000_000_003,
        ),
        Err(RedeemError::Replayed),
        "the same settlement cannot buy a second delivery"
    );
    assert_eq!(rail.balance("merchant-payout"), 990_000);
    assert_eq!(rail.balance(IL_DEST), 5_000);
    assert_eq!(rail.balance(WALLET_DEST), 3_000);
    assert_eq!(rail.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER), 1_000);
    assert_eq!(rail.balance(DEV_FUND_DEST_PLACEHOLDER), 1_000);
}

#[test]
fn zero_contest_window_still_requires_a_full_tick_before_reclaim() {
    // Attack (zero-contest-window, from M0's formal rules): a contest = 0 entry so a
    // reclaim executes in the same instant it opens, racing the merchant's
    // attestation. The guard: execute_reclaim requires rail time STRICTLY greater
    // than T_exec (= opened_at + contest), so even contest 0 needs a full tick —
    // there is no same-instant reclaim.
    let seed = [0x42; 32];
    let mut inst = paytp_rail::MeedInstance::new(
        [0x55; 32],
        vec![
            paytp_rail::MeedShare {
                bp: 50,
                dest: "d1".into(),
            },
            paytp_rail::MeedShare {
                bp: 50,
                dest: "d2".into(),
            },
        ],
        seed,
    );
    let now = 1_000_000_000;
    let entry_id = inst
        .fund_entry(
            [0x33; 32],
            10_000,
            "refund".into(),
            now,
            now + 10_000,
            0,
            now,
        )
        .unwrap();
    inst.open_reclaim(entry_id, now).unwrap();
    // Same instant (now == opened_at, contest 0 → T_exec == now): NOT executable.
    assert!(inst.execute_reclaim(entry_id, now).is_err());
    // One tick later (now+1 > T_exec): executable.
    assert!(inst.execute_reclaim(entry_id, now + 1).is_ok());
}

fn twoleg_params<'a>(nonce: [u8; 32]) -> paytp_merchant::TwoLegParams<'a> {
    paytp_merchant::TwoLegParams {
        resource: "https://api/premium",
        nonce,
        exp: 1_000_000_500,
        idem: b"idem-2leg".to_vec(),
        registry_version: 5,
        net_network: "eip155:137",
        net_asset: TWOLEG_NET_ASSET,
        net_amount: 990_000,
        baseline_network: "eip155:1",
        baseline_asset: TWOLEG_BASELINE_ASSET,
        meed_amount: 10_000,
        rate: "1",
        rate_source: "coinbase-spot",
        reclaim: 3_600,
        contest: 600,
        grace: 300,
        retry: 600,
        fin_meed: "final",
        fin_net: "final",
        vector: schema01_vector(),
    }
}
