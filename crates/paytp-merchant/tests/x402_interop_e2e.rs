//! M6 — shipped-x402-**V1** interop, RI side (envelope + faithful mirror, F3-j).
//!
//! Proves the wire contract the milestone rests on, at the x402 **envelope**
//! level (not the raw `paytp` object the M1 baseline test used):
//!
//! - the merchant emits a **shipped x402 V1** `PaymentRequired` (`x402Version:1`,
//!   `accepts[]` with named `network` + `maxAmountRequired` + per-req `resource`,
//!   `extensions.paytp`);
//! - a **plain, PayTP-unaware** client parses `accepts[0]` and pays its `payTo`
//!   — which IS the split address — and the meed divides on-chain with no
//!   PayTP awareness;
//! - `accepts[0]` **equals** the mirror the merchant signed inside the `paytp`
//!   object (F3-a), so a **PayTP-aware** client re-verifies the signature,
//!   re-derives the split, confirms `payTo`, pays, and redeems a receipt;
//! - a proxy that rewrites `accepts[0].payTo` in the envelope (leaving the signed
//!   mirror intact) is **detected** by a PayTP-aware client (mirror inequality),
//!   which refuses PayTP execution (F3-a).
//!
//! The confirmation against the *actual* `x402@1.2.0` library (real zod schema +
//! `selectPaymentRequirements`) is the `interop/x402/` Node harness; this test
//! pins the RI's own emission and consumption.

use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::tier0::quote::{MeedEntry, Quote};
use paytp_core::x402::{PaymentRequired, PaymentRequirements};
use paytp_merchant::{BaselineParams, InMemoryStore, Merchant};
use paytp_rail::{RailAdapter, Transfer, TransferKind, VirtualRail};

const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";
const RESOURCE: &str = "https://api.example/data";
const ASSET: &str = "eip155:1/native";

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

fn params<'a>(nonce: [u8; 32], amount: u128) -> BaselineParams<'a> {
    BaselineParams {
        resource: RESOURCE,
        nonce,
        exp: 1_000_000_500,
        idem: b"idem-1".to_vec(),
        registry_version: 5,
        baseline_network: "eip155:8453", // CAIP-2; emitted as the x402 name "base"
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

/// Emit and re-parse the merchant's shipped-x402-V1 `PaymentRequired`.
fn merchant_402(
    rail: &VirtualRail,
    merchant: &Merchant,
    nonce: [u8; 32],
) -> (PaymentRequired, String) {
    let bq = merchant.build_baseline_quote(rail, params(nonce, 1_000_000));
    let pr = bq.to_payment_required();
    let json = String::from_utf8(pr.to_json()).unwrap();
    // Round-trips through the shipped-V1 parse (version + shape invariants).
    let parsed = PaymentRequired::parse(&json).unwrap();
    (parsed, json)
}

#[test]
fn emitted_402_is_shipped_v1_shape() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let (pr, json) = merchant_402(&rail, &merchant, [0x01; 32]);

    assert!(json.contains("\"x402Version\":1"));
    assert_eq!(pr.x402_version, 1);
    assert!(pr.resource.is_none()); // resource is per-requirement in V1
    assert_eq!(pr.accepts.len(), 1);
    let a = &pr.accepts[0];
    assert_eq!(a.scheme, "exact");
    assert_eq!(a.network, "base"); // x402 named network for eip155:8453 (F3-j)
    assert_eq!(a.asset, ASSET);
    assert_eq!(a.max_amount_required, "1000000");
    assert_eq!(a.resource, RESOURCE); // bound to the signed quote's resource
    assert_eq!(a.max_timeout_seconds, 60);
    // A PayTP extension is present with info + schema.
    assert!(pr.paytp_info_json().is_some());
}

#[test]
fn plain_x402_client_pays_the_split_and_meed_divides() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let (pr, _json) = merchant_402(&rail, &merchant, [0x02; 32]);

    // A PLAIN client knows nothing of PayTP: it reads accepts[0] and pays payTo.
    let a = &pr.accepts[0];
    let amount: u128 = a.max_amount_required.parse().unwrap();
    rail.submit(Transfer {
        to: a.pay_to.clone(),
        asset: a.asset.clone(),
        amount,
        kind: TransferKind::Payment,
        // A plain x402 client can pay the split without PayTP awareness; here the split
        // simply divides on receipt.
        memo: None,
    })
    .expect("plain payment");
    rail.advance_clock(2);

    // The meed divided on-chain (99% merchant / 1% meed) with no PayTP
    // awareness on the client side — the USP.
    assert_eq!(rail.balance("merchant-payout"), 990_000);
    assert_eq!(rail.balance(IL_DEST), 5_000);
    assert_eq!(rail.balance(WALLET_DEST), 3_000);
    // 0x11 OS → independent OS fund; 0x13 Dev Fund → Dev Fund (distinct seats).
    assert_eq!(rail.balance(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER), 1_000);
    assert_eq!(rail.balance(DEV_FUND_DEST_PLACEHOLDER), 1_000);
}

#[test]
fn accepts_entry_equals_the_signed_mirror() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let (pr, _json) = merchant_402(&rail, &merchant, [0x03; 32]);

    // Extract the signed paytp object and re-verify the merchant signature.
    let info = pr.paytp_info_json().unwrap();
    let quote = Quote::parse_verify(&info, &merchant.key).unwrap();
    let offer = quote.offers.iter().find(|o| o.two_leg.is_none()).unwrap();

    // The outer accepts[0] equals the mirror the merchant SIGNED (F3-a): nothing
    // outside the signature can change which option a conformant client completes
    // as a PayTP payment or where it goes.
    let mirror = PaymentRequirements::from_strict(&offer.accept).unwrap();
    assert_eq!(mirror, pr.accepts[0]);
}

#[test]
fn paytp_aware_client_verifies_rederives_and_redeems() {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();
    let (pr, _json) = merchant_402(&rail, &merchant, [0x04; 32]);

    // Verify the merchant signature over the presented paytp object (F3.4).
    let info = pr.paytp_info_json().unwrap();
    let quote = Quote::parse_verify(&info, &merchant.key).unwrap();

    // F3-a via the library primitive: the client executes ONLY an accepts entry
    // a signed offer mirrors, and pays the **signed** terms — never the outer
    // entry's (which a proxy could have rewritten).
    let mirrored = pr.paytp_mirrored_accepts(&quote);
    let (idx, offer) = mirrored
        .iter()
        .copied()
        .find(|(_, o)| o.two_leg.is_none())
        .expect("a baseline offer mirrors accepts[0]");
    assert_eq!(idx, 0);
    let signed = PaymentRequirements::from_strict(&offer.accept).unwrap();

    // Re-derive the split from the SIGNED quote and refuse on payTo mismatch (
    // the split commits the offer's signed net destination `merchantNet`).
    let seed = quote
        .address_inputs(&merchant.key, ASSET, offer.merchant_net.as_deref())
        .seed_split()
        .unwrap();
    assert_eq!(rail.derive_address(&seed), signed.pay_to);

    // Prepare the SIGNED terms for the merchant to settle (Design A). No baseline
    // memo is required; the merchant binds the settled ref through its durable store.
    let amount: u128 = signed.max_amount_required.parse().unwrap();
    let transfer = Transfer {
        to: signed.pay_to.clone(),
        asset: signed.asset.clone(),
        amount,
        kind: TransferKind::Payment,
        memo: None,
    };

    // Present the signed paytp object back (F3.4) and redeem a receipt.
    let receipt = merchant
        .redeem_baseline(
            &info,
            RESOURCE,
            transfer,
            [0x44; 32],
            &rail,
            &store,
            1_000_000_003,
        )
        .expect("redeem");
    let rj = String::from_utf8(receipt.to_json()).unwrap();
    let verified = paytp_core::tier0::Receipt::parse_verify(&rj, &merchant.key).unwrap();
    assert_eq!(verified.nonce, [0x04; 32]);
}

/// Any envelope-only rewrite of a mirrored member (the signed `paytp` object
/// intact) makes the F3-a primitive exclude the entry — the conformant client
/// applies no PayTP execution to it (§F3-a). Covers `payTo`, `amount`, `asset`,
/// `network`, `maxTimeoutSeconds`, and `extra`.
#[test]
fn envelope_rewrite_of_any_mirrored_member_is_refused() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let (pr, _json) = merchant_402(&rail, &merchant, [0x05; 32]);
    let info = pr.paytp_info_json().unwrap();
    let quote = Quote::parse_verify(&info, &merchant.key).unwrap();
    // Untampered: exactly the baseline entry is mirrored.
    assert_eq!(pr.paytp_mirrored_accepts(&quote).len(), 1);

    // A rewrite of ANY mirrored member (signed paytp object intact) is refused.
    let refused = |mutate: &dyn Fn(&mut PaymentRequirements)| {
        let mut t = pr.clone();
        mutate(&mut t.accepts[0]);
        t.paytp_mirrored_accepts(&quote).is_empty()
    };
    let mut evil_extra = serde_json::Map::new();
    evil_extra.insert("feePayer".into(), serde_json::json!("0xEVIL"));
    assert!(refused(&|a| a.pay_to = "eip155:1:0xATTACKER".into()));
    assert!(refused(&|a| a.max_amount_required = "10000000".into()));
    assert!(refused(&|a| a.asset = "eip155:1/evil".into()));
    assert!(refused(&|a| a.network = "eip155:137".into()));
    assert!(refused(&|a| a.max_timeout_seconds = 1));
    assert!(refused(&|a| a.extra = Some(evil_extra.clone())));
    // The signed mirror still names the true split, whatever the envelope says.
    let signed = PaymentRequirements::from_strict(
        &quote
            .offers
            .iter()
            .find(|o| o.two_leg.is_none())
            .unwrap()
            .accept,
    )
    .unwrap();
    assert_ne!(signed.pay_to, "eip155:1:0xATTACKER");
}

/// Substituting `extensions.paytp.info` with a **different** validly-signed
/// quote (same merchant) does not let an attacker redirect PayTP execution: the
/// substituted quote's offer mirrors ITS accept, not the envelope's `accepts[0]`.
#[test]
fn substituted_valid_quote_does_not_match_envelope_accepts() {
    let rail = VirtualRail::new(2);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    // The envelope the client received (amount 1_000_000).
    let (pr, _j) = merchant_402(&rail, &merchant, [0x06; 32]);
    // A different, cheaper quote the same merchant signed (amount 10, other split).
    let cheap = merchant.build_baseline_quote(&rail, params([0x07; 32], 10));
    let other = Quote::parse_verify(
        std::str::from_utf8(&cheap.quote.to_json()).unwrap(),
        &merchant.key,
    )
    .unwrap();
    // The substituted quote is validly signed but mirrors none of THIS envelope's
    // accepts (different amount/split) → F3-a excludes everything.
    assert!(pr.paytp_mirrored_accepts(&other).is_empty());
}
