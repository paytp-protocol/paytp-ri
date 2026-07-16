//! F10.6 conformance fixtures — the machine-checkable wallet obligations for §7.2/§11.1 spending
//! policy, §10.3 path selection, and §10.3/§10.4/§7.2 interface-presence.
//! Each fixture pins the spec's directional assertion (`spec/formal/10-conformance-vectors.md`
//! F10.6:48-52); the concrete fixture values stand in for the harness the spec says pins them.
//!
//! What is NOT here — the **attestation-only** obligations (F10.6:52, and the adequacy/genuineness
//! caveats of :49/:51): §10.3 neutral presentation, the adequacy of user-facing disclosure, and
//! genuine market substitutability. No wire/API test can decide them; they are documented in
//! `conformance/COVERAGE.md` for certification review, deliberately not machine-tested here.
//!
//! Pluggability (§10.4) is COVERED by the two-wallet substitution test
//! (`paytp-client/tests/substitution.rs::two_distinct_wallets_drive_the_same_flow_through_the_same_interface`);
//! it is pointed at from COVERAGE.md rather than duplicated.

use paytp_core::channel::VectorEntry;
use paytp_wallet::channel::ChannelOpenParams;
use paytp_wallet::{
    ChannelClient, ChannelClientError, Clock, Custody, Decision, OfferPath, PathCandidate,
    PayerChannelTrust, RateSource, SelectReason, StaticPolicy, Wallet, WalletPolicy,
};

const ASSET: &str = "solana:dev/usdc";

/// A fixed clock — none of these fixtures exercise the `TH_TIME` deadline.
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        1_700_000_000
    }
}
static FIXED_CLOCK: FixedClock = FixedClock;

/// The schema-0x01 meed vector (IL 50 / OS 10 / Wallet 30 / Dev 10 = 100 bp).
fn vector() -> Vec<VectorEntry> {
    vec![
        VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "solana:dev:il".into(),
        },
        VectorEntry {
            role: 0x11,
            bp: 10,
            // Absent/unlisted OS → the independent open-source fund (§10.1/F9.4 step 2).
            dest: paytp_core::consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        VectorEntry {
            role: 0x12,
            bp: 30,
            dest: "solana:dev:wallet".into(),
        },
        VectorEntry {
            role: 0x13,
            bp: 10,
            dest: paytp_core::consts::DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

fn postpay_params(limit_l: u128) -> ChannelOpenParams {
    ChannelOpenParams {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        denom: ASSET.into(),
        baseline_asset: ASSET.into(),
        baseline_net: "solana:dev".into(),
        prepay: false,
        limit_l,
        limit_e: 500_000,
        th_value: 0,
        th_time: 3600,
        schema: 1,
        contract: 1,
        registry_v: 5,
        vector: vector(),
        refund_ptr: None, // postpay carries no REFUND_PTR
        rate_source: None,
        rate_dev: None,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        timestamp: 1_700_000_000,
    }
}

// ============================ §7.2/§11.1 spending-policy (F10.6:48) ============================
// "Given a configured budget/threshold/consent policy, the wallet refuses a payment (a slice, a
// Tier 0 leg) that would exceed it and admits one within it." — over-limit refuse / at-limit admit.

#[test]
fn f10_6_spending_policy_slice_at_limit_admitted_over_limit_refused() {
    let mut policy = StaticPolicy::new(ASSET, 1_000_000);
    policy.per_slice_limit = 50_000;
    // At the limit → admit; one µ-unit over → refuse.
    assert_eq!(policy.approve_slice([0; 8], 50_000), Decision::Approve);
    assert!(matches!(
        policy.approve_slice([0; 8], 50_001),
        Decision::Deny(_)
    ));
}

#[test]
fn f10_6_spending_policy_tier0_quote_at_budget_admitted_over_budget_refused() {
    let policy = StaticPolicy::new(ASSET, 1_000_000);
    let q = quote_stub();
    assert_eq!(
        policy.approve_quote(&q, 1_000_000, ASSET),
        Decision::Approve
    );
    assert!(matches!(
        policy.approve_quote(&q, 1_000_001, ASSET),
        Decision::Deny(_)
    ));
    // A non-allowlisted asset is refused regardless of amount (consent/allowlist gate).
    assert!(matches!(
        policy.approve_quote(&q, 1, "solana:dev/other"),
        Decision::Deny(_)
    ));
}

#[test]
fn f10_6_spending_policy_channel_open_at_budget_admitted_over_budget_refused() {
    use paytp_wallet::ChannelTerms;
    let policy = StaticPolicy::new(ASSET, 1_000_000);
    let at = ChannelTerms {
        denom: ASSET.into(),
        limit_l: 1_000_000,
        limit_e: 100_000,
        th_value: 0,
        th_time: 3600,
        prepay: false,
    };
    assert_eq!(policy.approve_channel(&at), Decision::Approve);
    let over = ChannelTerms {
        limit_l: 1_000_001,
        ..at
    };
    assert!(matches!(policy.approve_channel(&over), Decision::Deny(_)));
}

#[test]
fn f10_6_spending_policy_postpay_flow_bound_is_l_credit() {
    // The §7.2/§11.1 fixture EXTENDED with Part A's cumulative flow bound: a postpay channel admits
    // streamed value up to `L_credit` (the exact bound) and refuses the µ-unit past it — the wallet
    // independently caps the payer's outstanding liability regardless of the untrusted IL.
    let custody = Custody::from_root(&[9u8; 32]);
    // Production `open` (integration crate has no `cfg(test)` `open_with_secret`); the flow bound is
    // independent of the CSPRNG-generated session secret / channel id.
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        paytp_core::crypto::ed25519_public(&[0x55; 32]),
        "merchant.example.com",
        [0x07; 32],
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("solana:dev:wallet");
    let (_open, mut ch) = ChannelClient::open(
        &trust,
        &FIXED_CLOCK,
        StaticPolicy::new(ASSET, 10_000_000),
        &postpay_params(1_000_000),
        paytp_core::registry::SnapshotStore::empty_ref(),
    )
    .expect("postpay open");
    assert!(ch.next_slice(600_000).is_ok(), "within L_credit");
    assert!(ch.next_slice(400_000).is_ok(), "exactly at L_credit");
    assert_eq!(
        ch.next_slice(1),
        Err(ChannelClientError::WindowExceeded),
        "one µ-unit past L_credit is refused (Part A flow bound)"
    );
}

// ============================ §10.3 total-cost comparison (F10.6:50) ============================
// "Among offered paths the software selects one of minimum payer total cost … unless an explicit
// policy fixture authorizes the costlier path; any surfaced costlier alternative discloses the delta."

#[test]
fn f10_6_total_cost_selects_the_cost_minimal_path() {
    // Two offered paths with pinned payer-total costs; the meed-MAXIMAL path (higher earned share)
    // is the COSTLIER one. With no operator preference the wallet serves the payer: cost-minimal.
    let candidates = [
        PathCandidate {
            id: 0,
            cost: 1_200,
            meed_share_bp: 30,
        }, // PayTP path — costlier, earns more
        PathCandidate {
            id: 1,
            cost: 1_000,
            meed_share_bp: 0,
        }, // plain path — cheaper, earns nothing
    ];
    let sel = StaticPolicy::new(ASSET, 1)
        .select_path(&candidates)
        .expect("a path");
    assert_eq!(
        sel.chosen, 1,
        "the cost-minimal path is selected, not the meed-maximal one"
    );
    assert_eq!(sel.cost, 1_000);
    assert_eq!(sel.cost_minimal, 1_000);
    assert_eq!(sel.cost_delta, 0);
    assert_eq!(sel.reason, SelectReason::CostMinimal);
    assert_eq!(
        sel.meed_share_bp, 0,
        "disclosed earned share of the CHOSEN path"
    );
}

#[test]
fn f10_6_total_cost_operator_authorized_costlier_path_discloses_the_delta() {
    // An explicit operator policy authorizes the costlier (PayTP) path; the wallet selects it AND
    // discloses the payer delta over the cost-minimal one (§10.3: legitimate only under policy, and
    // the delta is disclosed).
    let candidates = [
        PathCandidate {
            id: 0,
            cost: 1_200,
            meed_share_bp: 30,
        },
        PathCandidate {
            id: 1,
            cost: 1_000,
            meed_share_bp: 0,
        },
    ];
    let policy = StaticPolicy::new(ASSET, 1).with_authorized_costlier(0);
    let sel = policy.select_path(&candidates).expect("a path");
    assert_eq!(
        sel.chosen, 0,
        "the operator-authorized costlier path is selected"
    );
    assert_eq!(sel.cost, 1_200);
    assert_eq!(sel.cost_minimal, 1_000);
    assert_eq!(
        sel.cost_delta, 200,
        "the payer delta over cost-minimal is disclosed"
    );
    assert_eq!(sel.reason, SelectReason::OperatorAuthorizedCostlier);
    assert_eq!(
        sel.meed_share_bp, 30,
        "the earned share of the chosen path is disclosed"
    );
}

// ==================== §10.3 honor operator policy over own meed (F10.6:49) ====================
// "Given an operator policy that excludes or deprioritizes a path, the software does not select that
// path even where it earns the software more meed."

#[test]
fn f10_6_honor_operator_policy_excludes_the_meed_maximal_path() {
    // Path 0 is BOTH the cheapest AND the meed-maximal — absent policy the wallet would pick it. The
    // operator EXCLUDES it; the wallet must then pick the other path even though it forgoes both the
    // lower cost and the higher meed. (Serving the payer is the default; an operator override wins.)
    let candidates = [
        PathCandidate {
            id: 0,
            cost: 1_000,
            meed_share_bp: 30,
        }, // cheapest AND meed-maximal
        PathCandidate {
            id: 1,
            cost: 1_100,
            meed_share_bp: 0,
        },
    ];
    // Sanity: without the exclusion the wallet picks the meed-maximal path 0 (it is also cheapest).
    let base = StaticPolicy::new(ASSET, 1);
    assert_eq!(base.select_path(&candidates).unwrap().chosen, 0);
    // With the operator exclusion of path 0, selection respects the policy → path 1.
    let policy = StaticPolicy::new(ASSET, 1).with_excluded_paths([0]);
    let sel = policy.select_path(&candidates).expect("a path");
    assert_eq!(
        sel.chosen, 1,
        "the operator-excluded meed-maximal path is not selected"
    );
    assert_eq!(sel.meed_share_bp, 0);
}

#[test]
fn f10_6_selection_is_none_when_every_path_is_excluded() {
    let candidates = [PathCandidate {
        id: 0,
        cost: 1,
        meed_share_bp: 0,
    }];
    let policy = StaticPolicy::new(ASSET, 1).with_excluded_paths([0]);
    assert!(
        policy.select_path(&candidates).is_none(),
        "no selectable path → None"
    );
    assert!(
        StaticPolicy::new(ASSET, 1).select_path(&[]).is_none(),
        "empty offer set → None"
    );
}

// ==================== §10.3 trust boundary — the selector build's core property ====================
// The cost inputs come from a TRUSTED source the wallet reads; the untrusted interaction layer has no
// channel to inject them. So an IL that would spoof a path cheap to steer the wallet into its own
// meed-maximal choice cannot: the wallet computes cost from its own rate source, not any IL figure.

struct TrustedRates; // the wallet's real oracle: the PayTP path (0) is genuinely expensive to settle
impl RateSource for TrustedRates {
    fn path_cost(&self, id: u32) -> u128 {
        match id {
            0 => 900, // rail/gas for the PayTP path
            _ => 0,
        }
    }
}
struct IlSpoofedRates; // what a hostile IL WOULD assert to steer the wallet to its meed-maximal path
impl RateSource for IlSpoofedRates {
    fn path_cost(&self, id: u32) -> u128 {
        match id {
            0 => 0, // "the PayTP path is free!" — a lie
            _ => 900,
        }
    }
}

#[test]
fn f10_6_spoofed_il_cost_cannot_steer_selection() {
    let custody = Custody::from_root(&[9u8; 32]);
    let wallet = Wallet::new(&custody, StaticPolicy::new(ASSET, 1));
    // Two signed offers: path 0 (PayTP, earns 30 bp) and path 1 (plain, earns 0). Signed prices equal.
    let offers = [
        OfferPath {
            id: 0,
            price: 100,
            meed_share_bp: 30,
        },
        OfferPath {
            id: 1,
            price: 100,
            meed_share_bp: 0,
        },
    ];
    // With the wallet's TRUSTED rates, path 0 costs 100+900=1000, path 1 costs 100+0=100 → path 1.
    let sel = wallet.select_path(&offers, &TrustedRates).expect("a path");
    assert_eq!(
        sel.chosen, 1,
        "the truly cost-minimal (plain) path wins under trusted rates"
    );
    assert_eq!(
        sel.meed_share_bp, 0,
        "the wallet forgoes its own 30 bp meed to serve the payer"
    );

    // Demonstrate the steering the trust boundary PREVENTS: had the wallet computed on the IL's
    // spoofed rates, path 0 (the IL's meed-maximal choice) would have won. The security property is
    // that the wallet's selection surface only ever reads the trusted source — the IL is not a party
    // to this call and has no argument through which to supply a cost.
    let steered = wallet
        .select_path(&offers, &IlSpoofedRates)
        .expect("a path");
    assert_eq!(
        steered.chosen, 0,
        "IL-supplied costs WOULD steer — which is exactly why they are never wired"
    );
}

// ==================== interface-presence: meed-share disclosure (F10.6:51) ====================
// "The software exposes the meed share it earns for a selected path (derivable from the signed
// MEED_VECTOR)." The wallet role under schema 0x01 earns 30 bp (role 0x12).

#[test]
fn f10_6_meed_share_disclosure_is_present_on_the_selection() {
    // The wallet's earned share under schema 0x01 is role 0x12 = 30 bp (see `vector()`); a selection
    // of a PayTP path surfaces that share, and a plain path surfaces 0 — the disclosure is present and
    // reflects the chosen path.
    let wallet_share_bp = vector()
        .iter()
        .find(|v| v.role == 0x12)
        .map(|v| v.bp)
        .unwrap();
    assert_eq!(wallet_share_bp, 30);
    let candidates = [
        PathCandidate {
            id: 0,
            cost: 1_000,
            meed_share_bp: wallet_share_bp,
        },
        PathCandidate {
            id: 1,
            cost: 2_000,
            meed_share_bp: 0,
        },
    ];
    let sel = StaticPolicy::new(ASSET, 1)
        .select_path(&candidates)
        .expect("a path");
    assert_eq!(
        sel.meed_share_bp, 30,
        "the earned share of the chosen PayTP path is disclosed"
    );
}

/// Build a minimal signed Tier-0 quote stub for the policy-gate fixtures (the amount/asset are passed
/// explicitly to `approve_quote`, so the quote body is a placeholder).
fn quote_stub() -> paytp_core::tier0::quote::Quote {
    paytp_core::tier0::quote::Quote {
        v: "1".into(),
        resource: "https://x/y".into(),
        nonce: [1; 32],
        exp: 0,
        idem: vec![],
        schema: 1,
        contract: 1,
        registry: 5,
        baseline: "solana:dev".into(),
        grace: 0,
        retry: 0,
        vector: vec![],
        offers: vec![],
        signature: None,
    }
}
