//! M7 wallet-substitution integration test (§10.4).
//!
//! "The interop proof, without which M5 is a monolith, not a protocol." A second,
//! genuinely different `WalletPolicy` implementation drives the **same** flows
//! through the **same** interfaces (the `WalletPolicy` trait, the `Client`), against
//! the same merchant. Both complete an identical purchase — proving the wallet is
//! substitutable by construction and the interaction layer selects it externally
//! (§10.4: "an interaction layer MUST allow the operator to select an external
//! wallet").
//!
//! The file also gives `paytp-wallet`'s `execute`/`channel` modules their first
//! end-to-end exercise: the F4.5 meed-first-means-final guard, channel slice
//! gating + the F6.5 halt, and reclaim automation.

use std::cell::Cell;

use num_bigint::BigUint;
use paytp_client::{Client, InteractionLayer, OriginContext, PayerWallet};
use paytp_core::channel::establish::{AcceptedBinding, BindingArtifact};
use paytp_core::channel::settle_msg::PrepayDrawCompleted;
use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::registry::SnapshotStore;
use paytp_core::tier0::quote::{MeedEntry, Quote};
use paytp_merchant::{BaselineParams, InMemoryStore, Merchant, TwoLegParams};
use paytp_rail::{RailAdapter, Transfer, TransferKind, VirtualRail};
use paytp_wallet::channel::{ChannelClient, ChannelOpenParams};
use paytp_wallet::policy::{ChannelTerms, Decision, HaltOrContinue};
use paytp_wallet::{
    BaselinePayment, Clock, Custody, PayerChannelTrust, PayerScope, StaticPolicy, Wallet,
    WalletPolicy,
};

/// A fixed wallet clock for these substitution/policy tests — none exercise the `TH_TIME`
/// deadline, so a constant time keeps them deterministic (the trigger never spuriously fires).
struct TestClock;
impl Clock for TestClock {
    fn now(&self) -> u64 {
        1_700_000_000
    }
}
static TEST_CLOCK: TestClock = TestClock;

const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";
const ASSET: &str = "eip155:1/native";
const RESOURCE: &str = "https://api.example/data";
/// The resource the two-leg quotes (`twoleg_params`) are issued for.
const TWO_LEG_RESOURCE: &str = "https://api.example/premium";
const ORIGIN_HOST: &str = "api.example";
const ORIGIN_CERT: [u8; 32] = [0xC3; 32];
const ORIGIN_NOW: u64 = 1_700_000_000;

fn origin_artifact(sk: [u8; 32]) -> Vec<u8> {
    let mut art = BindingArtifact {
        host: ORIGIN_HOST.into(),
        cert_hash: ORIGIN_CERT,
        enc_key: [0xE5; 32],
        not_before: 0,
        not_after: (1u64 << 53) - 1,
        sig: None,
    };
    art.sign(&sk).unwrap();
    art.encode().unwrap()
}

fn binding_for(merchant: &Merchant) -> AcceptedBinding {
    AcceptedBinding::for_test(merchant.key, ORIGIN_HOST, [0xE5; 32])
}

#[allow(clippy::too_many_arguments)]
fn client_pay_baseline(
    client: &Client,
    wallet: &dyn PayerWallet,
    rail: &VirtualRail,
    quote_json: &str,
    accept: &paytp_core::x402::PaymentRequirements,
    merchant: &Merchant,
    requested_resource: &str,
) -> Result<BaselinePayment, paytp_client::ClientError> {
    let artifact = origin_artifact([0x55; 32]);
    client.pay_baseline(
        wallet,
        rail,
        quote_json,
        accept,
        OriginContext {
            candidate_merchant_key: &merchant.key,
            artifact_bytes: &artifact,
            conn_cert_hash: &ORIGIN_CERT,
            conn_host: ORIGIN_HOST,
            now: ORIGIN_NOW,
        },
        requested_resource,
    )
}

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

fn baseline_params<'a>(nonce: [u8; 32], amount: u128) -> BaselineParams<'a> {
    BaselineParams {
        resource: RESOURCE,
        nonce,
        exp: 1_000_000_500,
        idem: b"idem".to_vec(),
        registry_version: 5,
        baseline_network: "eip155:8453", // a baseline offer's network MUST map to an x402 name (F3-j)
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

/// A SECOND wallet policy, genuinely distinct from `StaticPolicy`: a *stateful*
/// running-budget ledger (interior-mutable), debiting on each approval. Same
/// conformant halt; different budget mechanism — exactly the substitution the
/// trait must admit.
struct LedgerPolicy {
    asset: String,
    remaining: Cell<u128>,
}

impl WalletPolicy for LedgerPolicy {
    fn approve_quote(
        &self,
        _q: &paytp_core::tier0::quote::Quote,
        amount: u128,
        asset: &str,
    ) -> Decision {
        if asset != self.asset {
            return Decision::Deny("ledger: wrong asset");
        }
        if amount > self.remaining.get() {
            return Decision::Deny("ledger: budget exhausted");
        }
        self.remaining.set(self.remaining.get() - amount);
        Decision::Approve
    }
    fn approve_channel(&self, terms: &ChannelTerms) -> Decision {
        if terms.limit_l > self.remaining.get() {
            return Decision::Deny("ledger: channel over budget");
        }
        Decision::Approve
    }
    fn approve_slice(&self, _ch: [u8; 8], _amt: u64) -> Decision {
        Decision::Approve
    }
    fn on_overdue_meed(&self, _ch: [u8; 8]) -> HaltOrContinue {
        HaltOrContinue::Halt // conformant, like StaticPolicy
    }
}

/// A SECOND, wholly independent wallet — a different *type* (not the reference
/// `paytp_wallet::Wallet`), implementing the `PayerWallet` boundary with its own
/// minimal logic (its own key, its own split re-derivation). Substituting this for
/// the reference wallet through the same `Client` is the §10.4 external-wallet
/// selection proof: the IL selects between two distinct wallet implementations.
struct DirectWallet {
    signing_key: [u8; 32],
}

impl PayerWallet for DirectWallet {
    // This minimal independent wallet is the §10.4 SUBSTITUTABILITY proof (two
    // distinct wallet types behind one trait), not the F1-f unlinkability proof, so it
    // custodies one key and ignores the merchant scope. The reference wallet's scoped
    // derivation is exercised in `paytp-wallet` custody + channel tests.
    fn payer_key(&self, _scope: &PayerScope) -> [u8; 32] {
        paytp_core::crypto::ed25519_public(&self.signing_key)
    }
    fn accept_origin(
        &self,
        candidate_merchant_key: &[u8; 32],
        artifact_bytes: &[u8],
        conn_cert_hash: &[u8; 32],
        conn_host: &str,
        now: u64,
    ) -> Result<AcceptedBinding, String> {
        let artifact =
            BindingArtifact::parse(artifact_bytes).map_err(|_| "bad artifact".to_string())?;
        artifact
            .accept(candidate_merchant_key, conn_cert_hash, conn_host, now)
            .map_err(|_| "origin binding failed".to_string())
    }
    fn pay_baseline_quote(
        &self,
        rail: &VirtualRail,
        quote_json: &str,
        accept: &paytp_core::x402::PaymentRequirements,
        binding: &AcceptedBinding,
        requested_resource: &str,
    ) -> Result<BaselinePayment, String> {
        let merchant_key = binding.merchant_key();
        // Independent wallet: verify the merchant signature itself over the bytes.
        let quote = Quote::parse_verify(quote_json, merchant_key)
            .map_err(|_| "unverified quote".to_string())?;
        // ...and bind the operator-requested resource itself (F3.4) — the boundary
        // contract every conformant wallet enforces, not just the reference one.
        if quote.resource != requested_resource {
            return Err("resource mismatch".to_string());
        }
        quote
            .validate_tier0(SnapshotStore::empty_ref())
            .map_err(|_| "quote invalid".to_string())?;
        // F3-a mirror rule (the boundary contract every conformant wallet enforces):
        // apply PayTP execution only to a signed baseline offer that mirrors the outer
        // `accept` the operator approved — refusing a substituted same-resource quote.
        let offer = quote
            .offers
            .iter()
            .find(|o| {
                o.two_leg.is_none()
                    && paytp_core::x402::PaymentRequirements::from_strict(&o.accept)
                        .map(|m| &m == accept)
                        .unwrap_or(false)
            })
            .ok_or("no signed offer mirrors the approved accept")?;
        let (asset, amount) = match &offer.accept {
            paytp_core::jcs::StrictValue::Object(m) => {
                let get = |k: &str| m.iter().find(|(kk, _)| kk == k).map(|(_, v)| v);
                let asset = match get("asset") {
                    Some(paytp_core::jcs::StrictValue::String(s)) => s.clone(),
                    _ => return Err("no asset".into()),
                };
                let amount = match get("maxAmountRequired") {
                    Some(paytp_core::jcs::StrictValue::String(s)) => {
                        s.parse::<u128>().map_err(|_| "bad amount".to_string())?
                    }
                    _ => return Err("no amount".into()),
                };
                (asset, amount)
            }
            _ => return Err("accept not an object".into()),
        };
        let seed = quote
            .address_inputs(merchant_key, &asset, offer.merchant_net.as_deref())
            .seed_split()
            .map_err(|_| "derivation".to_string())?;
        let split = rail.derive_address(&seed);
        Ok(BaselinePayment {
            transfer: Transfer {
                to: split,
                asset,
                amount,
                kind: TransferKind::Payment,
                memo: None,
            },
            settle_id: paytp_core::crypto::random_bytes::<32>(),
        })
    }
}

/// Run one baseline purchase through the client with the given wallet (behind the
/// `PayerWallet` boundary), and assert the split divided and the merchant redeems.
/// The point is that the SAME `Client` code path works for ANY wallet.
fn drive_baseline(client: &Client, wallet: &dyn PayerWallet, nonce: [u8; 32]) {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let store = InMemoryStore::new();

    let bq = merchant.build_baseline_quote(&rail, baseline_params(nonce, 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();

    // The interaction layer drives the operator-selected wallet (§10.4), binding
    // the verified quote to the requested resource and the operator-approved outer
    // `accepts[0]` (the F3-a mirror the merchant built into the quote).
    let payment = client_pay_baseline(
        client,
        wallet,
        &rail,
        &json,
        &bq.accept_reqs,
        &merchant,
        RESOURCE,
    )
    .expect("client drives the wallet to pay");

    // And the merchant redeems the payment (settlement precedes delivery).
    let receipt = merchant
        .redeem_baseline(
            &json,
            RESOURCE,
            payment.transfer,
            payment.settle_id,
            &rail,
            &store,
            1_000_000_002,
        )
        .expect("redeem");
    assert_eq!(receipt.nonce, nonce);

    // The 99/1 split divided regardless of which wallet paid.
    assert_eq!(rail.balance("merchant-payout"), 990_000);
    assert_eq!(rail.balance(IL_DEST), 5_000);
    assert_eq!(rail.balance(WALLET_DEST), 3_000);
}

#[test]
fn two_distinct_wallets_drive_the_same_flow_through_the_same_interface() {
    // The IL is built once; the operator selects the wallet (§10.4).
    let il = InteractionLayer::new(IL_DEST).with_platform_os("os.apple.ios");
    let client = Client::new(il);

    // Wallet A: the reference `paytp_wallet::Wallet` with the static budget policy.
    let custody_a = Custody::from_root(&[0xA1; 32]);
    let wallet_a =
        Wallet::new(&custody_a, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);

    // Wallet B: a wholly independent wallet TYPE (not `paytp_wallet::Wallet`).
    let wallet_b = DirectWallet {
        signing_key: [0xB2; 32],
    };

    // Genuinely different implementations, distinct payer identities (compared at one
    // fixed merchant scope; the reference wallet's key is scoped per F1-f).
    let scope = PayerScope::resolve([0x55; 32], "merchant.example.com").unwrap();
    assert_ne!(
        PayerWallet::payer_key(&wallet_a, &scope),
        PayerWallet::payer_key(&wallet_b, &scope)
    );

    // The SAME client flow completes an identical purchase with each wallet,
    // selected only through the `PayerWallet` trait.
    drive_baseline(&client, &wallet_a, [0x01; 32]);
    drive_baseline(&client, &wallet_b, [0x02; 32]);

    // §10.4: the IL also assembles/validates the roles set naming the selected
    // wallet's destination — for either wallet.
    assert!(client.roles_for(Some(WALLET_DEST)).is_ok());
}

#[test]
fn wallet_refuses_a_baseline_quote_that_misroutes_its_own_0x12_share() {
    // F5-o REPRO (money-path): a HOSTILE MERCHANT signs a schema-conformant baseline quote
    // that reroutes the WALLET's own `0x12` meed share to the attacker. The governed check passes
    // it (`0x12` is pointer-free), so ONLY the wallet's own-pointer self-defense catches it — and
    // it does so BEFORE any value moves on the rail.
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xA1; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);

    let attacker = "eip155:1:0xMerchantStealsWalletShare";
    let mut evil = schema01_vector();
    evil[2].dest = attacker.into(); // reroute the 0x12 wallet share
    let mut p = baseline_params([0x31; 32], 1_000_000);
    p.vector = evil;
    let bq = merchant.build_baseline_quote(&rail, p);
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let binding = binding_for(&merchant);

    // The wallet REJECTS before paying (F5-o self-defense), and nothing moved on the rail.
    assert_eq!(
        wallet.pay_baseline(&rail, &json, &bq.accept_reqs, &binding, RESOURCE),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    );
    assert_eq!(rail.balance(attacker), 0);

    // Control: the SAME wallet pays a quote whose `0x12` IS its own configured pointer.
    let good_rail = VirtualRail::new(1);
    let good = merchant.build_baseline_quote(&good_rail, baseline_params([0x32; 32], 1_000_000));
    let gjson = String::from_utf8(good.quote.to_json()).unwrap();
    assert!(wallet
        .pay_baseline(&good_rail, &gjson, &good.accept_reqs, &binding, RESOURCE)
        .is_ok());
}

#[test]
fn baseline_wallet_binds_the_requested_resource() {
    // F3.4 REPRO (money-loss): a compromised interaction layer hands the reference WALLET
    // DIRECTLY a validly merchant-signed baseline quote for a DIFFERENT resource than the
    // operator requested. The `Client` wrapper binds the resource, but a hostile IL bypasses
    // the client and calls `pay_baseline` directly — so the wallet must bind the requested
    // resource ITSELF (independent verifier), exactly as `plan_two_leg` does. It refuses
    // BEFORE any value moves on the rail. Pre-fix, `pay_baseline` took no requested_resource
    // and paid the substituted quote in full.
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xCB; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);

    // A validly-signed quote whose signed resource is RESOURCE...
    let bq = merchant.build_baseline_quote(&rail, baseline_params([0x33; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let binding = binding_for(&merchant);
    // ...but the operator requested a DIFFERENT resource.
    assert_eq!(
        wallet.pay_baseline(
            &rail,
            &json,
            &bq.accept_reqs,
            &binding,
            "https://api.example/OTHER"
        ),
        Err(paytp_wallet::WalletError::ResourceMismatch)
    );
    // Nothing moved on the rail — the wallet refused before funding.
    assert_eq!(rail.balance("merchant-payout"), 0);

    // Control: the SAME wallet pays when the requested resource matches the signed one.
    let good_rail = VirtualRail::new(1);
    let good = merchant.build_baseline_quote(&good_rail, baseline_params([0x34; 32], 1_000_000));
    let gjson = String::from_utf8(good.quote.to_json()).unwrap();
    assert!(wallet
        .pay_baseline(&good_rail, &gjson, &good.accept_reqs, &binding, RESOURCE)
        .is_ok());
}

#[test]
fn baseline_wallet_enforces_the_f3a_mirror_against_a_substituted_quote() {
    // F3-a REPRO (money-loss / menu-tampering, F3.2): the wallet's mirror check is the
    // load-bearing bridge proving *the option the operator approved == the signed terms
    // the merchant committed*. An in-path party (hostile IL / cache / proxy) leaves the
    // outer `accepts[0]` the operator approved in place but SUBSTITUTES the signed
    // `paytp.info` with a DIFFERENT, still-validly-signed same-resource quote — a captured
    // HIGHER-amount offer. Neither F2-k origin-auth nor the resource bind catches it (same
    // merchant, same resource); only the F3-a mirror does. Pre-fix (`pay_baseline` never
    // invoked the mirror) the wallet read the amount from the substituted signed offer and
    // authorized 9_000_000 against an operator who approved 1_000_000 — a silent overcharge.
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xF3; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 50_000_000)).with_meed_dest(WALLET_DEST);
    let binding = binding_for(&merchant);

    // The 402 the operator saw and approved: the honest 1_000_000 quote's outer accepts[0].
    let approved = merchant.build_baseline_quote(&rail, baseline_params([0x71; 32], 1_000_000));

    // The substituted signed quote: SAME merchant, SAME resource, a DIFFERENT nonce and a
    // HIGHER amount. It is validly signed and passes origin-auth, the resource bind, the
    // governed-vector check, and the payer-side self-defense — every gate BUT the mirror.
    let captured = merchant.build_baseline_quote(&rail, baseline_params([0x72; 32], 9_000_000));
    let captured_json = String::from_utf8(captured.quote.to_json()).unwrap();

    // The wallet is handed the substituted quote but the operator-approved outer accept.
    // It MUST refuse before producing any authorization (F3-a: no offer mirrors this accept).
    assert_eq!(
        wallet.pay_baseline(
            &rail,
            &captured_json,
            &approved.accept_reqs,
            &binding,
            RESOURCE
        ),
        Err(paytp_wallet::WalletError::MirrorMismatch)
    );

    // Control: the honest quote — whose signed baseline offer DOES mirror the approved
    // accept — is authorized, at the amount the operator approved.
    let approved_json = String::from_utf8(approved.quote.to_json()).unwrap();
    let payment = wallet
        .pay_baseline(
            &rail,
            &approved_json,
            &approved.accept_reqs,
            &binding,
            RESOURCE,
        )
        .expect("the honest, mirrored quote is authorized");
    assert_eq!(payment.transfer.amount, 1_000_000);
}

#[test]
fn baseline_wallet_refuses_a_quote_that_cannot_finalize_in_the_honor_window() {
    // Baseline expiry/finality-headroom pre-flight (Design A): the baseline
    // (single-leg) wallet path had NO feasibility pre-flight — the two-leg path (`plan_two_leg`)
    // does. A payer could AUTHORIZE a quote whose split payment can NEVER reach the quoted finality
    // inside the honor boundary `exp+grace`; the merchant settles-then-refuses (`Expired`, §5.6)
    // and — unlike two-leg — the baseline split has NO reclaim, so the payer loses the money for no
    // delivery. The wallet must refuse BEFORE producing any authorization (same asymmetric-hole
    // class as the resource bind `baseline_wallet_binds_the_requested_resource` above).
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xE1; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let binding = binding_for(&merchant);

    // The honor window is `exp+grace − now = (1_000_000_500 + 300) − 1_000_000_000 = 800`s (the
    // rail clock starts at 1_000_000_000). A rail whose finality_delay (801s) EXCEEDS it: even
    // settled immediately the payment can never be honorable.
    let doomed_rail = VirtualRail::new(801);
    let bq = merchant.build_baseline_quote(&doomed_rail, baseline_params([0x51; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    assert_eq!(
        wallet.pay_baseline(&doomed_rail, &json, &bq.accept_reqs, &binding, RESOURCE),
        Err(paytp_wallet::WalletError::QuoteInfeasible(
            "baseline finality unreachable within exp+grace"
        ))
    );

    // Control: the SAME quote shape on a rail that CAN finalize inside the window is authorized.
    let ok_rail = VirtualRail::new(1);
    let good = merchant.build_baseline_quote(&ok_rail, baseline_params([0x52; 32], 1_000_000));
    let gjson = String::from_utf8(good.quote.to_json()).unwrap();
    assert!(wallet
        .pay_baseline(&ok_rail, &gjson, &good.accept_reqs, &binding, RESOURCE)
        .is_ok());
}

#[test]
fn baseline_wallet_does_not_over_reject_a_weak_finality_quote() {
    // Correctness guard: the pre-flight must
    // NOT over-reject a quote requiring a WEAKER-than-strongest finality that the merchant WOULD
    // honor if it redeems before the payment upgrades. The full `finality_delay` headroom applies
    // ONLY to a strongest-level-required quote (the settlement-precedes-delivery norm); a weaker
    // level needs only "not already expired". Here the SAME rail (strongest finality lands 1s past
    // the 800s window) that correctly refuses a "final"-required quote MUST authorize a
    // "pending"-required one.
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xE2; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let binding = binding_for(&merchant);

    let rail = VirtualRail::new(801); // strongest finality (801s) > window (800s)
    let mut p = baseline_params([0x53; 32], 1_000_000);
    p.finality = "pending"; // a weak level (reached at inclusion), not the rail's strongest
    let bq = merchant.build_baseline_quote(&rail, p);
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    // The quote is alive (rail time 1_000_000_000 ≤ exp+grace 1_000_000_800), so the wallet
    // authorizes it rather than over-rejecting on the strong-finality delay it does not require.
    assert!(wallet
        .pay_baseline(&rail, &json, &bq.accept_reqs, &binding, RESOURCE)
        .is_ok());

    // But an ALREADY-EXPIRED weak-finality quote is still a certain loss → refused. Advance the
    // rail clock past exp+grace, then a fresh weak quote must be rejected before any authorization.
    rail.advance_clock(1_000); // now 1_000_001_000 > exp+grace 1_000_000_800
    let mut p2 = baseline_params([0x54; 32], 1_000_000);
    p2.finality = "pending";
    let bq2 = merchant.build_baseline_quote(&rail, p2);
    let json2 = String::from_utf8(bq2.quote.to_json()).unwrap();
    assert_eq!(
        wallet.pay_baseline(&rail, &json2, &bq2.accept_reqs, &binding, RESOURCE),
        Err(paytp_wallet::WalletError::QuoteInfeasible(
            "baseline finality unreachable within exp+grace"
        ))
    );
}

// NOTE — the moneycode-triage reference's third baseline test
// (`baseline_preflight_is_rechecked_at_the_submit_point_not_stale`) is intentionally NOT ported:
// it tested a TOCTOU re-check at the wallet's `rail.submit` value-moving point, which does not
// exist under Design A (the wallet returns a `BaselinePayment` authorization and never submits;
// the merchant settles). The single authorize-time pre-flight above is the payer's certain-loss
// guard; settle-time honor is the merchant's `redeem_baseline` honor rule.

#[test]
fn client_refuses_a_baseline_quote_that_misroutes_the_il_0x10_share() {
    // F5-o REPRO: a HOSTILE MERCHANT reroutes the INTERACTION LAYER's own `0x10` share. The
    // client is the party holding the IL identity, so IT catches the misroute (against the IL's own
    // destination) before handing the quote to the wallet — each party defends its own share.
    let il = InteractionLayer::new(IL_DEST).with_platform_os("os.apple.ios");
    let client = Client::new(il);
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    let custody = Custody::from_root(&[0xA2; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);

    let mut evil = schema01_vector();
    evil[0].dest = "eip155:1:0xMerchantStealsIlShare".into(); // reroute the 0x10 IL share
    let mut p = baseline_params([0x41; 32], 1_000_000);
    p.vector = evil;
    let bq = merchant.build_baseline_quote(&rail, p);
    let json = String::from_utf8(bq.quote.to_json()).unwrap();

    assert_eq!(
        client_pay_baseline(
            &client,
            &wallet,
            &rail,
            &json,
            &bq.accept_reqs,
            &merchant,
            RESOURCE
        ),
        Err(paytp_client::ClientError::QuoteInvalid)
    );
}

#[test]
fn client_refuses_a_valid_quote_for_a_different_resource() {
    // Cross-resource substitution at the IL boundary: a compromised IL hands the
    // client a validly-signed quote for resource A while the operator requested B.
    // The client's resource binding refuses it (§5.4/F3.4).
    let il = InteractionLayer::new(IL_DEST);
    let client = Client::new(il);
    let custody = Custody::from_root(&[0xC7; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);

    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");
    // A valid quote whose signed resource is RESOURCE...
    let bq = merchant.build_baseline_quote(&rail, baseline_params([0x08; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    // ...but the operator requested a DIFFERENT resource.
    let r = client_pay_baseline(
        &client,
        &wallet,
        &rail,
        &json,
        &bq.accept_reqs,
        &merchant,
        "https://api.example/OTHER",
    );
    assert_eq!(r, Err(paytp_client::ClientError::ResourceMismatch));
    assert_eq!(rail.balance("merchant-payout"), 0); // nothing paid
}

#[test]
fn policy_denial_stops_the_purchase() {
    let client = Client::new(InteractionLayer::new(IL_DEST));
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-payout");

    // A wallet whose per-tx budget is below the amount refuses to pay.
    let custody = Custody::from_root(&[0xC3; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(ASSET, 500_000)).with_meed_dest(WALLET_DEST);
    let bq = merchant.build_baseline_quote(&rail, baseline_params([0x03; 32], 1_000_000));
    let json = String::from_utf8(bq.quote.to_json()).unwrap();
    let r = client_pay_baseline(
        &client,
        &wallet,
        &rail,
        &json,
        &bq.accept_reqs,
        &merchant,
        RESOURCE,
    );
    // The wallet's policy denial surfaces as an opaque wallet error at the IL.
    assert!(matches!(r, Err(paytp_client::ClientError::Wallet(_))));
    // Nothing moved on the rail.
    assert_eq!(rail.balance("merchant-payout"), 0);
}

/// Policy substitution (the other axis): two DIFFERENT `WalletPolicy` impls behind
/// the reference wallet also drive the same flow — the stateful `LedgerPolicy`
/// alongside `StaticPolicy`.
#[test]
fn policy_substitution_also_drives_the_same_flow() {
    let client = Client::new(InteractionLayer::new(IL_DEST));
    let custody = Custody::from_root(&[0xCD; 32]);
    let wallet = Wallet::new(
        &custody,
        LedgerPolicy {
            asset: ASSET.into(),
            remaining: Cell::new(5_000_000),
        },
    )
    .with_meed_dest(WALLET_DEST);
    drive_baseline(&client, &wallet, [0x09; 32]);
}

// ---- two-leg: the F4.5 meed-first-means-final guard (execute.rs) ----

const NET_ASSET: &str = "eip155:137/usdc";
const BASELINE_ASSET: &str = "eip155:1/native";

fn twoleg_params<'a>(nonce: [u8; 32]) -> TwoLegParams<'a> {
    TwoLegParams {
        resource: TWO_LEG_RESOURCE,
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
        vector: schema01_vector(),
    }
}

/// A rail for the two-leg wallet tests: finality after `d` ticks, and declaring BOTH the
/// net and baseline (meed) assets so the wallet's F4.5 route-availability pre-flight passes
/// — these tests exercise the finality/meed-first/policy gates, not route availability, so
/// the rail must route the CAIP assets the quotes name (the default rail routes only its
/// single demo asset). Route-rejection is covered by its own dedicated test.
fn twoleg_rail(d: u64) -> VirtualRail {
    VirtualRail::new(d).with_assets(vec![NET_ASSET.into(), BASELINE_ASSET.into()])
}

#[test]
fn two_leg_net_leg_refuses_until_meed_is_final() {
    let rail = twoleg_rail(2); // finality after 2 clock ticks
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD4; 32]);
    // A two-leg payer funds value in BOTH the net asset and the baseline (meed) asset,
    // so both are allowlisted (the meed leg is policy-gated).
    let wallet = Wallet::new(
        &custody,
        StaticPolicy::new_multi([(NET_ASSET, 5_000_000), (BASELINE_ASSET, 5_000_000)]),
    )
    .with_meed_dest(WALLET_DEST);

    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x04; 32]));
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    // The wallet verifies the signature + extracts all net-leg terms from the
    // SIGNED quote; only the refund pointer is payer-supplied.
    let plan = wallet
        .plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .expect("plan");
    // The wallet re-derives the SAME entry id + net dest the merchant quoted (F4-c),
    // trusting the signed quote, not any caller-supplied terms.
    assert_eq!(plan.entry_id(), tlq.entry_id);
    assert_eq!(plan.instance_address(), tlq.instance_address);
    assert_eq!(plan.net_to(), "merchant-net-payout");
    assert_eq!(plan.net_amount(), 990_000);

    let meed_ref = wallet.fund_meed_leg(&rail, &plan).expect("fund meed");

    // Meed not yet final → the net leg is refused (F4.5, first means final).
    assert_eq!(
        wallet.submit_net_leg(&rail, &plan, &meed_ref),
        Err(paytp_wallet::WalletError::MeedNotFinal)
    );

    // Once the meed leg reaches the quoted finality, the net leg proceeds.
    rail.advance_clock(2);
    assert!(wallet.submit_net_leg(&rail, &plan, &meed_ref).is_ok());
}

#[test]
fn two_leg_wallet_enforces_the_f3a_mirror_against_a_substituted_quote() {
    // F3-a REPRO (the two-leg sibling of the baseline mirror): F3-a lists two-leg FUNDING as
    // PayTP execution subject to the mirror rule. An in-path party (hostile IL / cache) leaves the
    // operator-approved two-leg `accept` in place but swaps in a DIFFERENT validly-signed
    // same-resource two-leg quote — a captured HIGHER net-amount offer. Origin auth (F2-k) and the
    // resource bind do NOT catch it (same merchant, same resource). Pre-fix `plan_two_leg` blindly
    // took the first two-leg offer via `.find(two_leg.is_some())` and, if the policy budget
    // allowed, funded the substituted amount; the mirror against the approved accept refuses it
    // BEFORE any leg funds (F3.2 menu-tampering). The budget here is generous so the MIRROR — not
    // the policy — is what rejects.
    let rail = twoleg_rail(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xF7; 32]);
    let wallet = Wallet::new(
        &custody,
        StaticPolicy::new_multi([(NET_ASSET, 50_000_000), (BASELINE_ASSET, 50_000_000)]),
    )
    .with_meed_dest(WALLET_DEST);

    // The two-leg option the operator approved (net 990_000, from twoleg_params).
    let approved = merchant.build_two_leg_quote(&rail, twoleg_params([0x71; 32]));

    // (a) NET-AMOUNT swap: a validly-signed same-resource two-leg quote with a HIGHER net amount.
    let mut p_net = twoleg_params([0x72; 32]);
    p_net.net_amount = 9_000_000;
    let sub_net = merchant.build_two_leg_quote(&rail, p_net);
    let sub_net_json = String::from_utf8(sub_net.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &sub_net_json,
            &approved.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::MirrorMismatch)
    ));

    // (b) MEED swap: an IDENTICAL net `accept` but a higher `meed` fee (still under the F7
    // carve cap 14_850, so the meed cap does NOT catch it). An accept-only mirror would MISS this;
    // binding the WHOLE offer refuses it — the operator approved a 10_000 meed, not 14_000.
    let mut p_meed = twoleg_params([0x73; 32]);
    p_meed.meed_amount = 14_000; // ≤ meed_carve_cap(990_000)=14_850, but ≠ approved 10_000
    let sub_meed = merchant.build_two_leg_quote(&rail, p_meed);
    assert_ne!(sub_meed.offer, approved.offer); // same net accept, different twoLeg.meed
    let sub_meed_json = String::from_utf8(sub_meed.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &sub_meed_json,
            &approved.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::MirrorMismatch)
    ));

    // Control: the honest quote whose signed two-leg offer equals the approved offer is planned.
    let approved_json = String::from_utf8(approved.quote.to_json()).unwrap();
    assert!(wallet
        .plan_two_leg(
            &rail,
            &approved_json,
            &approved.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .is_ok());

    // A structurally-invalid input — a BASELINE-only quote handed to the two-leg path — is
    // `QuoteInvalid` (no two-leg offer at all), NOT `MirrorMismatch` (which is reserved for a real
    // substitution). The error classification stays honest.
    let baseline_only = merchant.build_baseline_quote(&rail, baseline_params([0x74; 32], 990_000));
    let baseline_json = String::from_utf8(baseline_only.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &baseline_json,
            &approved.offer,
            &binding_for(&merchant),
            RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    ));
}

// ---- channel: slice gating + the F6.5 conformant halt (channel.rs) ----

fn channel_params() -> ChannelOpenParams {
    ChannelOpenParams {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 9],
        denom: "solana:dev/usdc".into(),
        baseline_asset: "solana:dev/usdc".into(),
        baseline_net: "solana:dev".into(),
        prepay: true,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        schema: 1,
        contract: 1,
        registry_v: 5,
        vector: vec![
            paytp_core::channel::VectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            paytp_core::channel::VectorEntry {
                role: 0x11,
                bp: 10,
                dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            paytp_core::channel::VectorEntry {
                role: 0x12,
                bp: 30,
                dest: "solana:dev:wallet".into(),
            },
            paytp_core::channel::VectorEntry {
                role: 0x13,
                bp: 10,
                dest: DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ],
        // A prepay channel MUST carry a REFUND_PTR (the deposit-return address, F5.2).
        refund_ptr: Some("solana:dev:payer-refund".into()),
        rate_source: None,
        rate_dev: None,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        timestamp: 1_700_000_000,
    }
}

#[test]
fn channel_open_generates_random_id_and_secret() {
    // §5.4: production open() generates the per-channel session secret + a nonzero channel
    // id from the OS CSPRNG (not the untrusted caller), so two opens of the same params
    // differ.
    let custody = Custody::from_root(&[0xE7; 32]);
    let enc_key = [0x07; 32];
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        paytp_core::crypto::ed25519_public(&[0x55; 32]),
        "merchant.example.com",
        enc_key,
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("solana:dev:wallet");
    let (o1, _) = ChannelClient::open(
        &trust,
        &TEST_CLOCK,
        StaticPolicy::new("solana:dev/usdc", 2_000_000),
        &channel_params(),
        SnapshotStore::empty_ref(),
    )
    .unwrap();
    let (o2, _) = ChannelClient::open(
        &trust,
        &TEST_CLOCK,
        StaticPolicy::new("solana:dev/usdc", 2_000_000),
        &channel_params(),
        SnapshotStore::empty_ref(),
    )
    .unwrap();
    assert_ne!(o1.encode().unwrap(), o2.encode().unwrap());
}

#[test]
fn channel_open_refuses_nonconformant_meed_vector() {
    // F5.4: the payer will not sign a CHANNEL_AUTH whose meed vector understates the governed
    // meed — here a 2-role [IL=50, WALLET=50] vector that starves OS and the Dev-Fund.
    // The wallet validates the vector itself before signing, never relying on the merchant
    // to police the split that routes the meed (mirrors the two-leg quote check).
    let custody = Custody::from_root(&[0xE9; 32]);
    let enc_key = [0x07; 32];
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        paytp_core::crypto::ed25519_public(&[0x55; 32]),
        "merchant.example.com",
        enc_key,
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("solana:dev:wallet");
    let mut params = channel_params();
    params.vector = vec![
        paytp_core::channel::VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "solana:dev:il".into(),
        },
        paytp_core::channel::VectorEntry {
            role: 0x12,
            bp: 50,
            dest: "solana:dev:wallet".into(),
        },
    ];
    assert!(matches!(
        ChannelClient::open(
            &trust,
            &TEST_CLOCK,
            StaticPolicy::new("solana:dev/usdc", 2_000_000),
            &params,
            SnapshotStore::empty_ref(),
        ),
        Err(paytp_wallet::channel::ChannelClientError::Establish)
    ));
}

#[test]
fn channel_slices_are_gated_and_halt_is_conformant() {
    let custody = Custody::from_root(&[0xE5; 32]);
    // per_slice_limit 50_000; channel budget fits the 1_000_000 L.
    let mut policy = StaticPolicy::new("solana:dev/usdc", 2_000_000);
    policy.per_slice_limit = 50_000;
    let enc_key = [0x07; 32];
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        paytp_core::crypto::ed25519_public(&[0x55; 32]),
        "merchant.example.com",
        enc_key,
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("solana:dev:wallet");
    let s = [0x42; 32];

    let (_open, mut ch) = ChannelClient::open_with_secret(
        &trust,
        &TEST_CLOCK,
        policy,
        &channel_params(),
        &s,
        SnapshotStore::empty_ref(),
    )
    .expect("open");

    // A slice within the per-slice limit is minted; over it is denied.
    assert!(ch.next_slice(40_000).is_ok());
    assert!(matches!(
        ch.next_slice(60_000),
        Err(paytp_wallet::channel::ChannelClientError::PolicyDenied(_))
    ));

    // SEQ advances across accepted slices.
    let s2 = ch.next_slice(10_000).expect("second slice");
    assert_eq!(s2.seq, 2); // seq 1 was the first accepted slice

    // The F6.5 conformant halt: an overdue meed round (proposal hash PH) MUST
    // stop the prepay wallet minting; resuming requires the merchant's confirmation
    // for exactly THAT round.
    let cid = [0, 0, 0, 0, 0, 0, 0, 9];
    let ckpt = [0xC7; 32]; // the overdue round's stable CKPT_REF
                           // The wallet co-signed an operative checkpoint metering a full TH_value round (100_000) — owed
                           // carve = 1000 (100 bp of 100_000). The wallet computes this itself and self-halts once a round's
                           // worth of meed is unsettled; no caller supplies the amount (F6-o).
    ch.seed_operative(ckpt, 100_000);
    assert_eq!(ch.on_overdue_meed(), HaltOrContinue::Halt);
    assert!(ch.is_halted());
    assert!(matches!(
        ch.next_slice(1_000),
        Err(paytp_wallet::channel::ChannelClientError::HaltedOnOverdueMeed)
    ));
    // The wallet resumes on the merchant-signed `PREPAY_DRAW_COMPLETED` (F5-o) for THIS round — a
    // liveness signal (the rail-for-value credit is covered by the paytp-wallet unit tests). The
    // channel's merchant key is `ed25519_public(&[0x55; 32])`.
    // The claim record the wallet derives itself (F4.2) — the valid notice must name exactly it.
    let seed = paytp_core::derive::AddressInputs {
        merchant_key: paytp_core::crypto::ed25519_public(&[0x55; 32]),
        asset: "solana:dev/usdc".into(),
        schema: 1,
        vector: channel_params()
            .vector
            .iter()
            .map(|v| paytp_core::derive::MeedVectorEntry {
                role: v.role,
                bp: v.bp,
                dest: v.dest.clone(),
            })
            .collect(),
        contract: 1,
        merchant_net: None,
    }
    .seed_instance()
    .unwrap();
    let good_claim = paytp_core::derive::claim_record_id(&seed, &cid, &ckpt, 1_000);
    let receipt = |ckpt_ref: [u8; 32], key: [u8; 32], claim_record: [u8; 32]| {
        let mut r = PrepayDrawCompleted {
            channel_id: cid,
            ckpt_ref,
            amount: BigUint::from(1_000u32),
            extinguished: vec![(0x10, BigUint::from(1u32))],
            claim_record,
            rail: "solana:dev".into(), // F5-o RAIL = CAIP-2 BASELINE_NET (not the CAIP-19 asset)
            tx_ref: "tx-ref".into(),
            finality: "final".into(),
            sig_merchant: None,
        };
        r.sign_merchant(&key);
        r
    };
    // A forged notice (wrong signer) for the right round does not resume...
    assert!(!ch.resume_on_prepay_draw(&receipt(ckpt, [0x99; 32], good_claim)));
    assert!(ch.is_halted());
    // ...a notice for a DIFFERENT (stale) round does not resume...
    assert!(!ch.resume_on_prepay_draw(&receipt([0xEE; 32], [0x55; 32], good_claim)));
    assert!(ch.is_halted());
    // ...only the merchant-signed notice for THIS channel's overdue round, naming the wallet-derived
    // claim record, lifts it (a liveness resume; the rail-for-value credit is in the paytp-wallet tests).
    assert!(ch.resume_on_prepay_draw(&receipt(ckpt, [0x55; 32], good_claim)));
    assert!(ch.next_slice(1_000).is_ok());
}

/// A prepay halt is MANDATORY even if the wallet's policy would say "continue" —
/// a non-conformant policy cannot keep a prepay payer streaming past an overdue
/// meed round (F6.5).
#[test]
fn prepay_halt_is_mandatory_even_for_a_permissive_policy() {
    struct NeverHalt;
    impl WalletPolicy for NeverHalt {
        fn approve_quote(
            &self,
            _q: &paytp_core::tier0::quote::Quote,
            _a: u128,
            _s: &str,
        ) -> Decision {
            Decision::Approve
        }
        fn approve_channel(&self, _t: &ChannelTerms) -> Decision {
            Decision::Approve
        }
        fn approve_slice(&self, _c: [u8; 8], _a: u64) -> Decision {
            Decision::Approve
        }
        fn on_overdue_meed(&self, _c: [u8; 8]) -> HaltOrContinue {
            HaltOrContinue::Continue // non-conformant policy
        }
    }
    let custody = Custody::from_root(&[0xE6; 32]);
    let enc_key = [0x07; 32];
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        paytp_core::crypto::ed25519_public(&[0x55; 32]),
        "merchant.example.com",
        enc_key,
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("solana:dev:wallet");
    let (_open, mut ch) = ChannelClient::open_with_secret(
        &trust,
        &TEST_CLOCK,
        NeverHalt,
        &channel_params(),
        &[0x43; 32],
        SnapshotStore::empty_ref(),
    )
    .unwrap();
    // A settleable operative round the wallet co-signed (owed carve = 1000); the policy says Continue,
    // but the prepay halt fires anyway (mandatory — a non-conformant policy cannot lift it).
    ch.seed_operative([0xC7; 32], 100_000);
    assert_eq!(ch.on_overdue_meed(), HaltOrContinue::Continue);
    assert!(ch.is_halted());
    assert!(ch.next_slice(1_000).is_err());
}

// ---- reclaim automation (channel.rs) ----

#[test]
fn reclaim_automation_recovers_an_unreceipted_entry() {
    let rail = twoleg_rail(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xF6; 32]);
    let wallet = Wallet::new(
        &custody,
        StaticPolicy::new_multi([(NET_ASSET, 5_000_000), (BASELINE_ASSET, 5_000_000)]),
    )
    .with_meed_dest(WALLET_DEST);

    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x06; 32]));
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    let plan = wallet
        .plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .unwrap();
    wallet.fund_meed_leg(&rail, &plan).expect("fund meed");

    // The merchant never attests (never delivered). Reclaim is two-phase: open it
    // once the window is open (rail clock ≥ T_open = exp+grace = 1_000_000_800),
    // then execute after the contest window (opened_at + 600) fully passes.
    rail.advance_clock(801); // clock → 1_000_000_801, inside [T_open, T_lapse]
    assert!(
        paytp_wallet::channel::open_reclaim_if_unreceipted(
            &rail,
            plan.instance_address(),
            plan.entry_id()
        ),
        "the reclaim opens once its window is open"
    );
    rail.advance_clock(601); // past opened_at + contest (600) → reclaim is due
    assert!(
        paytp_wallet::channel::execute_reclaim_if_due(
            &rail,
            plan.instance_address(),
            plan.entry_id()
        ),
        "an unreceipted entry is reclaimable once its contest window passes"
    );
}

// ---- wallet two-leg spend-boundary ----

#[test]
fn two_leg_over_cap_meed_is_rejected() {
    // F7: in the same-asset case (net and baseline settle in one asset, equal scale),
    // the meed is a tight ≤150 bp carve of the net. A merchant-signed meed above
    // the carve is refused even though it is within the per-tx budget and conformant.
    let rail = twoleg_rail(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD5; 32]);
    let wallet = Wallet::new(&custody, StaticPolicy::new(BASELINE_ASSET, 5_000_000))
        .with_meed_dest(WALLET_DEST);
    let mut p = twoleg_params([0x07; 32]);
    p.net_asset = BASELINE_ASSET; // net == baseline asset → the tight bp carve applies
    p.meed_amount = 500_000; // net = 990_000 → cap = 14_850; 500_000 ≫ cap
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::PolicyDenied(_))
    ));
}

#[test]
fn two_leg_payer_side_self_defense_catches_misrouted_0x10_and_0x12() {
    // `plan_two_leg` defends BOTH payer-side shares — the wallet's
    // OWN `0x12` (its configured pointer) AND, when the IL context is supplied, the IL's OWN
    // `0x10` (`expected_il`). A hostile merchant rerouting either is rejected BEFORE the meed
    // leg funds; with `expected_il = None` the `0x10` is an explicit scope-limit (unchecked).
    let rail = twoleg_rail(2);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD7; 32]);
    // Both legs' assets allowlisted so the HONEST control plan is fully feasible (the
    // misrouted cases reject at the earlier payer-side check, before feasibility/policy).
    let wallet = Wallet::new(
        &custody,
        StaticPolicy::new_multi([(NET_ASSET, 5_000_000), (BASELINE_ASSET, 5_000_000)]),
    )
    .with_meed_dest(WALLET_DEST);
    let refund = "eip155:1:0xPayerRefund";

    // Merchant reroutes the IL's `0x10` share to itself.
    let mut p_il = twoleg_params([0x21; 32]);
    p_il.vector[0].dest = "eip155:1:0xMerchantStealsIlShare".into();
    let tlq_il = merchant.build_two_leg_quote(&rail, p_il);
    let tljson_il = String::from_utf8(tlq_il.quote.to_json()).unwrap();
    // With the IL context, the misrouted 0x10 is rejected...
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson_il,
            &tlq_il.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            refund,
            Some(IL_DEST)
        ),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    ));
    // ...and it plans fine when the honest 0x10 matches the asserted IL pointer.
    let honest_tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x22; 32]));
    let honest = String::from_utf8(honest_tlq.quote.to_json()).unwrap();
    assert!(wallet
        .plan_two_leg(
            &rail,
            &honest,
            &honest_tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            refund,
            Some(IL_DEST)
        )
        .is_ok());

    // Merchant reroutes the WALLET's OWN `0x12` share — rejected regardless of the IL context.
    let mut p_w = twoleg_params([0x23; 32]);
    p_w.vector[2].dest = "eip155:1:0xMerchantStealsWalletShare".into();
    let tlq_w = merchant.build_two_leg_quote(&rail, p_w);
    let tljson_w = String::from_utf8(tlq_w.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson_w,
            &tlq_w.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            refund,
            None
        ),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    ));
}

#[test]
fn two_leg_meed_leg_is_policy_gated() {
    // F7: the meed leg funds value in the baseline asset, so it passes the policy
    // gate. A policy that allowlists only the net asset (not the baseline) refuses the
    // two-leg plan — the dimensionally-sound bound where a raw cross-asset amount cap is
    // not (the baseline is a different asset/scale than the net).
    let rail = twoleg_rail(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD8; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(NET_ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x0A; 32]));
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::PolicyDenied(_))
    ));
}

#[test]
fn two_leg_same_asset_legs_gated_by_sum() {
    // When the net and meed legs share an asset, the wallet gates their
    // SUM — two legs each under the per-asset budget must not pass while their total
    // breaches it. Here net alone and meed alone are under budget, but net + meed
    // exceed it (meed is within the ≤150 bp carve, so the SUM gate is what refuses).
    let rail = twoleg_rail(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD9; 32]);
    let wallet = Wallet::new(&custody, StaticPolicy::new(BASELINE_ASSET, 1_000_000))
        .with_meed_dest(WALLET_DEST);
    let mut p = twoleg_params([0x0B; 32]);
    p.net_asset = BASELINE_ASSET; // same asset → legs share one budget
    p.net_amount = 990_000; // under the 1_000_000 budget on its own
    p.meed_amount = 14_000; // ≤ carve (14_850), but 990_000 + 14_000 > 1_000_000
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::PolicyDenied(_))
    ));
}

#[test]
fn two_leg_resource_substitution_is_rejected() {
    // F5-o: a compromised interaction layer hands the wallet a valid merchant-signed
    // two-leg quote for a DIFFERENT resource than the operator requested. The wallet binds
    // the requested resource and refuses (as the baseline client flow does).
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xDA; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(NET_ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x0C; 32]));
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            "https://api.example/OTHER", // operator asked for a different resource
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::ResourceMismatch)
    ));
}

#[test]
fn two_leg_nonconformant_vector_is_rejected() {
    // F7: the wallet validates the meed vector against schema 0x01 before funding; a
    // vector with the wrong cardinality / bp total is refused (the payer never relies on
    // the merchant to validate the vector that routes the meed).
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD6; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(NET_ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let mut p = twoleg_params([0x08; 32]);
    p.vector = vec![MeedEntry {
        role: 0x10,
        bp: 50,
        dest: IL_DEST.into(),
    }]; // 50 bp, wrong cardinality → not schema-0x01
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    ));
}

#[test]
fn two_leg_overflow_reclaim_is_rejected() {
    // F8: a merchant-signed quote with a pathological reclaim is rejected by the
    // wallet (time fields bounded to 2^53-1), never overflow-panicking the payer.
    let rail = VirtualRail::new(1);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let custody = Custody::from_root(&[0xD7; 32]);
    let wallet =
        Wallet::new(&custody, StaticPolicy::new(NET_ASSET, 5_000_000)).with_meed_dest(WALLET_DEST);
    let mut p = twoleg_params([0x09; 32]);
    p.reclaim = u64::MAX;
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(matches!(
        wallet.plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        ),
        Err(paytp_wallet::WalletError::QuoteInvalid)
    ));
}

// ---- wallet two-leg F4.5/F8 feasibility pre-flight ----

/// A feasibility-pre-flight wallet (budget generous, both assets allowlisted) so the ONLY
/// thing under test is the F4.5/F8.5 pre-flight, never the spend/carve policy.
fn feasibility_wallet(custody: &Custody) -> Wallet<'_, StaticPolicy> {
    Wallet::new(
        custody,
        StaticPolicy::new_multi([(NET_ASSET, 50_000_000), (BASELINE_ASSET, 50_000_000)]),
    )
    .with_meed_dest(WALLET_DEST)
}

fn plan_infeasible(
    rail: &VirtualRail,
    custody: &Custody,
    p: TwoLegParams,
) -> paytp_wallet::WalletError {
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let wallet = feasibility_wallet(custody);
    let tlq = merchant.build_two_leg_quote(rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    wallet
        .plan_two_leg(
            rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .expect_err("infeasible quote must be refused before funding")
}

#[test]
fn two_leg_infeasible_net_finality_window_refused() {
    // The crux case: the honor window `exp+grace` is long enough for the MEED leg
    // to finalize, but NOT for the NET leg — which, meed-first (F4.5), cannot start until
    // the meed is final, so its finality lands at now + 2·delay. An independent per-leg
    // check would PASS (each leg's own delay fits the window); only accounting for the
    // serialization catches it. The wallet refuses BEFORE funding (else the payer recovers
    // via reclaim, not completion). Pre-fix, `plan_two_leg` returned Ok(plan).
    let rail = twoleg_rail(500); // finality after 500 ticks; clock starts 1_000_000_000
    let custody = Custody::from_root(&[0xE1; 32]);
    let mut p = twoleg_params([0x0E; 32]);
    // exp+grace = 1_000_000_600. meed final at now+500 = 1_000_000_500 (≤ window, feasible);
    // net final at now+1000 = 1_000_001_000 (> window, INfeasible: serialized after meed).
    p.exp = 1_000_000_300;
    p.grace = 300;
    assert_eq!(
        plan_infeasible(&rail, &custody, p),
        paytp_wallet::WalletError::QuoteInfeasible("net finality unreachable within exp+grace")
    );
}

#[test]
fn two_leg_infeasible_meed_finality_window_refused() {
    // The other headroom sub-case: the window is too short for even the MEED leg to
    // finalize (now+delay > exp+grace), so the flow cannot start at all.
    let rail = twoleg_rail(500);
    let custody = Custody::from_root(&[0xE2; 32]);
    let mut p = twoleg_params([0x0F; 32]);
    // exp+grace = 1_000_000_400 < now+delay = 1_000_000_500 → meed itself is unreachable.
    p.exp = 1_000_000_100;
    p.grace = 300;
    assert_eq!(
        plan_infeasible(&rail, &custody, p),
        paytp_wallet::WalletError::QuoteInfeasible("meed finality unreachable within exp+grace")
    );
}

#[test]
fn two_leg_feasible_at_window_boundary_is_planned() {
    // Conservative-but-not-over-strict: the honor rule is `t_fin ≤ exp+grace` (F8.1,
    // inclusive), so a quote whose net leg finalizes EXACTLY at the boundary is feasible
    // and MUST be planned (not refused). net_fin = now + 2·500 = 1_000_001_000 == exp+grace.
    let rail = twoleg_rail(500);
    let custody = Custody::from_root(&[0xE3; 32]);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let wallet = feasibility_wallet(&custody);
    let mut p = twoleg_params([0x10; 32]);
    p.exp = 1_000_000_700; // exp+grace = 1_000_001_000 == net_fin (boundary, inclusive)
    p.grace = 300;
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    assert!(
        wallet
            .plan_two_leg(
                &rail,
                &tljson,
                &tlq.offer,
                &binding_for(&merchant),
                TWO_LEG_RESOURCE,
                "eip155:1:0xPayerRefund",
                None,
            )
            .is_ok(),
        "a net leg finalizing exactly at exp+grace is honored, so the plan must be returned"
    );
}

#[test]
fn two_leg_unroutable_asset_refused() {
    // F4.5 route availability: a rail that does not route a leg's asset can never settle it.
    // The default rail routes only its single demo asset, not the quote's CAIP assets.
    let rail = VirtualRail::new(1); // default assets = ["virt-usd"] — does NOT route the legs
    let custody = Custody::from_root(&[0xE4; 32]);
    assert_eq!(
        plan_infeasible(&rail, &custody, twoleg_params([0x11; 32])),
        paytp_wallet::WalletError::QuoteInfeasible("net asset not routable on this rail")
    );
}

#[test]
fn two_leg_nonpositive_reclaim_refused() {
    // F8.5 positivity: reclaim == 0 (window closes before the execution gate can open).
    let rail = twoleg_rail(1);
    let custody = Custody::from_root(&[0xE5; 32]);
    let mut p = twoleg_params([0x12; 32]);
    p.reclaim = 0;
    assert_eq!(
        plan_infeasible(&rail, &custody, p),
        paytp_wallet::WalletError::QuoteInfeasible("reclaim must be positive")
    );
}

#[test]
fn two_leg_nonpositive_contest_refused() {
    // F8.5 positivity: contest == 0.
    let rail = twoleg_rail(1);
    let custody = Custody::from_root(&[0xE6; 32]);
    let mut p = twoleg_params([0x13; 32]);
    p.contest = 0;
    assert_eq!(
        plan_infeasible(&rail, &custody, p),
        paytp_wallet::WalletError::QuoteInfeasible("contest must be positive")
    );
}

#[test]
fn two_leg_stale_plan_refused_at_fund_time() {
    // TOCTOU: a plan feasible at plan time must NOT stay fundable
    // once the rail clock has decayed past the headroom. `plan_two_leg` accepts a
    // boundary-feasible quote; advancing the clock before funding makes the flow infeasible,
    // and `fund_meed_leg` re-checks and refuses BEFORE the meed value moves.
    let rail = twoleg_rail(500);
    let custody = Custody::from_root(&[0xE7; 32]);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let wallet = feasibility_wallet(&custody);
    let mut p = twoleg_params([0x14; 32]);
    p.exp = 1_000_000_700; // exp+grace = 1_000_001_000 == net_fin at plan time (boundary-feasible)
    p.grace = 300;
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    let plan = wallet
        .plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .expect("boundary quote is feasible at plan time");
    rail.advance_clock(1); // clock decays one tick → net_fin now 1_000_001_001 > window
    assert_eq!(
        wallet.fund_meed_leg(&rail, &plan),
        Err(paytp_wallet::WalletError::QuoteInfeasible(
            "net finality unreachable within exp+grace"
        ))
    );
    // The meed value never moved — no entry was funded at the instance.
    assert!(
        rail.entry_status(plan.instance_address(), &plan.entry_id())
            .is_none(),
        "fund_meed_leg refused before funding, so no entry exists"
    );
}

#[test]
fn two_leg_stale_net_leg_refused_after_meed_final_decay() {
    // The net-leg TOCTOU: the meed funds and finalizes on time, but the wallet waits too long
    // before the net leg. `submit_net_leg` re-checks and refuses to send the UNCONDITIONAL
    // ~99% net leg once it can no longer finalize inside the window — so the payer never
    // throws the net leg after a purchase that can no longer complete (only the reclaimable
    // meed is escrowed).
    let rail = twoleg_rail(100); // finality after 100 ticks
    let custody = Custody::from_root(&[0xE8; 32]);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let wallet = feasibility_wallet(&custody);
    let mut p = twoleg_params([0x15; 32]);
    // exp+grace = 1_000_000_250. meed_fin at plan = now+100 = 1_000_000_100; net_fin =
    // now+200 = 1_000_000_200 ≤ window → feasible at plan time.
    p.exp = 1_000_000_050;
    p.grace = 200;
    let tlq = merchant.build_two_leg_quote(&rail, p);
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    let plan = wallet
        .plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .expect("feasible at plan time");
    let meed_ref = wallet.fund_meed_leg(&rail, &plan).expect("fund meed");
    rail.advance_clock(100); // meed reaches finality at 1_000_000_100
                             // Wait too long before the net leg: at clock 1_000_000_160, net_fin = 160+100 =
                             // 1_000_000_260 > window 1_000_000_250 → refuse (meed itself was on time).
    rail.advance_clock(60);
    assert_eq!(
        wallet.submit_net_leg(&rail, &plan, &meed_ref),
        Err(paytp_wallet::WalletError::QuoteInfeasible(
            "net finality unreachable within exp+grace"
        ))
    );
    // The net leg (the unconditional ~99%) never moved to the merchant.
    assert_eq!(rail.balance("merchant-net-payout"), 0);
}

#[test]
fn two_leg_weak_finality_bounded_by_strongest_delay() {
    // Shadowing guard: the merchant's honor check reads each leg's
    // CURRENTLY-observed finality time, and finality only upgrades to STRONGER levels with
    // LATER times — so a late redemption can observe the strongest level. The wallet must
    // therefore bound even a WEAK-finality ("pending") quote against the rail's strongest
    // finality delay, not the weak level's near-zero delay: here "pending" is reached
    // instantly, but the strongest-finality time exceeds the window → refuse (a per-quoted-
    // level check would have wrongly funded it, then lost the net leg to a late redemption).
    let rail = twoleg_rail(500); // levels [pending, final]; strongest ("final") delay 500
    let custody = Custody::from_root(&[0xEA; 32]);
    let mut p = twoleg_params([0x17; 32]);
    p.fin_meed = "pending";
    p.fin_net = "pending";
    // exp+grace = 1_000_000_600. Strongest-delay bound: net_fin = now + 2*500 = 1_000_001_000
    // > window → refuse (an optimistic per-quoted-level bound would have passed at now+0).
    p.exp = 1_000_000_300;
    p.grace = 300;
    assert_eq!(
        plan_infeasible(&rail, &custody, p),
        paytp_wallet::WalletError::QuoteInfeasible("net finality unreachable within exp+grace")
    );
}

#[test]
fn two_leg_net_leg_refuses_unrelated_meed_ref() {
    // `submit_net_leg` must bind the `meed_ref` to THIS plan's entry (F4.4),
    // not accept any transfer that merely reached finality — else the wallet would throw the
    // unconditional ~99% net leg after a purchase whose meed entry was never funded (the
    // merchant then rejects, and the payer has paid the net for nothing).
    let rail = twoleg_rail(2);
    let custody = Custody::from_root(&[0xEB; 32]);
    let merchant = Merchant::new([0x55; 32], "merchant-net-payout");
    let wallet = feasibility_wallet(&custody);
    let tlq = merchant.build_two_leg_quote(&rail, twoleg_params([0x18; 32]));
    let tljson = String::from_utf8(tlq.quote.to_json()).unwrap();
    let plan = wallet
        .plan_two_leg(
            &rail,
            &tljson,
            &tlq.offer,
            &binding_for(&merchant),
            TWO_LEG_RESOURCE,
            "eip155:1:0xPayerRefund",
            None,
        )
        .unwrap();
    // An UNRELATED transfer that reaches finality but funds NO entry (funds_entry: None).
    let unrelated = rail
        .submit(Transfer {
            to: "somewhere".into(),
            asset: BASELINE_ASSET.into(),
            amount: 1,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
    rail.advance_clock(2); // the unrelated transfer reaches "final"
    assert_eq!(
        wallet.submit_net_leg(&rail, &plan, &unrelated),
        Err(paytp_wallet::WalletError::EntryIdMismatch)
    );
    // The net leg was never sent.
    assert_eq!(rail.balance("merchant-net-payout"), 0);
}
