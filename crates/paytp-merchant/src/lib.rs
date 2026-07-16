//! `paytp-merchant` — the merchant-side baseline Tier 0 flow.
//!
//! Part of the **baseline-profile reference implementation** (see the repo-root
//! `SCOPE.md`) — a conformance artifact, not production money software.
//!
//! Quote construction with F4.1 split derivation, the durable
//! [`MerchantStore`], and redemption with **settlement-precedes-delivery**
//! (F4.4): the merchant re-verifies its own signed quote, settles the payer-presented
//! payment authorization, confirms the payment reached the split at quoted finality,
//! atomically consumes the nonce before delivery, and signs the receipt.

pub mod attest_endpoint;
pub mod carriage;
pub mod channel;
pub mod http;
pub mod measure;
pub mod one_decision;
mod store;
pub mod twoleg;

pub use attest_endpoint::AttestationEndpoint;
pub use carriage::{Carriage, CarriageError, Response};
pub use channel::{ChannelDriver, ChannelError, Established, OpenOutcome, SettlementTerms};
#[cfg(any(test, feature = "demo"))]
pub use store::InMemoryStore;
pub use store::{
    DurableMerchantStore, MerchantStore, NonceRecord, OpenError, Peek, StoreError, WalMerchantStore,
};
pub use twoleg::{TwoLegParams, TwoLegQuote};

use paytp_core::crypto;
use paytp_core::jcs::StrictValue;
use paytp_core::registry::SnapshotStore;
use paytp_core::tier0::quote::{MeedEntry, Offer, Quote};
use paytp_core::tier0::Receipt;
use paytp_rail::{RailAdapter, Transfer};

pub(crate) fn sv_pub(s: impl Into<String>) -> StrictValue {
    StrictValue::String(s.into())
}
pub(crate) fn member_pub<'a>(v: &'a StrictValue, key: &str) -> Option<&'a StrictValue> {
    member(v, key)
}
pub(crate) fn member_str_pub(v: &StrictValue, key: &str) -> Option<String> {
    member_str(v, key)
}

/// Baseline redemption failures (a subset of the §5.7/F3.6 registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemError {
    /// The presented quote failed signature/mirror/resource validation (an
    /// ordinary HTTP client error — §5.7 has no code for a malformed quote).
    QuoteInvalid,
    /// Past expiry without a leg reaching quoted finality in grace
    /// (`PAYTP_PAYMENT_EXPIRED`).
    Expired,
    /// The payment did not reach the quoted split at quoted finality.
    PaymentUnverified,
    /// Mismatch against a consumed nonce (`PAYTP_PAYMENT_PROOF_REPLAYED`).
    Replayed,
    /// The durable consumed-nonce store could not record the consumption (a write failure / a
    /// poisoned log). The merchant did NOT deliver and did NOT record — the payer retries against a
    /// recovered store and completes exactly once (F4.4 durable-or-fail). An ordinary transient
    /// server error, not a payment failure.
    StoreUnavailable,
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RedeemError {}

/// A merchant identity and its payout address.
pub struct Merchant {
    pub(crate) signing_key: [u8; 32],
    /// The Ed25519 identity key (public).
    pub key: [u8; 32],
    /// Where the merchant's 99% residue lands on the baseline rail.
    pub payout: String,
    /// The merchant's retained role-registry snapshots (F9-d). Supplied at construction so the
    /// governed meed-vector check on receipt (F5-o/F9.4: `0x11` registry-listed-or-independent-fund,
    /// `0x13` pinned Dev-Fund) has the registry it needs — the compiler forces every redeem path
    /// through `validate_vector_governed`, so this is not optional config.
    pub(crate) registry: SnapshotStore,
}

/// What [`Merchant::build_baseline_quote`] returns.
pub struct BaselineQuote {
    pub quote: Quote,
    /// The deployed split address (the offer's `payTo`).
    pub split_address: String,
    /// The complete x402 V2 `PaymentRequirements` this quote's baseline offer
    /// mirrors (F3-a) — the exact `accepts[0]` a plain client pays. Held so
    /// [`BaselineQuote::to_payment_required`] emits an `accepts[0]` that equals
    /// the signed mirror by construction.
    pub accept_reqs: paytp_core::x402::PaymentRequirements,
}

/// A minimal JSON Schema advertising the `paytp` extension's shape (x402 V2
/// §5.1.2 requires `info` and `schema`). Advisory; the merchant signature over
/// the `paytp` object is the authority, not this schema.
fn paytp_extension_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "PayTP quote extension v1",
        "type": "object",
        "required": ["v", "nonce", "vector", "offers", "signature"],
    })
}

impl BaselineQuote {
    /// Wrap this baseline quote into a **shipped x402 V1** `PaymentRequired`
    /// (F3-j).
    ///
    /// A plain, PayTP-unaware client sees `accepts[0]` and authorizes payment to its
    /// `payTo` (the split address); the merchant settles that authorization and the
    /// meed divides on-chain. A PayTP-aware client additionally reads the signed
    /// `paytp` object from `extensions.paytp.info`
    /// (from the **raw** 402 — the shipped schema strips top-level `extensions`),
    /// re-verifies the merchant signature, maps the named network back to CAIP-2
    /// and confirms it == `paytp.baseline`, and checks the requirement's resource.
    /// `accepts[0]` equals the signed mirror by construction (`accept_reqs`); the
    /// per-requirement `resource` is bound to the signed quote's `resource`.
    pub fn to_payment_required(&self) -> paytp_core::x402::PaymentRequired {
        use paytp_core::x402;
        let paytp_obj: serde_json::Value =
            serde_json::from_slice(&self.quote.to_json()).expect("quote JCS is JSON");
        let extensions = Some(x402::paytp_extension(paytp_obj, paytp_extension_schema()));
        x402::PaymentRequired {
            x402_version: x402::X402_VERSION,
            error: None,    // shipped `error` is a strict enum; omit on the initial 402
            resource: None, // resource is per-requirement in V1 (F3-j rule 4)
            accepts: vec![self.accept_reqs.clone()],
            extensions,
        }
    }
}

fn member<'a>(v: &'a StrictValue, key: &str) -> Option<&'a StrictValue> {
    match v {
        StrictValue::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn member_str(v: &StrictValue, key: &str) -> Option<String> {
    match member(v, key) {
        Some(StrictValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Inputs for a baseline quote (the meed vector's destinations already resolved
/// via the registry, F9.4).
pub struct BaselineParams<'a> {
    pub resource: &'a str,
    pub nonce: [u8; 32],
    pub exp: u64,
    pub idem: Vec<u8>,
    pub registry_version: u32,
    pub baseline_network: &'a str,
    pub asset: &'a str,
    pub amount: u128,
    pub finality: &'a str,
    pub grace: u64,
    pub retry: u64,
    /// x402 V2 `maxTimeoutSeconds` (§5.1.2) — max seconds to complete payment.
    pub max_timeout_seconds: u64,
    /// x402 V2 scheme-specific `extra` (e.g. exact-svm `feePayer`); the merchant
    /// advertises it and a plain client uses it verbatim. Baseline nonce binding is
    /// NOT carried in `extra.memo`; redemption is bound by the merchant-settled
    /// payment authorization plus the durable consumed-settlement record. An
    /// **object** (x402 V2 §5.1.2); `None` omits it.
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
    /// The resolved meed vector `(role, bp, dest)` (schema 0x01), ascending role.
    pub vector: Vec<MeedEntry>,
}

impl Merchant {
    /// Construct a merchant with an **empty** registry. Suitable when every quote this merchant
    /// redeems routes its `0x11` OS share to the version-agnostic independent-OS-fund fallback
    /// (§10.1); a merchant that quotes registry-listed OS recipients MUST use
    /// [`Merchant::with_registry`] so the receive-side set-membership check can confirm them.
    pub fn new(signing_key: [u8; 32], payout: impl Into<String>) -> Self {
        Self::with_registry(signing_key, payout, SnapshotStore::new())
    }

    /// Construct a merchant with its retained role-registry snapshots (F9-d) — the registry the
    /// governed meed-vector check (F5-o/F9.4) resolves `0x11` OS destinations against on receipt.
    pub fn with_registry(
        signing_key: [u8; 32],
        payout: impl Into<String>,
        registry: SnapshotStore,
    ) -> Self {
        Merchant {
            key: crypto::ed25519_public(&signing_key),
            signing_key,
            payout: payout.into(),
            registry,
        }
    }

    /// The merchant's attestation for `(nonce, entry_id)` (F3.5) — deterministic,
    /// so the control endpoint can (re-)serve it unauthenticated (F2.6).
    pub fn make_attestation(
        &self,
        nonce: [u8; 32],
        entry_id: [u8; 32],
    ) -> paytp_core::tier0::attest::Signed {
        paytp_core::tier0::attest::Signed::create(
            paytp_core::tier0::attest::Kind::Attestation,
            nonce,
            entry_id,
            &self.signing_key,
        )
    }

    /// Build, deploy the split for, and sign a baseline quote.
    pub fn build_baseline_quote(
        &self,
        rail: &paytp_rail::VirtualRail,
        p: BaselineParams,
    ) -> BaselineQuote {
        // Derive the split seed from ADDRESS_INPUTS and deploy it on the rail.
        let mut q = Quote {
            v: "1".into(),
            resource: p.resource.into(),
            nonce: p.nonce,
            exp: p.exp,
            idem: p.idem,
            schema: paytp_core::consts::SCHEMA_V0_1,
            contract: paytp_core::consts::CONTRACT_VERSION_V0_1,
            registry: p.registry_version,
            baseline: p.baseline_network.into(),
            grace: p.grace,
            retry: p.retry,
            vector: p.vector.clone(),
            offers: Vec::new(),
            signature: None,
        };
        let inputs = q.address_inputs(&self.key, p.asset, Some(&self.payout));
        let seed = inputs.seed_split().expect("seed");
        // The bound deploy recomputes the seed from `inputs` and derives the recipient set from
        // the SAME canonical ADDRESS_INPUTS, so the split's recipients are provably bound to its
        // address — a caller cannot inject an unbound recipient. `.expect`: the only
        // failures are merchant misconfig (a meed total exceeding BP_DENOM, the case the prior
        // `10 000 − total` subtraction would have underflow-panicked on), never payer input.
        let split_address = rail
            .deploy_split(&seed, &inputs)
            .expect("merchant baseline split inputs are well-formed");

        // The baseline offer: its accept.payTo IS the split address (§5.6), and
        // it carries no `twoLeg` (that absence is what marks it baseline). The
        // mirror is a COMPLETE **shipped x402 V1** PaymentRequirements (F3-a/F3-j:
        // named `network`, `maxAmountRequired`, per-req `resource`), stored typed
        // so `accepts[0]` and the signed mirror are provably equal.
        // F3-j rule 1/3: render the CAIP-2 baseline as the x402 **named** network
        // (fail-closed if the baseline rail has no x402 name — a merchant misconfig).
        let network = paytp_core::x402_net::caip2_to_x402(p.baseline_network)
            .expect("baseline rail has a mapped x402 network name (F3-j table)");
        // Baseline no longer injects exact-svm `extra.memo`: shipped x402 clients neither emit nor
        // honor it, and the facilitator rejects the extra instruction. Preserve caller extra
        // verbatim (e.g. `feePayer`) and bind redemption through Design A settlement + used_refs.
        let extra = p.extra.clone();
        let accept_reqs = paytp_core::x402::PaymentRequirements {
            scheme: "exact".into(),
            network: network.to_string(),
            max_amount_required: p.amount.to_string(),
            asset: p.asset.into(),
            pay_to: split_address.clone(),
            resource: p.resource.into(),
            description: String::new(),
            mime_type: "application/json".into(),
            max_timeout_seconds: p.max_timeout_seconds,
            extra,
        };
        let accept = accept_reqs
            .to_strict()
            .expect("PaymentRequirements is representable as a mirror");
        q.offers = vec![Offer {
            accept,
            finality: Some(p.finality.into()),
            // commit the merchant's net destination so the split address binds it.
            merchant_net: Some(self.payout.clone()),
            two_leg: None,
        }];
        q.sign(&self.signing_key);
        BaselineQuote {
            quote: q,
            split_address,
            accept_reqs,
        }
    }

    /// Redeem a presented baseline quote against the payer's payment authorization
    /// (F4.4). Settlement precedes delivery: the merchant settles the presented
    /// transfer itself, confirms rail finality, atomically consumes the nonce, then
    /// returns the signed receipt.
    ///
    /// **construction-proof**: the store MUST be a sealed [`DurableMerchantStore`] (the durable
    /// [`WalMerchantStore`], a future DB profile) — an in-memory / downstream volatile store cannot
    /// be passed, so a proof deployment cannot lose its consumed-nonce record on a restart and
    /// double-deliver a replayed payment. The demo/test build additionally exposes a
    /// `&dyn MerchantStore` form (feature-gated) for the virtual-rail suite.
    #[cfg(not(any(test, feature = "demo")))]
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_baseline<S: DurableMerchantStore>(
        &self,
        presented_json: &str,
        expected_resource: &str,
        transfer: Transfer,
        settle_id: [u8; 32],
        rail: &paytp_rail::VirtualRail,
        store: &S,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        self.redeem_baseline_inner(
            presented_json,
            expected_resource,
            transfer,
            settle_id,
            rail,
            store,
            now,
        )
    }

    /// Demo/test form — accepts any [`MerchantStore`] (incl. the in-memory one). Feature-gated OUT of
    /// a proof build, where [`Merchant::redeem_baseline`] requires a durable store.
    #[cfg(any(test, feature = "demo"))]
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_baseline(
        &self,
        presented_json: &str,
        expected_resource: &str,
        transfer: Transfer,
        settle_id: [u8; 32],
        rail: &paytp_rail::VirtualRail,
        store: &dyn MerchantStore,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        self.redeem_baseline_inner(
            presented_json,
            expected_resource,
            transfer,
            settle_id,
            rail,
            store,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_baseline_inner(
        &self,
        presented_json: &str,
        expected_resource: &str,
        transfer: Transfer,
        settle_id: [u8; 32],
        rail: &paytp_rail::VirtualRail,
        store: &dyn MerchantStore,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        // 1. Re-verify our own signature and parse (§5.6: stores nothing yet).
        let q = Quote::parse_verify(presented_json, &self.key)
            .map_err(|_| RedeemError::QuoteInvalid)?;
        // Governed meed-vector validation (F5-o/F9.4): shape AND destination correctness
        // (0x13 == pinned Dev-Fund, 0x11 registry-listed-or-independent-fund) against our
        // retained registry snapshots. The merchant re-checks its own signed vector on receipt.
        q.validate_vector_governed(&self.registry)
            .map_err(|_| RedeemError::QuoteInvalid)?;
        // Resource binding (F3.4): the signed resource must match what is served.
        if q.resource != expected_resource {
            return Err(RedeemError::QuoteInvalid);
        }

        // 2. Locate the baseline offer and its terms. A baseline offer is one
        //    carrying no `twoLeg` (F3-h — the discriminator is twoLeg-
        //    presence, never the network value). `finality` is REQUIRED on it
        //    (F3.2); its absence is a malformed quote.
        let offer = q
            .offers
            .iter()
            .find(|o| o.two_leg.is_none())
            .ok_or(RedeemError::QuoteInvalid)?;
        let pay_to = member_str(&offer.accept, "payTo").ok_or(RedeemError::QuoteInvalid)?;
        let asset = member_str(&offer.accept, "asset").ok_or(RedeemError::QuoteInvalid)?;
        let amount: u128 = member_str(&offer.accept, "maxAmountRequired")
            .and_then(|s| s.parse().ok())
            .ok_or(RedeemError::QuoteInvalid)?;
        let required_finality = offer.finality.clone().ok_or(RedeemError::QuoteInvalid)?;

        // 3. Re-derive the split from the signed quote and refuse a payTo mismatch.
        // the split commits the signed net destination (`merchantNet`); a baseline
        // offer without it fails seed_split → QuoteInvalid (fail-closed).
        let seed = q
            .address_inputs(&self.key, &asset, offer.merchant_net.as_deref())
            .seed_split()
            .map_err(|_| RedeemError::QuoteInvalid)?;
        if rail.derive_address(&seed) != pay_to {
            return Err(RedeemError::QuoteInvalid);
        }

        // 4. Validate and settle the payer-presented payment authorization. The
        // transfer must match the signed quote before the merchant submits it; a
        // retry of the same `settle_id` returns the cached ref and moves no value.
        if transfer.to != pay_to || transfer.asset != asset || transfer.amount < amount {
            return Err(RedeemError::PaymentUnverified);
        }
        let payment_ref = rail
            .settle(transfer, settle_id)
            .map_err(|_| RedeemError::PaymentUnverified)?;

        // 5. Confirm the payment itself (settlement precedes delivery, F4.4).
        //    The leg MUST reach the QUOTED finality token (F4.4), compared in the
        //    rail's declared total order (F8.1) — never a hard-coded level.
        let honor_deadline = q.exp.saturating_add(q.grace);
        let fin = rail
            .finality(&payment_ref)
            .ok_or(RedeemError::PaymentUnverified)?;
        let levels = rail.caps().finality_levels;
        let idx = |lvl: &str| levels.iter().position(|l| l == lvl);
        let reached_ok = match (idx(&fin.level), idx(&required_finality)) {
            (Some(reached), Some(required)) => reached >= required,
            _ => false,
        };
        if !reached_ok {
            return if now > honor_deadline {
                Err(RedeemError::Expired)
            } else {
                Err(RedeemError::PaymentUnverified)
            };
        }
        // Honor rule (§5.6): a leg reaching quoted finality within exp+grace MUST
        // be honored; reaching it *after* the window is expired.
        if fin.time > honor_deadline {
            return Err(RedeemError::Expired);
        }

        // Re-read the canonical rail fact after settlement. The payment must be the
        // full amount, in the quoted asset, to the quoted split. Cross-nonce replay
        // is decided below by `consume_nonce` keyed on `info.canonical`.
        let info = rail
            .ref_target(&payment_ref)
            .ok_or(RedeemError::PaymentUnverified)?;
        if info.to != pay_to || info.asset != asset || info.amount < amount {
            return Err(RedeemError::PaymentUnverified);
        }
        if store::has_reserved_ref_delimiter(&info.canonical) {
            return Err(RedeemError::PaymentUnverified);
        }

        // 6. Atomically consume the nonce BEFORE delivery, then sign the receipt.
        //    The record binds the full decision tuple (F4.4) — ref, idem, and the
        //    resource — so only an exact retry returns the stored receipt.
        let accept = offer.accept.clone();
        let network = q.baseline.clone();
        let split_ref = payment_ref.0.clone();
        let sk = self.signing_key;
        let record = store::NonceRecord {
            // Key the payment-ref replay guard on the rail's CANONICAL reference, so the settlement
            // the merchant created for one nonce cannot back a different nonce. On `VirtualRail`
            // refs are 1:1 so canonical == presented. Consistent with the channel plane's F6-d.
            payment_ref: info.canonical.clone(),
            idem: q.idem.clone(),
            resource: q.resource.clone(),
            quote_sig: q.signature.unwrap_or([0u8; 64]),
        };
        let mut build = || {
            let mut r = Receipt::baseline(&q, accept.clone(), &network, &split_ref, now);
            r.sign(&sk);
            r
        };
        store
            .consume_nonce(q.nonce, &record, &mut build)
            .map_err(|e| match e {
                StoreError::Replayed => RedeemError::Replayed,
                StoreError::Unavailable => RedeemError::StoreUnavailable,
            })
    }
}
