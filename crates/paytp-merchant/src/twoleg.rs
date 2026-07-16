//! The two-leg Tier 0 flow (**F4.4/F4.5/F7.2**, §5.6).
//!
//! A two-leg purchase splits into a **net** leg (the merchant's share, on the
//! agreed rail) and a **meed** leg (converted to baseline units, funded into
//! the meed instance as an entry). The merchant re-derives the instance and
//! `entry_id` from its own signed quote (F4.2 — the id commits the amount and
//! window deadlines), confirms both legs at quoted finality, consumes the nonce,
//! signs the receipt, and posts the attestation that releases the entry to the
//! meed recipients.

use crate::{member_pub, member_str_pub, store, sv_pub, Merchant, MerchantStore, RedeemError};
use paytp_core::derive::entry_id_purchase;
use paytp_core::jcs::StrictValue;
use paytp_core::tier0::quote::{MeedEntry, Offer, Quote};
use paytp_core::tier0::receipt::PaidLeg;
use paytp_core::tier0::Receipt;
use paytp_rail::{RailAdapter, RailRef, VirtualRail};

/// F3-g/F8: `twoLeg` time fields are bounded to 2^53−1 so the derived T_open/T_lapse
/// windows cannot overflow — the merchant rejects an out-of-domain quote rather than
/// wrap/panic when re-deriving the entry.
const MAX_TIME: u64 = (1u64 << 53) - 1;

/// Parse a canonical (F1-c) unsigned integer string, rejecting non-minimal forms like
/// "007" that a conformant peer would reject — never `parse` an un-validated numeric.
fn canon_u128(s: impl AsRef<str>) -> Option<u128> {
    let s = s.as_ref();
    paytp_core::jcs::validate_uint_string(s).ok()?;
    s.parse().ok()
}
fn canon_u64(s: impl AsRef<str>) -> Option<u64> {
    let s = s.as_ref();
    paytp_core::jcs::validate_uint_string(s).ok()?;
    s.parse().ok()
}

/// Inputs for a two-leg quote.
pub struct TwoLegParams<'a> {
    pub resource: &'a str,
    pub nonce: [u8; 32],
    pub exp: u64,
    pub idem: Vec<u8>,
    pub registry_version: u32,
    /// The net-leg rail (CAIP-2) and asset, and the net amount to the merchant.
    pub net_network: &'a str,
    pub net_asset: &'a str,
    pub net_amount: u128,
    /// The baseline rail (CAIP-2) and asset the meed instance settles on.
    pub baseline_network: &'a str,
    pub baseline_asset: &'a str,
    /// The meed amount in baseline minimum units (already converted, F7.2).
    pub meed_amount: u128,
    /// The pinned conversion rate as a canonical decimal string (F3-c).
    pub rate: &'a str,
    pub rate_source: &'a str,
    pub reclaim: u64,
    pub contest: u64,
    pub grace: u64,
    pub retry: u64,
    pub fin_meed: &'a str,
    pub fin_net: &'a str,
    pub vector: Vec<MeedEntry>,
}

/// What [`Merchant::build_two_leg_quote`] returns.
pub struct TwoLegQuote {
    pub quote: Quote,
    pub instance_address: String,
    pub entry_id: [u8; 32],
    /// The absolute rail-clock deadlines the entry was derived with (F4.3/F8).
    pub t_open: u64,
    pub t_lapse: u64,
    /// The WHOLE two-leg offer — the net-leg `accept` AND the `twoLeg` terms the operator
    /// approves, and the wallet's F3-a mirror check (`Wallet::plan_two_leg`) binds the funded
    /// offer to. Held so a caller passes the operator-approved terms the wallet proves the signed
    /// offer equals (closing net- AND meed-term substitution alike).
    pub offer: Offer,
}

fn two_leg_offer(p: &TwoLegParams, merchant_net_payout: &str) -> Offer {
    let accept = StrictValue::Object(vec![
        ("scheme".into(), sv_pub("exact")),
        ("network".into(), sv_pub(p.net_network)),
        ("asset".into(), sv_pub(p.net_asset)),
        // The shipped x402 V1 amount field is `maxAmountRequired` (F3-j), the same name the
        // baseline offer's mirror uses — a two-leg `accept` is an accepts-entry mirror too.
        ("maxAmountRequired".into(), sv_pub(p.net_amount.to_string())),
        ("payTo".into(), sv_pub(merchant_net_payout)),
    ]);
    let two_leg = StrictValue::Object(vec![
        ("asset".into(), sv_pub(p.baseline_asset)),
        ("meed".into(), sv_pub(p.meed_amount.to_string())),
        ("rate".into(), sv_pub(p.rate)),
        ("rateSource".into(), sv_pub(p.rate_source)),
        ("reclaim".into(), sv_pub(p.reclaim.to_string())),
        ("contest".into(), sv_pub(p.contest.to_string())),
        (
            "finality".into(),
            StrictValue::Object(vec![
                ("meed".into(), sv_pub(p.fin_meed)),
                ("net".into(), sv_pub(p.fin_net)),
            ]),
        ),
    ]);
    Offer {
        accept,
        finality: None,
        // A two-leg offer has no split: its net leg pays `accept.payTo` directly, so it
        // carries no split merchant-net seat (the field is baseline-split-only).
        merchant_net: None,
        two_leg: Some(two_leg),
    }
}

impl Merchant {
    /// Build, deploy the meed instance for, and sign a two-leg quote.
    pub fn build_two_leg_quote(&self, rail: &VirtualRail, p: TwoLegParams) -> TwoLegQuote {
        let offer = two_leg_offer(&p, &self.payout);
        // The whole two-leg offer — the terms the operator approves; the wallet's F3-a mirror
        // binds the funded offer to it (see `TwoLegQuote::offer`).
        let approved_offer = offer.clone();
        let mut q = Quote {
            v: "1".into(),
            resource: p.resource.into(),
            nonce: p.nonce,
            exp: p.exp,
            idem: p.idem.clone(),
            schema: paytp_core::consts::SCHEMA_V0_1,
            contract: paytp_core::consts::CONTRACT_VERSION_V0_1,
            registry: p.registry_version,
            baseline: p.baseline_network.into(),
            grace: p.grace,
            retry: p.retry,
            vector: p.vector.clone(),
            offers: vec![offer],
            signature: None,
        };
        // Build intentionally does NOT schema-validate `p.vector` (F3.2/§10.1): the
        // ENDPOINTS validate, not the quote builder. The wallet checks the vector at plan
        // time (`plan_two_leg`) — the payer never relies on the merchant to validate the
        // vector that routes its meed (end-to-end) — and the merchant itself
        // re-validates at `redeem_two_leg` before it attests/distributes (validate before
        // you ACT, not when you quote). A self-invalid vector here only yields a quote no
        // one can redeem — a merchant misconfig, never a payer risk — and
        // `MeedInstance::new` saturates rather than panics on a malformed same-dest fold.
        // Deploy the meed instance (counterfactual) and derive its address. The bound deploy
        // recomputes the seed from `inputs` and binds the merchant key + meed destinations the
        // SAME canonical ADDRESS_INPUTS commit.
        let inputs = q.address_inputs(&self.key, p.baseline_asset, None);
        let seed = inputs.seed_instance().expect("seed");
        let instance_address = rail
            .deploy_instance(&seed, &inputs)
            .expect("merchant two-leg instance inputs are well-formed");
        // Absolute rail-clock deadlines (F4.3/F8): T_open = exp+grace,
        // T_lapse = T_open + reclaim. Saturating (consistent with honor_deadline) so a
        // misconfigured/hostile time field never overflow-panics the builder; the
        // verifying sides (wallet plan, redeem) reject an out-of-domain window.
        let t_open = p.exp.saturating_add(p.grace);
        let t_lapse = t_open.saturating_add(p.reclaim);
        let entry_id =
            entry_id_purchase(&seed, &p.nonce, p.meed_amount, t_open, t_lapse, p.contest);
        q.sign(&self.signing_key);
        TwoLegQuote {
            quote: q,
            instance_address,
            entry_id,
            t_open,
            t_lapse,
            offer: approved_offer,
        }
    }

    /// Redeem a two-leg quote against the meed-leg funding ref and the net-leg
    /// payment ref (F4.4). Verifies both legs at quoted finality, consumes the
    /// nonce, signs the receipt, and posts the attestation that releases the
    /// entry to the meed recipients.
    ///
    /// **construction-proof**: the store MUST be a sealed [`crate::DurableMerchantStore`] — a proof
    /// deployment cannot pass an in-memory / downstream volatile store and double-deliver a replayed
    /// two-leg payment on restart. (The two-leg cross-nonce bar is the derived `entry_id`,
    /// which commits the nonce; the consumed-nonce guard is durable defense-in-depth.) The demo/test
    /// build additionally exposes a `&dyn MerchantStore` form (feature-gated).
    #[cfg(not(any(test, feature = "demo")))]
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_two_leg<S: crate::DurableMerchantStore>(
        &self,
        presented_json: &str,
        expected_resource: &str,
        meed_ref: &RailRef,
        net_ref: &RailRef,
        rail: &VirtualRail,
        store: &S,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        self.redeem_two_leg_inner(
            presented_json,
            expected_resource,
            meed_ref,
            net_ref,
            rail,
            store,
            now,
        )
    }

    /// Demo/test form — accepts any [`MerchantStore`]. Feature-gated OUT of a proof build.
    #[cfg(any(test, feature = "demo"))]
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_two_leg(
        &self,
        presented_json: &str,
        expected_resource: &str,
        meed_ref: &RailRef,
        net_ref: &RailRef,
        rail: &VirtualRail,
        store: &dyn MerchantStore,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        self.redeem_two_leg_inner(
            presented_json,
            expected_resource,
            meed_ref,
            net_ref,
            rail,
            store,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_two_leg_inner(
        &self,
        presented_json: &str,
        expected_resource: &str,
        meed_ref: &RailRef,
        net_ref: &RailRef,
        rail: &VirtualRail,
        store: &dyn MerchantStore,
        now: u64,
    ) -> Result<Receipt, RedeemError> {
        let q = Quote::parse_verify(presented_json, &self.key)
            .map_err(|_| RedeemError::QuoteInvalid)?;
        // Governed meed-instance-vector validation (F5-o/F9.4): shape AND destination correctness
        // against the merchant's retained registry snapshots (the payer must never rely on the
        // merchant to check it, and vice versa).
        q.validate_vector_governed(&self.registry)
            .map_err(|_| RedeemError::QuoteInvalid)?;
        // (F3-a): a two-leg offer MUST NOT carry `merchantNet`; a baseline offer MUST.
        q.validate_baseline_merchant_net()
            .map_err(|_| RedeemError::QuoteInvalid)?;
        if q.resource != expected_resource {
            return Err(RedeemError::QuoteInvalid);
        }

        if store::has_reserved_ref_delimiter(&meed_ref.0)
            || store::has_reserved_ref_delimiter(&net_ref.0)
        {
            return Err(RedeemError::PaymentUnverified);
        }

        // Idempotency (§5.6): a retry matching the consumed-nonce record exactly
        // returns the stored receipt — checked BEFORE re-verifying the payment,
        // whose entry may since have advanced (FUNDED → ATTESTED).
        let combined_ref = format!(
            "{}{}{}",
            meed_ref.0,
            store::PAYMENT_REF_DELIMITER,
            net_ref.0
        );
        let record = store::NonceRecord {
            payment_ref: combined_ref,
            idem: q.idem.clone(),
            resource: q.resource.clone(),
            quote_sig: q.signature.unwrap_or([0u8; 64]),
        };
        match store.peek(q.nonce, &record) {
            store::Peek::Stored(r) => return Ok(*r),
            store::Peek::Replayed => return Err(RedeemError::Replayed),
            store::Peek::Fresh => {}
        }
        // The two-leg offer is the one carrying `twoLeg` (F3-h).
        let offer = q
            .offers
            .iter()
            .find(|o| o.two_leg.is_some())
            .ok_or(RedeemError::QuoteInvalid)?;
        let tl = offer.two_leg.as_ref().ok_or(RedeemError::QuoteInvalid)?;

        let net_pay_to = member_str_pub(&offer.accept, "payTo").ok_or(RedeemError::QuoteInvalid)?;
        let net_asset = member_str_pub(&offer.accept, "asset").ok_or(RedeemError::QuoteInvalid)?;
        // The net amount is an x402-envelope field (external conventions, not PayTP F1-c) — parse
        // permissively. Shipped x402 V1 uses `maxAmountRequired` (F3-j, what the RI emits); fall
        // back to the older `amount` key ONLY when `maxAmountRequired` is absent, mirroring the
        // baseline path's backward-compat read, so a two-leg quote from an un-updated peer is not
        // hard-rejected for the key spelling alone. The PayTP-native twoLeg fields below ARE canonical.
        let net_amount: u128 = member_str_pub(&offer.accept, "maxAmountRequired")
            .or_else(|| member_str_pub(&offer.accept, "amount"))
            .and_then(|s| s.parse().ok())
            .ok_or(RedeemError::QuoteInvalid)?;
        let baseline_asset = member_str_pub(tl, "asset").ok_or(RedeemError::QuoteInvalid)?;
        let meed_amount: u128 = member_str_pub(tl, "meed")
            .and_then(canon_u128)
            .ok_or(RedeemError::QuoteInvalid)?;
        let reclaim: u64 = member_str_pub(tl, "reclaim")
            .and_then(canon_u64)
            .filter(|&t| t <= MAX_TIME)
            .ok_or(RedeemError::QuoteInvalid)?;
        let contest: u64 = member_str_pub(tl, "contest")
            .and_then(canon_u64)
            .filter(|&t| t <= MAX_TIME)
            .ok_or(RedeemError::QuoteInvalid)?;
        let fin = member_pub(tl, "finality").ok_or(RedeemError::QuoteInvalid)?;
        let fin_meed = member_str_pub(fin, "meed").ok_or(RedeemError::QuoteInvalid)?;
        let fin_net = member_str_pub(fin, "net").ok_or(RedeemError::QuoteInvalid)?;

        // Re-derive the instance + entry_id from our own signed quote (F4.2).
        let seed = q
            .address_inputs(&self.key, &baseline_asset, None)
            .seed_instance()
            .map_err(|_| RedeemError::QuoteInvalid)?;
        let instance_addr = rail.derive_address(&seed);
        // Checked: a pathological grace/reclaim in the presented quote must not
        // overflow-panic the merchant when re-deriving the entry window.
        let t_open = q
            .exp
            .checked_add(q.grace)
            .ok_or(RedeemError::QuoteInvalid)?;
        let t_lapse = t_open
            .checked_add(reclaim)
            .ok_or(RedeemError::QuoteInvalid)?;
        let entry_id = entry_id_purchase(&seed, &q.nonce, meed_amount, t_open, t_lapse, contest);

        let honor_deadline = q.exp.saturating_add(q.grace);
        let levels = rail.caps().finality_levels;
        let idx = |lvl: &str| levels.iter().position(|l| l == lvl);
        let leg_final = |r: &RailRef, required: &str| -> Result<(), RedeemError> {
            let f = rail.finality(r).ok_or(RedeemError::PaymentUnverified)?;
            let ok = match (idx(&f.level), idx(required)) {
                (Some(a), Some(b)) => a >= b,
                _ => false,
            };
            if !ok {
                return Err(if now > honor_deadline {
                    RedeemError::Expired
                } else {
                    RedeemError::PaymentUnverified
                });
            }
            if f.time > honor_deadline {
                return Err(RedeemError::Expired);
            }
            Ok(())
        };

        // Meed leg: the funding ref must be THE ref that funded THIS derived
        // entry (F4-c commits the amount), in the baseline asset, bound to the
        // nonce, and reached the quoted meed finality. Binding to
        // `funds_entry` prevents an unrelated final transfer to the instance from
        // satisfying the meed-leg finality check.
        let ri = rail
            .ref_target(meed_ref)
            .ok_or(RedeemError::PaymentUnverified)?;
        if ri.funds_entry != Some(entry_id)
            || ri.asset != baseline_asset
            || ri.memo != Some(q.nonce)
        {
            return Err(RedeemError::PaymentUnverified);
        }
        leg_final(meed_ref, &fin_meed)?;
        // FUNDED or RECLAIM_OPEN — both mean the meed is funded and not yet
        // terminal; the merchant MAY deliver against a reclaim-open entry (F4.4)
        // only if enough contest margin remains for its attestation to land.
        match rail.entry_status(&instance_addr, &entry_id) {
            Some(paytp_rail::EntryStatus::Funded) => {}
            // C1-4: a crash between posting the attestation (rail, durable) and consuming the nonce
            // (merchant store) leaves the entry ATTESTED with the nonce still FRESH — so the peek
            // above does NOT short-circuit and the flow reaches here on retry. Only THIS merchant
            // could have attested THIS derived entry_id, so an already-attested entry is idempotent
            // SUCCESS: fall through, the re-post below is a tolerated no-op, and the nonce is consumed
            // and the receipt returned. Rejecting it (the old `_` arm) left the payer paid on BOTH
            // legs with no delivery and no receipt.
            Some(paytp_rail::EntryStatus::Attested) => {}
            Some(paytp_rail::EntryStatus::ReclaimOpen) => {
                let t_exec = rail
                    .reclaim_exec_time(&instance_addr, &entry_id)
                    .ok_or(RedeemError::PaymentUnverified)?;
                // F8-f: require a safety margin of TWICE the adapter's declared inclusion
                // latency before T_exec — so the attestation posted below lands before a
                // permissionless execute_reclaim strips the meed on an async rail.
                let margin = rail.caps().inclusion_latency.saturating_mul(2);
                if now.saturating_add(margin) >= t_exec {
                    return Err(RedeemError::PaymentUnverified); // insufficient reclaim margin
                }
            }
            _ => return Err(RedeemError::PaymentUnverified),
        }

        // Net leg: full amount, quoted asset, to the merchant, bound to the nonce.
        leg_final(net_ref, &fin_net)?;
        let ni = rail
            .ref_target(net_ref)
            .ok_or(RedeemError::PaymentUnverified)?;
        if ni.to != net_pay_to
            || ni.asset != net_asset
            || ni.amount < net_amount
            || ni.memo != Some(q.nonce)
        {
            return Err(RedeemError::PaymentUnverified);
        }

        // Post the attestation that releases the meed to the recipients BEFORE
        // delivery (settlement precedes delivery, F4.4) and REQUIRE it to take
        // effect — tolerating an already-ATTESTED entry (idempotent), rejecting a
        // withdrawn (reclaimed/cancelled) one.
        let att = self.make_attestation(q.nonce, entry_id);
        if rail.attest_entry(&instance_addr, entry_id, &att).is_err()
            && rail.entry_status(&instance_addr, &entry_id)
                != Some(paytp_rail::EntryStatus::Attested)
        {
            return Err(RedeemError::PaymentUnverified);
        }

        // Consume the nonce BEFORE delivery (F4.4), keyed by both legs' refs.
        let accept = offer.accept.clone();
        let sk = self.signing_key;
        let (net_network, baseline_network) = (
            member_str_pub(&offer.accept, "network").unwrap_or_default(),
            q.baseline.clone(),
        );
        let (rmeed, rnet) = (meed_ref.0.clone(), net_ref.0.clone());
        let mut build = || {
            let mut r = Receipt {
                nonce: q.nonce,
                idem: q.idem.clone(),
                resource: q.resource.clone(),
                accept: accept.clone(),
                // Execution order: meed then net (F3.4).
                paid: vec![
                    PaidLeg {
                        leg: "meed".into(),
                        network: baseline_network.clone(),
                        reference: rmeed.clone(),
                    },
                    PaidLeg {
                        leg: "net".into(),
                        network: net_network.clone(),
                        reference: rnet.clone(),
                    },
                ],
                entry: Some(entry_id),
                ts: now,
                signature: None,
            };
            r.sign(&sk);
            r
        };
        let receipt = store
            .consume_nonce(q.nonce, &record, &mut build)
            .map_err(|e| match e {
                store::StoreError::Replayed => RedeemError::Replayed,
                store::StoreError::Unavailable => RedeemError::StoreUnavailable,
            })?;
        Ok(receipt)
    }
}

// The instance meed division is now derived by the bound `VirtualRail::deploy_instance` from the
// signed quote's `ADDRESS_INPUTS` and aggregated by `MeedInstance::new`; the saturating
// same-dest fold is covered directly by `paytp-rail` `instance::new_saturates_bp_subtotal_no_
// overflow_panic_or_zero`, so the former `instance_shares` mirror + its test were retired.
