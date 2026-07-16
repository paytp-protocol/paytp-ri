//! Tier 0 execution — baseline and two-leg (§5.6, F4.4/F4.5).
//!
//! The wallet never trusts a merchant-supplied address: it **re-derives** where to
//! pay from the signed quote (F4.1) and refuses if the derivation disagrees. Two
//! safety properties are enforced here, not left to the caller:
//! - every value-moving step passes the [`WalletPolicy`] gate first;
//! - the two-leg net leg **MUST NOT** start before the meed leg shows the quoted
//!   finality (F4.5, "meed first — and first means final").

use crate::custody::{Custody, PayerScope};
use crate::policy::{Decision, PathCandidate, PathSelection, WalletPolicy};
use paytp_core::channel::establish::{AcceptedBinding, BindingArtifact};
use paytp_core::consts::MEED_CAP_BP;
use paytp_core::derive::entry_id_purchase;
use paytp_core::jcs::StrictValue;
use paytp_core::registry::SnapshotStore;
use paytp_core::tier0::quote::{ExpectedDest, Offer, Quote};
use paytp_core::x402::PaymentRequirements;
use paytp_rail::{RailAdapter, RailCaps, RailRef, Transfer, TransferKind, VirtualRail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// The policy declined (with its static reason).
    PolicyDenied(&'static str),
    /// The signed quote failed validation (F3).
    QuoteInvalid,
    /// The split/instance address could not be derived from the quote.
    Derivation,
    /// The rail refused the transfer.
    Rail(String),
    /// The meed leg had not reached the quoted finality when the net leg was
    /// attempted (F4.5 — first means final).
    MeedNotFinal,
    /// The merchant-quoted entry id disagrees with the wallet's re-derivation.
    EntryIdMismatch,
    /// The signed quote's resource is not the one the operator requested — a compromised
    /// interaction layer substituting a different-resource quote (F3-a).
    ResourceMismatch,
    /// No signed baseline offer mirrors the outer x402 `accepts[]` entry the operator
    /// approved — the F3-a mirror rule. A different but validly-signed same-resource quote
    /// was substituted for the one the outer envelope prices (menu-tampering / bait-and-switch,
    /// F3.2), so the wallet MUST NOT apply PayTP execution to it.
    MirrorMismatch,
    /// The authenticated merchant origin host is not the host of the operator-requested
    /// resource. A quote signed by a self-consistent but different origin cannot fund itself
    /// for another host's resource.
    OriginResourceMismatch,
    /// The merchant binding artifact failed parsing or F2.2 acceptance against the
    /// intended origin connection.
    OriginBindingInvalid,
    /// The quote is well-formed and signed, but the two-leg flow it describes cannot
    /// COMPLETE inside the honor boundary (F4.5/F8.5 pre-flight): a non-positive
    /// reclaim/contest, an asset the rail does not route, or a declared finality
    /// unreachable within `exp + grace`. The wallet refuses BEFORE funding the meed leg,
    /// so the payer never funds a purchase that can only end in reclaim. The
    /// static reason names which feasibility gate failed.
    QuoteInfeasible(&'static str),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WalletError {}

/// The baseline payment authorization a payer presents to the merchant under Design A.
/// The `Transfer` is the signed payment intent; `settle_id` stands in for the signed
/// transaction identity and makes merchant settlement idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselinePayment {
    pub transfer: Transfer,
    pub settle_id: [u8; 32],
}

/// A TRUSTED source of the non-price cost components — rail fee / gas / conversion — the wallet
/// adds to a path's merchant-signed price to get the payer's total cost (§10.3). The wallet reads
/// costs from THIS, **never** from the untrusted interaction layer: a rate/oracle adapter the
/// wallet controls in production; the F10.6 harness pins it with fixture values. Keeping the cost
/// input on the trusted side is what stops the IL spoofing a path cheap to steer selection into
/// its own meed-maximal choice.
pub trait RateSource {
    /// The payer's non-price cost (µ-units) to settle the path identified by `id` — a stable,
    /// wallet-controlled figure independent of anything the interaction layer asserts.
    fn path_cost(&self, id: u32) -> u128;
}

/// One offered path as the wallet assembles it from the **verified** signed quote, before adding
/// the trusted rate. `price` and `meed_share_bp` both come from merchant-SIGNED data (the offer's
/// amount and the `MEED_VECTOR`), so the only thing the interaction layer contributes is which
/// signed offers exist — never a cost or a meed figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfferPath {
    /// Path/offer id (e.g. the offer index in the signed quote).
    pub id: u32,
    /// The merchant-SIGNED price for this path (µ-units), read from the verified quote.
    pub price: u128,
    /// The meed share (bp) the wallet earns on this path, from the signed `MEED_VECTOR`
    /// (`0` for a non-PayTP path). Disclosure-only — never an input to the choice.
    pub meed_share_bp: u16,
}

/// A wallet: custody (the spend boundary) + a policy (spending authority) + the payer's retained
/// role-registry snapshots (F9-d). The policy is a type parameter so an interaction layer can
/// substitute any [`WalletPolicy`] implementation (§10.4). The `registry` is the trusted anchor the
/// governed meed-vector check (F5-o/F9.4) resolves `0x11` OS destinations against **before paying**
/// (F3 `03-tier0-objects.md:58`) — the payer never relies on the merchant to validate the vector.
pub struct Wallet<'c, P: WalletPolicy> {
    custody: &'c Custody,
    policy: P,
    registry: &'c SnapshotStore,
    /// The wallet's OWN expected `0x12` meed-payout pointer (**F5-o self-defense**).
    /// `Some(dest)` when the wallet participates in the meed (its `0x12` share MUST
    /// route here); `None` when it asserts no share (its `0x12` entry MUST be the
    /// Dev-Fund fallback, F9.4 step 3). This is **trusted wallet config**, NEVER taken
    /// from the untrusted interaction layer or the merchant-signed quote — that is the
    /// whole point: neither can reroute the wallet's own share by asserting a different
    /// `0x12`, because the wallet checks the vector against THIS before paying/signing.
    meed_dest: Option<String>,
}

impl<'c, P: WalletPolicy> Wallet<'c, P> {
    /// Construct a wallet with an **empty** registry — enough when every quote it pays routes its
    /// `0x11` OS share to the version-agnostic independent-OS-fund fallback (§10.1). A payer that
    /// pays quotes naming registry-listed OS recipients MUST use [`Wallet::with_registry`].
    /// The wallet asserts **no** `0x12` meed share by default (its `0x12` entry must be the
    /// Dev-Fund fallback); a wallet that earns meed sets its payout pointer with
    /// [`Wallet::with_meed_dest`].
    pub fn new(custody: &'c Custody, policy: P) -> Self {
        Wallet {
            custody,
            policy,
            registry: SnapshotStore::empty_ref(),
            meed_dest: None,
        }
    }

    /// As [`Wallet::new`], with the payer's retained role-registry snapshots (F9-d) — the registry
    /// the governed meed-vector check resolves `0x11` OS destinations against before paying.
    pub fn with_registry(custody: &'c Custody, policy: P, registry: &'c SnapshotStore) -> Self {
        Wallet {
            custody,
            policy,
            registry,
            meed_dest: None,
        }
    }

    /// Set the wallet's OWN `0x12` meed-payout pointer (F5-o self-defense) — where its
    /// earned wallet share MUST route. With this set, the wallet REJECTS any quote /
    /// `CHANNEL_AUTH` whose `0x12` entry is a different destination, so a hostile
    /// merchant or interaction layer cannot reroute the wallet's meed to itself and
    /// have the wallet pay/sign it. Trusted config; the reference wallet's own address.
    pub fn with_meed_dest(mut self, dest: impl Into<String>) -> Self {
        self.meed_dest = Some(dest.into());
        self
    }

    /// The wallet's own `0x12` expectation for the payer-side self-defense check: its
    /// configured payout pointer if it earns meed, else the Dev-Fund fallback (F9.4
    /// step 3 — an unasserted `0x12` routes to the Dev Fund, never a caller-chosen dest).
    fn wallet_meed_expectation(&self) -> ExpectedDest<'_> {
        match &self.meed_dest {
            Some(d) => ExpectedDest::Asserted(d),
            None => ExpectedDest::Unasserted,
        }
    }

    /// The payer's public identity key **for a given merchant scope** (F1-f/F2.3).
    /// A scoped wallet has no single global identity — the key it presents is
    /// per-`(merchant, registrable-domain)`, so a caller that wants "the payer key at
    /// merchant X" resolves a [`PayerScope`] (via [`PayerScope::resolve`]) and asks for
    /// that. Baseline Tier-0 payment (`pay_baseline`) puts no payer key on the wire, so
    /// this is an identity accessor, not part of the baseline value path.
    pub fn payer_key(&self, scope: &PayerScope) -> [u8; 32] {
        self.custody.payer_key(scope)
    }

    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// §10.3 path selection behind the TRUSTED wallet boundary. The payer's total cost for each path
    /// is the merchant-SIGNED `price` plus the TRUSTED `rates` source's non-price cost —
    /// **never a cost figure the untrusted interaction layer asserts** — so the IL cannot spoof a
    /// path cheap to steer the wallet off the cost-minimal / operator-policy choice into its own
    /// meed-maximal one. The pure operator policy ([`WalletPolicy::select_path`]) then decides:
    /// cost-minimal unless the operator authorizes a costlier path (delta disclosed), honoring any
    /// operator exclusion over the wallet's own meed. Returns `None` iff no path is selectable.
    ///
    /// This is the selection SURFACE (the wallet↔offer-set API); assembling `paths` from a specific
    /// signed quote (offer amounts + the earned `MEED_VECTOR` share) is the caller's, exactly as
    /// F10.6 pins the harness cost fixtures — the multi-quote PayTP-vs-plain offer set the payer
    /// chooses among is not modeled by the RI's single-quote flow today.
    pub fn select_path(
        &self,
        paths: &[OfferPath],
        rates: &dyn RateSource,
    ) -> Option<PathSelection> {
        let candidates: Vec<PathCandidate> = paths
            .iter()
            .map(|p| PathCandidate {
                id: p.id,
                // Total payer cost = signed price + trusted non-price cost. `saturating_add` bounds a
                // pathological rate rather than wrapping; a saturated cost only makes a path look
                // MORE expensive (never spuriously cheapest), so it cannot mis-steer selection.
                cost: p.price.saturating_add(rates.path_cost(p.id)),
                meed_share_bp: p.meed_share_bp,
            })
            .collect();
        self.policy.select_path(&candidates)
    }

    /// Authenticate a candidate merchant identity to the origin connection the wallet
    /// intends to pay over (F2.2). The artifact is parsed and accepted by the same
    /// channel binding mechanism; Tier-0 then uses only the authenticated merchant key.
    pub fn accept_origin(
        &self,
        candidate_merchant_key: &[u8; 32],
        artifact_bytes: &[u8],
        conn_cert_hash: &[u8; 32],
        conn_host: &str,
        now: u64,
    ) -> Result<AcceptedBinding, WalletError> {
        let artifact = BindingArtifact::parse(artifact_bytes)
            .map_err(|_| WalletError::OriginBindingInvalid)?;
        let binding = artifact
            .accept(candidate_merchant_key, conn_cert_hash, conn_host, now)
            .map_err(|_| WalletError::OriginBindingInvalid)?;
        // The artifact's ENC_KEY is channel-only; Tier-0 needs only the authenticated merchant key.
        Ok(binding)
    }

    /// Pay a baseline Tier 0 quote (§5.6) from its **raw signed bytes**. The wallet
    /// **verifies the merchant signature itself** (`Quote::parse_verify`) — it does
    /// not trust a pre-parsed `Quote` struct handed to it by the (untrusted)
    /// interaction layer, which could forge one. The `amount`/`asset` are then read
    /// from the verified signed offer (never caller args), the split address is
    /// re-derived from the signed quote, and the payer returns a fresh payment
    /// authorization for the merchant to settle (F4.4 Design A). The merchant key
    /// comes from an [`AcceptedBinding`] minted by [`Wallet::accept_origin`], not
    /// from an unauthenticated discovery-context parameter. `requested_resource` is
    /// the resource the operator actually asked to pay for.
    /// The wallet binds the latter itself (`quote.resource == requested_resource`,
    /// F3.4) BEFORE any value moves — so a compromised IL that hands the wallet a
    /// validly-signed quote for a *different* resource cannot make it pay, exactly as
    /// [`Wallet::plan_two_leg`] does. The client re-checks this too (belt-and-
    /// suspenders), but the wallet must not depend on it: a hostile IL can call the
    /// wallet directly, bypassing the client, so the wallet is an independent verifier.
    ///
    /// `accept` is the outer x402 `accepts[]` entry the operator approved (a trusted
    /// operator-context input, exactly like `requested_resource`, never taken from the
    /// interaction layer). The wallet enforces the **F3-a mirror rule**: it applies
    /// PayTP execution ONLY to a signed baseline offer that mirrors `accept` — so an
    /// in-path party that substitutes a different validly-signed same-resource quote
    /// (a captured higher-amount offer) for the one the operator's envelope prices is
    /// refused BEFORE any authorization is produced (F3.2 menu-tampering). This is the
    /// wallet-side half of F3-a; the mirror-check primitive is
    /// [`paytp_core::x402::PaymentRequired::paytp_mirrored_accepts`].
    pub fn pay_baseline(
        &self,
        rail: &VirtualRail,
        quote_json: &str,
        accept: &PaymentRequirements,
        binding: &AcceptedBinding,
        requested_resource: &str,
    ) -> Result<BaselinePayment, WalletError> {
        let merchant_key = binding.merchant_key();
        require_binding_host_matches_resource(binding, requested_resource)?;
        // Verify the merchant signature over the received bytes FIRST — the wallet's
        // own trust anchor, independent of the interaction layer.
        let quote =
            Quote::parse_verify(quote_json, merchant_key).map_err(|_| WalletError::QuoteInvalid)?;
        // Bind the operator-requested resource BEFORE any value moves (F3.4): a compromised
        // interaction layer must not substitute a valid merchant-signed baseline quote for a
        // DIFFERENT resource than the operator requested. The client binds this too, but the
        // wallet must not rely on it — a hostile IL can call the wallet directly (`plan_two_leg`
        // binds the same way).
        if quote.resource != requested_resource {
            return Err(WalletError::ResourceMismatch);
        }
        // Governed Tier-0 validation BEFORE paying (F3 `03-tier0-objects.md:58`): the meed vector's
        // shape AND destination correctness (0x13 == pinned Dev-Fund, 0x11 registry-listed-or-fund)
        // against the payer's own registry — the wallet never relies on the merchant to check it.
        quote
            .validate_tier0(self.registry)
            .map_err(|_| WalletError::QuoteInvalid)?;
        // Payer-side self-defense (F5-o): the wallet's OWN `0x12` share MUST route to the
        // wallet's configured payout pointer (or the Dev-Fund fallback if it asserts none) —
        // so a hostile merchant that signed a quote rerouting the wallet's meed to itself is
        // rejected BEFORE the wallet pays. `0x10` is the interaction layer's own share to
        // defend (Unchecked here; the client checks it against the IL's assertion, F5-o).
        quote
            .validate_payer_side(ExpectedDest::Unchecked, self.wallet_meed_expectation())
            .map_err(|_| WalletError::QuoteInvalid)?;
        // F3-a mirror rule (the wallet-side half): apply PayTP execution ONLY to a signed
        // baseline offer that MIRRORS the outer `accept` the operator approved — equality of
        // the parsed x402 JSON (`PaymentRequirements::from_strict`, the same comparison
        // `PaymentRequired::paytp_mirrored_accepts` performs). A different but validly-signed
        // same-resource quote substituted for the one the operator's envelope prices mirrors
        // ITS OWN accept, not this one, so nothing matches → refuse before any authorization
        // (F3.2: the menu-tampering / bait-and-switch substitution attacks "die here"). Origin
        // auth (F2-k) and the resource bind above do NOT catch this — same merchant, same
        // resource — only the mirror does. Require EXACTLY ONE match: the merchant builds one
        // offer per priced accepts entry (F3-a), so two offers mirroring one approved accept is
        // a malformed quote, refused rather than silently picking one.
        let mut mirrored = quote.offers.iter().filter(|o| {
            o.two_leg.is_none()
                && PaymentRequirements::from_strict(&o.accept)
                    .map(|m| &m == accept)
                    .unwrap_or(false)
        });
        let offer = mirrored.next().ok_or(WalletError::MirrorMismatch)?;
        if mirrored.next().is_some() {
            return Err(WalletError::MirrorMismatch);
        }
        let asset = field_str(&offer.accept, "asset")?.to_string();
        let amount = baseline_amount(&offer.accept)?;

        // Baseline single-leg feasibility pre-flight (F8.1 `t_fin ≤ exp+grace` / F8.5): refuse to
        // AUTHORIZE a payment the merchant could only settle-then-Expire. Under Design A the
        // merchant settles the payer's authorization and THEN applies the honor rule
        // (`redeem_baseline`): a leg that cannot reach the required finality within `exp+grace` is
        // Expired AFTER settlement, and the baseline split has NO reclaim — so the payer would lose
        // the money for no delivery. The wallet is the payer's ONLY guard here (the baseline
        // analogue of `plan_two_leg`'s headroom pre-flight). The merchant settles no earlier than
        // the wallet authorizes (one shared, monotonic rail clock), so `chain_time() +
        // finality_delay` is a LOWER bound on the merchant's observed finality time — a quote
        // failing this is CERTAINLY Expired. Strictly conservative: it only ever REJECTS. (A quote
        // feasible here that a late merchant settle pushes past the window is the weaker residual
        // the merchant honor rule + a responsive merchant handle, outside this certain-loss guard.)
        let required_finality = offer.finality.as_deref().ok_or(WalletError::QuoteInvalid)?;
        let caps = rail.caps();
        // The quoted level must be one the rail DECLARES, else the payment can never reach it.
        if !caps.finality_levels.iter().any(|l| l == required_finality) {
            return Err(WalletError::QuoteInfeasible(
                "baseline finality level not on this rail",
            ));
        }
        // Honor boundary `T_open = exp + grace` (F8.4). Both `exp` and `grace` are ≤ 2^53−1 at
        // parse (F3-g), so the sum never overflows u64 — the `checked_add` is a fail-closed
        // backstop that yields the SAME value the merchant's `saturating_add` does for any
        // parseable quote (no false refusal from an overflow-handling mismatch).
        let t_open = quote
            .exp
            .checked_add(quote.grace)
            .ok_or(WalletError::QuoteInvalid)?;
        // The full `finality_delay` headroom applies only when the quote requires the rail's
        // STRONGEST finality (the settlement-precedes-delivery norm — every baseline quote the RI
        // issues requires it); a weaker level is honorable if the merchant redeems before it
        // upgrades, so only an already-expired quote is a certain loss.
        let is_strongest =
            caps.finality_levels.last().map(String::as_str) == Some(required_finality);
        if !baseline_headroom_ok(&caps, rail.chain_time(), is_strongest, t_open)? {
            return Err(WalletError::QuoteInfeasible(
                "baseline finality unreachable within exp+grace",
            ));
        }

        if let Decision::Deny(why) = self.policy.approve_quote(&quote, amount, &asset) {
            return Err(WalletError::PolicyDenied(why));
        }
        // F4.1: the split commits the merchant's signed net destination (`merchantNet`),
        // so the re-derived address binds the net seat. validate_tier0 above already
        // required it for a baseline offer; extract it for the derivation.
        let merchant_net = offer
            .merchant_net
            .as_deref()
            .ok_or(WalletError::QuoteInvalid)?;
        let seed = quote
            .address_inputs(merchant_key, &asset, Some(merchant_net))
            .seed_split()
            .map_err(|_| WalletError::Derivation)?;
        let split_addr = rail.derive_address(&seed);
        // Defense-in-depth (§5.6/F5.6): the re-derived split MUST equal the merchant's
        // signed `payTo`. Paying the re-derived split is already cryptographically safe,
        // but a mismatch signals a faulty/malicious merchant envelope — refuse, don't mask.
        let pay_to = field_str(&offer.accept, "payTo")?;
        quote
            .verify_split_pay_to(merchant_key, &asset, merchant_net, pay_to, |s| {
                rail.derive_address(s)
            })
            .map_err(|_| WalletError::QuoteInvalid)?;
        Ok(BaselinePayment {
            transfer: Transfer {
                to: split_addr,
                asset,
                amount,
                kind: TransferKind::Payment,
                memo: None,
            },
            settle_id: paytp_core::crypto::random_bytes::<32>(),
        })
    }

    /// Build a two-leg execution plan by reading every routing/amount field from
    /// the **verified signed quote** (F4.1/F4-c) — the meed instance address is
    /// re-derived, and the net leg's `payTo`/`amount`/`asset` plus the meed
    /// terms are extracted from the merchant-signed offer, **never** from the
    /// (untrusted) interaction layer. A compromised IL that passes a valid quote
    /// therefore cannot redirect the net leg or inflate the amount. The only
    /// payer-supplied input is `refund_ptr` (where the payer's own meed deposit
    /// returns on reclaim — not part of the merchant's offer).
    ///
    /// `approved_offer` is the WHOLE operator-approved two-leg offer (the net-leg `accept` **and**
    /// the `twoLeg` terms — meed, reclaim, contest, rate, finality — the operator selected; a
    /// trusted operator-context input, like `requested_resource`, never from the IL). The wallet
    /// enforces the **F3-a mirror rule** on two-leg funding (which F3-a lists as PayTP execution):
    /// it funds ONLY a signed offer that equals `approved_offer`, exactly one, else
    /// `MirrorMismatch`. Binding the FULL offer (not just the x402 `accept`) closes the whole
    /// substitution surface — a captured quote with an identical net `accept` but an inflated
    /// `meed` fee or a stretched `reclaim` window is refused too, not left to the policy budget /
    /// meed carve alone (F3.2 menu-tampering). It is the two-leg sibling of `pay_baseline`'s check.
    ///
    /// `expected_il` is the interaction layer's OWN asserted `0x10` meed pointer (F5-o):
    /// `Some(il)` makes the wallet reject a merchant-signed quote that reroutes the IL's
    /// `0x10` share to an attacker (the same self-defense the baseline client applies);
    /// `None` is an explicit scope-limit — no IL context is held here, so `0x10` is not
    /// checked (the wallet still always defends its OWN `0x12`).
    #[allow(clippy::too_many_arguments)]
    pub fn plan_two_leg(
        &self,
        rail: &VirtualRail,
        quote_json: &str,
        approved_offer: &Offer,
        binding: &AcceptedBinding,
        requested_resource: &str,
        refund_ptr: &str,
        expected_il: Option<&str>,
    ) -> Result<TwoLegPlan, WalletError> {
        let merchant_key = binding.merchant_key();
        require_binding_host_matches_resource(binding, requested_resource)?;
        // Verify the merchant signature over the received bytes FIRST (the wallet's
        // own anchor — it does not trust a pre-parsed struct from the IL). Two-leg
        // validation is the offer-shape checks below, not the baseline `validate_tier0`.
        let quote =
            Quote::parse_verify(quote_json, merchant_key).map_err(|_| WalletError::QuoteInvalid)?;
        // Bind the operator-requested resource: a compromised interaction layer must not
        // substitute a valid merchant-signed two-leg quote for a DIFFERENT resource (F3-a;
        // the baseline client flow binds this too).
        if quote.resource != requested_resource {
            return Err(WalletError::ResourceMismatch);
        }
        // Validate the meed vector against schema 0x01 AND governed destination correctness
        // (F5-o/F9.4: roles/bp/CAIP + 0x13 pinned Dev-Fund + 0x11 registry-listed-or-fund against
        // the payer's registry): the wallet must not fund a meed routed by a non-conformant OR
        // misrouted vector. The merchant's redeem path checks this, but the payer must
        // never rely on the merchant to.
        quote
            .validate_vector_governed(self.registry)
            .map_err(|_| WalletError::QuoteInvalid)?;
        // Payer-side self-defense (F5-o): the wallet's OWN `0x12` meed share MUST route to its
        // configured payout pointer (or the Dev-Fund fallback if unasserted), AND — when the IL
        // context is supplied — the IL's OWN `0x10` share MUST route to its asserted pointer. A
        // hostile merchant rerouting either payer-side share to itself is rejected BEFORE the meed
        // leg funds. `expected_il = None` is an explicit scope-limit (0x10 unchecked here).
        let il_expectation = match expected_il {
            Some(il) => ExpectedDest::Asserted(il),
            None => ExpectedDest::Unchecked,
        };
        quote
            .validate_payer_side(il_expectation, self.wallet_meed_expectation())
            .map_err(|_| WalletError::QuoteInvalid)?;
        // (F3-a): a two-leg offer MUST NOT carry `merchantNet` (no split, no net
        // seat); any baseline offer in the same quote MUST. Reject a non-conformant shape.
        quote
            .validate_baseline_merchant_net()
            .map_err(|_| WalletError::QuoteInvalid)?;
        // Structural check FIRST (distinct from the mirror below): a quote with NO two-leg offer
        // at all is not a two-leg quote — `QuoteInvalid`, not `MirrorMismatch` (which is reserved
        // for a real substitution, F3-a).
        if !quote.offers.iter().any(|o| o.two_leg.is_some()) {
            return Err(WalletError::QuoteInvalid);
        }
        // F3-a mirror rule for two-leg funding (F3-a lists it as PayTP execution): fund ONLY a
        // signed offer that EQUALS the WHOLE operator-approved offer — the net `accept` AND the
        // `twoLeg` terms (meed, reclaim, contest, rate, finality). Binding the full offer (not just
        // the x402 `accept`) closes the entire substitution surface: a captured quote with an
        // identical net accept but an inflated `meed` or stretched `reclaim` mirrors ITS OWN offer,
        // not this one, so it matches nothing → refuse before any leg funds (F3.2), never left to
        // the policy budget / meed carve alone. `Offer` compares by structural equality (its JCS
        // members). Require EXACTLY ONE (the merchant builds one offer per priced accepts entry).
        let mut mirrored = quote
            .offers
            .iter()
            .filter(|o| o.two_leg.is_some() && offer_mirrors(o, approved_offer));
        let offer = mirrored.next().ok_or(WalletError::MirrorMismatch)?;
        if mirrored.next().is_some() {
            return Err(WalletError::MirrorMismatch);
        }
        let tl = offer.two_leg.as_ref().ok_or(WalletError::QuoteInvalid)?;
        let net_to = field_str(&offer.accept, "payTo")?.to_string();
        let net_asset = field_str(&offer.accept, "asset")?.to_string();
        // Net amount from the x402 mirror. Shipped x402 V1 uses `maxAmountRequired` (F3-j, what the
        // RI emits); `baseline_amount` falls back to the older `amount` key ONLY when
        // `maxAmountRequired` is absent — the same backward-compat read the baseline path uses, so
        // a two-leg quote from an un-updated peer is not hard-rejected for the key spelling alone.
        let net_amount = baseline_amount(&offer.accept)?;
        let baseline_asset = field_str(tl, "asset")?.to_string();
        let meed_amount = native_u128(tl, "meed")?;
        let reclaim = field_time(tl, "reclaim")?;
        let contest = field_time(tl, "contest")?;
        let fin = field(tl, "finality").ok_or(WalletError::QuoteInvalid)?;
        let fin_meed = field_str(fin, "meed")?.to_string();
        // The net leg's own finality (`fin.net`, offer validity). The wallet gates the net
        // leg's *submission* on the MEED finality (F4.5) and the merchant verifies the net
        // leg's finality at redemption, but the pre-flight below still needs `fin.net` to
        // check the net leg's finality is REACHABLE inside the window before funding.
        let fin_net = field_str(fin, "net")?;

        // ---- F4.5/F8.5 two-leg feasibility pre-flight ----
        // Refuse a well-formed, signed quote whose two-leg flow cannot COMPLETE inside the
        // honor boundary, BEFORE funding the meed leg — else the payer recovers via reclaim
        // instead of completing (value temporarily stranded). Strictly conservative: every
        // check only ever REJECTS; none can loosen or fund. Cheapest checks first.
        //
        // (a) Positivity (F8.5): a quote whose reclaim window would close before the
        // instance's execution gate opens is invalid, which F8.5 reduces to reclaim > 0 and
        // contest > 0. (`grace`/`retry` are u64, so their `≥ 0` holds structurally.)
        if reclaim == 0 {
            return Err(WalletError::QuoteInfeasible("reclaim must be positive"));
        }
        if contest == 0 {
            return Err(WalletError::QuoteInfeasible("contest must be positive"));
        }
        // The honor boundary T_open = exp + grace (F8.4) — computed once here (checked, so a
        // pathological grace never overflow-panics the payer) and reused for the entry
        // derivation below.
        let t_open = quote
            .exp
            .checked_add(quote.grace)
            .ok_or(WalletError::QuoteInvalid)?;
        let caps = rail.caps();
        // (b) Route availability (F4.5): the rail must route BOTH legs' assets, else a leg can
        // never settle. A same-asset two-leg names one asset and both checks coincide.
        if !caps.assets.iter().any(|a| a == &net_asset) {
            return Err(WalletError::QuoteInfeasible(
                "net asset not routable on this rail",
            ));
        }
        if !caps.assets.iter().any(|a| a == &baseline_asset) {
            return Err(WalletError::QuoteInfeasible(
                "meed asset not routable on this rail",
            ));
        }
        // (c) Finality headroom (F8.1: t_fin ≤ exp+grace; F8.5): each leg's declared finality
        // must be reachable inside the honor window under meed-first serialization — see
        // `finality_headroom`. **Re-checked at every value-moving step** (`fund_meed_leg`,
        // `submit_net_leg`), because a plan feasible NOW can go stale if the rail clock
        // advances before the value actually moves: a plan-time check alone would let a
        // boundary-feasible plan strand the meed once time decays past the headroom.
        finality_headroom(&caps, rail.chain_time(), &fin_meed, fin_net, t_open)?;

        // Gate both value-moving legs against the operator's PER-ASSET budget. When the
        // meed settles in the SAME asset as the net leg, the two legs share one budget —
        // gate their SUM (a stateless policy would otherwise pass each leg independently
        // while their total breaches the budget) and enforce the tight ≤ MEED_CAP_BP
        // carve (equal scale → dimensionally sound, computed exactly). When they settle in
        // DIFFERENT assets, gate each leg against its own asset's budget; tight cross-asset
        // bounding is deferred with the rate oracle, so the per-asset policy budget is the
        // authority there.
        if baseline_asset == net_asset {
            let total = net_amount
                .checked_add(meed_amount)
                .ok_or(WalletError::QuoteInvalid)?;
            if let Decision::Deny(why) = self.policy.approve_quote(&quote, total, &net_asset) {
                return Err(WalletError::PolicyDenied(why));
            }
            if meed_amount > meed_carve_cap(net_amount) {
                return Err(WalletError::PolicyDenied("meed over the bounded carve"));
            }
        } else {
            if let Decision::Deny(why) = self.policy.approve_quote(&quote, net_amount, &net_asset) {
                return Err(WalletError::PolicyDenied(why));
            }
            if let Decision::Deny(why) =
                self.policy
                    .approve_quote(&quote, meed_amount, &baseline_asset)
            {
                return Err(WalletError::PolicyDenied(why));
            }
        }

        let seed = quote
            .address_inputs(merchant_key, &baseline_asset, None)
            .seed_instance()
            .map_err(|_| WalletError::Derivation)?;
        let instance_address = rail.derive_address(&seed);
        // T_lapse = T_open + reclaim (F4.3/F8; T_open = exp+grace was computed and checked in
        // the pre-flight above). Checked — a pathological reclaim must not overflow-panic the
        // payer's wallet; the field_time bound keeps reclaim in range, checked_add the
        // fail-closed backstop.
        let t_lapse = t_open
            .checked_add(reclaim)
            .ok_or(WalletError::QuoteInvalid)?;
        let entry_id =
            entry_id_purchase(&seed, &quote.nonce, meed_amount, t_open, t_lapse, contest);

        Ok(TwoLegPlan {
            instance_address,
            entry_id,
            nonce: quote.nonce,
            t_open,
            t_lapse,
            baseline_asset,
            meed_amount,
            contest,
            refund_ptr: refund_ptr.to_string(),
            net_to,
            net_asset,
            net_amount,
            fin_meed,
            fin_net: fin_net.to_string(),
        })
    }

    /// Fund the meed leg (F4.5 — meed first). The instance re-derives the
    /// entry id; the wallet asserts it equals its own derivation.
    pub fn fund_meed_leg(
        &self,
        rail: &VirtualRail,
        plan: &TwoLegPlan,
    ) -> Result<RailRef, WalletError> {
        // Re-verify finality headroom at the funding moment (F4.5 "before starting"): the
        // plan-time check in `plan_two_leg` can go stale if the rail clock advanced between
        // planning and funding, so a boundary-feasible plan must be re-checked here BEFORE
        // the meed value moves — never fund a meed the flow can no longer complete in time.
        finality_headroom(
            &rail.caps(),
            rail.chain_time(),
            &plan.fin_meed,
            &plan.fin_net,
            plan.t_open,
        )?;
        let (meed_ref, funded_id) = rail
            .fund_entry(
                &plan.instance_address,
                plan.nonce,
                plan.meed_amount,
                plan.refund_ptr.clone(),
                plan.t_open,
                plan.t_lapse,
                plan.contest,
                plan.baseline_asset.clone(),
            )
            .map_err(|e| WalletError::Rail(format!("{e:?}")))?;
        if funded_id != plan.entry_id {
            return Err(WalletError::EntryIdMismatch);
        }
        Ok(meed_ref)
    }

    /// Submit the net leg — but only after the meed leg shows the quoted
    /// finality (F4.5, "first means final"). This guard is the whole point of the
    /// ordering: a wallet that streams the net leg before the meed is final
    /// lets the merchant strip the meed by reclaiming it. The destination and
    /// amount come from the signed quote (via [`plan_two_leg`]), not the caller.
    pub fn submit_net_leg(
        &self,
        rail: &VirtualRail,
        plan: &TwoLegPlan,
        meed_ref: &RailRef,
    ) -> Result<RailRef, WalletError> {
        // The `meed_ref` MUST be the funding of THIS plan's entry — not merely some transfer
        // that reached finality — else the wallet would throw the unconditional net leg after
        // a purchase whose meed entry was never funded (the merchant then rejects). Bind it
        // exactly as the merchant's meed-leg check does (F4.4): funds THIS `entry_id`, in the
        // baseline asset, bound to the nonce.
        let ri = rail
            .ref_target(meed_ref)
            .ok_or(WalletError::EntryIdMismatch)?;
        if ri.funds_entry != Some(plan.entry_id)
            || ri.asset != plan.baseline_asset
            || ri.memo != Some(plan.nonce)
        {
            return Err(WalletError::EntryIdMismatch);
        }
        // Meed must show the quoted finality LEVEL first (F4.5, "first means final").
        let meed_time =
            meed_finality_time(rail, meed_ref, &plan.fin_meed).ok_or(WalletError::MeedNotFinal)?;
        // TOCTOU re-check at the net leg's value-moving point. The net leg is the
        // UNCONDITIONAL ~99% payment, so refuse to send it if the purchase can no longer be
        // honored (F8.1): the meed's OBSERVED finality time must be within the honor window,
        // and the net leg — submitted now, bounded against the strongest finality a late
        // redemption could observe — must still land inside it. Refusing here keeps the payer
        // whole: only the reclaimable meed is ever escrowed, never the net leg thrown after a
        // purchase that can no longer complete. (The meed's strongest-finality time is already
        // bounded ≤ t_open by `fund_meed_leg`'s headroom check.)
        let net_fin = rail
            .chain_time()
            .checked_add(rail.caps().finality_delay)
            .ok_or(WalletError::QuoteInvalid)?;
        if meed_time > plan.t_open {
            return Err(WalletError::QuoteInfeasible(
                "meed finality elapsed past the honor window",
            ));
        }
        if net_fin > plan.t_open {
            return Err(WalletError::QuoteInfeasible(
                "net finality unreachable within exp+grace",
            ));
        }
        rail.submit(Transfer {
            to: plan.net_to.clone(),
            asset: plan.net_asset.clone(),
            amount: plan.net_amount,
            kind: TransferKind::Payment,
            memo: Some(plan.nonce),
        })
        .map_err(|e| WalletError::Rail(format!("{e:?}")))
    }
}

fn require_binding_host_matches_resource(
    binding: &AcceptedBinding,
    requested_resource: &str,
) -> Result<(), WalletError> {
    let resource_host = normalized_resource_host(requested_resource)?;
    if binding.host() != resource_host {
        return Err(WalletError::OriginResourceMismatch);
    }
    Ok(())
}

fn normalized_resource_host(resource: &str) -> Result<&str, WalletError> {
    let host = resource_url_host(resource).ok_or(WalletError::OriginResourceMismatch)?;
    paytp_host::validate_normalized_host(host).map_err(|_| WalletError::OriginResourceMismatch)?;
    Ok(host)
}

fn resource_url_host(resource: &str) -> Option<&str> {
    let (_, rest) = resource.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() || host_port.starts_with('[') {
        return None;
    }
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        Some(host)
    } else {
        Some(host_port)
    }
}

/// A ready-to-execute two-leg plan — every routing/amount field extracted from the
/// merchant-signed quote (not the interaction layer), the instance address
/// re-derived by the wallet.
///
/// **All fields are private.** They are set once by [`Wallet::plan_two_leg`] from
/// the verified quote and are read-only thereafter — a caller cannot mutate
/// `net_to`/`net_amount` between planning and [`Wallet::submit_net_leg`] to
/// redirect the net leg. Read access is via the getters below.
#[derive(Debug, Clone)]
pub struct TwoLegPlan {
    instance_address: String,
    entry_id: [u8; 32],
    nonce: [u8; 32],
    t_open: u64,
    t_lapse: u64,
    baseline_asset: String,
    meed_amount: u128,
    contest: u64,
    // The only payer-supplied field (not in the merchant's offer).
    refund_ptr: String,
    net_to: String,
    net_asset: String,
    net_amount: u128,
    fin_meed: String,
    fin_net: String,
}

impl TwoLegPlan {
    pub fn instance_address(&self) -> &str {
        &self.instance_address
    }
    pub fn entry_id(&self) -> [u8; 32] {
        self.entry_id
    }
    pub fn net_to(&self) -> &str {
        &self.net_to
    }
    pub fn net_asset(&self) -> &str {
        &self.net_asset
    }
    pub fn net_amount(&self) -> u128 {
        self.net_amount
    }
    pub fn meed_amount(&self) -> u128 {
        self.meed_amount
    }
    pub fn t_open(&self) -> u64 {
        self.t_open
    }
    pub fn t_lapse(&self) -> u64 {
        self.t_lapse
    }
}

/// Whether two offers mirror each other, compared as **JCS forms** (F3-a: "equality of the
/// parsed JSON values (compare the JCS forms)"). Member order does not matter — the signed offer
/// round-trips through JCS (which sorts keys), so a StrictValue `==` (order-sensitive) would
/// false-reject the merchant's own re-parsed offer; JCS-normalizing the `accept` and `twoLeg`
/// objects compares the canonical bytes. The `finality`/`merchantNet` scalars compare directly.
fn offer_mirrors(a: &Offer, b: &Offer) -> bool {
    a.finality == b.finality
        && a.merchant_net == b.merchant_net
        && paytp_core::jcs::to_jcs(&a.accept) == paytp_core::jcs::to_jcs(&b.accept)
        && match (&a.two_leg, &b.two_leg) {
            (Some(x), Some(y)) => paytp_core::jcs::to_jcs(x) == paytp_core::jcs::to_jcs(y),
            (None, None) => true,
            _ => false,
        }
}

// StrictValue field accessors over the signed offer (F3 objects are JCS objects).
fn field<'a>(v: &'a StrictValue, key: &str) -> Option<&'a StrictValue> {
    match v {
        StrictValue::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, val)| val),
        _ => None,
    }
}
fn field_str<'a>(v: &'a StrictValue, key: &str) -> Result<&'a str, WalletError> {
    match field(v, key) {
        Some(StrictValue::String(s)) => Ok(s),
        _ => Err(WalletError::QuoteInvalid),
    }
}
// x402-envelope numeric fields follow x402 conventions, NOT PayTP's F1-c canonical rule —
// parse them permissively (a conformant x402 server may emit e.g. "01"). PayTP-native
// numeric fields use `native_u128`/`field_time`, which DO enforce F1-c.
fn field_u128(v: &StrictValue, key: &str) -> Result<u128, WalletError> {
    field_str(v, key)?
        .parse()
        .map_err(|_| WalletError::QuoteInvalid)
}
/// A PayTP-native numeric (F1-c canonical): reject non-minimal strings like "007" that a
/// conformant peer would reject — never `parse` an un-validated native numeric.
fn native_u128(v: &StrictValue, key: &str) -> Result<u128, WalletError> {
    let s = field_str(v, key)?;
    paytp_core::jcs::validate_uint_string(s).map_err(|_| WalletError::QuoteInvalid)?;
    s.parse().map_err(|_| WalletError::QuoteInvalid)
}
/// The F7 basis-point denominator (10 000) — the meed-cap divisor.
const BP_DENOM: u128 = 10_000;
/// The `≤ MEED_CAP_BP` carve of `net`, computed exactly and overflow-free for any
/// in-domain `net` (`net·bp/BP_DENOM` split so the product never exceeds `u128` and no
/// saturating clamp can wrongly lower the cap).
fn meed_carve_cap(net: u128) -> u128 {
    let bp = MEED_CAP_BP as u128;
    net / BP_DENOM * bp + (net % BP_DENOM) * bp / BP_DENOM
}
/// F3-g/F8: `twoLeg` time fields are bounded to 2^53−1 so the derived T_open/T_lapse
/// windows cannot overflow — the same bound the quote's top-level time fields use. A
/// reclaim/contest above this is rejected, never wrapped.
const MAX_TIME: u64 = (1u64 << 53) - 1;
fn field_time(v: &StrictValue, key: &str) -> Result<u64, WalletError> {
    let s = field_str(v, key)?;
    paytp_core::jcs::validate_uint_string(s).map_err(|_| WalletError::QuoteInvalid)?;
    let t: u64 = s.parse().map_err(|_| WalletError::QuoteInvalid)?;
    if t > MAX_TIME {
        return Err(WalletError::QuoteInvalid);
    }
    Ok(t)
}
/// The baseline (single-leg) finality-headroom check, evaluated at the authorization point
/// (F8.1/F8.5) with `now` sampled there. Returns `Ok(true)` iff the payment is honorable within
/// `t_open = exp+grace`. The merchant (`redeem_baseline`) refuses iff the finality TIME it observes
/// after settlement exceeds `t_open`: when the quote requires the rail's STRONGEST level that time
/// is `settle_time + finality_delay ≥ now + finality_delay` (the merchant settles no earlier than
/// the wallet authorizes on the shared clock, and finality only upgrades to a later time), so a
/// payment that cannot finalize by `t_open` even if settled now is CERTAINLY refused; for a WEAKER
/// level the payment is honorable if redeemed before it upgrades, so only an already-expired quote
/// (`now > t_open`) is a certain loss. `Err` only on a pathological (rail-declared, trusted)
/// `finality_delay` overflow — fail-closed.
fn baseline_headroom_ok(
    caps: &RailCaps,
    now: u64,
    is_strongest: bool,
    t_open: u64,
) -> Result<bool, WalletError> {
    let reach = if is_strongest {
        now.checked_add(caps.finality_delay)
            .ok_or(WalletError::QuoteInvalid)?
    } else {
        now
    };
    Ok(reach <= t_open)
}

/// The baseline offer's amount, robust to the x402 shape: the shipped V1 uses
/// `maxAmountRequired`; an earlier V2 draft used `amount`. Fall back to `amount` only when
/// `maxAmountRequired` is ABSENT — never when it is present-but-unparseable, or a malformed
/// `maxAmountRequired` could silently route to a hidden `amount` the x402 mirror ignores and
/// the wallet would overpay.
fn baseline_amount(accept: &StrictValue) -> Result<u128, WalletError> {
    if field(accept, "maxAmountRequired").is_some() {
        field_u128(accept, "maxAmountRequired")
    } else {
        field_u128(accept, "amount")
    }
}

/// The observed finality **time** of `meed_ref` IF it has reached the `quoted` finality
/// level, else `None`. Compares the observed level against the rail's declared total order
/// (F8.1) — the same rule the merchant redeems by — and returns the time so the caller can
/// re-check it against the honor boundary.
fn meed_finality_time(rail: &VirtualRail, meed_ref: &RailRef, quoted: &str) -> Option<u64> {
    let f = rail.finality(meed_ref)?;
    let caps = rail.caps();
    let reached = caps.finality_levels.iter().position(|l| l == &f.level);
    let want = caps.finality_levels.iter().position(|l| l == quoted);
    match (reached, want) {
        (Some(r), Some(w)) if r >= w => Some(f.time),
        _ => None,
    }
}

/// Finality headroom (F8.1 `t_fin ≤ exp+grace`; F8.5): both legs' estimated finality must
/// land inside the honor boundary `t_open = exp+grace`. Two things it gets right:
/// - **Strongest-finality bound.** The merchant's redemption honor check reads each leg's
///   CURRENTLY-observed finality time, and finality only ever upgrades to a STRONGER level
///   with a LATER time (F8.1) — so a late redemption can observe the strongest level. Each
///   leg is honorable only if its strongest-finality time `≤ t_open`, so both legs bound
///   against the rail's single conservative `finality_delay` (never a weaker quoted level's
///   delay — which would under-reject and strand the net leg under a late redemption).
/// - **Meed-first serialization (F4.5).** The net leg cannot start until the meed is final,
///   so it carries TWO such delays — an independent per-leg check would fund a quote whose
///   net leg, serialized after meed finality, finalizes past the window.
///
/// The quoted levels must be DECLARED by the rail (else a leg can never reach the quoted
/// finality → infeasible). `now` is the caller's current rail time, so re-running this at
/// every value-moving step keeps a plan from going stale before value moves. Strictly
/// conservative — only ever returns an error.
fn finality_headroom(
    caps: &RailCaps,
    now: u64,
    fin_meed: &str,
    fin_net: &str,
    t_open: u64,
) -> Result<(), WalletError> {
    if !caps.finality_levels.iter().any(|l| l == fin_meed) {
        return Err(WalletError::QuoteInfeasible(
            "meed finality level not on this rail",
        ));
    }
    if !caps.finality_levels.iter().any(|l| l == fin_net) {
        return Err(WalletError::QuoteInfeasible(
            "net finality level not on this rail",
        ));
    }
    let d = caps.finality_delay;
    let meed_fin = now.checked_add(d).ok_or(WalletError::QuoteInvalid)?;
    let net_fin = meed_fin.checked_add(d).ok_or(WalletError::QuoteInvalid)?;
    if meed_fin > t_open {
        return Err(WalletError::QuoteInfeasible(
            "meed finality unreachable within exp+grace",
        ));
    }
    if net_fin > t_open {
        return Err(WalletError::QuoteInfeasible(
            "net finality unreachable within exp+grace",
        ));
    }
    Ok(())
}
