//! Payer-side channel lifecycle (F5/F6) + reclaim automation (F4.5).
//!
//! The wallet drives the payer half of a Tier 1 channel: it signs the
//! `CHANNEL_AUTH`, seals the session secret, mints slices under the flow-control
//! policy, and closes. The flow-control + conformance behaviors here:
//! - the F6.5 **conformant settlement halt** — on a prepay channel the wallet stops
//!   minting slices when a round is overdue, on EITHER trigger: the **value** trigger
//!   (a full `TH_value` round streamed unsettled) or the **`TH_TIME`** time trigger on
//!   the wallet's own local clock (C1-9);
//! - the postpay **`L_credit` flow bound** — the wallet independently caps postpay
//!   cumulative liability at `limit_l` (F6-g/§7.2), so an untrusted interaction layer
//!   cannot drive its spend past the agreed credit limit;
//! - **reclaim automation** — a two-leg entry the merchant never receipted is
//!   reclaimed once its window opens (F4.5); an entry the merchant *did* attest is
//!   terminal, so the reclaim simply fails, and the wallet treats that as "the
//!   merchant delivered."

use crate::clock::Clock;
use crate::custody::{Custody, PayerScope};
use crate::policy::{ChannelTerms, Decision, HaltOrContinue, WalletPolicy};
use paytp_core::channel::checkpoint::{Checkpoint, CheckpointRequest};
use paytp_core::channel::establish::{
    AcceptedBinding, ChannelAuth, ChannelOpen, Close, MODE_POSTPAY, MODE_PREPAY,
};
use paytp_core::channel::settle_msg::PrepayDrawCompleted;
use paytp_core::channel::VectorEntry;
use paytp_core::crypto;
use paytp_core::derive::{claim_record_id, AddressInputs, MeedVectorEntry};
use paytp_core::fee::{biguint_from_u256, divide_round, u256_from_biguint, Rate, BP_DENOM, U256};
use paytp_core::registry::SnapshotStore;
use paytp_core::slice::Slice;
use paytp_core::tier0::quote::ExpectedDest;
use paytp_rail::{RailAdapter, RailRef, VirtualRail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelClientError {
    PolicyDenied(&'static str),
    /// The wallet halted streaming because a meed round is overdue (F6.5).
    HaltedOnOverdueMeed,
    /// Building/sealing the channel-open failed (bad terms).
    Establish,
    /// A `CHECKPOINT` the wallet was asked to co-sign does not recompute to the wallet's
    /// own carve basis (wrong channel, `CUM_TOTAL` above what the wallet streamed, or
    /// `ACCRUALS` that are not `CUM_TOTAL·bp_r` under the signed vector) — the analogue
    /// of refusing a non-conformant `MEED_VECTOR` before signing `CHANNEL_AUTH`.
    Checkpoint(&'static str),
    /// A postpay slice would push the payer's OUTSTANDING liability past `LIMIT_L`
    /// (`L_credit`) — the wallet independently caps postpay spend at the agreed credit
    /// limit (F6/§7.2), so an untrusted interaction layer cannot drive it past the bound
    /// (the payer-side mirror of the merchant's `PAYTP_WINDOW_EXCEEDED`, F6.1).
    WindowExceeded,
    Rail(String),
}

impl std::fmt::Display for ChannelClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ChannelClientError {}

/// The wire-level terms the interaction layer assembles for a channel open — the
/// fields the wallet signs into `CHANNEL_AUTH`. The wallet derives the policy view
/// ([`ChannelTerms`]) from these before signing.
#[derive(Debug, Clone)]
pub struct ChannelOpenParams {
    pub channel_id: [u8; 8],
    pub denom: String,
    pub baseline_asset: String,
    pub baseline_net: String,
    /// `true` = prepay, `false` = postpay.
    pub prepay: bool,
    pub limit_l: u128,
    pub limit_e: u128,
    pub th_value: u128,
    pub th_time: u64,
    pub schema: u32,
    pub contract: u32,
    pub registry_v: u32,
    pub vector: Vec<VectorEntry>,
    pub refund_ptr: Option<String>,
    pub rate_source: Option<String>,
    pub rate_dev: Option<u128>,
    pub fin_meed: String,
    pub fin_denom: String,
    pub timestamp: u64,
}

/// A live payer-side channel: the derived session key, the next SEQ, and the
/// policy gate for every slice.
pub struct ChannelClient<'c, P: WalletPolicy> {
    custody: &'c Custody,
    policy: P,
    /// The wallet's own monotonic clock (C1-9) — the anchor for the `TH_TIME` settlement
    /// trigger. ALWAYS the wallet's LOCAL clock, never a `Checkpoint.timestamp` (the wallet
    /// does not validate that field, so a hostile IL/merchant could skew it to defer the
    /// halt forever). Injected, so the lib holds no wall-clock and tests are deterministic.
    clock: &'c dyn Clock,
    channel_id: [u8; 8],
    merchant_key: [u8; 32],
    /// The per-(merchant, registrable-domain) payer-key scope (F1-f/F2.3). Every payer
    /// signature this channel makes — `CHANNEL_AUTH`, each `CHECKPOINT`, `CLOSE` —
    /// derives from custody under THIS scope, so the identity is stable within the
    /// channel and unlinkable from the payer's identity at any other merchant/domain.
    scope: PayerScope,
    k_session: [u8; 32],
    next_seq: u64,
    prepay: bool,
    /// The postpay credit limit `L_credit` (`LIMIT_L`, µ-units), the SELF-ENFORCED cap on the
    /// payer's OUTSTANDING postpay liability (F6-g/§7.2). The wallet refuses in `next_slice`
    /// any postpay slice that would push outstanding past this — so an untrusted interaction
    /// layer cannot drive two individually-policy-valid slices to sum past `L_credit`
    /// (`10-conformance-vectors.md:24` — a fresh postpay channel admits up to `L_credit`, not
    /// past it). Prepay ignores it: prepay is bounded by its deposit floor + the one-round
    /// value self-halt (`round_carve`), and applying an `L_credit` cap to prepay's monotone
    /// lifetime `cum_streamed` would freeze a legitimately on-rail-refilled deposit.
    limit_l: u128,
    /// The channel's `TH_TIME` settlement-time threshold (seconds, F5.2). `0` disables the
    /// time trigger (value-only settlement); a nonzero value arms the wallet-clock deadline
    /// evaluated in [`refresh_halt`](Self::refresh_halt) against [`last_settle`](Self::last_settle).
    th_time: u64,
    /// `last_settle` — the wallet-LOCAL clock time of the last **genuine settlement**, the anchor for
    /// the `TH_TIME` trigger (F6.5 / F8.4b `08-timeouts-clocks.md:35`: `now − last_settle ≥ TH_time`
    /// WITH settleable value present). Initialized to the local clock at `open_inner` (the RI's
    /// local-clock analogue of the spec's `CHANNEL_AUTH.TIMESTAMP`-at-open — the wallet's own trusted
    /// view, **NEVER** a `Checkpoint.timestamp` the wallet does not validate). Advanced ONLY when a
    /// round rail-**credits** (`verify_pending_draw` success). Deliberately NOT advanced on
    /// `record_operative` (a merchant re-anchoring the operative cannot defer the deadline without
    /// settling) nor on `resume_on_prepay_draw` (a validly-signed but UNFUNDED draw is a liveness
    /// signal, not a settlement — an earlier `owed_since` design was unsafe here: an unfunded
    /// in-flight resume could transiently clear it, deferring the deadline before any rail
    /// verification). The halt gates this against a SEPARATE "settleable value present" conjunct
    /// (`carve_at(cum_streamed) > 0`, net of CREDITED only — NOT of in-flight), so a withheld first
    /// checkpoint (no operative) still halts on time and a genuinely-settling channel does not halt early.
    last_settle: u64,
    /// The channel's meed-instance seed (F4.1), computed once at open. The wallet derives the
    /// claim-record id itself (F4.2) to bind a `PREPAY_DRAW_COMPLETED` receipt's claim record to
    /// THIS round's `(channel_id, ckpt_ref, target_P)` — a merchant cannot pass off another round's
    /// funded record as this one's (F5-o rail-for-value).
    seed_instance: [u8; 32],
    /// The channel-established meed finality (F5.2 `FIN_MEED`) the wallet requires on the
    /// rail before crediting a round.
    fin_meed: String,
    /// The signed meed vector as `(role, bp)` in the checkpoint's ascending-role order — the
    /// wallet's OWN copy of the carve basis (F5.4). It recomputes `ACCRUALS = CUM_TOTAL·bp_r`
    /// from this before co-signing any `CHECKPOINT`, exactly as it recomputes the fee split before
    /// signing `CHANNEL_AUTH`, so the carve it later owes rests on nothing the interaction layer says.
    roles_bp: Vec<(u8, u16)>,
    /// One round's carve — `floor(TH_value · Σbp / 10000)` — the SELF-ENFORCED bound on how much
    /// unsettled meed the wallet streams before it must stop (F5-o/§6.4). `next_slice` re-derives the
    /// halt from the wallet's own metering, so the one-round bound rests on the wallet, not on the
    /// interaction layer choosing to signal an overdue round.
    /// `0` when `TH_value = 0` disables the value trigger — a **time-only** channel then settles on the
    /// `TH_TIME` clock (Part B / C1-9): [`refresh_halt`](Self::refresh_halt) halts on the operative's own
    /// owed round AND on `now − last_settle ≥ th_time` with settleable value present.
    round_carve: u128,
    /// The wallet's OWN metering of cumulative streamed value (µ-units of accepted slices it minted).
    /// `CUM_TOTAL` in a `CHECKPOINT` the wallet co-signs may never exceed this — the wallet never
    /// attests to more consumption (hence more carve) than it actually streamed (F5-o carve basis).
    cum_streamed: u128,
    /// The operative checkpoint the wallet has co-signed (F6.3) — the metering position the merchant's
    /// interim draw settles against, and the ONLY basis for the owed carve. Monotone in `CUM_TOTAL`:
    /// [`record_operative`](Self::record_operative) refuses a stale/older bilateral checkpoint, so a
    /// replayed lower-`CUM` checkpoint can never shrink the owed carve (the unbounded-strip re-entry).
    operative: Option<Operative>,
    /// Per-role **credited** meed numerators `Σ E_r` (role-aligned to `roles_bp`), advanced only
    /// when a round rail-credits in [`verify_pending_draw`](Self::verify_pending_draw) — the payer-side
    /// mirror of the merchant's `settled_r` fold (F6-f). The owed carve is computed against
    /// `ACCRUALS − credited` with the SAME F7 division the merchant runs, so the two never diverge.
    credited_r: Vec<U256>,
    halted: bool,
    /// A round the wallet RESUMED on a receipt (liveness) but has not yet rail-credited (value).
    /// The next round's resume is gated on this being cleared, so a merchant that signs a receipt
    /// it never funds cannot string receipts past one round (F5-o verify-before-next).
    pending_verify: Option<PendingVerify>,
}

/// The operative checkpoint the wallet co-signed (F6.3) — its bilateral reference (F5-f) and the
/// metered `CUM_TOTAL` it fixes. The owed carve is `meed_carve(CUM_TOTAL·bp) − credited`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Operative {
    ckpt_ref: [u8; 32],
    cum_total: u128,
}

/// A round resumed on a receipt (liveness) but not yet rail-credited (value, F5-o). The wallet
/// derives `claim_record_id(seed_instance, channel_id, ckpt_ref, amount)` and verifies the rail
/// shows THAT record funded by the distributing kind (F6-m) to `FIN_MEED` before crediting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingVerify {
    ckpt_ref: [u8; 32],
    claim_record: [u8; 32],
    amount: u128,
    /// The operative `CUM_TOTAL` this round settled against — snapshotted at resume so the per-role
    /// `E_r` fold (F6-f) at credit time is computed against the round's own checkpoint, not a later one.
    cum_total: u128,
    tx_ref: String,
    /// Set once a rail-verification attempt has FAILED (the draw did not fund / reach finality). A
    /// defaulted round is no longer "in-flight" for the halt calc — it is again OWED, so the wallet
    /// re-halts and stops streaming (the bounded-strip: a signed notice for an unfunded draw resumes
    /// once, then the halt does not clear). It stays recorded so the next round is still barred
    /// (verify-before-next); a later genuine funding still verifies and credits it.
    defaulted: bool,
}

/// The **TRUSTED** inputs to a channel open — the wallet operator's own state and the
/// **VERIFIED** merchant binding — held SEPARATE from the interaction-layer-assembled
/// [`ChannelOpenParams`]. This hardens the channel-open trust boundary: the merchant host
/// (which scopes the payer key, F1-f/F2.3), the merchant identity + channel-sealing key
/// (F2.5), and the wallet's OWN `0x12` meed pointer (F5-o) were previously reachable from
/// IL-controlled or unverified inputs. Provenance is now **structural**: the merchant
/// triple comes ONLY from an [`AcceptedBinding`] (which only
/// [`paytp_core::channel::establish::BindingArtifact::accept`] constructs — it binds host
/// ↔ cert ↔ enc_key ↔ merchant_key), and the wallet's `0x12` pointer is bundled with
/// [`Custody`] (which the IL cannot hold). So a caller can supply NEITHER an unverified
/// merchant host / sealing key (scope spoof / session-secret reseal) NOR the wallet's own
/// meed pointer. The interaction layer supplies only `params`.
pub struct PayerChannelTrust<'c, 'a> {
    /// The wallet custody — the secret spend boundary. **Private**: bundling the wallet's
    /// own `0x12` pointer behind a constructor that REQUIRES `&Custody` is what makes both
    /// provably wallet-owned — the interaction layer holds no custody, so it cannot
    /// construct this at all (fields are private, so not even via a struct literal).
    custody: &'c Custody,
    /// The wallet's OWN `0x12` meed-payout pointer (F5-o). `Some(d)` → the wallet's share
    /// MUST route to `d`; `None` → it asserts no share (its `0x12` MUST be the Dev-Fund
    /// fallback, F9.4 step 3). Set via [`PayerChannelTrust::with_meed_dest`]; NEVER a value
    /// an untrusted party can supply.
    wallet_meed_dest: Option<&'a str>,
    /// The ACCEPTED merchant binding — the ONLY source of the merchant host (payer-key
    /// scope), sealing key, and identity key for this open. Its authenticity is enforced
    /// by construction (only `BindingArtifact::accept` mints one).
    binding: &'a AcceptedBinding,
}

impl<'c, 'a> PayerChannelTrust<'c, 'a> {
    /// The trusted channel-open inputs — the wallet's [`Custody`] and the VERIFIED merchant
    /// [`AcceptedBinding`]. Both are wallet/operator-side; the interaction layer, which
    /// holds neither custody nor the means to mint an `AcceptedBinding`, cannot construct
    /// one. The wallet asserts NO `0x12` meed share by default (its `0x12` MUST route to
    /// the Dev-Fund fallback); a wallet that earns meed sets its own payout pointer with
    /// [`PayerChannelTrust::with_meed_dest`].
    pub fn new(custody: &'c Custody, binding: &'a AcceptedBinding) -> Self {
        PayerChannelTrust {
            custody,
            wallet_meed_dest: None,
            binding,
        }
    }

    /// Set the wallet's OWN `0x12` meed-payout pointer (F5-o self-defense) — where its
    /// earned wallet share MUST route. The wallet then refuses to sign a `CHANNEL_AUTH`
    /// whose `0x12` is any other destination. Trusted wallet config, the mirror of
    /// [`crate::Wallet::with_meed_dest`] for the channel path.
    pub fn with_meed_dest(mut self, dest: &'a str) -> Self {
        self.wallet_meed_dest = Some(dest);
        self
    }
}

impl<'c, P: WalletPolicy> ChannelClient<'c, P> {
    /// Open a channel: policy-gate the terms, sign `CHANNEL_AUTH` under custody, seal the
    /// session secret. Returns the `CHANNEL_OPEN` to send and the live client state.
    /// `trust` bundles the wallet's custody + own `0x12` pointer and the verified
    /// merchant artifact's host + sealing key (see [`PayerChannelTrust`]); `params` is
    /// the interaction-layer-assembled wire terms. The per-channel session secret and
    /// channel id are generated internally from the OS CSPRNG — the wallet never takes
    /// this randomness from the (untrusted) interaction layer (§5.4). Deterministic
    /// inputs are available via [`open_with_secret`] for tests.
    pub fn open(
        trust: &PayerChannelTrust<'c, '_>,
        clock: &'c dyn Clock,
        policy: P,
        params: &ChannelOpenParams,
        registry: &SnapshotStore,
    ) -> Result<(ChannelOpen, Self), ChannelClientError> {
        // F2.5: a fresh session secret + a nonzero channel id from the OS CSPRNG.
        let s = crypto::random_bytes::<32>();
        let mut channel_id = crypto::random_bytes::<8>();
        while channel_id == [0u8; 8] {
            channel_id = crypto::random_bytes::<8>();
        }
        let mut params = params.clone();
        params.channel_id = channel_id;
        Self::open_inner(trust, clock, policy, &params, &s, registry)
    }

    /// Open a channel with a CALLER-SUPPLIED session secret `s` and `params.channel_id` —
    /// the deterministic constructor for reproducible tests and vectors. Gated behind
    /// `cfg(test)`/the `test-util` feature and `#[doc(hidden)]` so a production build cannot
    /// reach it (the default build excludes it entirely; a build that opts into `test-util`
    /// / `--all-features` gets a hidden, explicitly test-only API) — production MUST use
    /// [`open`], which generates both from the OS CSPRNG (§5.4).
    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub fn open_with_secret(
        trust: &PayerChannelTrust<'c, '_>,
        clock: &'c dyn Clock,
        policy: P,
        params: &ChannelOpenParams,
        s: &[u8; 32],
        registry: &SnapshotStore,
    ) -> Result<(ChannelOpen, Self), ChannelClientError> {
        Self::open_inner(trust, clock, policy, params, s, registry)
    }

    /// The core open logic shared by [`open`] (production randomness) and the test-only
    /// [`open_with_secret`]. Private — a caller reaches it only through those.
    fn open_inner(
        trust: &PayerChannelTrust<'c, '_>,
        clock: &'c dyn Clock,
        policy: P,
        params: &ChannelOpenParams,
        s: &[u8; 32],
        registry: &SnapshotStore,
    ) -> Result<(ChannelOpen, Self), ChannelClientError> {
        let terms = ChannelTerms {
            denom: params.denom.clone(),
            limit_l: params.limit_l,
            limit_e: params.limit_e,
            th_value: params.th_value,
            th_time: params.th_time,
            prepay: params.prepay,
        };
        if let Decision::Deny(why) = policy.approve_channel(&terms) {
            return Err(ChannelClientError::PolicyDenied(why));
        }
        // Resolve the per-(merchant, registrable-domain) payer-key scope (F1-f/F2.3)
        // from the merchant's F2.4 host BEFORE signing anything. Fail closed on a host
        // that is not a valid normalized F2.4 host — the wallet will not open a channel
        // whose counterparty scope it cannot resolve (the same normalizer the artifact
        // HOST validation uses, so the scope matches what the channel authenticated to).
        let scope = PayerScope::resolve(*trust.binding.merchant_key(), trust.binding.host())
            .map_err(|_| ChannelClientError::Establish)?;
        let mut auth = ChannelAuth {
            payer_key: trust.custody.payer_key(&scope),
            channel_id: params.channel_id,
            merchant_key: *trust.binding.merchant_key(),
            denom: params.denom.clone(),
            mode: if params.prepay {
                MODE_PREPAY
            } else {
                MODE_POSTPAY
            },
            limit_l: params.limit_l,
            limit_e: params.limit_e,
            th_value: params.th_value,
            th_time: params.th_time,
            refund_ptr: params.refund_ptr.clone(),
            baseline_net: params.baseline_net.clone(),
            rate_source: params.rate_source.clone(),
            rate_dev: params.rate_dev,
            schema: params.schema,
            vector: params.vector.clone(),
            registry_v: params.registry_v,
            hs: crypto::h_commit(s),
            predecessor: None,
            timestamp: params.timestamp,
            baseline_asset: params.baseline_asset.clone(),
            contract: params.contract,
            fin_meed: params.fin_meed.clone(),
            fin_denom: params.fin_denom.clone(),
            sig: None,
        };
        // The payer refuses to sign a CHANNEL_AUTH whose meed vector is not conformant schema-0x01
        // OR whose GOVERNED destinations are wrong (F5-o/F9.4: 0x13 == pinned Dev-Fund, 0x11
        // registry-listed-or-independent-fund against `registry`) — it never relies on the merchant
        // to validate the vector that routes the governed meed (mirroring the two-leg check).
        auth.validate_vector_governed(registry)
            .map_err(|_| ChannelClientError::Establish)?;
        // Payer-side self-defense (F5-o): the interaction layer assembled this vector, so the
        // wallet ALSO checks its OWN `0x12` share routes to its configured payout pointer (or the
        // Dev-Fund fallback when it earns none) BEFORE it signs — a hostile IL that rerouted the
        // wallet's meed share to itself is rejected here. `0x10` is the IL's own share (Unchecked):
        // the channel vector is IL-ASSEMBLED (no merchant signature over it), so a hostile IL
        // rerouting its OWN `0x10` harms only itself — not wallet/payer value — and the IL defends
        // its own `0x10` in its own code (F5-o); the wallet holds no basis to pin the IL's pointer.
        let wallet_expectation = match trust.wallet_meed_dest {
            Some(d) => ExpectedDest::Asserted(d),
            None => ExpectedDest::Unasserted,
        };
        auth.validate_payer_side(ExpectedDest::Unchecked, wallet_expectation)
            .map_err(|_| ChannelClientError::Establish)?;
        // Derive the meed-instance seed (F4.1) ONCE from the signed terms — the wallet
        // computes the claim-record id itself to rail-verify a `PREPAY_DRAW_COMPLETED` (F5-o),
        // never trusting the merchant's asserted id. Meed-only instance → `merchant_net: None`
        // (F4.1), mirroring the merchant's channel-open derivation.
        let seed_instance = AddressInputs {
            merchant_key: auth.merchant_key,
            asset: auth.baseline_asset.clone(),
            schema: auth.schema,
            vector: auth
                .vector
                .iter()
                .map(|v| MeedVectorEntry {
                    role: v.role,
                    bp: v.bp,
                    dest: v.dest.clone(),
                })
                .collect(),
            contract: auth.contract,
            merchant_net: None,
        }
        .seed_instance()
        .map_err(|_| ChannelClientError::Establish)?;
        let fin_meed = auth.fin_meed.clone();
        // The wallet's own copy of the carve basis (F5.4): the `(role, bp)` pairs in the
        // vector's canonical (ascending-role) order, so it can recompute a `CHECKPOINT`'s `ACCRUALS`
        // from `CUM_TOTAL` itself and never owe a carve the interaction layer asserted.
        let roles_bp: Vec<(u8, u16)> = auth.vector.iter().map(|v| (v.role, v.bp)).collect();
        let n_roles = roles_bp.len();
        // One round's carve `floor(TH_value · Σbp / 10000)` — the self-enforced streaming bound (F5-o).
        // A NONZERO `TH_value` is a live value trigger, so the bound is at least 1 carve unit even when the
        // floor rounds to 0 (a tiny `TH_value`) — else Mechanism 2 would be silently disabled and the
        // wallet could stream unbounded. `TH_value = 0` explicitly disables the value
        // trigger (time-only settlement, F5.2) → `0`, which `refresh_halt` reads as "no value self-halt".
        // Computed in `U256` (the product can exceed `u128`) then narrowed.
        let sum_bp: u128 = roles_bp.iter().map(|(_, bp)| *bp as u128).sum();
        let round_carve = if params.th_value == 0 {
            0
        } else {
            u128::try_from(
                (U256::from(params.th_value) * U256::from(sum_bp)) / U256::from(BP_DENOM),
            )
            .unwrap_or(u128::MAX)
            .max(1)
        };
        trust
            .custody
            .with_signing_key(&scope, |sk| auth.sign(sk))
            .map_err(|_| ChannelClientError::Establish)?;
        let open = ChannelOpen::build(auth, trust.binding.enc_key(), s)
            .map_err(|_| ChannelClientError::Establish)?;
        let k_session = crypto::k_session(
            s,
            &crypto::bind_salt(
                &trust.custody.payer_key(&scope),
                trust.binding.merchant_key(),
            ),
            &params.channel_id,
        );
        Ok((
            open,
            ChannelClient {
                custody: trust.custody,
                clock,
                policy,
                channel_id: params.channel_id,
                merchant_key: *trust.binding.merchant_key(),
                scope,
                k_session,
                next_seq: 1,
                prepay: params.prepay,
                limit_l: params.limit_l,
                th_time: params.th_time,
                // The TH_TIME anchor `last_settle` is established at OPEN on the wallet's LOCAL clock
                // (spec F8.4b: `last_settle` initializes from `CHANNEL_AUTH.TIMESTAMP` at open, so
                // `TH_time` is well-defined from birth — here the trusted local clock, never a wire
                // timestamp). The deadline does not bite until value is actually streamed (the halt's
                // separate "settleable value present" conjunct), and it advances only on a genuine
                // rail-credited settlement — so a merchant withholding the first checkpoint cannot
                // disarm the trigger, and re-anchoring / an unfunded resume cannot defer it. (Chained
                // import of an already-owed position is a deferred wallet item — this wallet opens
                // first-generation channels only, `predecessor: None`, like item B's opening basis.)
                last_settle: clock.now(),
                seed_instance,
                fin_meed,
                roles_bp,
                round_carve,
                cum_streamed: 0,
                operative: None,
                credited_r: vec![U256::ZERO; n_roles],
                halted: false,
                pending_verify: None,
            },
        ))
    }

    /// Mint the next slice for `amt` µ-units — policy-gated and honoring an active
    /// meed halt (a halted prepay wallet mints nothing until the round settles).
    pub fn next_slice(&mut self, amt: u64) -> Result<Slice, ChannelClientError> {
        // Re-derive the halt from the wallet's OWN metering FIRST (F5-o/§6.4): a conformant prepay wallet
        // stops once it has streamed a round's worth (`TH_value`) of unsettled meed, whether or not the
        // interaction layer signalled an overdue round. This makes the "bounded to one round" strip bound
        // rest on the wallet itself — not on the interaction layer choosing to call `on_overdue`/verify
        // (a withheld verify let a hostile layer stream past unpaid meed).
        self.refresh_halt();
        if self.halted {
            return Err(ChannelClientError::HaltedOnOverdueMeed);
        }
        // Spend authority gates first (§7.2): a policy-denied slice is never minted, so it cannot advance
        // the meed metering.
        if let Decision::Deny(why) = self.policy.approve_slice(self.channel_id, amt) {
            return Err(ChannelClientError::PolicyDenied(why));
        }
        // Then refuse a policy-approved slice that would push unsettled meed PAST a full round — the
        // bound is checked against `cum_streamed + amt`, NOT the post-mint state, so a single large slice
        // cannot overshoot (one `next_slice(huge)` stripping several rounds before the *next* call
        // self-halts). Strictly `>` so a slice landing EXACTLY on the one-round
        // boundary is admitted (then `refresh_halt`'s `>=` stops the next one) — the strip is bounded to
        // one round, and the wallet can still checkpoint the full round it halts on.
        if self.prepay
            && self.round_carve > 0
            && self.owed_beyond_in_flight(self.cum_streamed.saturating_add(amt as u128))
                > self.round_carve
        {
            self.halted = true;
            return Err(ChannelClientError::HaltedOnOverdueMeed);
        }
        // Part A — postpay outstanding-liability cap (`L_credit`, F6-g/§7.2). Independently bound
        // the payer's OUTSTANDING postpay liability at `limit_l`: two individually-policy-valid
        // slices must not sum past `L_credit` (`10-conformance-vectors.md:24` — a fresh postpay
        // channel admits up to `L_credit`, NOT past it), so an untrusted interaction layer cannot
        // drive postpay spend past the agreed bound (`checkpoint_basis_ok` would otherwise co-sign
        // any `CUM ≤ cum_streamed`). Checked pre-mint against `outstanding + amt`, so a single
        // large slice cannot overshoot. Postpay-only: prepay is bounded above (deposit floor + the
        // one-round `round_carve` self-halt); a naive `L_credit` cap on prepay's monotone lifetime
        // `cum_streamed` would freeze a legitimately on-rail-refilled deposit. CHECKED
        // add, fail-closed — NOT `saturating_add` (which would clamp an overflow to `u128::MAX` and,
        // since `MAX > limit_l`, still REFUSE here — but express the intent as "overflow ⇒ refuse").
        // (`limit_e`, the *unevidenced*-value bound, is the MERCHANT's evidence-risk cap — spec
        // `07-security-model.md:7` "enforced by the merchant itself"; core `state.rs:326` — not a
        // distinct payer-liability cap, so it is deliberately NOT re-enforced wallet-side; see
        // `postpay_unevidenced_liability_is_bounded_by_l_credit_not_a_separate_e_cap`.)
        if !self.prepay {
            match self.postpay_outstanding().checked_add(amt as u128) {
                Some(projected) if projected <= self.limit_l => {}
                _ => return Err(ChannelClientError::WindowExceeded),
            }
        }
        let slice = Slice::seal(self.next_seq, amt, &self.k_session)
            .map_err(|_| ChannelClientError::Establish)?;
        self.next_seq += 1;
        // Meter the streamed value the wallet itself authorized — the independent upper bound on any
        // `CUM_TOTAL` it will later co-sign, and hence on the carve it can be asked to settle (F5-o).
        self.cum_streamed = self.cum_streamed.saturating_add(amt as u128);
        Ok(slice)
    }

    /// Co-sign a `CHECKPOINT` (F5.5/F6.3) the interaction layer assembled — producing the payer
    /// countersignature the merchant will bilateralize. Before signing, the wallet INDEPENDENTLY
    /// validates the **carve basis** it is about to attest ([`checkpoint_basis_ok`](Self::checkpoint_basis_ok)):
    /// `CUM_TOTAL` never exceeds what the wallet actually streamed, and `ACCRUALS = CUM_TOTAL·bp_r`
    /// under the wallet's OWN signed vector — exactly as it recomputes the fee split before signing
    /// `CHANNEL_AUTH` (F5.4). The non-carve fields (balance/ranges/transcript) are the merchant's to
    /// recompute (F6-c): a wrong one simply yields no countersignature, never a wrong carve, so the
    /// wallet need not reproduce them. The carve the wallet later owes rests on nothing the untrusted
    /// layer asserts.
    pub fn cosign_checkpoint(&self, cp: &mut Checkpoint) -> Result<(), ChannelClientError> {
        if self.checkpoint_basis_ok(cp).is_none() {
            return Err(ChannelClientError::Checkpoint(
                "checkpoint fails the wallet's own carve basis",
            ));
        }
        self.custody
            .with_signing_key(&self.scope, |sk| cp.sign_payer(sk))
            .map_err(|_| ChannelClientError::Checkpoint("payer countersignature failed"))?;
        Ok(())
    }

    /// Build the wallet's `CHECKPOINT_REQUEST` (**F5.5**) for a checkpoint the interaction
    /// layer assembled: co-sign the inner proposal's payer slot (the same carve-basis check
    /// as [`cosign_checkpoint`](Self::cosign_checkpoint)) and sign the outer
    /// `PayTPv1-ckpt-req` wrapper — BOTH with the payer key from custody, since the outer
    /// signature is the initiator's and the untrusted interaction layer holds no key. The
    /// returned request encodes to the F5.5 wire form `{0x00 PROPOSED, 0x70 SIG(ckpt-req)}`;
    /// the responder countersigns the inner half into one bilateral `CHECKPOINT`.
    pub fn request_checkpoint(
        &self,
        cp: Checkpoint,
    ) -> Result<CheckpointRequest, ChannelClientError> {
        let mut cp = cp;
        self.cosign_checkpoint(&mut cp)?; // inner payer slot + carve-basis check
        let mut req = CheckpointRequest::proposing(cp);
        self.custody
            .with_signing_key(&self.scope, |sk| req.sign(sk))
            .map_err(|_| ChannelClientError::Checkpoint("checkpoint-request signature failed"))?;
        Ok(req)
    }

    /// Record the operative checkpoint (F6.3) the wallet co-signed, from the bilateral `CHECKPOINT`
    /// the merchant returned — the ONLY basis for the owed carve, and the position the merchant's draw
    /// settles against. Verifies BOTH signatures over the identical `COVERED` bytes (so `CUM_TOTAL` is
    /// exactly what the wallet co-signed, not a value the merchant substituted), re-checks the carve
    /// basis, and enforces **supersession monotonicity**: the operative never regresses to a lower
    /// `CUM_TOTAL` (F5.5 monotone). That closes the replay — a hostile interaction
    /// layer replaying an OLDER valid checkpoint to shrink the owed carve below what has accrued
    /// (re-opening the unbounded strip). Equal-or-greater `CUM_TOTAL` advances in lockstep with the
    /// merchant's own operative (both countersign the same checkpoint), keeping the two references in
    /// sync; the carve is monotone in `CUM_TOTAL`, so an advance never shrinks what is owed. After
    /// advancing it recomputes the halt — co-signing a checkpoint with a fresh settleable carve halts the
    /// wallet at once (the F6.5 halt is self-triggered, not merely on an interaction-layer overdue tick).
    ///
    /// **Ordering assumption (synchronous rail).** The wallet credits a resumed round before the operative
    /// advances past it, which the synchronous VirtualRail + an in-order interaction layer provide (a draw
    /// finalizes and its notice is credited before the next checkpoint). An OUT-OF-ORDER delivery — the
    /// operative advancing past a drawn-but-uncredited round — is the async-rail-finality case tracked as
    /// a separate milestone, not reachable here.
    pub fn record_operative(&mut self, bilateral: &Checkpoint) -> bool {
        if bilateral
            .verify_bilateral(&self.custody.payer_key(&self.scope), &self.merchant_key)
            .is_err()
        {
            return false;
        }
        let Some(cum) = self.checkpoint_basis_ok(bilateral) else {
            return false;
        };
        let Ok(ckpt_ref) = bilateral.reference() else {
            return false;
        };
        // Supersession (F6.3): advance ONLY to a strictly-greater `(CUM_TOTAL, CKPT_REF)`. Never a lower
        // `CUM_TOTAL` (F5.5 monotone — a lower one would shrink the owed carve), and at EQUAL `CUM_TOTAL`
        // only to a lexicographically greater `CKPT_REF` — the SAME tiebreaker the merchant applies
        // (`core_state`/F6.3), so the two endpoints never disagree on which same-`CUM` checkpoint is
        // operative (a disagreement would wedge the channel — the wallet expecting one reference while
        // the merchant draws against the other). A re-anchor of the current checkpoint
        // (equal `CUM`, equal `CKPT_REF`) is a no-op that returns `false` without changing the operative.
        if let Some(op) = &self.operative {
            if cum < op.cum_total || (cum == op.cum_total && ckpt_ref <= op.ckpt_ref) {
                return false;
            }
        }
        self.operative = Some(Operative {
            ckpt_ref,
            cum_total: cum,
        });
        self.refresh_halt();
        true
    }

    /// **Test-only:** seed the operative checkpoint directly, bypassing the `cosign_checkpoint` →
    /// `record_operative` round-trip, for tests that exercise the halt/resume/credit path without
    /// standing up a full bilateral `CHECKPOINT`. Gated behind `cfg(test)`/`test-util` and
    /// `#[doc(hidden)]` so a production build cannot reach it — production MUST use
    /// [`record_operative`], which authenticates the bilateral checkpoint and enforces supersession.
    /// `cum_total` also advances `cum_streamed` so the carve basis (`cum ≤ streamed`) holds, mirroring
    /// a wallet that streamed then checkpointed that value.
    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub fn seed_operative(&mut self, ckpt_ref: [u8; 32], cum_total: u128) {
        if cum_total > self.cum_streamed {
            self.cum_streamed = cum_total;
        }
        self.operative = Some(Operative {
            ckpt_ref,
            cum_total,
        });
    }

    /// The F6.5 conformant meed halt on an overdue round. On a **prepay** channel the halt is
    /// MANDATORY and policy-independent (a policy returning `Continue` cannot lift it) — BUT it fires
    /// only on a genuinely **settleable** round, which the wallet determines from its OWN metering: a
    /// round comes due only on settleable value (F5-o Triggers), so a positive owed carve at the
    /// co-signed operative checkpoint is the precondition. The owed carve
    /// (`floor((ACCRUALS − credited) / 10000)`) is computed with the SAME F7 division the merchant
    /// runs, from the checkpoint the wallet co-signed and the meed it has itself credited — never an
    /// interaction-layer input. No operative yet / zero owed /
    /// out-of-domain accrual ⇒ nothing the merchant can draw ⇒ no halt (halting there would wait
    /// forever for a notice that never comes). The policy is consulted for its record/telemetry.
    pub fn on_overdue_meed(&mut self) -> HaltOrContinue {
        let decision = self.policy.on_overdue_meed(self.channel_id);
        self.refresh_halt();
        decision
    }

    /// Resume a prepay meed halt on the merchant's `PREPAY_DRAW_COMPLETED` (F5-o) — a
    /// **liveness** signal. The wallet verifies the merchant signature and that the notice settles
    /// the wallet's OWN operative checkpoint (F6.3) drawing its FULL owed carve, then resumes
    /// streaming AT ONCE. It does NOT yet credit the round: crediting is rail-for-value
    /// ([`verify_pending_draw`](Self::verify_pending_draw)). **Verify-before-next:** while a PRIOR round
    /// is still awaiting rail-verification, only a byte-identical re-delivery of THAT round is admitted
    /// (an idempotent re-ack of the merchant's F5-o re-emit) — a different round is REFUSED, so a
    /// merchant that signs receipts it never funds cannot string them past one round. Returns whether
    /// the halt cleared (or the re-delivery was admitted).
    pub fn resume_on_prepay_draw(&mut self, receipt: &PrepayDrawCompleted) -> bool {
        // `P` must be in the settlement domain (F7.2 `P < 2^128`) on every path.
        let Ok(amount) = u128::try_from(receipt.amount.clone()) else {
            return false;
        };
        // A round always draws `P ≥ 1` (the merchant draws only when `E ≥ 1`, F7.3; a zero-carve
        // checkpoint is not settleable). `parse` rejects `P = 0` on the wire, but a directly-constructed
        // struct could carry it — refuse it here so a zero draw cannot occupy `pending_verify` and wedge
        // the next real round.
        if amount == 0 {
            return false;
        }
        // Re-delivery of the round already awaiting rail-verification (F5-o idempotent re-emit). It must be
        // the SAME round — same checkpoint, channel, merchant signature, amount, and DERIVED claim record
        // (bound to `ckpt_ref`+`amount`, so this can never swap in another round's value). A DIFFERENT
        // round is barred until this one credits (verify-before-next), so a merchant cannot string
        // receipts past one round.
        if let Some(pv) = self.pending_verify.as_ref() {
            let same_round = pv.ckpt_ref == receipt.ckpt_ref
                && receipt.channel_id == self.channel_id
                && receipt.verify_merchant(&self.merchant_key).is_ok()
                && pv.amount == amount
                && pv.claim_record == receipt.claim_record;
            if !same_round {
                return false;
            }
            // While still pending (not defaulted), only a byte-identical re-delivery is admitted. Once the
            // round has DEFAULTED (a prior draw failed to fund/finalize), admit a re-attempt at a NEW
            // funding reference and re-point verification at it — a merchant that genuinely funds the round
            // after a failed first draw can then credit it, instead of the bogus first `tx_ref`
            // permanently poisoning it. The round stays defaulted (so still halted); only a
            // successful `verify_pending_draw` against the new reference clears it — no un-halt cycling.
            if !pv.defaulted && pv.tx_ref != receipt.tx_ref {
                return false;
            }
            if pv.defaulted {
                if let Some(pv_mut) = self.pending_verify.as_mut() {
                    pv_mut.tx_ref = receipt.tx_ref.clone();
                }
            }
            return true;
        }
        // First acceptance of a round. The notice must settle the wallet's OWN operative checkpoint
        // (F6.3) — because the checkpoint is bilateral, the reference the wallet co-signed IS the one the
        // merchant draws against, so no caller supplies the round identity. Crediting is DECOUPLED from
        // the halt: the interim draw is merchant-initiated (§6.4), so a valid notice is accepted and
        // tracked whether or not the wallet had already halted — the wallet must credit every round the
        // merchant funds to keep `credited_r` in lockstep with the merchant's `settled_r`.
        let Some(op) = self.operative.clone() else {
            return false;
        };
        if receipt.channel_id != self.channel_id
            || receipt.ckpt_ref != op.ckpt_ref
            || receipt.verify_merchant(&self.merchant_key).is_err()
        {
            return false;
        }
        // The wallet computes the round's own-cumulative WATERMARK TARGET ITSELF (Option W / F5-o) —
        // the SAME `floor((Σ ACCRUALS − Σ imported_settled) / 10 000)` the merchant advances `funded_p`
        // to and names in the receipt (`carriage.rs::cumulative_target_p`, `carriage.rs:2088`), over its
        // co-signed `ACCRUALS` — NEVER a caller input. It resumes on the CUMULATIVE target, not the
        // per-round carve (which lags it by every prior round — the v-prev per-round check refused the
        // honest round-2 receipt and trapped the payer's float). A merchant under-drawing a SMALLER
        // cumulative target it truthfully funds does NOT match, so the carve a hostile merchant can
        // defer stays bounded to this one round (§6.4 — self-metered, not a trusted `expected_carve`).
        let Some(expected) = self.cumulative_target_at(op.cum_total) else {
            return false;
        };
        if amount != expected {
            return false;
        }
        // The receipt names the cumulative watermark POSITION, which (unlike the per-round carve) does NOT
        // shrink after a round credits. So a hostile merchant can re-sign an ALREADY-SETTLED operative
        // (same cumulative `amount`, correct derived claim, but a bogus `tx_ref`) whose INCREMENTAL carve
        // is 0. Installed as `pending_verify` it would default on the bogus tx and then WEDGE the next real
        // round (verify-before-next bars a different `CKPT_REF` until this clears) — a merchant-triggered
        // liveness trap on the payer's float, with NO unpaid carve to justify it.
        // Refuse unless the operative owes a POSITIVE incremental carve — a
        // genuinely settleable round, exactly what the merchant's own draw guard emits (`carriage.rs`
        // `meed_amount` / `cumulative_target_p` never draws a zero-delta round). The pre-migration
        // per-round check had this immunity for free (`carve_at` went to 0 after crediting); the cumulative
        // target does not, so it is restored explicitly here.
        let Some(incremental_carve) = self.carve_at(op.cum_total) else {
            return false;
        };
        if incremental_carve == 0 {
            return false;
        }
        // The claim record is deterministic (F4.2) — the wallet DERIVES it and refuses a notice naming a
        // different one, so a locally-checkable malformed notice is rejected up front (halt stands)
        // rather than accepted and then deadlocking the corrected re-delivery.
        let claim = claim_record_id(
            &self.seed_instance,
            &self.channel_id,
            &receipt.ckpt_ref,
            amount,
        );
        if receipt.claim_record != claim {
            return false;
        }
        // Record the round pending rail-verification, then recompute the halt (crash-durability: in this
        // in-memory RI, ordering within the method; a durable store is deferred). Snapshot the
        // operative `CUM_TOTAL` so the credit-time `E_r` fold uses THIS round's checkpoint. `refresh_halt`
        // now excludes this in-flight round, so the halt clears iff nothing further is owed.
        self.pending_verify = Some(PendingVerify {
            ckpt_ref: receipt.ckpt_ref,
            claim_record: claim,
            amount,
            cum_total: op.cum_total,
            tx_ref: receipt.tx_ref.clone(),
            defaulted: false,
        });
        self.refresh_halt();
        true
    }

    /// Rail-verify a resumed round and CREDIT it (F5-o **rail-for-value**). Independently
    /// confirms the receipt's claim record is THIS round's
    /// (`claim_record_id(seed_instance, channel_id, ckpt_ref, P)`), that the rail shows that
    /// record FUNDED by the distributing kind (F6-m `funds_claim`, never a plain transfer that
    /// merely carries the key), and that it reached the channel-required `FIN_MEED`. On
    /// success it folds the round's per-role `E_r` into `credited_r` (the payer-side mirror of the
    /// merchant's `settled_r` fold, F6-f) and clears `pending_verify`, permitting the next round's
    /// resume; on any failure the round stays uncredited — signed evidence of merchant default
    /// (F5-o). MUST run before the next round's resume, NEVER deferred to close (else a merchant
    /// could fake the *final* round's receipt and short the recipients for that session). Returns
    /// whether the round is now credited.
    pub fn verify_pending_draw(&mut self, rail: &dyn RailAdapter) -> bool {
        let Some(pv) = self.pending_verify.clone() else {
            return false; // nothing to verify
        };
        if self.try_credit(&pv, rail) {
            self.pending_verify = None; // credited — the next round may resume
                                        // A GENUINE rail-credited settlement — advance the `TH_TIME`
                                        // anchor to now (F8.4b: `last_settle` = time of the last
                                        // settlement round). ONLY a credit moves it; a mere resume /
                                        // re-anchor / unfunded draw never does, so the deadline cannot
                                        // be deferred without actually settling.
            self.last_settle = self.clock.now();
            // Settled: recompute the halt so a credited round never leaves a stale halt.
            self.refresh_halt();
            true
        } else {
            // The draw did not verify — an unfunded/short draw (default), or funding not yet final. Mark
            // the round DEFAULTED so the halt calc no longer treats it as in-flight, then re-halt: the
            // wallet stops streaming, so the strippable meed stays bounded to this one already-accrued
            // round (§6.4 — a signed notice for an unfunded draw resumes ONCE, then the halt does not
            // clear). The round stays recorded (verify-before-next bars the next one); a later genuine
            // funding still verifies and credits it (this method is idempotent-retryable).
            if let Some(p) = self.pending_verify.as_mut() {
                p.defaulted = true;
            }
            self.refresh_halt();
            false
        }
    }

    /// The F5-o rail-for-value checks + F6-f fold for a resumed round: the claim record is THIS round's
    /// derived id (binds the cumulative `target_P`+`CKPT_REF`+instance, so a merchant cannot name another round's funded
    /// record), the rail shows THAT record funded by the distributing kind (F6-m `funds_claim`, never a
    /// plain transfer that merely carries the key), and it reached the channel-required `FIN_MEED`.
    /// On success it folds the per-role `E_r` into `credited_r`. Returns whether the round credited.
    fn try_credit(&mut self, pv: &PendingVerify, rail: &dyn RailAdapter) -> bool {
        let want = claim_record_id(
            &self.seed_instance,
            &self.channel_id,
            &pv.ckpt_ref,
            pv.amount,
        );
        if pv.claim_record != want {
            return false;
        }
        // (2) The rail must show THAT advance moved the per-channel meed watermark to at least
        // the wallet's cumulative `target_P` (Option W, F6-o) — the enablers-actually-paid fact, on THIS channel's instance — never
        // a plain transfer or a state read. The aggregate `funded_p` reaching the wallet's own
        // cumulative target is sufficient; the wallet never re-floors per role (the instance's
        // deterministic division is authoritative — this is what eliminates the v2 floor-desync).
        let rref = RailRef(pv.tx_ref.clone());
        let distributed = rail
            .ref_target(&rref)
            .and_then(|i| i.advanced_channel_meed)
            .map(|f| {
                f.channel_id == self.channel_id
                    && f.seed_instance == self.seed_instance
                    && f.funded_p >= pv.amount
            })
            .unwrap_or(false);
        if !distributed {
            return false;
        }
        if !finality_reached(rail, &rref, &self.fin_meed) {
            return false;
        }
        // Fold THIS round's per-role `E_r` into `credited_r` from the round's own operative `CUM_TOTAL`
        // with the SAME F7 arithmetic, NEVER the notice's asserted `EXTINGUISHED`, so `credited_r` tracks
        // the merchant's cumulative `settled_r`. Under Option W `pv.amount` is the CUMULATIVE watermark
        // target (the absolute position), so the round's incremental carve is `divide_round(outstanding)`
        // (= cumulative_target − already-credited), NOT `pv.amount` (which would double-count every prior
        // round). `credited_r` is unchanged since resume (verify-before-next admits one round at a time),
        // so this is exactly this round's own draw. An inconsistent metering (out-of-domain accrual)
        // leaves the round uncredited.
        self.fold_credited(pv.cum_total)
    }

    /// The carve-basis check the wallet runs before co-signing or recording a `CHECKPOINT` (F5.4).
    /// Returns the validated `CUM_TOTAL` iff: it is OUR channel; `CUM_TOTAL` fits `u128` and
    /// does not exceed what the wallet has streamed (never attest more consumption — hence more carve —
    /// than it authorized); and `ACCRUALS` are exactly `CUM_TOTAL·bp_r`, role-aligned to the wallet's
    /// own signed vector. Everything else is the merchant's to recompute (F6-c).
    fn checkpoint_basis_ok(&self, cp: &Checkpoint) -> Option<u128> {
        if cp.channel_id != self.channel_id {
            return None;
        }
        let cum = u128::try_from(cp.cum_total.clone()).ok()?;
        if cum > self.cum_streamed {
            return None;
        }
        if cp.accruals.len() != self.roles_bp.len() {
            return None;
        }
        let cum_u = U256::from(cum);
        for ((role, bp), (crole, cnum)) in self.roles_bp.iter().zip(cp.accruals.iter()) {
            if *crole != *role {
                return None;
            }
            let want = cum_u.checked_mul(U256::from(*bp as u128))?;
            // The per-role accrual must be in the F7-a settlement domain (`< 2^128`). The wire `parse`
            // rejects an out-of-domain `ACCRUALS`, but a directly-constructed `Checkpoint` struct could
            // carry one; recording it would make the owed carve uncomputable (`divide_round` rejects),
            // so the wallet would neither halt on nor settle the round — refuse it here.
            if u128::try_from(want).is_err() {
                return None;
            }
            if u256_from_biguint(cnum).ok()? != want {
                return None;
            }
        }
        Some(cum)
    }

    /// The wallet's own owed carve at a co-signed operative `cum_total` (F5-o): the outstanding
    /// `floor((ACCRUALS − credited) / 10000)`, computed with the SAME per-role F7 division the merchant
    /// runs ([`divide_round`] at unity rate), so the two never diverge. Per-role, so it mirrors the
    /// merchant's `check_domain` exactly — an out-of-domain accrual (one the merchant could not settle
    /// either, so it would emit no draw) yields `None`, never a phantom carve to halt-and-wait on. Also
    /// `None` on the inconsistent state `credited > accrued` (checked, never saturated — a saturated `0`
    /// would mask a metering fault and mis-credit).
    fn carve_at(&self, cum_total: u128) -> Option<u128> {
        let outstanding = self.outstanding_at(cum_total)?;
        let div = divide_round(&outstanding, &Rate::new(1, 1).ok()?).ok()?;
        u128::try_from(biguint_from_u256(div.p)).ok()
    }

    /// The Option W own-cumulative meed **watermark target** the merchant advances `funded_p` to at
    /// this operative `cum_total`: `floor((Σ ACCRUALS_r − Σ imported_settled_r) / 10 000)` — the SAME
    /// quantity `carriage.rs::cumulative_target_p` computes (its `outstanding_meed_per_role →
    /// divide_round` at unity rate) and names in `PREPAY_DRAW_COMPLETED.amount` (`carriage.rs:2088`).
    /// The wallet resumes on THIS cumulative position, never the per-round [`carve_at`] (net of
    /// already-credited meed) which lags the cumulative target by every prior round. This wallet
    /// meters only its OWN accrual (`imported_settled = 0` — a first-generation channel; chained-import
    /// metering is a deferred wallet item, exactly as item B's `credited_r = 0` opening basis), so the
    /// target reduces to `floor(Σ ACCRUALS_r / 10 000)`, computed via the same per-role F7 division
    /// [`carve_at`] uses so the two ends never diverge. It is the wallet's OWN self-metering, NEVER a
    /// caller input — a merchant naming a SMALLER cumulative target does not match, so it cannot strip
    /// past one round (§6.4). `None` on an out-of-domain accrual (one the merchant could not settle
    /// either, so it would emit no draw), never a phantom target to halt-and-wait on.
    fn cumulative_target_at(&self, cum_total: u128) -> Option<u128> {
        let cum = U256::from(cum_total);
        let mut accrued = Vec::with_capacity(self.roles_bp.len());
        for (_, bp) in self.roles_bp.iter() {
            accrued.push(cum.checked_mul(U256::from(*bp as u128))?);
        }
        let div = divide_round(&accrued, &Rate::new(1, 1).ok()?).ok()?;
        u128::try_from(biguint_from_u256(div.p)).ok()
    }

    /// The carve currently in-flight — a round the wallet resumed and is still settling (pending
    /// rail-verification). This is the round's OWN carve — its DELTA above the already-credited watermark
    /// position, `carve_at(pv.cum_total)` — NOT its cumulative watermark target `pv.amount` (which under
    /// Option W is the absolute position, subsuming every prior round). `owed_beyond_in_flight` subtracts
    /// this from `carve_at(cum_streamed)` (also a per-round quantity net of `credited_r`), and `credited_r`
    /// is unchanged while the round is in-flight, so this equals `cumulative_target(op) − already-credited`
    /// = exactly the round's draw. A **defaulted** round (a failed rail check) is again OWED, so it is NOT
    /// counted as in-flight: the wallet stays halted on it, keeping the strip bounded to the one
    /// already-accrued round (a re-signaled overdue tick cannot un-halt a stream whose meed was never
    /// funded). An uncomputable in-flight carve fails safe to `0` (more owed → halt).
    fn in_flight_amount(&self) -> u128 {
        self.pending_verify
            .as_ref()
            .filter(|pv| !pv.defaulted)
            .and_then(|pv| self.carve_at(pv.cum_total))
            .unwrap_or(0)
    }

    /// The payer's OUTSTANDING postpay liability (F6-e/F6-g): cumulative streamed value net of what
    /// the payer has settled — the quantity `limit_l` (`L_credit`) bounds, NOT lifetime `cum_streamed`
    /// (mirroring the merchant's `outstanding = CUM − Σfunding − Σnet − settled_carve`, `carriage.rs`
    /// `imported_balance_f6e`). Wallet-side postpay SETTLEMENT (the payer funds the merchant in its own
    /// round — postpay settles via the payer's round, not a merchant draw: `carriage.rs`
    /// `compute_pending_draw` returns `None` for postpay) is NOT wired in this RI (a tracked deferral,
    /// like chained-import metering), so the settled watermark is `0` and this equals `cum_streamed`
    /// today. It is kept as an explicit `outstanding` seam so that wiring settlement later cannot
    /// silently turn the cap into a naive lifetime bound that freezes a long-lived, repeatedly-settled
    /// postpay channel.
    fn postpay_outstanding(&self) -> u128 {
        // settled watermark = 0 (no wallet-side postpay settlement path yet); outstanding == cum_streamed.
        self.cum_streamed
    }

    /// Whether the wallet has **settleable value present** — unsettled streamed meed the debtor could
    /// settle (F6.5 Triggers' second conjunct). This is `carve_at(cum_streamed) > 0`, i.e. the wallet
    /// streamed more meed than it has **credited** — net of CREDITED ONLY, deliberately **NOT** of
    /// in-flight rounds. Using the credited watermark (not `owed_beyond_in_flight`, which subtracts an
    /// in-flight `pending_verify`) is what makes the `TH_TIME` gate immune to an unfunded resume: a
    /// validly-signed but unfunded draw installs a `pending_verify` but credits nothing, so it cannot
    /// mask settleable value or reset the deadline. An out-of-domain
    /// `cum_streamed` (`carve_at` → `None`) fails safe to "present" (a halt), never a swallowed `0`.
    fn settleable_value_present(&self) -> bool {
        !matches!(self.carve_at(self.cum_streamed), Some(0))
    }

    /// Re-evaluate the conformant prepay halt (F6.5/§6.4) from the wallet's OWN metering + local clock —
    /// a pure function of the metering + clock state, so no interleaving strands a stale halt. Halted iff
    /// prepay and EITHER the **value** trigger or the **time** trigger fires:
    /// - **Value** (F5.2): the wallet has STREAMED a full round (`TH_value`'s carve, `round_carve`) of meed
    ///   beyond what it has credited and in-flight. This makes the §6.4 "bounded to one round" strip bound
    ///   rest on the wallet's OWN metering — it stops at the next `TH_value` whether or not the interaction
    ///   layer ever signals an overdue round (the strip where a withheld `verify_pending_draw`
    ///   let a hostile layer stream unbounded past unpaid meed). A round is due only AT `TH_value`, so the
    ///   threshold is a full `round_carve`, never `≥ 1`. With `round_carve = 0` (value trigger disabled) the
    ///   wallet still halts on the OPERATIVE's own owed round (an uncomputable carve fails safe to a halt).
    /// - **Time** (`TH_TIME`, C1-9): `now − last_settle ≥ th_time` on the wallet's LOCAL clock, WITH
    ///   settleable value present (the two spec conjuncts, F8.4b / `06-channel-state-machine.md:62`).
    ///   `last_settle` advances ONLY on a genuine rail credit and never on a mere resume/re-anchor, and the
    ///   "settleable present" conjunct is net of CREDITED (not in-flight) — so a withheld first checkpoint
    ///   (no operative) STILL halts on time, a merchant re-anchoring or floating an UNFUNDED draw cannot
    ///   defer the deadline, and a genuinely-settling channel (each credit advances `last_settle`) does NOT
    ///   halt early. `th_time = 0` disables it (value-only settlement, F5.2). Never a `Checkpoint.timestamp`.
    fn refresh_halt(&mut self) {
        if !self.prepay {
            // Postpay: the wallet is the debtor; postpay flow-control is the pre-mint `L_credit` cap
            // (Part A, `next_slice`). No prepay meed self-halt or wallet-driven time halt here — the
            // payer-as-debtor `TH_TIME` round is a coherent future extension (the wallet's postpay
            // settlement path is not wired in this RI).
            self.halted = false;
            return;
        }
        // (1) Value trigger + operative-owed fallback (unchanged semantics, factored out).
        let value_halt = if self.round_carve > 0 {
            self.owed_beyond_in_flight(self.cum_streamed) >= self.round_carve
        } else {
            let in_flight = self.in_flight_amount();
            self.operative
                .as_ref()
                .is_some_and(|op| self.carve_at(op.cum_total).is_none_or(|c| c > in_flight))
        };
        // (2) TH_TIME time trigger — `now − last_settle ≥ th_time` AND settleable value present.
        let time_halt = self.th_time > 0
            && self.clock.now().saturating_sub(self.last_settle) >= self.th_time
            && self.settleable_value_present();
        self.halted = value_halt || time_halt;
    }

    /// The unsettled carve OWED beyond the in-flight round, at cumulative streamed value `cum`
    /// (`carve_at(cum) − in_flight`). An out-of-domain `cum` (past the F7-a `2^128` accrual ceiling) is
    /// UNCOMPUTABLE — treated as **maximum debt** so the wallet halts FAIL-SAFE rather than silently
    /// un-halting and streaming unbounded (a `None` swallowed to `0` was the strip). A metering
    /// fault (`credited > accrued`) is likewise `None` → max debt → halt, never mis-credited to `0`.
    fn owed_beyond_in_flight(&self, cum: u128) -> u128 {
        let in_flight = self.in_flight_amount();
        self.carve_at(cum)
            .map_or(u128::MAX, |c| c.saturating_sub(in_flight))
    }

    /// The per-role outstanding numerators `accrued_r − credited_r` at `cum_total` (`accrued_r =
    /// cum_total·bp_r`), in `roles_bp` order — the input to the F7 division. `None` on an overflowing
    /// accrual or the inconsistent `credited_r > accrued_r` (checked, never saturated).
    fn outstanding_at(&self, cum_total: u128) -> Option<Vec<U256>> {
        let cum = U256::from(cum_total);
        let mut outstanding = Vec::with_capacity(self.roles_bp.len());
        for ((_, bp), credited) in self.roles_bp.iter().zip(self.credited_r.iter()) {
            let accrued = cum.checked_mul(U256::from(*bp as u128))?;
            outstanding.push(accrued.checked_sub(*credited)?);
        }
        Some(outstanding)
    }

    /// Fold a rail-credited round's per-role `E_r` into `credited_r` (F6-f), recomputed from the round's
    /// own operative `CUM_TOTAL` with the SAME F7 arithmetic the merchant used. The round's incremental
    /// carve is `divide_round(outstanding).p` (`= floor((ACCRUALS − credited)/10 000)`, the DELTA above
    /// the already-credited watermark — never the receipt's CUMULATIVE `pv.amount`), and `div.e_r` is its
    /// canonical F7-c per-role attribution (`E = P·BP_DENOM` at unity rate). Folding it keeps
    /// `Σ credited_r = settled_p · BP_DENOM`, so the next round's `carve_at` (and hence the streaming
    /// self-halt) reflects exactly the unsettled meed. Returns `false` on an inconsistent metering
    /// (out-of-domain accrual, or `credited > accrued`), leaving `credited_r` unchanged so a fault never
    /// corrupts the running credit.
    fn fold_credited(&mut self, cum_total: u128) -> bool {
        let Some(outstanding) = self.outstanding_at(cum_total) else {
            return false;
        };
        let Ok(rate) = Rate::new(1, 1) else {
            return false;
        };
        let Ok(div) = divide_round(&outstanding, &rate) else {
            return false;
        };
        for (credited, er) in self.credited_r.iter_mut().zip(div.e_r.iter()) {
            *credited += *er;
        }
        true
    }

    pub fn is_halted(&self) -> bool {
        self.halted
    }

    pub fn channel_id(&self) -> [u8; 8] {
        self.channel_id
    }

    /// Build a payer `CLOSE` (F5-l). Only a payer-signed close may carry chain
    /// intent, so this is where a chained follow-on channel is requested.
    pub fn close(
        &self,
        ckpt_ref: [u8; 32],
        chain_intent: bool,
    ) -> Result<Close, ChannelClientError> {
        let mut c = Close {
            channel_id: self.channel_id,
            ckpt_ref,
            chain_intent,
            sig: None,
        };
        self.custody
            .with_signing_key(&self.scope, |sk| c.sign(sk))
            .map_err(|_| ChannelClientError::Establish)?;
        Ok(c)
    }
}

/// Whether `r` reached at least `required` finality on `rail` (F8.1 — levels are compared
/// within one adapter's ordered list, never across rails). Mirrors the merchant's check so the
/// payer credits a round on exactly the finality the merchant confirmed against.
fn finality_reached(rail: &dyn RailAdapter, r: &RailRef, required: &str) -> bool {
    let levels = rail.caps().finality_levels;
    let idx = |lvl: &str| levels.iter().position(|l| l == lvl);
    match (rail.finality(r).and_then(|f| idx(&f.level)), idx(required)) {
        (Some(reached), Some(need)) => reached >= need,
        _ => false,
    }
}

/// Reclaim automation (F4.5) is inherently two-phase, because the contest window
/// (`T_exec = opened_at + contest`, F4.3) must elapse **between** opening a reclaim
/// and executing it — the merchant may still deliver (attest) inside the window,
/// which makes the entry terminal and the reclaim a no-op.
///
/// Phase 1: open a reclaim on an unreceipted entry once its `[T_open, T_lapse]`
/// window is open. Returns `true` if the reclaim is (now) open; `false` if the
/// entry is terminal — the merchant attested, so it was delivered and MUST NOT be
/// reclaimed (the rail refuses it) — or the window is not yet open. Time is the
/// rail's authoritative clock (F8-a).
#[must_use]
pub fn open_reclaim_if_unreceipted(
    rail: &VirtualRail,
    instance_addr: &str,
    entry_id: [u8; 32],
) -> bool {
    rail.open_reclaim(instance_addr, entry_id).is_ok()
}

/// Phase 2: execute a reclaim whose contest window has fully passed, returning the
/// meed deposit to the payer. Returns `false` if the window has not passed or
/// the merchant attested in the meantime (terminal) — either way the payer keeps
/// no claim it should not have.
#[must_use]
pub fn execute_reclaim_if_due(rail: &VirtualRail, instance_addr: &str, entry_id: [u8; 32]) -> bool {
    matches!(rail.execute_reclaim(instance_addr, entry_id), Ok(()))
}

#[cfg(test)]
mod tests {
    //! F5-o / F6-n payer-resume: the wallet resumes on a merchant-signed `PREPAY_DRAW_COMPLETED`
    //! (liveness) but credits a round only from the rail (value), and a hostile merchant that signs
    //! a receipt it never funded is bounded to one round (verify-before-next).
    use super::*;
    use crate::clock::ManualClock;
    use crate::custody::Custody;
    use crate::policy::StaticPolicy;
    use num_bigint::BigUint;
    use paytp_core::channel::VectorEntry;
    use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
    use paytp_core::derive::{claim_record_id, AddressInputs, MeedVectorEntry};
    use paytp_merchant::ChannelDriver;
    use paytp_rail::{MeedShare, VirtualRail};

    const PAYER_SK: [u8; 32] = [1u8; 32];
    const MERCH_SK: [u8; 32] = [2u8; 32];
    const ENC_SEED: [u8; 32] = [7u8; 32];
    const CID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];
    const NOW: u64 = 1_700_000_000;
    const BASELINE: &str = "solana:dev/usdc";

    /// A fixed clock reading `NOW` — injected by the tests that do NOT exercise the `TH_TIME`
    /// deadline (they just need a clock present). It never advances, so the time trigger never
    /// spuriously fires (`now − last_settle = 0 < th_time`). The Part B time tests inject a
    /// [`ManualClock`](crate::clock::ManualClock) and advance it explicitly.
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> u64 {
            NOW
        }
    }
    static FIXED_CLOCK: FixedClock = FixedClock;

    fn test_vector() -> Vec<VectorEntry> {
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

    /// The meed-instance seed the wallet derives internally — recomputed here so the test can
    /// deploy the matching on-rail instance.
    fn seed_instance_for(merchant_key: [u8; 32]) -> [u8; 32] {
        AddressInputs {
            merchant_key,
            asset: BASELINE.into(),
            schema: 1,
            vector: test_vector()
                .iter()
                .map(|v| MeedVectorEntry {
                    role: v.role,
                    bp: v.bp,
                    dest: v.dest.clone(),
                })
                .collect(),
            contract: 1,
            merchant_net: None,
        }
        .seed_instance()
        .unwrap()
    }

    /// Build the `PayerChannelTrust` (wallet custody + own 0x12 pointer + verified
    /// artifact host/enc_key) and open — the test-side mirror of how a caller assembles
    /// the trusted, non-IL inputs. `enc` is bound here so the trust can borrow it.
    #[allow(clippy::too_many_arguments)]
    fn open_ws<'c>(
        custody: &'c Custody,
        dch: &ChannelDriver,
        host: &str,
        clock: &'c dyn Clock,
        policy: StaticPolicy,
        params: &ChannelOpenParams,
        s: &[u8; 32],
        meed: Option<&str>,
    ) -> Result<(ChannelOpen, ChannelClient<'c, StaticPolicy>), ChannelClientError> {
        let binding = AcceptedBinding::for_test(dch.key(), host, dch.enc_key());
        let trust = PayerChannelTrust {
            custody,
            wallet_meed_dest: meed,
            binding: &binding,
        };
        ChannelClient::open_with_secret(
            &trust,
            clock,
            policy,
            params,
            s,
            SnapshotStore::empty_ref(),
        )
    }

    fn open_prepay_wallet<'c>(
        custody: &'c Custody,
        dch: &ChannelDriver,
    ) -> ChannelClient<'c, StaticPolicy> {
        let params = ChannelOpenParams {
            channel_id: CID,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: true,
            limit_l: 1_000_000,
            limit_e: 500_000,
            th_value: 100_000,
            th_time: 3600,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector: test_vector(),
            refund_ptr: Some("solana:dev:refund".into()),
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        };
        let (_open, client) = open_ws(
            custody,
            dch,
            "merchant.example.com",
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &params,
            &[0x5a; 32],
            Some("solana:dev:wallet"),
        )
        .unwrap();
        client
    }

    /// A POSTPAY wallet (`prepay: false`) — the merchant extends credit up to `limit_l`
    /// (`L_credit`), settled in arrears. `th_value = 0` so no prepay one-round value self-halt
    /// applies; the payer-liability bound under test is the cumulative `limit_l` cap.
    fn open_postpay_wallet<'c>(
        custody: &'c Custody,
        dch: &ChannelDriver,
        limit_l: u128,
    ) -> ChannelClient<'c, StaticPolicy> {
        let params = ChannelOpenParams {
            channel_id: CID,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: false,
            limit_l,
            limit_e: 500_000,
            th_value: 0,
            th_time: 3600,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector: test_vector(),
            // Postpay carries NO refund pointer (F5.2 `check_presence`: REFUND_PTR iff prepay).
            refund_ptr: None,
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        };
        let (_open, client) = open_ws(
            custody,
            dch,
            "merchant.example.com",
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &params,
            &[0x5a; 32],
            Some("solana:dev:wallet"),
        )
        .unwrap();
        client
    }

    /// Open a channel and return the on-wire `CHANNEL_OPEN` (so a test can read the
    /// `CHANNEL_AUTH.payer_key` an observer would see) for a given merchant + host.
    fn open_auth_to(
        custody: &Custody,
        dch: &ChannelDriver,
        host: &str,
        cid: [u8; 8],
    ) -> ChannelOpen {
        let params = ChannelOpenParams {
            channel_id: cid,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: true,
            limit_l: 1_000_000,
            limit_e: 500_000,
            th_value: 100_000,
            th_time: 3600,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector: test_vector(),
            refund_ptr: Some("solana:dev:refund".into()),
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        };
        let (open, _client) = open_ws(
            custody,
            dch,
            host,
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &params,
            &[0x5a; 32],
            Some("solana:dev:wallet"),
        )
        .unwrap();
        open
    }

    #[test]
    fn payer_is_unlinkable_across_merchants_on_the_wire_lab() {
        // UNLINKABILITY LAB TEST (F1-f/F2.3): ONE payer (one custody root) opens
        // channels at different merchants. An on-path observer reads `CHANNEL_AUTH.payer_key`
        // from each open; the property is that it cannot correlate the payer across merchants,
        // while a returning payer keeps ONE stable identity at a given (merchant, domain).
        let payer = Custody::from_root(&[9u8; 32]);
        let dch_a = ChannelDriver::new([0x2a; 32], &ENC_SEED, "solana:dev:settle");
        let dch_b = ChannelDriver::new([0x3b; 32], &ENC_SEED, "solana:dev:settle");

        let cid1 = [0, 0, 0, 0, 0, 0, 0, 1];
        let cid2 = [0, 0, 0, 0, 0, 0, 0, 2];
        let a1 = open_auth_to(&payer, &dch_a, "alice-shop.com", cid1);
        let b1 = open_auth_to(&payer, &dch_b, "bob-store.com", cid1);

        // Different merchant → different on-wire payer identity: the observer cannot link.
        assert_ne!(a1.auth.payer_key, b1.auth.payer_key);
        // Session keys are unlinkable too — the payer_key feeds `bind_salt` → `k_session`,
        // so no shared salt leaks the correlation either.
        assert_ne!(
            crypto::bind_salt(&a1.auth.payer_key, &dch_a.key()),
            crypto::bind_salt(&b1.auth.payer_key, &dch_b.key())
        );

        // Same merchant + same registrable domain, a LATER channel (different channel id):
        // the payer presents the SAME stable identity (a returning customer is recognizable
        // to that one merchant — the intended, scoped linkage).
        let a2 = open_auth_to(&payer, &dch_a, "alice-shop.com", cid2);
        assert_eq!(a1.auth.payer_key, a2.auth.payer_key);
        // A different subdomain of the SAME registrable domain folds to the same scope →
        // same identity (a merchant's api./www. hosts are one unlinkability boundary).
        let a_sub = open_auth_to(&payer, &dch_a, "api.alice-shop.com", cid2);
        assert_eq!(a1.auth.payer_key, a_sub.auth.payer_key);
    }

    /// Build channel params carrying a caller-chosen meed `vector` (for the payer-side
    /// self-defense repro), otherwise identical to the prepay test params.
    fn params_with_vector(vector: Vec<VectorEntry>) -> ChannelOpenParams {
        ChannelOpenParams {
            channel_id: CID,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: true,
            limit_l: 1_000_000,
            limit_e: 500_000,
            th_value: 100_000,
            th_time: 3600,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector,
            refund_ptr: Some("solana:dev:refund".into()),
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        }
    }

    #[test]
    fn wallet_refuses_to_sign_a_channel_auth_that_misroutes_its_own_0x12() {
        // F5-o REPRO: a hostile interaction layer assembles a CHANNEL_AUTH whose `0x12`
        // wallet meed share is rerouted to the attacker. The vector is still schema-conformant and
        // its governed `0x11`/`0x13` are correct, so `validate_vector_governed` PASSES it — only
        // the wallet's OWN-pointer self-defense catches it, and it does so BEFORE the payer signs.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let wallet_dest = "solana:dev:wallet"; // the wallet's OWN configured payout pointer

        // Honest vector (0x12 == the wallet's own dest) → the open succeeds.
        let honest = params_with_vector(test_vector());
        assert!(open_ws(
            &custody,
            &dch,
            "merchant.example.com",
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &honest,
            &[0x5a; 32],
            Some(wallet_dest),
        )
        .is_ok());

        // Hostile vector: reroute 0x12 to the attacker. Governed check still passes it...
        let mut evil = test_vector();
        evil[2].dest = "solana:dev:attacker".into();
        let evil_params = params_with_vector(evil);
        let res = open_ws(
            &custody,
            &dch,
            "merchant.example.com",
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &evil_params,
            &[0x5a; 32],
            Some(wallet_dest),
        );
        // ...but the wallet REFUSES to sign it (F5-o self-defense), so no misrouted CHANNEL_AUTH
        // is ever produced.
        assert!(matches!(res, Err(ChannelClientError::Establish)));
    }

    #[test]
    fn postpay_slices_past_l_credit_are_refused() {
        // Part A repro (money-adjacent): a fresh postpay channel admits up to L_credit and NOT past it
        // (spec F10/`10-conformance-vectors.md:24`). Two individually policy-valid slices must not sum
        // past `limit_l` — the wallet independently bounds the payer's OUTSTANDING liability, so an
        // untrusted IL cannot drive postpay spend past the agreed credit limit (before Part A the second
        // slice was admitted and `checkpoint_basis_ok` would co-sign any `CUM ≤ cum_streamed`).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_postpay_wallet(&custody, &dch, 1_000_000);
        assert!(
            client.next_slice(600_000).is_ok(),
            "first slice within L_credit"
        );
        // The second policy-valid slice would push outstanding to 1_200_000 > limit_l → REFUSED.
        assert_eq!(
            client.next_slice(600_000),
            Err(ChannelClientError::WindowExceeded),
            "a postpay slice past L_credit is refused with WindowExceeded"
        );
        // Bookkeeping is unchanged by the refusal: a within-headroom slice up to the exact bound is
        // still admitted (400_000 → cumulative 1_000_000 == limit_l), and the next µ-unit is refused.
        assert!(
            client.next_slice(400_000).is_ok(),
            "a slice landing exactly on L_credit is admitted"
        );
        assert_eq!(
            client.next_slice(1),
            Err(ChannelClientError::WindowExceeded),
            "one µ-unit past the exact L_credit boundary is refused"
        );
    }

    #[test]
    fn prepay_is_not_frozen_by_the_postpay_cap() {
        // Part A hazard: the L_credit cap is POSTPAY-ONLY. A prepay channel's `limit_l`
        // is a DEPOSIT limit, and `cum_streamed` is a monotone LIFETIME counter that legitimately grows
        // past the deposit as the on-rail deposit is refilled and rounds settle. Applying the postpay
        // cap to prepay would freeze such a channel the instant lifetime consumption crossed `limit_l`.
        // Here a prepay channel streams+settles rounds until lifetime `cum_streamed` far exceeds
        // `limit_l`, and is NEVER refused with WindowExceeded — only the normal one-round `round_carve`
        // self-halt applies (and clears on settlement).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch); // limit_l = 1_000_000; round_carve = 1000
        let mut lifetime = 0u128;
        // Stream and settle enough rounds that lifetime streamed > limit_l (1_000_000). Each round is
        // one `TH_value` (100_000) of value, settled on the rail so the halt clears and streaming resumes.
        for round in 1..=15u128 {
            // Stream a full round (self-halts at the boundary).
            for _ in 0..10 {
                match client.next_slice(10_000) {
                    Ok(_) => lifetime += 10_000,
                    Err(ChannelClientError::HaltedOnOverdueMeed) => break,
                    Err(e) => panic!("prepay must never be WindowExceeded-frozen, got {e:?}"),
                }
            }
            // Settle the round on the rail (co-sign → record → resume → verify) so the halt clears.
            let cum = 100_000 * round;
            let cp = bilateral_checkpoint(&client, cum);
            let ckpt_ref = cp.reference().unwrap();
            assert!(client.record_operative(&cp));
            let receipt = fund_and_sign(&rail, dch.key(), ckpt_ref, cum / 100); // cumulative target
            assert!(client.resume_on_prepay_draw(&receipt));
            assert!(client.verify_pending_draw(&rail));
        }
        assert!(
            lifetime > 1_000_000,
            "prepay streamed lifetime {lifetime} µ-units — well past limit_l — without any WindowExceeded"
        );
    }

    #[test]
    fn postpay_unevidenced_liability_is_bounded_by_l_credit_not_a_separate_e_cap() {
        // Part A DISPUTED point resolved by repro: the wallet does NOT
        // enforce `limit_e` (the *unevidenced*-value bound) as a payer-side cap. `E` is the MERCHANT's
        // evidence-risk bound — "credit at most L_credit … AND accepted-but-unevidenced value at most E,
        // each enforced by the merchant itself" (`07-security-model.md:7`; the sole runtime `E` check is
        // core `state.rs:326`). A payer is not harmed by unevidenced value (it is the merchant that
        // cannot PROVE the debt); the payer's liability is bounded by `L_credit` + `checkpoint_basis_ok`.
        //
        // Concretely: a hostile IL WITHHOLDS all checkpoints (so every streamed µ-unit is unevidenced)
        // and streams PAST `limit_e` (500_000) — which the wallet ADMITS (no wallet-side E cap) — but it
        // is still stopped at `limit_l` (1_000_000). Unevidenced growth cannot push the payer's liability
        // past L_credit, because unevidenced value ⊆ `cum_streamed`, which the L_credit cap bounds.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        // limit_l = 1_000_000, limit_e = 500_000.
        let mut client = open_postpay_wallet(&custody, &dch, 1_000_000);
        // Stream 600_000 unevidenced (NO checkpoint co-signed) — PAST limit_e (500_000). Admitted: the
        // wallet enforces no separate E cap (E is the merchant's bound, not the payer's liability).
        assert!(
            client.next_slice(600_000).is_ok(),
            "streaming past limit_e unevidenced is admitted — the wallet enforces no payer-side E cap"
        );
        // But the L_credit cap still bounds the total: 600_000 + 500_000 = 1_100_000 > limit_l → refused.
        assert_eq!(
            client.next_slice(500_000),
            Err(ChannelClientError::WindowExceeded),
            "the payer's liability is bounded by L_credit regardless of evidence status"
        );
        // Up to the exact L_credit is admitted (the remaining 400_000 headroom).
        assert!(
            client.next_slice(400_000).is_ok(),
            "the rest of the L_credit headroom is available"
        );
    }

    /// A synchronous (immediately final) rail with the meed instance deployed.
    fn setup_rail(merchant_key: [u8; 32]) -> VirtualRail {
        let rail = VirtualRail::new(0);
        rail.deploy_instance_unchecked(
            &seed_instance_for(merchant_key),
            merchant_key,
            vec![
                MeedShare {
                    dest: "solana:dev:il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
                    bp: 10,
                },
                MeedShare {
                    dest: "solana:dev:wallet".into(),
                    bp: 30,
                },
                MeedShare {
                    dest: DEV_FUND_DEST_PLACEHOLDER.into(),
                    bp: 10,
                },
            ],
        );
        // The instance must hold value to distribute from a claim-record funding.
        rail.submit(paytp_rail::Transfer {
            to: rail.derive_address(&seed_instance_for(merchant_key)),
            asset: BASELINE.into(),
            amount: 10_000_000,
            kind: paytp_rail::TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        rail
    }

    fn signed_receipt(
        ckpt: [u8; 32],
        p: u128,
        claim_record: [u8; 32],
        tx_ref: String,
    ) -> PrepayDrawCompleted {
        let mut r = PrepayDrawCompleted {
            channel_id: CID,
            ckpt_ref: ckpt,
            amount: BigUint::from(p),
            extinguished: vec![(0x10, BigUint::from(1u32))], // a valid E_r (the wallet credits on P + rail)
            claim_record,
            rail: "solana:dev".into(), // F5-o RAIL = CAIP-2 BASELINE_NET (not the CAIP-19 BASELINE)
            tx_ref,
            finality: "final".into(),
            sig_merchant: None,
        };
        r.sign_merchant(&MERCH_SK);
        r
    }

    /// The merchant genuinely funds the round on-rail, then emits the receipt — the honest path.
    /// Option W: it ADVANCES the per-channel watermark to `p` (the round's cumulative target), which
    /// sets the `advanced_channel_meed` distribution fact the wallet verifies (F6-o).
    fn fund_and_sign(
        rail: &VirtualRail,
        merchant_key: [u8; 32],
        ckpt: [u8; 32],
        p: u128,
    ) -> PrepayDrawCompleted {
        let seed = seed_instance_for(merchant_key);
        let addr = rail.derive_address(&seed);
        let rref = rail
            .advance_channel_meed(None, &addr, CID, p, BASELINE.into())
            .unwrap();
        let claim_id = claim_record_id(&seed, &CID, &ckpt, p);
        signed_receipt(ckpt, p, claim_id, rref.0)
    }

    /// A hostile merchant: a validly-signed receipt naming THIS round's correct claim record, but a
    /// draw it never funded (a bogus tx_ref) — signed evidence of default.
    fn hostile_receipt(merchant_key: [u8; 32], ckpt: [u8; 32], p: u128) -> PrepayDrawCompleted {
        let claim = claim_record_id(&seed_instance_for(merchant_key), &CID, &ckpt, p);
        signed_receipt(ckpt, p, claim, "never-funded-tx".into())
    }

    /// An unsigned `CHECKPOINT` whose `ACCRUALS` are exactly `CUM_TOTAL·bp_r` under `test_vector()` —
    /// the conformant carve basis the wallet co-signs. (Non-carve fields are placeholders; the wallet
    /// does not validate them and the merchant-recompute path is exercised elsewhere.)
    fn unsigned_checkpoint(cum: u128) -> Checkpoint {
        let accruals = test_vector()
            .iter()
            .map(|v| (v.role, BigUint::from(cum) * BigUint::from(v.bp as u128)))
            .collect();
        Checkpoint {
            channel_id: CID,
            balance: BigUint::from(0u8),
            balance_negative: false,
            cum_total: BigUint::from(cum),
            accruals,
            last_seq: 1,
            ranges: vec![],
            transcript: [0u8; 32],
            events: vec![],
            timestamp: NOW,
            prev_ref: [0u8; 32],
            sig_payer: None,
            sig_merchant: None,
        }
    }

    /// A bilateral checkpoint: the wallet co-signs (validating its carve basis), then the merchant
    /// countersigns — the real artifact `record_operative` authenticates. Requires the wallet to have
    /// streamed at least `cum` (the carve basis).
    fn bilateral_checkpoint(client: &ChannelClient<'_, StaticPolicy>, cum: u128) -> Checkpoint {
        let mut cp = unsigned_checkpoint(cum);
        client.cosign_checkpoint(&mut cp).unwrap();
        cp.sign_merchant(&MERCH_SK).unwrap();
        cp
    }

    /// The cumulative streamed value whose owed carve (`floor(cum·ΣbP/10000)`, `ΣbP = 100`) is exactly
    /// `carve` — i.e. `cum = carve · 100`.
    fn cum_for(carve: u128) -> u128 {
        carve * 100
    }

    #[test]
    fn resume_on_receipt_liveness_then_credit_on_rail() {
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        let ckpt = [0x33u8; 32];
        let p = 1_000u128;
        // The wallet co-signed an operative checkpoint owing carve `p` (cum·100/10000 = p).
        client.seed_operative(ckpt, cum_for(p));
        let receipt = fund_and_sign(&rail, dch.key(), ckpt, p);

        client.on_overdue_meed();
        assert!(
            client.is_halted(),
            "a conformant prepay wallet halts on the overdue settleable round"
        );
        // Liveness: resume at once on the merchant-signed notice.
        assert!(
            client.resume_on_prepay_draw(&receipt),
            "resume on the signed notice"
        );
        assert!(!client.is_halted());
        // Value: credit only once the rail shows the claim record funded (the distributing kind).
        assert!(
            client.verify_pending_draw(&rail),
            "the round credits once the rail shows it funded (F6-m)"
        );
    }

    #[test]
    fn hostile_receipt_resumes_once_but_never_credits_and_deadlocks() {
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // Round 1: a validly-signed receipt for a draw the merchant NEVER funded.
        let ckpt1 = [0x33u8; 32];
        let p = 1_000u128;
        client.seed_operative(ckpt1, cum_for(p));
        let fake1 = hostile_receipt(dch.key(), ckpt1, p);
        client.on_overdue_meed();
        assert!(
            client.resume_on_prepay_draw(&fake1),
            "resumes on the signature (liveness) — bounded trust, no new payer loss"
        );
        assert!(
            !client.verify_pending_draw(&rail),
            "the rail shows no funding → the round is NOT credited (signed evidence of default)"
        );

        // Round 2 comes due: the wallet streamed past round 1 and co-signed a NEW operative (cum 200_000,
        // owed 2000). The halt re-fires on the fresh round (round 1's in-flight carve does not cover it),
        // and verify-before-next bars stringing receipts: a second round cannot resume with round 1
        // uncredited, so the strip stays bounded to the one already-accrued round.
        let ckpt2 = [0x44u8; 32];
        client.seed_operative(ckpt2, 200_000);
        let fake2 = hostile_receipt(dch.key(), ckpt2, p);
        client.on_overdue_meed();
        assert!(
            client.is_halted(),
            "a fresh round is due at the advanced operative → halt"
        );
        assert!(
            !client.resume_on_prepay_draw(&fake2),
            "round 1 uncredited → resume on round 2 is REFUSED (cannot string receipts)"
        );
        assert!(
            client.is_halted(),
            "the channel deadlocks — the merchant stripped at most ONE round's meed (bounded)"
        );
    }

    #[test]
    fn receipt_rejected_for_wrong_round_or_non_merchant_signature() {
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        let ckpt = [0x33u8; 32];
        let p = 1_000u128;
        client.seed_operative(ckpt, cum_for(p));
        client.on_overdue_meed();

        // A receipt for a DIFFERENT round (≠ the operative checkpoint) does not resume this halt.
        let wrong_round = fund_and_sign(&rail, dch.key(), [0x99u8; 32], p);
        assert!(
            !client.resume_on_prepay_draw(&wrong_round),
            "wrong round does not resume"
        );

        // A non-merchant signature (payer-signed) does not resume.
        let claim = claim_record_id(&seed_instance_for(dch.key()), &CID, &ckpt, p);
        let mut forged = signed_receipt(ckpt, p, claim, "x".into());
        forged.sig_merchant = None;
        forged.sign_merchant(&PAYER_SK); // wrong signer
        assert!(
            !client.resume_on_prepay_draw(&forged),
            "a non-merchant signature does not resume"
        );

        assert!(client.is_halted(), "the halt stands against a bad receipt");
    }

    #[test]
    fn under_draw_does_not_resume_the_halt_bounding_the_strip() {
        // a hostile merchant that draws a TOKEN carve (P=1) for
        // a round owing 1000, funds it truthfully, and signs a matching notice does NOT resume the
        // halt — else it could settle a token amount each round and strip the accrued carve
        // unboundedly, breaking §6.4's "bounded to one round". The wallet resumes ONLY on a notice
        // drawing the round's FULL owed carve (F5-o).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        let ckpt = [0x33u8; 32];
        let owed = 1_000u128; // the round's full outstanding carve
        client.seed_operative(ckpt, cum_for(owed));
        client.on_overdue_meed();

        // The merchant genuinely funds only P=1 and attests it truthfully.
        let under = fund_and_sign(&rail, dch.key(), ckpt, 1);
        assert!(
            !client.resume_on_prepay_draw(&under),
            "an under-draw (P=1 for an owed 1000) does not resume — the strip stays bounded"
        );
        assert!(client.is_halted(), "the halt stands against a token draw");

        // The FULL owed carve resumes it, and credits on the rail.
        let full = fund_and_sign(&rail, dch.key(), ckpt, owed);
        assert!(
            client.resume_on_prepay_draw(&full),
            "the full owed carve resumes"
        );
        assert!(client.verify_pending_draw(&rail), "and credits on the rail");
    }

    #[test]
    fn honest_two_round_prepay_resume_credits_on_the_cumulative_target() {
        // Liveness (the payer's float): under Option W the merchant emits
        // `PREPAY_DRAW_COMPLETED.amount` as the CUMULATIVE watermark target
        // (`carriage.rs::cumulative_target_p = floor((Σaccrued − Σimported_settled)/1e4)`), NOT a
        // per-round carve. Round 1's cumulative target equals its per-round carve, so it always
        // resumed; round 2 comes due at a LARGER cumulative target, and a wallet gating on the
        // PER-ROUND carve (`carve_at`, net of already-credited) refuses the honest receipt → the
        // prepay halt never clears → the payer's float is trapped. The wallet must resume on its OWN
        // self-computed cumulative target (no test exercised an honest round-2 resume before — the
        // two-round tests were all round-1 or the hostile round-2 that deadlocks by design).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // Round 1: the wallet co-signed an operative owing carve 1000 (cumulative target == per-round).
        let ckpt1 = [0x33u8; 32];
        client.seed_operative(ckpt1, cum_for(1_000));
        client.on_overdue_meed();
        assert!(client.is_halted(), "round 1 is due → halt");
        let r1 = fund_and_sign(&rail, dch.key(), ckpt1, 1_000);
        assert!(
            client.resume_on_prepay_draw(&r1),
            "round 1 resumes on its receipt"
        );
        assert!(
            client.verify_pending_draw(&rail),
            "round 1 credits on the rail (watermark 1000)"
        );
        assert!(!client.is_halted(), "round 1 settled → streaming resumes");

        // Round 2 comes due: the wallet streamed another full round and co-signed a fresh operative at
        // cum 200_000 → CUMULATIVE target 2000 (a per-round delta of 1000 above the credited 1000). The
        // HONEST merchant advances the watermark to the cumulative 2000 and emits `amount = 2000`.
        let ckpt2 = [0x44u8; 32];
        client.seed_operative(ckpt2, cum_for(2_000));
        client.on_overdue_meed();
        assert!(
            client.is_halted(),
            "round 2 is due at the advanced operative → halt"
        );
        let r2 = fund_and_sign(&rail, dch.key(), ckpt2, 2_000); // amount = the CUMULATIVE target
        assert!(
            client.resume_on_prepay_draw(&r2),
            "the wallet resumes on the honest CUMULATIVE receipt (pre-fix: 2000 != per-round 1000 → deadlock)"
        );
        assert!(
            !client.is_halted(),
            "the honest round-2 receipt clears the halt"
        );
        assert!(
            client.verify_pending_draw(&rail),
            "round 2 credits once the watermark reaches the cumulative target 2000"
        );
    }

    #[test]
    fn cumulative_strip_bound_rejects_a_stale_under_cumulative_draw() {
        // The §6.4 strip bound (SELF-METERED): after round 1 settles the watermark at cumulative 1000,
        // a hostile merchant re-presents round 1's position (a SMALLER cumulative target 1000) for the
        // now-due round 2 whose true cumulative target is 2000. The wallet must REFUSE it — the strip
        // stays bounded to one round — because it self-computes the cumulative target from its OWN
        // co-signed metering, never a caller-supplied `expected_carve` (the exact vuln item B
        // closes). Pre-fix, a wallet gating on the PER-ROUND carve (also 1000 here) wrongly resumes AND
        // credits, stripping round 2's carve while the merchant funds nothing new.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // Round 1 settles honestly at cumulative 1000.
        let ckpt1 = [0x33u8; 32];
        client.seed_operative(ckpt1, cum_for(1_000));
        client.on_overdue_meed();
        let r1 = fund_and_sign(&rail, dch.key(), ckpt1, 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(client.verify_pending_draw(&rail));

        // Round 2 comes due at cumulative target 2000.
        let ckpt2 = [0x44u8; 32];
        client.seed_operative(ckpt2, cum_for(2_000));
        client.on_overdue_meed();
        assert!(client.is_halted(), "round 2 is due → halt");

        // The merchant re-presents the STALE cumulative 1000 (round 1's watermark position) for round 2
        // — an under-draw of the true 2000. It "funds" truthfully (an idempotent no-op advance) and
        // signs a notice naming the derived claim record for 1000.
        let stale = fund_and_sign(&rail, dch.key(), ckpt2, 1_000);
        assert!(
            !client.resume_on_prepay_draw(&stale),
            "an under-cumulative draw does NOT resume — the self-metered strip stays bounded (pre-fix: 1000 == per-round carve → wrongly resumes)"
        );
        assert!(
            client.is_halted(),
            "the halt stands against the stale under-draw"
        );

        // Only the FULL self-computed cumulative target resumes it (and credits) — the bound is precise.
        let honest = fund_and_sign(&rail, dch.key(), ckpt2, 2_000);
        assert!(
            client.resume_on_prepay_draw(&honest),
            "the full cumulative target 2000 resumes"
        );
        assert!(client.verify_pending_draw(&rail), "and credits on the rail");
    }

    #[test]
    fn zero_delta_replay_of_a_settled_operative_does_not_wedge_the_wallet() {
        // The receipt names the cumulative
        // watermark POSITION, which does NOT shrink after a round credits. A hostile merchant re-signing an
        // ALREADY-SETTLED operative (same cumulative `amount`, correct derived claim, but a bogus `tx_ref`)
        // presents a ZERO incremental carve. If the wallet installed it as `pending_verify` it would
        // default on the bogus tx and then WEDGE the next real round (verify-before-next bars a different
        // `CKPT_REF`), trapping the payer's float with NO unpaid carve to justify it. The wallet must REFUSE
        // a zero-delta operative — the immunity the pre-migration per-round check had for free (`carve_at`
        // went to 0 after crediting; the cumulative target does not).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // Round 1 settles honestly at cumulative 1000; the operative stays ckpt1 (not advanced).
        let ckpt1 = [0x33u8; 32];
        client.seed_operative(ckpt1, cum_for(1_000));
        client.on_overdue_meed();
        let r1 = fund_and_sign(&rail, dch.key(), ckpt1, 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(client.verify_pending_draw(&rail));

        // The attack: re-present the SETTLED position (amount = cumulative 1000, correct claim for
        // (ckpt1, 1000)) with a bogus tx_ref — a ZERO-delta round on the already-credited operative.
        let replay = hostile_receipt(dch.key(), ckpt1, 1_000);
        assert!(
            !client.resume_on_prepay_draw(&replay),
            "a zero-delta replay of an already-settled operative is REFUSED (no pending_verify poisoning)"
        );
        assert!(
            client.pending_verify.is_none(),
            "no round is installed for the settled position → the next real round is not wedged"
        );

        // A genuinely-owed next round still resumes and credits — proof the float was never trapped.
        let ckpt2 = [0x44u8; 32];
        client.seed_operative(ckpt2, cum_for(2_000));
        client.on_overdue_meed();
        assert!(client.is_halted(), "round 2 is due → halt");
        let r2 = fund_and_sign(&rail, dch.key(), ckpt2, 2_000);
        assert!(
            client.resume_on_prepay_draw(&r2),
            "the next real round resumes — the zero-delta replay did not wedge the wallet"
        );
        assert!(client.verify_pending_draw(&rail));
    }

    #[test]
    fn sub_denom_residue_settles_to_zero_no_phantom_debt() {
        // Sub-denom residue is NOT phantom debt. A plausible concern, refuted here: for Σbp < BP_DENOM,
        // a "phantom debt" floor-desync — that `fold_credited` adds `P·Σbp`
        // (not `P·BP_DENOM`) to `credited_r`, so after a full settlement `carve_at` stays > 0, self-halting
        // a paid-up channel AND bypassing the zero-delta guard. That is an ARITHMETIC ERROR: the F7
        // extinguished numerator is `E = P·BP_DENOM` (`compute_e` at unity) and `div.e_r` SUMS to `E`, so
        // `credited_r` tracks `P·BP_DENOM`; the residual after settling is `(Σaccrued mod BP_DENOM) <
        // BP_DENOM`, which floors to 0. (A Σbp = 5000 is moreover UNREACHABLE — schema-01 pins the
        // vector to the fixed base roles totalling Σbp = 100 for EVERY channel, and 100 is ITSELF <
        // BP_DENOM, exactly the claimed-desync regime.) `cum = 150` → Σaccrued = 15000 → target 1, a large
        // 5000 sub-denom residue; the operative still settles to owed 0. Verdict: SAFE.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        let ckpt = [0x33u8; 32];
        client.seed_operative(ckpt, 150); // Σaccrued = 150·100 = 15000, cumulative target 1, residue 5000
        client.on_overdue_meed();
        let r = fund_and_sign(&rail, dch.key(), ckpt, 1);
        assert!(
            client.resume_on_prepay_draw(&r),
            "honest round resumes on the cumulative target 1"
        );
        assert!(client.verify_pending_draw(&rail), "and credits on the rail");

        // (1) No phantom debt: the fully-settled operative owes 0, despite the 5000 sub-denom residue
        // (the phantom-debt concern would put carve_at > 0 here).
        assert_eq!(
            client.carve_at(150),
            Some(0),
            "residual < BP_DENOM floors to 0 — no phantom debt (E = P·BP_DENOM)"
        );
        // (2) credited_r accumulates E = P·BP_DENOM = 1·10000 = 10000 (NOT P·Σbp = 100).
        use paytp_core::fee::{BP_DENOM, U256};
        let credited = client
            .credited_r
            .iter()
            .copied()
            .fold(U256::ZERO, |a, c| a + c);
        assert_eq!(
            credited,
            U256::from(BP_DENOM),
            "Σ credited_r = P·BP_DENOM = 10000 (not P·Σbp = 100)"
        );
        // (3) No premature self-halt, and (4) the zero-delta guard holds — both follow from carve_at = 0.
        assert!(
            !client.is_halted(),
            "a fully-settled channel does not self-halt (liveness holds)"
        );
        let replay = hostile_receipt(dch.key(), ckpt, 1);
        assert!(
            !client.resume_on_prepay_draw(&replay),
            "zero-delta replay refused — the guard is not bypassed by any phantom debt"
        );
    }

    #[test]
    fn on_overdue_no_op_without_a_settleable_round() {
        // A round is due only AT `TH_value` (the Triggers rule): the wallet halts once it has streamed a
        // full round's carve unsettled — never below threshold, and never on a bare no-operative /
        // sub-unit position. (`TH_value = 100_000`, `round_carve = 1000` for the test channel.)
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);

        // (a) Nothing streamed → no round due → no halt.
        client.on_overdue_meed();
        assert!(!client.is_halted(), "no streamed meed ⇒ no halt");

        // (b) Streamed BELOW one round (50_000 ⇒ owed 500 < round_carve 1000) → not yet due → no halt.
        client.seed_operative([0x01; 32], 50_000);
        client.on_overdue_meed();
        assert!(
            !client.is_halted(),
            "a partial round (below TH_value) is not yet due ⇒ no halt"
        );

        // (c) A FULL round streamed (100_000 ⇒ owed 1000 = round_carve) DOES halt.
        client.seed_operative([0x02; 32], 100_000);
        client.on_overdue_meed();
        assert!(client.is_halted(), "a full round (TH_value) is due ⇒ halt");
    }

    #[test]
    fn record_operative_rejects_a_stale_checkpoint_replay() {
        // The unbounded-strip re-entry: after co-signing a LATER checkpoint (higher
        // CUM ⇒ larger owed carve), a hostile interaction layer replays an OLDER valid bilateral checkpoint
        // (lower CUM ⇒ smaller carve). record_operative MUST reject it (supersession monotonicity), so a
        // merchant cannot draw the smaller carve and strip the difference.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed (one round — the self-halt bound)
        }

        // Co-sign + record the LATER checkpoint B (cum 100_000 ⇒ owed 1000).
        let cp_b = bilateral_checkpoint(&client, 100_000);
        let ref_b = cp_b.reference().unwrap();
        assert!(client.record_operative(&cp_b));

        // Replay the OLDER checkpoint A (cum 50_000 ⇒ owed 500) — REJECTED, the operative stays B.
        let cp_a = bilateral_checkpoint(&client, 50_000);
        assert!(
            !client.record_operative(&cp_a),
            "a lower-CUM checkpoint never supersedes (would shrink the owed carve → strip)"
        );

        client.on_overdue_meed();
        assert!(client.is_halted());
        // A merchant-funded draw for A's stale round does NOT resume (wrong operative).
        let strip = fund_and_sign(&rail, dch.key(), cp_a.reference().unwrap(), 500);
        assert!(
            !client.resume_on_prepay_draw(&strip),
            "the stale (superseded) round cannot resume — no strip"
        );
        // Only B's full owed carve at B's reference resumes.
        let full = fund_and_sign(&rail, dch.key(), ref_b, 1_000);
        assert!(client.resume_on_prepay_draw(&full));
        assert!(client.verify_pending_draw(&rail));
    }

    #[test]
    fn multi_round_credited_telescoping() {
        // credited_r tracks the merchant's CUMULATIVE settled_r: round 2 resumes on the NEW cumulative
        // watermark target (Option W), and crediting folds only the INCREMENTAL carve, so the two ends
        // never double-count and never diverge (the telescoping the whole migration rests on).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // Round 1 at cum 100_000 ⇒ cumulative target 1000.
        let ck1 = [0x33; 32];
        client.seed_operative(ck1, 100_000);
        client.on_overdue_meed();
        let r1 = fund_and_sign(&rail, dch.key(), ck1, 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(client.verify_pending_draw(&rail));

        // Round 2 at cum 300_000 ⇒ cumulative target 3000 (a per-round delta of 2000 above the credited 1000).
        let ck2 = [0x44; 32];
        client.seed_operative(ck2, 300_000);
        client.on_overdue_meed();
        assert!(client.is_halted());
        // A per-round (under-cumulative) draw of only the incremental 2000 does NOT resume — the wallet
        // resumes on the cumulative watermark POSITION, so the strip stays bounded (§6.4).
        let under = fund_and_sign(&rail, dch.key(), ck2, 2_000);
        assert!(
            !client.resume_on_prepay_draw(&under),
            "an under-cumulative (per-round) draw does not resume"
        );
        // The full CUMULATIVE target 3000 resumes; crediting then folds only the incremental 2000.
        let r2 = fund_and_sign(&rail, dch.key(), ck2, 3_000);
        assert!(
            client.resume_on_prepay_draw(&r2),
            "the cumulative watermark target resumes"
        );
        assert!(client.verify_pending_draw(&rail));

        // credited_r telescopes to the cumulative 3000 (1000 + 2000) — matching the merchant's settled_r,
        // with NO double-count of round 1 (the strip / divergence a naive cumulative fold would cause).
        use paytp_core::fee::{BP_DENOM, U256};
        let credited = client
            .credited_r
            .iter()
            .copied()
            .fold(U256::ZERO, |a, c| a + c);
        assert_eq!(
            credited,
            U256::from(3_000u128) * U256::from(BP_DENOM),
            "Σ credited_r = cumulative 3000 · BP_DENOM (telescoped, no double-count)"
        );
    }

    #[test]
    fn wallet_carve_matches_merchant_divide_round() {
        // The wallet's self-computed carve equals the merchant's F7 `divide_round` P for a spread of
        // cumulative values and prior-credited states — the equivalence the whole change rests on.
        use paytp_core::fee::{biguint_from_u256, divide_round, Rate, U256};
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);

        // The merchant's P for outstanding = cum·bp_r − credited_r, via the SAME divide_round.
        let merchant_p = |client: &ChannelClient<'_, StaticPolicy>, cum: u128| -> u128 {
            let outstanding: Vec<U256> = client
                .roles_bp
                .iter()
                .zip(client.credited_r.iter())
                .map(|((_, bp), cr)| U256::from(cum) * U256::from(*bp as u128) - *cr)
                .collect();
            let div = divide_round(&outstanding, &Rate::new(1, 1).unwrap()).unwrap();
            u128::try_from(biguint_from_u256(div.p)).unwrap()
        };

        // Fresh (credited 0): match across a spread including sub-unit residues.
        for &cum in &[0u128, 99, 100, 100_000, 100_050, 1_234_567] {
            assert_eq!(
                client.carve_at(cum),
                Some(merchant_p(&client, cum)),
                "fresh cum={cum}"
            );
        }

        // After crediting one round the equivalence still holds (credited_r == settled_r).
        let ck = [0x33; 32];
        client.seed_operative(ck, 100_000);
        client.on_overdue_meed();
        let r1 = fund_and_sign(&rail, dch.key(), ck, 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(client.verify_pending_draw(&rail));
        for &cum in &[100_000u128, 100_050, 300_000, 1_234_567] {
            assert_eq!(
                client.carve_at(cum),
                Some(merchant_p(&client, cum)),
                "post-credit cum={cum}"
            );
        }
    }

    #[test]
    fn real_cosign_record_then_resume_end_to_end() {
        // The real path with no seed_operative bypass: the wallet co-signs a CHECKPOINT (validating its
        // carve basis), the merchant countersigns, the wallet records it as operative, and resumes the
        // round the merchant draws against THAT bilateral reference.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed
        }

        let cp = bilateral_checkpoint(&client, 100_000);
        let ckpt_ref = cp.reference().unwrap();
        assert!(
            client.record_operative(&cp),
            "the wallet records its own co-signed operative"
        );

        client.on_overdue_meed();
        assert!(client.is_halted());
        let receipt = fund_and_sign(&rail, dch.key(), ckpt_ref, 1_000); // floor(100_000·100/10000) = 1000
        assert!(client.resume_on_prepay_draw(&receipt));
        assert!(client.verify_pending_draw(&rail));
    }

    #[test]
    fn cosign_refuses_a_basis_the_wallet_did_not_stream_or_that_overstates_accruals() {
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);

        // (a) CUM_TOTAL above what the wallet streamed (0) → refuse to co-sign, no countersignature.
        let mut over = unsigned_checkpoint(100_000);
        assert!(matches!(
            client.cosign_checkpoint(&mut over),
            Err(ChannelClientError::Checkpoint(_))
        ));
        assert!(
            over.sig_payer.is_none(),
            "no countersignature over an unvalidated basis"
        );

        // (b) ACCRUALS that overstate cum·bp (would over-owe carve) → refuse, even within the streamed cum.
        for _ in 0..10 {
            client.next_slice(10_000).unwrap();
        }
        let mut tampered = unsigned_checkpoint(100_000);
        tampered.accruals[0].1 += BigUint::from(1u32);
        assert!(
            client.cosign_checkpoint(&mut tampered).is_err(),
            "ACCRUALS ≠ CUM_TOTAL·bp_r are refused (carve basis)"
        );
    }

    #[test]
    fn item_b_accrual_basis_is_self_metered_and_cannot_be_regressed() {
        // Part D PRESERVATION (item B, closed 2026-07-12): the
        // wallet meters per-role accruals INDEPENDENTLY and co-signs a checkpoint ONLY if
        // `ACCRUALS == CUM_TOTAL·bp_r` under its OWN signed vector, with `CUM_TOTAL ≤ cum_streamed`.
        // This locks that basis exhaustively so a future refactor cannot silently regress it (e.g.
        // trusting a caller-supplied carve, or accepting an off-by-one accrual in either direction).
        // Complements the single-case `cosign_refuses_a_basis_…` above.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        // Postpay so the wallet streams the full 200_000 without the prepay one-round meed self-halt;
        // the accrual-basis check (`checkpoint_basis_ok`/`carve_at`) is mode-independent.
        let mut client = open_postpay_wallet(&custody, &dch, 10_000_000);
        for _ in 0..20 {
            client.next_slice(10_000).unwrap(); // stream 200_000 → carve basis up to cum 200_000
        }

        // (1) A CONFORMANT basis at every cum ≤ streamed is co-signed, and the owed carve is the
        // wallet's OWN `floor(cum·Σbp / 10_000)` (Σbp = 100) — self-metered, never a caller input.
        for &cum in &[0u128, 1_000, 50_000, 100_000, 200_000] {
            let mut cp = unsigned_checkpoint(cum);
            assert!(
                client.cosign_checkpoint(&mut cp).is_ok(),
                "a conformant CUM={cum} basis co-signs"
            );
            assert_eq!(
                client.carve_at(cum),
                Some(cum / 100),
                "the owed carve is self-metered floor(cum·Σbp/10000) = cum/100"
            );
        }

        // (2) CUM_TOTAL past what the wallet streamed is refused — it never attests more consumption
        // (hence more carve) than it authorized.
        let mut over = unsigned_checkpoint(200_001);
        assert!(
            client.cosign_checkpoint(&mut over).is_err(),
            "CUM_TOTAL above cum_streamed is refused"
        );

        // (3) ANY per-role accrual that deviates from `CUM_TOTAL·bp_r` — in EITHER direction, for ANY
        // role — is refused. An understated accrual (would under-owe carve) is refused just like an
        // overstated one; the wallet attests only its exact self-computed basis.
        for role_idx in 0..test_vector().len() {
            for delta_up in [true, false] {
                let mut cp = unsigned_checkpoint(100_000);
                if delta_up {
                    cp.accruals[role_idx].1 += BigUint::from(1u32);
                } else if cp.accruals[role_idx].1 > BigUint::from(0u32) {
                    cp.accruals[role_idx].1 -= BigUint::from(1u32);
                } else {
                    continue; // a 0 accrual cannot be understated
                }
                assert!(
                    client.cosign_checkpoint(&mut cp).is_err(),
                    "a tampered accrual (role {role_idx}, up={delta_up}) is refused — self-metered basis"
                );
            }
        }
    }

    #[test]
    fn verify_failure_re_halts_the_wallet_bounding_the_strip() {
        // a resumed round whose rail-verification FAILS (an
        // unfunded draw) must RE-HALT the wallet — else `owed_carve_for_halt` keeps subtracting the
        // in-flight amount and the wallet streams unbounded past meed the merchant never paid. The
        // round stays recorded (defaulted), so the next round is barred and the strip stays bounded.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        client.seed_operative([0x33; 32], 100_000);
        client.on_overdue_meed();

        // Resume on a hostile (unfunded) notice — liveness clears the halt momentarily...
        let fake = hostile_receipt(dch.key(), [0x33; 32], 1_000);
        assert!(client.resume_on_prepay_draw(&fake));
        assert!(
            !client.is_halted(),
            "liveness: the halt clears on the signed notice"
        );
        // ...but the rail shows no funding, so verify does not credit AND re-halts — no unbounded stream.
        assert!(
            !client.verify_pending_draw(&rail),
            "the unfunded draw does not credit"
        );
        assert!(
            client.is_halted(),
            "a defaulted round RE-HALTS the wallet (no unbounded streaming)"
        );
        assert!(
            client.next_slice(1_000).is_err(),
            "streaming stays stopped after a default"
        );
        // A spurious overdue tick must NOT un-halt a defaulted round (it is owed, not in-flight).
        client.on_overdue_meed();
        assert!(client.is_halted(), "a defaulted round stays owed");
    }

    #[test]
    fn operative_advances_in_lockstep_even_when_halted() {
        // Deadlock guard: the wallet's operative must track the merchant's. record_operative advances
        // even while halted (both endpoints countersigned the new checkpoint), so a receipt the merchant
        // draws for the advanced checkpoint resumes cleanly — no wallet/merchant operative desync deadlock.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed (one round — the self-halt bound)
        }
        // Co-sign + record A (50_000) → self-halts (owed 500).
        let cp_a = bilateral_checkpoint(&client, 50_000);
        assert!(client.record_operative(&cp_a));
        assert!(client.is_halted());
        // The merchant advanced to B (100_000); the wallet co-signs + records it WHILE halted (lockstep).
        let cp_b = bilateral_checkpoint(&client, 100_000);
        let ref_b = cp_b.reference().unwrap();
        assert!(
            client.record_operative(&cp_b),
            "the operative tracks the merchant even while halted"
        );
        // The merchant draws B (1000, subsuming A's outstanding); the wallet resumes + credits it.
        let receipt = fund_and_sign(&rail, dch.key(), ref_b, 1_000);
        assert!(client.resume_on_prepay_draw(&receipt));
        assert!(client.verify_pending_draw(&rail));
        assert!(!client.is_halted());
    }

    #[test]
    fn credit_is_decoupled_from_the_halt() {
        // The interim draw is merchant-initiated (§6.4): the merchant may draw and deliver a notice before
        // the wallet halts. The wallet still accepts and credits it — crediting is DECOUPLED from the halt
        // — so credited_r stays in lockstep with the merchant's settled_r and a LATER round's incremental
        // carve matches (otherwise the channel diverges and deadlocks).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        client.seed_operative([0x33; 32], 100_000);

        // No on_overdue: the wallet is NOT halted, but a valid notice for the operative is still credited.
        assert!(!client.is_halted());
        let r1 = fund_and_sign(&rail, dch.key(), [0x33; 32], 1_000);
        assert!(
            client.resume_on_prepay_draw(&r1),
            "a valid notice is accepted even without a prior halt"
        );
        assert!(client.verify_pending_draw(&rail));

        // The next round then resumes on its CUMULATIVE watermark target (credited_r tracked round 1, so
        // the credit folds only the incremental 2000 — no double-count, no divergence).
        client.seed_operative([0x44; 32], 300_000);
        let r2 = fund_and_sign(&rail, dch.key(), [0x44; 32], 3_000); // cumulative target = 1000 credited + 2000 new
        assert!(client.resume_on_prepay_draw(&r2));
        assert!(client.verify_pending_draw(&rail));
    }

    #[test]
    fn a_spurious_overdue_tick_while_pending_verify_does_not_strand_the_halt() {
        // a re-signaled overdue tick fired AFTER a round resumed but BEFORE
        // it rail-credits must not re-halt on the in-flight round's OWN carve — else, once it credits, the
        // wallet is stranded halted with owed 0 and no notice can ever clear it.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        client.seed_operative([0x33; 32], 100_000);
        client.on_overdue_meed();
        let r1 = fund_and_sign(&rail, dch.key(), [0x33; 32], 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(!client.is_halted());

        // A spurious overdue tick before verify: the in-flight round is excluded, so NO re-halt.
        client.on_overdue_meed();
        assert!(
            !client.is_halted(),
            "the in-flight round is not a fresh overdue debt"
        );

        // It credits and the wallet streams on — never stranded.
        assert!(client.verify_pending_draw(&rail));
        assert!(!client.is_halted());
        assert!(
            client.next_slice(1_000).is_ok(),
            "not stranded halted after the round credits"
        );
    }

    #[test]
    fn resume_rejects_a_bogus_claim_record_and_stays_recoverable() {
        // a merchant-signed notice with the right channel/ref/amount but a WRONG
        // claim_record is rejected at resume (the wallet derives the claim itself, F4.2) — the halt stands
        // and a corrected notice still resumes, rather than the bad one wedging the round in pending-verify.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        let ckpt = [0x33u8; 32];
        client.seed_operative(ckpt, 100_000);
        client.on_overdue_meed();

        // Right channel/ref/amount + merchant signature, but a bogus claim_record.
        let bogus = signed_receipt(ckpt, 1_000, [0xBE; 32], "tx".into());
        assert!(
            !client.resume_on_prepay_draw(&bogus),
            "a wrong claim_record is refused up front"
        );
        assert!(client.is_halted(), "the halt stands");

        // The corrected notice (derived claim + funded) resumes and credits.
        let good = fund_and_sign(&rail, dch.key(), ckpt, 1_000);
        assert!(client.resume_on_prepay_draw(&good));
        assert!(client.verify_pending_draw(&rail));
    }

    #[test]
    fn resume_rejects_a_zero_amount_draw() {
        // A round always draws P ≥ 1. A directly-constructed zero-amount notice (the
        // wire `parse` rejects P=0) matching a zero-carve operative must be refused — else it occupies
        // `pending_verify` (never rail-creditable) and wedges the next real round.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);
        let ckpt = [0x33u8; 32];
        client.seed_operative(ckpt, 50); // carve_at(50) = floor(50·100/10000) = 0

        let claim = claim_record_id(&seed_instance_for(dch.key()), &CID, &ckpt, 0);
        let zero = signed_receipt(ckpt, 0, claim, "tx".into());
        assert!(
            !client.resume_on_prepay_draw(&zero),
            "a zero-amount draw is refused (never occupies pending_verify)"
        );
    }

    #[test]
    fn a_transient_draw_error_cannot_advance_the_operative_past_an_unreceipted_round() {
        // A SYNCHRONOUS divergence was considered: co-sign A, the merchant's draw hits a
        // transient error (round A locked, no receipt), the wallet then streams to B and the operatives
        // desync. Executable refutation: co-signing a settleable checkpoint SELF-HALTS the wallet
        // (record_operative → refresh_halt), so it mints nothing and cannot stream past A while A's round
        // is outstanding-and-unreceipted — the operative CANNOT advance to B. The divergence therefore
        // needs out-of-order receipt delivery (the async-rail case), not this in-order path.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed
        }
        let cp_a = bilateral_checkpoint(&client, 100_000);
        assert!(client.record_operative(&cp_a));
        assert!(
            client.is_halted(),
            "co-signing a settleable checkpoint self-halts the wallet"
        );
        // The merchant's draw for A hits a transient error → no receipt. The halted wallet cannot stream,
        // so it can neither advance nor even co-sign a checkpoint beyond what it streamed.
        assert!(
            client.next_slice(10_000).is_err(),
            "a halted wallet cannot stream past the unreceipted round"
        );
        let mut cp_b = unsigned_checkpoint(200_000);
        assert!(
            client.cosign_checkpoint(&mut cp_b).is_err(),
            "cannot co-sign a checkpoint beyond streamed value while halted — operative stays A"
        );
    }

    #[test]
    fn wallet_self_halts_after_streaming_one_round_without_settlement() {
        // the §6.4 "bounded to one round" strip bound must rest on the WALLET, not
        // on the interaction layer calling on_overdue/verify. After resuming a round, the wallet streams at
        // most one more round (`TH_value`'s carve) before `next_slice` SELF-halts — even if verify is never
        // called and no overdue signal ever arrives.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        // Resume round 1 at cum 100_000 on a genuine notice (halt clears) — but the layer never verifies it.
        client.seed_operative([0x33; 32], 100_000);
        let r1 = fund_and_sign(&rail, dch.key(), [0x33; 32], 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(
            !client.is_halted(),
            "the resumed round is in-flight — streaming resumes"
        );
        // Stream on: one more round's worth (TH_value = 100_000) is admitted, then `next_slice` self-halts,
        // with NO on_overdue/verify call from the interaction layer.
        let mut minted = 0u64;
        for _ in 0..20 {
            match client.next_slice(10_000) {
                Ok(_) => minted += 10_000,
                Err(_) => break,
            }
        }
        assert!(
            client.is_halted(),
            "the wallet self-halts once a full round is streamed unsettled"
        );
        assert!(
            (90_000..=100_000).contains(&minted),
            "streamed ~one round past the in-flight one, not unbounded (got {minted})"
        );
    }

    #[test]
    fn request_checkpoint_produces_verifiable_f5_5_wrapper() {
        // F5.5: the wallet builds the two-label CHECKPOINT_REQUEST, signing BOTH
        // the inner PayTPv1-ckpt payer slot (via `cosign_checkpoint`, carve-basis checked)
        // and the outer PayTPv1-ckpt-req wrapper — both from custody, since the outer sig is
        // the initiator's and the interaction layer holds no key. The result verifies under
        // the wallet's own payer key and carries a half-signed inner proposal (merchant absent).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let params = ChannelOpenParams {
            channel_id: CID,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: true,
            limit_l: 1_000_000,
            limit_e: 500_000,
            th_value: 100_000,
            th_time: 3600,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector: test_vector(),
            refund_ptr: Some("solana:dev:refund".into()),
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        };
        let (open, mut client) = open_ws(
            &custody,
            &dch,
            "merchant.example.com",
            &FIXED_CLOCK,
            StaticPolicy::new(BASELINE, 10_000_000),
            &params,
            &[0x5a; 32],
            Some("solana:dev:wallet"),
        )
        .unwrap();
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed → carve basis met
        }
        let req = client
            .request_checkpoint(unsigned_checkpoint(100_000))
            .unwrap();
        // Verifies under the wallet's own payer key (outer wrapper + inner payer sig).
        req.verify(&open.auth.payer_key).unwrap();
        assert!(req.proposed.sig_payer.is_some() && req.proposed.sig_merchant.is_none());
        assert!(req.sig.is_some());
        // Encodes to the F5.5 wire form and re-parses identically.
        assert_eq!(
            CheckpointRequest::parse(&req.encode().unwrap()).unwrap(),
            req
        );
        // The wallet refuses to wrap a checkpoint that fails its own carve basis (inflated
        // CUM_TOTAL beyond what it streamed) — no request is produced.
        let mut inflated = unsigned_checkpoint(100_000);
        inflated.cum_total = BigUint::from(10_000_000u32);
        assert!(client.request_checkpoint(inflated).is_err());
    }

    #[test]
    fn record_operative_uses_the_ckpt_ref_tiebreaker_at_equal_cum() {
        // at EQUAL CUM_TOTAL two distinct checkpoints have distinct references. The wallet must
        // pick the SAME one the merchant does — the lexicographically greater CKPT_REF — else they desync
        // (the wallet expecting one reference while the merchant draws the other, wedging the channel).
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed
        }
        // Two bilateral checkpoints at the SAME cum (100_000), distinguished by prev_ref → distinct refs.
        let mut cp1 = unsigned_checkpoint(100_000);
        cp1.prev_ref = [0x01; 32];
        client.cosign_checkpoint(&mut cp1).unwrap();
        cp1.sign_merchant(&MERCH_SK).unwrap();
        let mut cp2 = unsigned_checkpoint(100_000);
        cp2.prev_ref = [0x02; 32];
        client.cosign_checkpoint(&mut cp2).unwrap();
        cp2.sign_merchant(&MERCH_SK).unwrap();

        let (r1, r2) = (cp1.reference().unwrap(), cp2.reference().unwrap());
        assert_ne!(r1, r2);
        let (hi, lo) = if r1 > r2 { (&cp1, &cp2) } else { (&cp2, &cp1) };

        // Record the HIGHER-ref checkpoint; the LOWER-ref twin at the same cum is then REFUSED.
        assert!(client.record_operative(hi));
        assert!(
            !client.record_operative(lo),
            "an equal-CUM checkpoint with a lower CKPT_REF does not supersede (tiebreaker)"
        );
    }

    #[test]
    fn a_defaulted_round_recovers_when_the_merchant_funds_a_new_tx() {
        // a bogus first tx_ref must not permanently poison a round the merchant later genuinely
        // funds. After a default, a re-delivery at a NEW funding reference (same DERIVED claim) is admitted,
        // and a successful verify against it credits the round — the amount+claim are fixed, so no swap.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let mut client = open_prepay_wallet(&custody, &dch);
        let ckpt = [0x33u8; 32];
        client.seed_operative(ckpt, 100_000);
        client.on_overdue_meed();

        // A first notice with the correct derived claim but an UNFUNDED tx_ref: resume, then verify defaults.
        let fake = hostile_receipt(dch.key(), ckpt, 1_000); // tx = "never-funded-tx"
        assert!(client.resume_on_prepay_draw(&fake));
        assert!(
            !client.verify_pending_draw(&rail),
            "the unfunded draw defaults"
        );
        assert!(client.is_halted(), "a defaulted round re-halts");

        // The merchant genuinely funds the SAME claim at a real tx and re-sends; verify now credits it.
        let funded = fund_and_sign(&rail, dch.key(), ckpt, 1_000);
        assert!(
            client.resume_on_prepay_draw(&funded),
            "the corrected-tx re-delivery is admitted (same derived claim)"
        );
        assert!(
            client.verify_pending_draw(&rail),
            "verify against the new tx credits the round"
        );
        assert!(!client.is_halted());
    }

    #[test]
    fn an_out_of_domain_metering_fails_safe_to_a_halt() {
        // if cumulative streamed value grows past the F7-a accrual domain
        // (`cum·bp_r ≥ 2^128`), `carve_at` is uncomputable (`None`). The self-halt must FAIL-SAFE to a
        // halt (treat `None` as maximum debt), NOT silently un-halt — a `None` swallowed to owed `0` would
        // disable the value trigger and let the wallet stream the rest of its capacity unbounded.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let mut client = open_prepay_wallet(&custody, &dch);
        client.seed_operative([0x33; 32], u128::MAX); // cum·bp_r overflows the F7-a settlement domain
        client.on_overdue_meed();
        assert!(
            client.is_halted(),
            "an out-of-domain cumulative fails safe to a halt, not an unbounded stream"
        );
        assert!(client.next_slice(1).is_err(), "and streaming stays stopped");
    }

    /// Build a prepay channel on a caller-supplied clock, with explicit `th_value`/`th_time` — the
    /// shape the Part B `TH_TIME` tests drive. `th_value = 0` disables the value trigger (time-only);
    /// a nonzero `th_value` keeps the one-round value self-halt live alongside the time trigger.
    fn open_prepay_clocked<'c>(
        custody: &'c Custody,
        clock: &'c dyn Clock,
        dch: &ChannelDriver,
        th_value: u128,
        th_time: u64,
    ) -> ChannelClient<'c, StaticPolicy> {
        let params = ChannelOpenParams {
            channel_id: CID,
            denom: BASELINE.into(),
            baseline_asset: BASELINE.into(),
            baseline_net: "solana:dev".into(),
            prepay: true,
            limit_l: 1_000_000,
            limit_e: 500_000,
            th_value,
            th_time,
            schema: 1,
            contract: 1,
            registry_v: 5,
            vector: test_vector(),
            refund_ptr: Some("solana:dev:refund".into()),
            rate_source: None,
            rate_dev: None,
            fin_meed: "final".into(),
            fin_denom: "final".into(),
            timestamp: NOW,
        };
        let (_open, client) = open_ws(
            custody,
            dch,
            "merchant.example.com",
            clock,
            StaticPolicy::new(BASELINE, 10_000_000),
            &params,
            &[0x5a; 32],
            Some("solana:dev:wallet"),
        )
        .unwrap();
        client
    }

    #[test]
    fn a_time_only_channel_halts_on_the_operative_round() {
        // `TH_value = 0` disables the value trigger (`round_carve = 0`). The wallet must STILL halt on
        // the operative's own owed round, else a time-only prepay channel would stream unbounded past
        // unpaid meed. (Preserved from before the wallet clock; now on an injected clock.)
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let clock = ManualClock::new(NOW);
        let mut client = open_prepay_clocked(&custody, &clock, &dch, 0, 3600);

        // No operative AND nothing streamed → nothing owed → no halt.
        client.on_overdue_meed();
        assert!(!client.is_halted());
        // The operative owes a settleable round → halt (independent of the time deadline).
        client.seed_operative([0x33; 32], 100_000);
        client.on_overdue_meed();
        assert!(
            client.is_halted(),
            "a time-only channel still halts on the operative's owed round"
        );
        assert!(client.next_slice(1).is_err());
    }

    #[test]
    fn a_time_only_channel_with_a_withheld_first_checkpoint_halts_on_time() {
        // Part B repro (C1-9): a time-only channel whose merchant WITHHOLDS the first checkpoint (so
        // there is never an operative) must STILL halt once `TH_TIME` elapses with unsettled streamed
        // value — the trigger anchors on the wallet's OWN local clock + its OWN metering, never a
        // checkpoint (there is none). Before the clock, such a channel never halted (the operative-owed
        // branch is `false` with no operative) and would stream unbounded up to `L_credit`.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let clock = ManualClock::new(NOW);
        let mut client = open_prepay_clocked(&custody, &clock, &dch, 0, 3600);

        // Stream unsettled value with NO checkpoint ever co-signed → the anchor arms on the wallet's
        // own metering (no operative involved). The deadline has not elapsed → still streaming.
        client.next_slice(50_000).unwrap();
        assert!(
            !client.is_halted(),
            "within the time window the wallet streams"
        );
        client.next_slice(50_000).unwrap();
        assert!(!client.is_halted(), "still within the window");

        // Time passes past TH_TIME with the value still unsettled (checkpoint withheld) → halt on time.
        clock.advance(3600);
        assert!(
            client.next_slice(1).is_err(),
            "TH_TIME elapsed with unsettled streamed value and NO operative → the wallet halts on time"
        );
        assert!(client.is_halted());
    }

    #[test]
    fn a_merchant_refreshing_operatives_cannot_defer_the_time_deadline() {
        // Part B repro: `last_settle` advances ONLY on a genuine rail credit — so a
        // merchant that keeps re-anchoring the operative (a same-`CUM` tiebreaker, or a higher-`CUM`
        // advance) WITHOUT settling cannot push the deadline out. `record_operative` never touches
        // `last_settle`, so the halt fires on schedule from open / the last settlement.
        //
        // Uses a live VALUE trigger (`th_value = 100_000` → `round_carve = 1000`) and streams only
        // 50_000 (owed carve 500 < 1000) so the value/operative-owed halt does NOT fire — isolating
        // the TIME trigger as the sole halt cause, which the re-anchor must not be able to defer.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let clock = ManualClock::new(NOW);
        let mut client = open_prepay_clocked(&custody, &clock, &dch, 100_000, 3600);

        // Stream unsettled value at t0 (owed carve 500 < round_carve 1000) → the deadline anchors at
        // NOW; the value trigger is NOT tripped.
        client.next_slice(50_000).unwrap();
        assert!(!client.is_halted(), "below one round → not value-halted");

        // Half the window elapses, then the merchant re-anchors the operative (co-sign + countersign a
        // fresh bilateral checkpoint at the streamed cum, then record it) — WITHOUT settling anything.
        clock.advance(1800);
        let cp = bilateral_checkpoint(&client, 50_000);
        assert!(
            client.record_operative(&cp),
            "a fresh operative is recorded"
        );
        assert!(
            !client.is_halted(),
            "re-anchoring is not itself a halt, and it must not RESET the deadline either"
        );

        // The remaining half of the ORIGINAL window elapses (total = TH_TIME since first owed). The
        // re-anchor did not defer it → halt now (a naive `record_operative`-reset anchor would have
        // pushed the deadline to 1800 + 3600 and NOT halted here).
        clock.advance(1800);
        assert!(
            client.next_slice(1).is_err(),
            "the deadline runs from open / the last settlement, not the last re-anchor"
        );
        assert!(client.is_halted());
    }

    #[test]
    fn an_unfunded_resume_cannot_defer_or_defeat_the_time_deadline() {
        // Part B repro: a
        // validly-signed but UNFUNDED `PREPAY_DRAW_COMPLETED` is a LIVENESS signal, NOT a settlement.
        // It installs an in-flight `pending_verify` but credits nothing, so it must not reset the
        // TH_TIME deadline. The earlier `owed_since` design keyed the anchor on
        // `owed_beyond_in_flight(cum_streamed)` (which nets in-flight), so an unfunded resume
        // transiently drove it to 0 and CLEARED the anchor before any rail verification — deferring
        // (value+time channel) or entirely defeating (time-only channel) the halt. `last_settle`
        // advances ONLY on a genuine rail credit, and the halt's "settleable present" conjunct is
        // `carve_at(cum_streamed) > 0` net of CREDITED only — so the resume cannot touch it.
        //
        // Uses a TIME-ONLY channel (`th_value = 0` → `round_carve = 0`): the value/strip trigger is
        // disabled, so the TIME trigger is the sole backstop — the worst case, where a fake
        // resume left the wallet halting on NOTHING.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let clock = ManualClock::new(NOW);
        let mut client = open_prepay_clocked(&custody, &clock, &dch, 0, 3600);

        // Stream unsettled value and co-sign an operative on it → the operative-owed round halts.
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // 100_000 streamed
        }
        let cp = bilateral_checkpoint(&client, 100_000);
        let ckpt_ref = cp.reference().unwrap();
        assert!(client.record_operative(&cp));
        assert!(
            client.is_halted(),
            "the co-signed operative owes a round → halted"
        );

        // A hostile merchant resumes on a validly-signed but UNFUNDED draw (correct derived claim,
        // bogus tx_ref). Liveness clears the meed halt momentarily.
        let fake = hostile_receipt(dch.key(), ckpt_ref, 1_000); // floor(100_000·100/10000) = 1000
        assert!(
            client.resume_on_prepay_draw(&fake),
            "liveness: the resume is admitted"
        );
        assert!(
            !client.is_halted(),
            "the resume clears the meed halt (liveness) — momentarily"
        );

        // The round never rail-credits; time passes past TH_TIME. The wallet HALTS on time (the
        // unfunded resume left `last_settle` untouched and the value still settleable) — it did NOT
        // defer or defeat the deadline.
        clock.advance(3600);
        assert!(
            client.next_slice(1).is_err(),
            "TH_TIME elapsed with value unsettled — an unfunded resume cannot defer/defeat the halt"
        );
        assert!(client.is_halted());
        // The draw genuinely defaults on the rail (it was never funded), and the halt stands.
        assert!(
            !client.verify_pending_draw(&rail),
            "the unfunded draw does not credit"
        );
        assert!(client.is_halted());
    }

    #[test]
    fn a_genuine_credit_advances_the_time_deadline_no_early_halt() {
        // Part B repro: `last_settle` advances on a GENUINE
        // rail credit (F8.4b), so a channel that keeps settling on time is NOT halted at open+TH_TIME.
        // The earlier `owed_since` design pinned the anchor at first-stream and never advanced on
        // credit, so a healthy, continuously-streaming, regularly-settling channel halted early.
        let custody = Custody::from_root(&[9u8; 32]);
        let dch = ChannelDriver::new(MERCH_SK, &ENC_SEED, "solana:dev:settle");
        let rail = setup_rail(dch.key());
        let clock = ManualClock::new(NOW);
        let mut client = open_prepay_clocked(&custody, &clock, &dch, 0, 3600); // time-only, th_time=3600

        // Round 1: stream 100_000, co-sign, and GENUINELY settle it on the rail at t0+1800.
        for _ in 0..10 {
            client.next_slice(10_000).unwrap();
        }
        let cp1 = bilateral_checkpoint(&client, 100_000);
        let ck1 = cp1.reference().unwrap();
        assert!(client.record_operative(&cp1));
        clock.advance(1800);
        let r1 = fund_and_sign(&rail, dch.key(), ck1, 1_000);
        assert!(client.resume_on_prepay_draw(&r1));
        assert!(
            client.verify_pending_draw(&rail),
            "round 1 rail-credits → last_settle advances to t0+1800"
        );
        assert!(!client.is_halted());

        // Stream round 2 (unsettled again) — settleable value present; the deadline runs from t0+1800.
        for _ in 0..10 {
            client.next_slice(10_000).unwrap(); // cum_streamed = 200_000
        }

        // At t0+3600 (the ORIGINAL open+TH_TIME) the wallet is NOT halted — the credit advanced the
        // deadline to t0+1800+3600 = t0+5400. (The old owed_since design would have halted here.)
        clock.advance(1800); // now = t0 + 3600
        assert!(
            !client.is_halted(),
            "a genuinely-settled channel is not halted early"
        );
        assert!(client.next_slice(1).is_ok(), "and it can still stream");

        // Only at t0+5400 (TH_TIME past the LAST settlement) does the time halt fire.
        clock.advance(1800); // now = t0 + 5400
        assert!(
            client.next_slice(1).is_err(),
            "TH_TIME past the last settlement → halt"
        );
        assert!(client.is_halted());
    }
}
