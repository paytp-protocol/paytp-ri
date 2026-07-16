//! The `RailAdapter` trait and its value types (grounded
//! in §11.1 + F4 + F8).

/// A rail transaction reference, bound as [`RailAdapter::caps`] declares.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RailRef(pub String);

/// What kind of transfer this is (M1 uses `Payment`; the channel/entry kinds
/// arrive with M2/M3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    /// A plain, unconditional payment (a Tier 0 baseline split funding).
    Payment,
}

/// One value movement: a destination, asset, amount, and kind (F5.6 OUTPUTS /
/// F4 funding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub to: String,
    pub asset: String,
    pub amount: u128,
    pub kind: TransferKind,
    /// The quote nonce this payment is bound to (the payer's x402 payment
    /// authorization binds the transfer to a specific purchase, §5.6). A plain,
    /// PayTP-unaware payer sets `None` — the split still divides, but the payment
    /// cannot be redeemed against a PayTP nonce.
    pub memo: Option<[u8; 32]>,
}

/// What a submitted reference actually moved — the merchant confirms rail
/// arrival itself (F4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefInfo {
    pub to: String,
    pub asset: String,
    pub amount: u128,
    pub memo: Option<[u8; 32]>,
    /// For an entry-funding ref: the `entry_id` this transfer funded, so the
    /// merchant can bind the finality proof to the specific derived entry (F4.4).
    pub funds_entry: Option<[u8; 32]>,
    /// For a channel **meed leg**: the claim-record id (`claim_record_id(
    /// seed_instance, CHANNEL_ID, CKPT_REF, P)`) this transfer both **funded and
    /// distributed** (F6-m). Set **only** by the distributing funding kind
    /// (`fund_claim_record` postpay / `draw_claim_record` prepay), which runs the
    /// F7-d division to the meed destinations; a plain `submit` to the instance
    /// address — even one carrying the (rail-public) claim key as its `memo` — leaves
    /// it `None`, because it funds no record and distributes nothing. The settlement
    /// proof's `0x01` leg is credited only against THIS rail fact, never the
    /// caller-supplied `memo` alone (F6-m: the memo *names* the round, the funding
    /// **kind** *proves the distribution*) — the meed-side sibling of the
    /// `funds_entry` bind and the net leg's memo bind (F6-h).
    pub funds_claim: Option<[u8; 32]>,
    /// For a channel **meed advance** (Option W, F6-o): the per-channel watermark this
    /// transfer advanced and distributed. Set **only** by the distributing advance kind
    /// ([`RailAdapter::advance_channel_meed`]), which runs the F7.3 division to the
    /// meed destinations — the per-channel form of the F6-m distribution-fact
    /// discipline. A plain transfer (even one copying the watermark's identifiers) leaves
    /// it `None`, so the merchant/wallet credit a round only against THIS rail fact, never
    /// a state read ("`funded_p` reached at least target"). On the async rail it is `Some`
    /// only once the advance FINALIZED (the value moved).
    pub advanced_channel_meed: Option<AdvancedFact>,
    /// The **canonical** reference this alias resolves to (F6-d step 3): the
    /// adapter maps every spelling of one on-chain transfer (`T`, `T#0`) to one
    /// string here, and the merchant's global one-decision record keys on THIS —
    /// never the caller-supplied `RailRef` — so no alias can be credited twice.
    pub canonical: String,
}

/// The rail fact a finalized channel-meed **advance** exposes (Option W, F6-o) — what
/// the advance instruction cumulatively funded and distributed to the meed
/// destinations. Set only by the distributing advance kind, AFTER the source-debit +
/// per-role distribution. It binds the channel and the instance so the merchant verifies
/// THIS advance reached its own-cumulative `target_p` (never a rogue instance, never
/// another channel's payment) at FIN_MEED — the complete bind requires
/// (`channel_id` + `seed_instance` + `funded_p`-reaches-target + `delta` + asset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedFact {
    pub channel_id: [u8; 8],
    pub seed_instance: [u8; 32],
    /// The cumulative aggregate `funded_p` AFTER this advance (the watermark position the
    /// merchant checks against its own-cumulative `target_p`).
    pub funded_p: u128,
    /// The aggregate delta this advance distributed (0 on an idempotent re-advance — the
    /// fact still proves the instance holds `funded_p`, so a 0-delta retry is value-safe).
    pub delta: u128,
    pub asset: String,
}

/// A finality observation for a reference (F8.1): the declared level token and
/// the on-chain time it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finality {
    pub level: String,
    pub time: u64,
}

/// Capability declaration (§11.1): what the quote/settlement logic consumes.
#[derive(Debug, Clone)]
pub struct RailCaps {
    /// Whether this rail can host the contract kit (split / instance).
    pub supports_contracts: bool,
    /// Declared finality levels, weakest→strongest (a total order, F8.1).
    pub finality_levels: Vec<String>,
    /// The **hard conservative upper bound** (chain-seconds) on the delay from submitting a
    /// transfer until it reaches the rail's **strongest / irreversible** finality — the delay
    /// a leg's finality time can grow to. The wallet's F4.5/F8.5 pre-flight uses this SINGLE
    /// worst-case (not a per-level value): a merchant's redemption honor check reads whatever
    /// finality level the leg has reached by then, and finality only ever upgrades to a
    /// STRONGER level with a LATER time (F8.1), so a late redemption can observe the strongest
    /// level. A leg is therefore safely honorable only if its strongest-finality time
    /// `≤ exp + grace`; the wallet estimates that as `now + finality_delay` before funding.
    /// **The pre-flight's stranding guarantee is only as sound as this bound: a proof-profile
    /// adapter MUST declare a true worst-case ceiling, not a mere p99 — a p99 makes the
    /// guarantee operational, not unconditional.** A synchronous rail (finality at submit)
    /// declares 0. Distinct from `inclusion_latency` (the merchant's reclaim-margin constant):
    /// this bounds submit→*finality*, not submit→*inclusion*, and already subsumes inclusion.
    pub finality_delay: u64,
    /// Supported asset identifiers.
    pub assets: Vec<String>,
    /// The adapter's declared inclusion latency in chain-seconds (F8-f). Before delivering
    /// under a reclaim-open entry the merchant requires TWICE this as remaining margin to
    /// `T_exec`, so its attestation lands before a permissionless `execute_reclaim` can
    /// strip the meed. A synchronous rail (no mempool race) declares 0.
    pub inclusion_latency: u64,
}

/// The trait every settlement path implements. M1 uses the subset below; the
/// channel-reconciliation read `settled_for_channel` arrives with M3.
pub trait RailAdapter {
    /// Capability declaration.
    fn caps(&self) -> RailCaps;

    /// Address derivation for the contract kit (F4.1): a 32-byte seed → a rail
    /// address (CREATE2/PDA-class, kit-defined).
    fn derive_address(&self, seed: &[u8; 32]) -> String;

    /// Submit a payment; returns a reference bound as `caps()` declares.
    fn submit(&self, transfer: Transfer) -> Result<RailRef, RailError>;

    /// Settle a payer-presented payment authorization, keyed by its signed-transaction identity.
    /// The FIRST call for `settle_id` performs the same value movement as [`Self::submit`] for a
    /// payment transfer and records `settle_id -> RailRef`; every later call with that same
    /// `settle_id` returns the SAME reference and moves no value. This is the RI stand-in for an
    /// x402 facilitator / chain duplicate-settlement cache: a retried signed transaction is
    /// idempotent, never a second mint.
    fn settle(&self, transfer: Transfer, settle_id: [u8; 32]) -> Result<RailRef, RailError>;

    /// Release `amount` of `asset` **FROM** an address this rail custodies **TO**
    /// another — a source-DEBITED transfer, the escrow counterpart of `submit`
    /// (which only credits). The channel plane uses it to return a prepay channel's
    /// unconsumed deposit to the payer's refund pointer at close (F6-f). The source
    /// balance is guarded: a release can never mint value or overdraw the escrow. On
    /// a non-custodial rail (a merchant-controlled address, not a contract) this is a
    /// **conformant-merchant action, not an enforced escrow release** (the §6.5 trust
    /// posture; enforced on-chain custody is the deferred work).
    fn release(
        &self,
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError>;

    /// [`Self::release`] keyed by `(channel_id, ckpt_ref)` for **idempotency**: the FIRST release
    /// for a key moves value; every later call with the same key returns that SAME reference and
    /// moves nothing. The channel plane refunds a prepay close through this so a replay / retry /
    /// crash-restart never double-releases the shared `settle_ptr` (the drain) — the rail-level
    /// half of the durable close-refund one-decision (the merchant's [`crate`]-side `refund`
    /// [`OneDecisionStore`](../paytp_merchant/one_decision/trait.OneDecisionStore.html) record is the
    /// other half). On a non-custodial rail this remains a conformant-merchant action (§6.5).
    fn release_keyed(
        &self,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError>;

    /// ADVANCE a channel's cumulative meed watermark to `target_p` (Option W, F6-o) —
    /// the sole per-channel meed settlement primitive on the channel path (it retired the
    /// per-round claim-record draw, so a channel settles through this instruction alone).
    /// Sources the delta `target_p − funded_p` FROM the held deposit at `from` (`Some`, the
    /// prepay `settle_ptr` — source-debited so value conserves and an overdraw is rejected)
    /// or as a fresh credit (`None`, the postpay leg the payer's own wallet funds), into the
    /// meed instance at `addr`, advancing the per-channel watermark and distributing per
    /// role (F7.3). **Idempotent by absolute position:** advancing to a `target_p ≤ funded_p`
    /// distributes nothing — a drop-then-redraw or crash retry is a no-op, the F6-o
    /// closure. Returns the reference; the merchant reads [`RefInfo::advanced_channel_meed`]
    /// (set only by this distributing kind) at FIN_MEED to confirm the watermark reached
    /// `target_p`. **On the async rail the value moves and the fact is set at FINALITY, not
    /// submit** — a pending advance shows `advanced_channel_meed: None`, a dropped one
    /// `ref_target: None` (F8.1). Retires the per-round claim-record on the channel path (no
    /// dual ledger — a channel settles through this instruction alone).
    fn advance_channel_meed(
        &self,
        from: Option<&str>,
        addr: &str,
        channel_id: [u8; 8],
        target_p: u128,
        asset: String,
    ) -> Result<RailRef, RailError>;

    /// The finality an on-chain reference has reached, and when (F8-a).
    fn finality(&self, r: &RailRef) -> Option<Finality>;

    /// What a submitted reference actually moved (F4.4/F6.4) — the merchant confirms
    /// rail arrival itself: destination, asset, amount, and the channel-binding memo.
    ///
    /// **Canonicalization contract (F6-d step 3):** an adapter MUST map every
    /// alias of one on-chain transfer to a **single canonical `RailRef`** — if `T` and
    /// `T#0` name the same finalized transfer, `ref_target` must resolve both to the
    /// same reference the merchant's global one-decision record keys on. An adapter
    /// that admits two spellings of one transfer would let it be credited twice
    /// (the double-credit). A rail whose finalized records expose neither an
    /// immutable sender-chosen memo nor a per-channel-unique pointer MUST NOT carry
    /// channel **funding** (F5-n) **or a settlement net leg** (F6-h) — the same
    /// capability limit, not optional hardening: both binds require an immutable
    /// on-rail identifier. This RI enforces the memo form (option a) for both, since
    /// its `VirtualRail` is memo-capable; the per-channel-pointer form (option b) is
    /// the job of a future memoless-rail adapter and is not implemented here.
    ///
    /// **Distribution-fact contract (F6-m):** an adapter MUST set
    /// [`RefInfo::funds_claim`] **only** for the finalized record of a claim-record
    /// **funding** — the distinct on-chain kind (F4.2/F4.3) that funds AND distributes
    /// the aggregate `P` to the meed destinations (on the baseline rail, the kit's
    /// `fund_claim_record` instruction). A plain transfer to the instance address —
    /// even one whose memo copies the rail-public claim key — MUST leave `funds_claim`
    /// `None`: it creates no record and distributes nothing. The merchant's settlement
    /// `0x01` meed leg is credited against this rail fact, never the memo alone, so
    /// an adapter that set `funds_claim` on a non-distributing transfer would reopen the
    /// non-distributing-leg forge (the debtor discharges its meed while the enablers
    /// receive nothing). A rail that cannot distinguish the funding kind from a plain
    /// transfer MUST NOT carry a channel's meed leg (§11.1, as for F5-n/F6-h).
    fn ref_target(&self, r: &RailRef) -> Option<RefInfo>;

    /// The rail's on-chain time source (F8-a): Unix seconds.
    fn chain_time(&self) -> u64;
}

/// Rail-layer errors (a real rail's revert; the virtual rail's rejections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailError {
    /// A transfer to an address that hosts no deployed contract / account.
    NoSuchAccount,
    /// A contract precondition rejected the call (an entry-machine revert).
    Rejected(&'static str),
    /// The claim-record / entry this call targets is **already funded** (the
    /// counterfactual, address-deterministic record's idempotency guard). A caller
    /// retrying an idempotent funding/draw treats this as **success** — the record
    /// already landed — NOT as a transient failure to retry. Kept distinct from the
    /// generic [`RailError::Rejected`] so a caller cannot confuse an already-funded
    /// record with an overdraw / insufficient-balance precondition failure (which MUST
    /// be retried, never treated as done).
    AlreadyFunded,
    /// The rail was injected into an outage.
    Outage,
}

impl std::fmt::Display for RailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RailError {}
