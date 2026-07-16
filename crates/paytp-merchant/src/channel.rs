//! Merchant-side channel **establishment** driver (F5.2–F5.4 / F6.1) — M3.
//!
//! Processes an incoming `CHANNEL_OPEN` in §5.4's verbatim order (F1.6 dropped
//! the old "compute `ConnBinding` and match `0x11`" step): confirm the auth names
//! *this* merchant → verify the payer `SIG` → check the `TIMESTAMP` acceptance
//! window (F8.2) → **F5-m replay-suppression** (a retained `CHANNEL_ID` is never
//! re-initialized; an identical retransmit returns the stored `CHANNEL_ACK`) →
//! unseal `s` and validate `H(s)` against `HS` → derive `K_session` from the
//! public `BindSalt` (Change A) → sign and retain the `CHANNEL_ACK`.
//!
//! The binding artifact / cert acceptance (F2.2) is the *payer's* gate — it
//! verifies the artifact against the certificate it saw on the establishing
//! connection before it seals `s` to the origin's `ENC_KEY`. An origin-authorized
//! TLS terminator that fronts the origin still forms a channel end-to-end (it
//! carries the origin's artifact and cannot unseal `s`); an unauthorized
//! terminator presents a cert the merchant never signed an artifact for, so the
//! payer's [`BindingArtifact::accept`] refuses and no `CHANNEL_OPEN` is ever built.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use num_bigint::BigUint;
use paytp_core::channel::state::{ChannelState, Mode};
use paytp_core::channel::{AckRequest, BindingArtifact, ChannelAck, ChannelOpen};
use paytp_core::consts::{LATENCY_SECS, SKEW_SECS};
use paytp_core::crypto;
use paytp_core::derive::{AddressInputs, MeedVectorEntry};
use paytp_core::registry::SnapshotStore;

use crate::one_decision::{Decision, OneDecisionStore};

/// Durable F5-m key namespace: a channel identifier this merchant has ACCEPTED (§5.4 "one durable
/// decision per channel identifier"). Recorded when an open succeeds; restored into `tombstones` at
/// startup so a restart rejects any reuse of the id (a captured `CHANNEL_OPEN` replayed onto a new
/// connection within the timestamp window). Distinct prefix from the carriage's `fund:`/
/// `disp:`/`rfnd:` namespaces so ONE shared store holds all channel-plane decisions.
const CHOPEN_NS: &[u8] = b"chopen:";

fn chopen_key(cid: &[u8; 8]) -> Vec<u8> {
    [CHOPEN_NS, &cid[..]].concat()
}

/// Why a `CHANNEL_OPEN` was refused (all map to the §5.4 rejections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The `CHANNEL_AUTH` names a different merchant key.
    WrongMerchant,
    /// The payer `SIG` did not verify (or the object was malformed).
    BadAuth,
    /// `TIMESTAMP` outside the F8.2 acceptance window (`|now − TIMESTAMP| > 600 s`).
    TimestampOutOfWindow,
    /// `CHANNEL_ID` reused with *different* terms, or reused after termination
    /// (F5-m: a retained id is never re-initialized).
    ChannelReplay,
    /// The named predecessor checkpoint reference was already imported by another
    /// successor (§5.4 one-decision chaining bar — a predecessor is chained at most once).
    ChainReplay,
    /// A `predecessor`-referenced open that cannot be imported (F6.6): no
    /// chain snapshot for the named `(predecessor, final checkpoint)`, a different payer,
    /// changed economic terms (clause (c)), an off-baseline chain (deferred), or an
    /// out-of-window imported position. **Fail-closed** — never a silent fresh open
    /// dropping the predecessor's position (`PAYTP_CHAIN_REJECTED`).
    ChainRejected,
    /// The durable F5-m store could not record the channel-open acceptance (a write failure / a
    /// poisoned log) — the merchant cannot durably suppress a future replay of this id, so it
    /// **refuses the open** rather than accept a channel it could not adjudicate after a restart
    /// (F4.4/F5-m durable-or-fail). Retryable against a recovered store.
    StoreUnavailable,
    /// The sealed secret would not open under the merchant's `ENC_KEY`/aad.
    SealInvalid,
    /// `H(s)` of the unsealed secret ≠ the `HS` commitment.
    HsMismatch,
    /// `DENOM ≠ BASELINE_ASSET` — an off-baseline channel. Fail-closed **at open**: this RI
    /// defers off-baseline settlement wholesale (a converted round needs the rate oracle, and
    /// an off-baseline chain is rejected), so such a channel could only *carry* metered value it
    /// can never settle or chain out. Rejecting at establishment keeps value off an unsettleable
    /// channel. The spec still permits off-baseline channels (F5.6/F6.5) — this is an
    /// RI conformance-scope limitation, not a protocol change.
    OffBaselineUnsupported,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ChannelError {}

/// The reconciled imported position a `chain_intent` close snapshots for its successor
/// to open at (F6.6). **Immutable**, keyed by the successor's `CHANNEL_AUTH.
/// predecessor` = `(predecessor CHANNEL_ID, final checkpoint reference)` — the exact
/// one-decision key. The carriage COMPUTES it at close (it holds the ledger) and records
/// it here; the driver reads it to build the successor's imported state, **fail-closed,
/// before it retains/ACKs**. Binding the math to the exact key means a late funding/proof
/// on the predecessor cannot change what the successor imports.
#[derive(Clone)]
pub struct ChainSnapshot {
    /// Whole-chain metered gross (imported `CUM_TOTAL`).
    pub cum_total: u128,
    /// Per-role accrued meed numerators (ascending role) — the payer still owes these.
    pub accruals: Vec<(u8, BigUint)>,
    /// Imported cumulative settled meed per role (F6-f `opening_settled_r`).
    pub opening_settled_r: Vec<(u8, BigUint)>,
    /// Imported cumulative net-leg DENOM value (F6-f `opening_net_legs`).
    pub opening_net_legs: u128,
    /// Imported cumulative credited funding (F6-f `opening_funding`).
    pub opening_funding: u128,
    /// The canonical imported flow-control `B` (F6-e/F6-g).
    pub imported_balance: i128,
    /// The predecessor's payer key — the successor MUST be the same payer (§5.4).
    pub payer_key: [u8; 32],
    /// The predecessor's mode — the successor MUST match (F6.6 clause (c)).
    pub mode: Mode,
    /// The F6.6 clause-(c) identical-terms fingerprint the successor MUST match.
    pub terms_fingerprint: [u8; 32],
    /// The predecessor's `established_at` — the successor inherits it so chaining never
    /// resets the `TH_TIME` settlement clock (no infinite-chain settlement evasion).
    pub established_at: u64,
}

/// The predecessor ledger cumulatives a chained successor seeds its own ledger with
/// (F6-f reads `opening_* + Σ own`). Threaded on [`Established`] to the carriage, which
/// owns the ledger.
#[derive(Clone)]
pub struct LedgerOpenings {
    pub settled_r: Vec<(u8, BigUint)>,
    pub net_legs: u128,
    pub funding: u128,
}

/// The F6.6 clause-(c) **identical-terms fingerprint** — the fields a chained successor
/// MUST match its predecessor on (baseline-deterministic v1): the mode, the meed
/// **instance seed** (which commits merchant key / asset / schema / MEED_VECTOR
/// shares+dests / contract — the instance-address inputs), the channel `DENOM`, the
/// **baseline network `BASELINE_NET`** (F6.6(c) "baseline network identical":
/// the seed commits `BASELINE_ASSET`, not the network, so the network is pinned here), the
/// two channel-life finality levels, **and the settlement thresholds `TH_value`/`TH_time`**
/// (GAP-FILL F6-j — a successor opening with slacker thresholds would let an
/// imported already-due obligation defer past where it came due in the predecessor,
/// contradicting F6.6's "a deferred round comes due exactly as it would have"; equality is
/// the fail-closed v1 rule). (Off-baseline rate discipline is vacuous in v1 — a
/// conversion-required chain is rejected until the off-baseline settlement path ships.)
// The arity is the F6.6(c) term set itself; grouping into a struct would only rename the
// same fields the callers already hold flat on `SettlementTerms`/`ChannelAuth`.
#[allow(clippy::too_many_arguments)]
pub fn chain_terms_fingerprint(
    mode: Mode,
    seed_instance: &[u8; 32],
    denom: &str,
    baseline_net: &str,
    fin_meed: &str,
    fin_denom: &str,
    th_value: u128,
    th_time: u64,
) -> [u8; 32] {
    let mut body = Vec::new();
    body.push(match mode {
        Mode::Postpay => 0x01,
        Mode::Prepay => 0x00,
    });
    body.extend_from_slice(seed_instance);
    // `baseline_net` is included per F6.6 clause (c) ("baseline network identical"): a
    // successor identical in every other term but a different `BASELINE_NET` must NOT
    // match its predecessor's fingerprint. This is an internal validation
    // hash (never a cross-impl wire byte), so widening it changes no encoded object.
    for s in [denom, baseline_net, fin_meed, fin_denom] {
        body.extend_from_slice(&(s.len() as u32).to_be_bytes());
        body.extend_from_slice(s.as_bytes());
    }
    body.extend_from_slice(&th_value.to_be_bytes());
    body.extend_from_slice(&th_time.to_be_bytes());
    crypto::sha256(&body)
}

/// One F5-m record per LIVE channel identifier — the in-memory metering/session state that serves
/// funding, slices, checkpoints, and ACK retrieval this process's life.
///
/// **Durability (F5-m):** the *live* state here is in-memory (recovering it across a restart —
/// channel resumption — is ASYNC-1). But the **replay-suppression decision** (that this id was
/// accepted) IS durable: `open_channel` records `chopen:<cid>` in the shared one-decision store, and
/// a restart restores those ids into `tombstones`, which reject any reuse (F5-m across restart).
/// So a captured `CHANNEL_OPEN` replayed after a restart is refused even though this live
/// record is gone.
struct Retained {
    /// `SHA-256(COVERED(CHANNEL_AUTH))` — recognizes the channel's terms.
    auth_hash: [u8; 32],
    /// `SHA-256(CHANNEL_OPEN bytes)` — distinguishes a byte-identical retransmit
    /// (answered with the stored ACK) from a re-sealed replay under the same id
    /// (rejected), since `AUTH_HASH` alone does not cover `SEAL`.
    open_hash: [u8; 32],
    /// That channel's payer key, to authenticate `ACK_REQUEST` retrieval (F5.3).
    payer_key: [u8; 32],
    ack: ChannelAck,
    terminated: bool,
    /// Establishment terms a settlement round is validated against (F5.6/§5.4):
    /// the channel `DENOM`, the baseline settlement asset, and the meed-vector
    /// destinations bound at open — a proposal naming any other destination, or the
    /// wrong `CONVERSION` presence, is rejected.
    terms: SettlementTerms,
}

/// The channel-life establishment terms funding + a settlement round are checked
/// against (F5.2/F5.6).
#[derive(Clone)]
pub struct SettlementTerms {
    pub denom: String,
    pub baseline_asset: String,
    /// The baseline rail's **CAIP-2 network id** (`CHANNEL_AUTH.BASELINE_NET`, 0x0A) — the
    /// rail id an F5-o/F9.1 `PREPAY_DRAW_COMPLETED` names in its `0x05 RAIL` field. Distinct
    /// from the CAIP-19 `baseline_asset` (which the meed instance settles): `RAIL` is the
    /// network, not the asset (a conformant peer strictly parses it as CAIP-2).
    pub baseline_net: String,
    /// The destinations a round's `OUTPUTS` may name (F5.6 — "match those bound at
    /// establishment"): the meed-vector recipients (F4-b) plus the merchant's
    /// settlement pointer where a postpay net leg pays.
    pub bound_dests: Vec<String>,
    /// `true` iff `DENOM ≠ BASELINE_ASSET` — a round then MUST carry `CONVERSION`
    /// (F5.6), else MUST NOT.
    pub conversion_required: bool,
    /// The merchant's settlement pointer (`CHANNEL_ACK.SETTLE_PTR`) — where a funding
    /// transfer must land on the `DENOM` rail (F6.4).
    pub settle_ptr: String,
    /// Required `DENOM`-rail finality for funding + the net leg (F5.2 `FIN_DENOM`).
    pub fin_denom: String,
    /// Required baseline-rail finality for the meed leg (F5.2 `FIN_MEED`).
    pub fin_meed: String,
    /// `seed_instance` (F4-a) — the channel's meed-instance seed, fixed at
    /// establishment (merchant key + `BASELINE_ASSET` + schema + vector + contract).
    /// A settlement round's meed leg pays the address this derives to (F4.1/F4.2).
    pub seed_instance: [u8; 32],
    /// The payer's refund pointer (`CHANNEL_AUTH.REFUND_PTR`) — where a **prepay**
    /// channel's unconsumed deposit is returned at close (F6-f). `Some` iff prepay
    /// (postpay forbids it, §5.4); `on_close` routes the refund here.
    pub refund_ptr: Option<String>,
    /// Settlement thresholds `TH_value`/`TH_time` (F5.2), carried so the F6.6 chain
    /// fingerprint can require a successor to match them (GAP-FILL F6-j).
    pub th_value: u128,
    pub th_time: u64,
}

/// The outcome of processing a `CHANNEL_OPEN` (F5-m).
pub enum OpenOutcome {
    /// A fresh channel: install [`Established::state`] and return its `ack`. Boxed
    /// because it dwarfs the retransmit variant (it carries the full metering state).
    Established(Box<Established>),
    /// A byte-identical retransmission of an already-acknowledged `CHANNEL_OPEN`:
    /// re-send this `CHANNEL_ACK`, and **do not** re-initialize the channel or its
    /// metering state (F5-m — re-initializing would reset the slice plane and let
    /// captured slices re-bill from `SEQ = 1`).
    Retransmit(ChannelAck),
}

/// What a freshly established channel hands the caller.
pub struct Established {
    pub channel_id: [u8; 8],
    pub auth_hash: [u8; 32],
    /// The slice-plane key both ends derive (Change A: salt = public `BindSalt`).
    pub k_session: [u8; 32],
    /// The signed acknowledgment to return to the payer.
    pub ack: ChannelAck,
    /// A metering state seeded from the auth's mode/limits/vector.
    pub state: ChannelState,
    /// Settlement-threshold terms carried from `CHANNEL_AUTH` for the trigger
    /// matrix (F8.4b): `TH_VALUE`/`TH_TIME`, and `established_at` = the auth
    /// `TIMESTAMP` that seeds `last_settle` so both parties evaluate the time
    /// threshold identically from birth. (Trigger *evaluation* is the channel
    /// lifecycle's; establishment's job is not to drop these terms.)
    pub th_value: u128,
    pub th_time: u64,
    pub established_at: u64,
    /// For a **chained** open (F6.6): the predecessor ledger cumulatives the
    /// carriage MUST seed the successor's ledger with. `None` for a fresh open.
    pub ledger_openings: Option<LedgerOpenings>,
}

/// The merchant's channel plane: its identity + `ENC_KEY` secret + settlement
/// pointer, and the F5-m retention map.
pub struct ChannelDriver {
    signing_key: [u8; 32],
    key: [u8; 32],
    enc_secret: [u8; 32],
    enc_key: [u8; 32],
    settle_ptr: String,
    retained: HashMap<[u8; 8], Retained>,
    /// Consumed chaining references, keyed by (predecessor `CHANNEL_ID`, its final
    /// checkpoint reference) — §5.4's one-decision bar on chaining: a predecessor
    /// checkpoint is imported by **at most one** successor, so a second `CHANNEL_OPEN`
    /// naming an already-consumed predecessor reference is rejected. Keying by
    /// (channel id, checkpoint) — never the id alone — is what lets a chain pass through
    /// a stillborn: the predecessor's checkpoint (consumed once, by this channel) and
    /// this channel's own final checkpoint (consumed by a further successor) are
    /// distinct keys, so a channel that died at establishment strands nothing and
    /// double-consumes nothing. Same in-memory/durability caveat as `retained`.
    consumed_chain_refs: std::collections::HashSet<([u8; 8], [u8; 32])>,
    /// Reconciled imported positions a `chain_intent` close snapshots for a successor
    /// (F6.6), keyed by `(predecessor CHANNEL_ID, final checkpoint reference)` —
    /// the successor's `CHANNEL_AUTH.predecessor`. Written by the carriage at close (which
    /// holds the ledger); read here to build the successor's imported state fail-closed.
    /// **In-memory (not durable): a chained open across a restart fails closed** (`ChainRejected` —
    /// no snapshot), never a double-import; channel-resumption is ASYNC-1.
    chain_snapshots: HashMap<([u8; 8], [u8; 32]), ChainSnapshot>,
    /// The **durable F5-m store**: a channel-open acceptance is recorded here (`chopen:`) and
    /// the id restored into `tombstones` at startup. Shared with the carriage (ONE store backs the
    /// whole channel plane). `None` on a demo build (in-memory only, no restart durability).
    decisions: Option<Arc<dyn OneDecisionStore>>,
    /// Channel identifiers this merchant accepted in a PRIOR life, restored from the durable store
    /// at [`ChannelDriver::attach_decisions`]. A restart loses the live `retained` state, so a
    /// captured `CHANNEL_OPEN` reusing one of these ids is rejected (`ChannelReplay`) — a **rejecting
    /// tombstone**, NOT a fresh channel and NOT an ACK retransmit into an unservable channel (
    /// an ACK for a dead channel would induce the payer to fund it). Disjoint from live
    /// `retained` (a tombstoned id never becomes a live channel this life).
    tombstones: HashSet<[u8; 8]>,
    /// The merchant's retained role-registry snapshots (F9-d) — the registry the governed
    /// `CHANNEL_AUTH` meed-vector check ([`ChannelAuth::validate_vector_governed`], F5-o/F9.4)
    /// resolves `0x11` OS destinations against at open. Empty ⇒ only the independent-OS-fund
    /// fallback and the pinned Dev-Fund seat are accepted (fail-closed for a claimed-listed OS).
    registry: SnapshotStore,
}

impl ChannelDriver {
    /// `enc_seed` derives the X25519 `ENC_KEY` the payer seals `s` to (F2.5). Constructs the driver
    /// with an **empty** registry (accepts only the independent-OS-fund fallback / pinned Dev-Fund
    /// seat for governed destinations); use [`ChannelDriver::with_registry`] to supply retained
    /// snapshots so a registry-listed `0x11` OS destination can be confirmed (F5-o/F9.4).
    pub fn new(signing_key: [u8; 32], enc_seed: &[u8; 32], settle_ptr: impl Into<String>) -> Self {
        Self::with_registry(signing_key, enc_seed, settle_ptr, SnapshotStore::new())
    }

    /// As [`ChannelDriver::new`], with the merchant's retained role-registry snapshots (F9-d) — the
    /// registry the governed `CHANNEL_AUTH` meed-vector check resolves `0x11` destinations against.
    pub fn with_registry(
        signing_key: [u8; 32],
        enc_seed: &[u8; 32],
        settle_ptr: impl Into<String>,
        registry: SnapshotStore,
    ) -> Self {
        let (enc_secret, enc_key) = crypto::x25519_keypair_from_seed(enc_seed);
        ChannelDriver {
            key: crypto::ed25519_public(&signing_key),
            signing_key,
            enc_secret,
            enc_key,
            settle_ptr: settle_ptr.into(),
            retained: HashMap::new(),
            consumed_chain_refs: std::collections::HashSet::new(),
            chain_snapshots: HashMap::new(),
            decisions: None,
            tombstones: HashSet::new(),
            registry,
        }
    }

    /// Install the shared durable F5-m store and REPLAY the accepted-channel tombstones from it (a
    /// restart / a second replica bootstraps its replay-suppression from the durable log). A
    /// `chopen:` record whose key is not a valid channel id is corruption → **fail closed**
    /// (`ChannelError::StoreUnavailable`), never silently skipped. Called by
    /// [`crate::carriage::Carriage::proof`] with the SAME store it installs in the carriage.
    pub fn attach_decisions(
        &mut self,
        store: Arc<dyn OneDecisionStore>,
    ) -> Result<(), ChannelError> {
        for (key, _val) in store.entries() {
            if let Some(cid_bytes) = key.strip_prefix(CHOPEN_NS) {
                let cid: [u8; 8] = cid_bytes
                    .try_into()
                    .map_err(|_| ChannelError::StoreUnavailable)?;
                self.tombstones.insert(cid);
            }
        }
        self.decisions = Some(store);
        Ok(())
    }

    /// Whether this driver's F5-m retention is backed by the given durable store (identity check —
    /// the carriage verifies driver and carriage share ONE store).
    pub fn shares_decision_store(&self, store: &Arc<dyn OneDecisionStore>) -> bool {
        self.decisions
            .as_ref()
            .is_some_and(|d| Arc::ptr_eq(d, store))
    }

    /// Record the reconciled imported position of a `chain_intent`-closed channel so its
    /// successor opens at it (F6.6). The carriage computes the [`ChainSnapshot`]
    /// at close (it holds the ledger) and hands it here keyed by `(this channel id, its
    /// final checkpoint reference)`.
    pub fn record_chain_snapshot(&mut self, key: ([u8; 8], [u8; 32]), snapshot: ChainSnapshot) {
        self.chain_snapshots.insert(key, snapshot);
    }

    /// Drop a recorded chain snapshot (F6.6). The carriage clears any snapshot a prior
    /// (possibly failed) open left BEFORE recomputing at the next import, so a snapshot that
    /// has since gone stale — e.g. a birth/stillborn predecessor whose synthetic reference
    /// moved after a late funding credit — can never be imported by a successor naming the
    /// old reference. Without this, a recompute that fails the reference match leaves the
    /// stale snapshot in place and `chained_import` would import it.
    pub fn remove_chain_snapshot(&mut self, key: &([u8; 8], [u8; 32])) {
        self.chain_snapshots.remove(key);
    }

    /// The merchant's Ed25519 identity key.
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The X25519 `ENC_KEY` a payer seals the session secret to.
    pub fn enc_key(&self) -> [u8; 32] {
        self.enc_key
    }

    /// Issue a binding artifact (F2.2) naming the establishing connection's
    /// certificate and this origin's `ENC_KEY`, signed by the merchant identity.
    /// For a reverse-proxy deployment `cert_hash` is the *terminator's* leaf cert.
    pub fn issue_artifact(
        &self,
        host: impl Into<String>,
        cert_hash: [u8; 32],
        not_before: u64,
        not_after: u64,
    ) -> BindingArtifact {
        let mut art = BindingArtifact {
            host: host.into(),
            cert_hash,
            enc_key: self.enc_key,
            not_before,
            not_after,
            sig: None,
        };
        art.sign(&self.signing_key).expect("sign artifact");
        art
    }

    /// Process a `CHANNEL_OPEN` (§5.4 order). On a fresh channel the metering
    /// state is initialized and a signed `CHANNEL_ACK` is retained under its
    /// `CHANNEL_ID` (F5-m); an identical retransmit returns only the stored ACK.
    pub fn open_channel(
        &mut self,
        open: &ChannelOpen,
        now: u64,
    ) -> Result<OpenOutcome, ChannelError> {
        let auth = &open.auth;

        // 1. The auth must name *this* merchant, and the payer SIG must verify.
        if auth.merchant_key != self.key {
            return Err(ChannelError::WrongMerchant);
        }
        auth.verify().map_err(|_| ChannelError::BadAuth)?;

        // 1b. The meed vector MUST be conformant schema-0x01 AND its GOVERNED destinations
        //     correct (F5-o/F9.4): exact roles/bp/CAIP/100-bp total, PLUS 0x13 == the pinned
        //     Dev-Fund constant and 0x11 registry-listed-or-independent-fund against the auth's
        //     named registry version. A channel cannot open understating, reordering, or
        //     **misrouting** the governed meed — the merchant re-checks the payer-signed vector at
        //     open so the interaction layer cannot redirect the OS / Dev-Fund shares to an attacker
        //     (the prior shape-only check caught a stripped share but not a misrouted one).
        auth.validate_vector_governed(&self.registry)
            .map_err(|_| ChannelError::BadAuth)?;

        // 1c. Off-baseline fail-closed AT OPEN: this RI defers off-baseline settlement
        //     wholesale — a converted round is rejected (needs the rate oracle) and an off-baseline
        //     chain is rejected (`chained_import`) — so a `DENOM ≠ BASELINE_ASSET` channel could
        //     only carry metered value it can never settle or chain out, stranding it. Reject at
        //     establishment so value is never carried on an unsettleable channel. (Spec-permitted
        //     off-baseline, F5.6/F6.5, is an RI conformance-scope deferral.)
        if auth.denom != auth.baseline_asset {
            return Err(ChannelError::OffBaselineUnsupported);
        }

        // 2. TIMESTAMP acceptance window (F8.2: |now − TIMESTAMP| ≤ SKEW + LATENCY).
        let window = SKEW_SECS + LATENCY_SECS;
        if now.abs_diff(auth.timestamp) > window {
            return Err(ChannelError::TimestampOutOfWindow);
        }

        let auth_hash = auth.auth_hash().map_err(|_| ChannelError::BadAuth)?;
        let open_hash = crypto::sha256(&open.encode().map_err(|_| ChannelError::BadAuth)?);

        // 2b. Durable F5-m tombstone: a channel id this merchant ACCEPTED in a prior
        //     life (restored from the durable store at startup) is rejected outright. The live
        //     `retained`/metering state is gone after a restart, so a reused id can only be a replay
        //     of a captured OPEN within the timestamp window — reject it (`ChannelReplay`), never a
        //     fresh channel (slice-plane reset) and never an ACK retransmit into an unservable
        //     channel. This is the rejecting-tombstone rule.
        if self.tombstones.contains(&auth.channel_id) {
            return Err(ChannelError::ChannelReplay);
        }

        // 3. F5-m replay-suppression, keyed on CHANNEL_ID. Only a byte-identical
        //    retransmission of the already-acknowledged OPEN is answered — with the
        //    stored ACK and WITHOUT re-initializing the channel (no fresh state, no
        //    unseal of an attacker-chosen SEAL). Anything else reusing the id — a
        //    terminated channel, different terms, or a re-sealed SEAL — is rejected.
        if let Some(r) = self.retained.get(&auth.channel_id) {
            if !r.terminated && r.auth_hash == auth_hash && r.open_hash == open_hash {
                return Ok(OpenOutcome::Retransmit(r.ack.clone()));
            }
            return Err(ChannelError::ChannelReplay);
        }

        // 3b. Chaining one-decision bar (§5.4): a named predecessor checkpoint is imported
        //     by at most one successor. Reject a fresh OPEN whose predecessor reference is
        //     already consumed (a retransmit short-circuited above, so this never fires on
        //     the lost-ACK retry — the reference is consumed once, by this channel). The
        //     record itself is written only after establishment fully succeeds (below), so
        //     an OPEN that then fails unseal/H(s) consumes nothing.
        if let Some(pred) = auth.predecessor {
            if self.consumed_chain_refs.contains(&pred) {
                return Err(ChannelError::ChainReplay);
            }
        }

        // 4. Unseal s and validate H(s) against the HS commitment BEFORE retaining.
        let s = self.unseal(open)?;
        if crypto::h_commit(&s) != auth.hs {
            return Err(ChannelError::HsMismatch);
        }
        let k_session = self.derive_key(auth, &s);

        // `seed_instance` is channel-life-fixed (F4.1 ADDRESS_INPUTS) — computed ONCE here
        // and reused for the retained terms AND the F6.6 chain fingerprint. The vector was
        // validated conformant above, so a derivation failure is fail-closed BadAuth
        // rather than a zero instance the meed leg would pay.
        let mut bound_dests: Vec<String> = auth.vector.iter().map(|v| v.dest.clone()).collect();
        bound_dests.push(self.settle_ptr.clone());
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
            // A channel's meed leg pays the instance (meed-only) — no merchant-net
            // seat (split-only).
            merchant_net: None,
        }
        .seed_instance()
        .map_err(|_| ChannelError::BadAuth)?;
        let mode = if auth.mode == paytp_core::channel::establish::MODE_POSTPAY {
            Mode::Postpay
        } else {
            Mode::Prepay
        };

        // 4b. F6.6 chained import — fail-CLOSED BEFORE we retain/ACK, so a
        //     `predecessor`-referenced open that cannot import a consistent reconciled
        //     position is rejected, never silently opened as a fresh zero-state channel
        //     (previously a silent false success). The one-decision bar (3b) already barred a
        //     double-import; `chained_import` validates the snapshot, same-payer, identical
        //     terms (clause (c)), and that the imported position fits the successor's window.
        let import = match auth.predecessor {
            Some(pred) => Some(self.chained_import(pred, auth, k_session, &seed_instance, mode)?),
            None => None,
        };

        // 5. Sign the ACK, retain the decision.
        let mut ack = ChannelAck {
            auth_hash,
            settle_ptr: self.settle_ptr.clone(),
            sig: None,
        };
        ack.sign(&self.signing_key)
            .map_err(|_| ChannelError::BadAuth)?;
        // Durable F5-m: record the channel-open ACCEPTANCE BEFORE retaining/returning, so a
        // restart restores this id as a tombstone and rejects any replay. Fail-closed — a merchant
        // that cannot durably record the acceptance MUST NOT accept the channel (it could not
        // suppress a future replay). `AlreadyDecided` means another replica/a restart-race already
        // accepted this id → reject as a replay. `Fresh` → proceed. (Demo build: no store, skip.)
        if let Some(store) = &self.decisions {
            match store.decide(&chopen_key(&auth.channel_id), b"") {
                Decision::Fresh => {}
                Decision::AlreadyDecided(_) => return Err(ChannelError::ChannelReplay),
                Decision::Failed => return Err(ChannelError::StoreUnavailable),
            }
        }
        self.retained.insert(
            auth.channel_id,
            Retained {
                auth_hash,
                open_hash,
                payer_key: auth.payer_key,
                ack: ack.clone(),
                terminated: false,
                terms: SettlementTerms {
                    denom: auth.denom.clone(),
                    baseline_asset: auth.baseline_asset.clone(),
                    baseline_net: auth.baseline_net.clone(),
                    bound_dests,
                    conversion_required: auth.denom != auth.baseline_asset,
                    settle_ptr: self.settle_ptr.clone(),
                    fin_denom: auth.fin_denom.clone(),
                    fin_meed: auth.fin_meed.clone(),
                    seed_instance,
                    refund_ptr: auth.refund_ptr.clone(),
                    th_value: auth.th_value,
                    th_time: auth.th_time,
                },
            },
        );
        // Establishment succeeded: consume the predecessor reference (one-decision, §5.4).
        // A chained open reaches here only after `chained_import` validated + built it, so
        // consuming now is exactly the successful-import path — a fail-closed import returned
        // above (nothing retained/consumed), and a non-chained open consumes nothing.
        if let (Some(pred), Some(_)) = (auth.predecessor, &import) {
            self.consumed_chain_refs.insert(pred);
        }
        Ok(OpenOutcome::Established(Box::new(
            self.established(auth, auth_hash, k_session, ack, import),
        )))
    }

    /// F6.6 chained import: build the successor's imported [`ChannelState`] and
    /// ledger openings from the recorded [`ChainSnapshot`], **fail-closed**. Returns
    /// `(imported_state, ledger_openings, inherited established_at)`.
    fn chained_import(
        &self,
        pred: ([u8; 8], [u8; 32]),
        auth: &paytp_core::channel::ChannelAuth,
        k_session: [u8; 32],
        seed_instance: &[u8; 32],
        mode: Mode,
    ) -> Result<(ChannelState, LedgerOpenings, u64), ChannelError> {
        // The snapshot exists only for a `chain_intent`-closed predecessor (F6.6) — its
        // absence (unknown/stale/still-open/non-chain-closed predecessor) fails closed.
        let snap = self
            .chain_snapshots
            .get(&pred)
            .ok_or(ChannelError::ChainRejected)?;
        // Same payer (§5.4 same-party) and same mode (clause (c)).
        if snap.payer_key != auth.payer_key || mode != snap.mode {
            return Err(ChannelError::ChainRejected);
        }
        // v1 chains baseline-deterministic only; an off-baseline (conversion) chain is
        // deferred with the off-baseline settlement path.
        if auth.denom != auth.baseline_asset {
            return Err(ChannelError::ChainRejected);
        }
        // F6.6 clause (c): identical terms (mode + instance-address inputs via
        // `seed_instance` + DENOM + the two finality levels).
        let fp = chain_terms_fingerprint(
            mode,
            seed_instance,
            &auth.denom,
            &auth.baseline_net,
            &auth.fin_meed,
            &auth.fin_denom,
            auth.th_value,
            auth.th_time,
        );
        if fp != snap.terms_fingerprint {
            return Err(ChannelError::ChainRejected);
        }
        // Map the snapshot's per-role accruals to the successor's vector order (the same
        // roles, guaranteed by the fingerprint match over `seed_instance`).
        let mut imported_accruals: Vec<BigUint> = Vec::with_capacity(auth.vector.len());
        for v in &auth.vector {
            let a = snap
                .accruals
                .iter()
                .find(|(r, _)| *r == v.role)
                .ok_or(ChannelError::ChainRejected)?;
            imported_accruals.push(a.1.clone());
        }
        let state = ChannelState::new_imported(
            auth.channel_id,
            k_session,
            mode,
            auth.limit_l,
            auth.limit_e,
            auth.vector.iter().map(|v| (v.role, v.bp)).collect(),
            snap.cum_total,
            imported_accruals,
            snap.imported_balance,
        )
        .map_err(|_| ChannelError::ChainRejected)?;
        let openings = LedgerOpenings {
            settled_r: snap.opening_settled_r.clone(),
            net_legs: snap.opening_net_legs,
            funding: snap.opening_funding,
        };
        Ok((state, openings, snap.established_at))
    }

    /// Countersign a checkpoint in the merchant's role slot (F5-k / F6.3) — used to
    /// complete a bilateral `CHECKPOINT` after the merchant recomputes the proposed
    /// state, and to sign the merchant's own checkpoint in a `PAYTP_STATE_MISMATCH`
    /// answer.
    pub fn countersign_checkpoint(
        &self,
        cp: &mut paytp_core::channel::checkpoint::Checkpoint,
    ) -> Result<(), ChannelError> {
        cp.sign_merchant(&self.signing_key)
            .map_err(|_| ChannelError::BadAuth)
    }

    /// Sign a `SETTLEMENT_CONFIRMED` as the creditor (F5.6, `PayTPv1-settle-confirm`).
    pub fn sign_confirmed(&self, c: &mut paytp_core::channel::settle_msg::SettlementConfirmed) {
        c.sign_merchant(&self.signing_key);
    }

    /// Sign a `PREPAY_DRAW_COMPLETED` as the prepay meed debtor (F5-o,
    /// `PayTPv1-prepay-draw`) — the merchant's own draw completion, NOT a creditor confirm.
    pub fn sign_prepay_draw(&self, m: &mut paytp_core::channel::settle_msg::PrepayDrawCompleted) {
        m.sign_merchant(&self.signing_key);
    }

    /// Mark a channel terminated (F6.1: the channel ends when its establishing
    /// connection closes). It is then never re-initialized under its old id.
    pub fn terminate(&mut self, channel_id: &[u8; 8]) {
        if let Some(r) = self.retained.get_mut(channel_id) {
            r.terminated = true;
        }
    }

    /// The retained payer key for an open channel (for verifying its `FUNDING_PROOF`
    /// / `CLOSE`), or `None` if the id names no channel this driver holds.
    pub fn payer_key(&self, channel_id: &[u8; 8]) -> Option<[u8; 32]> {
        self.retained.get(channel_id).map(|r| r.payer_key)
    }

    /// The retained `AUTH_HASH` for an open channel (to bind a `FUNDING_PROOF` to
    /// the channel it names, §5.4 — "a proof can never be presented against a
    /// different channel"), or `None` if the id names no channel this driver holds.
    pub fn auth_hash(&self, channel_id: &[u8; 8]) -> Option<[u8; 32]> {
        self.retained.get(channel_id).map(|r| r.auth_hash)
    }

    /// The establishment terms a settlement round is validated against (F5.6), or
    /// `None` if the id names no channel this driver holds.
    pub fn settlement_terms(&self, channel_id: &[u8; 8]) -> Option<&SettlementTerms> {
        self.retained.get(channel_id).map(|r| &r.terms)
    }

    /// Serve `CHANNEL_ACK` retrieval for a signed `ACK_REQUEST` (F5.3): the request
    /// must be signed by *that channel's* payer key and its `TIMESTAMP` must be
    /// within the F8.2 acceptance window — nobody else learns a channel's terms
    /// from its identifier. Returns `None` for an unknown/terminated channel, a
    /// bad signature, or a stale timestamp.
    pub fn serve_ack_request(&self, req: &AckRequest, now: u64) -> Option<ChannelAck> {
        let r = self.retained.get(&req.channel_id)?;
        if now.abs_diff(req.timestamp) > SKEW_SECS + LATENCY_SECS {
            return None;
        }
        req.verify(&r.payer_key).ok()?;
        Some(r.ack.clone())
    }

    fn unseal(&self, open: &ChannelOpen) -> Result<[u8; 32], ChannelError> {
        let aad = open
            .auth
            .canonical_content()
            .map_err(|_| ChannelError::BadAuth)?;
        crypto::open_session_secret(&self.enc_secret, &open.seal, &aad)
            .map_err(|_| ChannelError::SealInvalid)
    }

    fn derive_key(&self, auth: &paytp_core::channel::ChannelAuth, s: &[u8; 32]) -> [u8; 32] {
        let salt = crypto::bind_salt(&auth.payer_key, &auth.merchant_key);
        crypto::k_session(s, &salt, &auth.channel_id)
    }

    fn established(
        &self,
        auth: &paytp_core::channel::ChannelAuth,
        auth_hash: [u8; 32],
        k_session: [u8; 32],
        ack: ChannelAck,
        import: Option<(ChannelState, LedgerOpenings, u64)>,
    ) -> Established {
        // A chained open (F6.6) installs the imported state + ledger openings and
        // inherits the predecessor's `established_at` (so chaining never resets the TH_TIME
        // clock); a fresh open builds a zero-state channel opening at `auth.timestamp`.
        let (state, ledger_openings, established_at) = match import {
            Some((state, openings, at)) => (state, Some(openings), at),
            None => {
                let mode = if auth.mode == paytp_core::channel::establish::MODE_POSTPAY {
                    Mode::Postpay
                } else {
                    Mode::Prepay
                };
                let vector: Vec<(u8, u16)> = auth.vector.iter().map(|v| (v.role, v.bp)).collect();
                let state = ChannelState::new(
                    auth.channel_id,
                    k_session,
                    mode,
                    auth.limit_l,
                    auth.limit_e,
                    vector,
                );
                (state, None, auth.timestamp)
            }
        };
        Established {
            channel_id: auth.channel_id,
            auth_hash,
            k_session,
            ack,
            state,
            th_value: auth.th_value,
            th_time: auth.th_time,
            established_at,
            ledger_openings,
        }
    }
}

#[cfg(test)]
mod tests;
