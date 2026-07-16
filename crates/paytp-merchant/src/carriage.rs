//! Channel-plane **carriage** — the `/channel`, `/ack`, `/batch` control-plane
//! dispatch (**F5.1 / F5-a / F5-b / F5-c**).
//!
//! Control objects are POSTed to `/channel` as `type-octet ‖ object bytes` (F5-a),
//! one message per request; `/ack` carries only `ACK_REQUEST` (retrieval lives
//! there, never on `/channel`); `/batch` carries a `BATCH_HEAD` naming one channel
//! followed by F1-j-framed slices (F5-c), all verified under that channel's keys
//! and accepted atomically. The type octet is **routing, not security**: an altered
//! octet mis-parses into a different registry and the signature under the wrong
//! domain label fails (F1.3) — nothing rides on it.
//!
//! This sits above the [`ChannelDriver`] (establishment + F5-m retention) and a
//! per-channel [`ChannelState`] (metering); it owns both so one open channel has
//! exactly one metering state.

use std::collections::HashMap;

use std::sync::Arc;

use crate::one_decision::{Decision, DurableOneDecision, OneDecisionStore};

use num_bigint::BigUint;
use paytp_core::channel::checkpoint::CheckpointRequest;
use paytp_core::channel::establish::{ChannelOpen, Close, FundingProof};
use paytp_core::channel::settle_msg::{
    Output, PrepayDrawCompleted, SettlementConfirmed, SettlementProof, SettlementPropose,
};
use paytp_core::channel::state::{ChannelState, Mode, Status};
use paytp_core::channel::AckRequest;
use paytp_core::crypto::sha256;
use paytp_core::derive::{claim_record_id, settlement_net_memo};
use paytp_core::fee::{self, reconcile, Rate, U256};
use paytp_core::tlv::{self, Object, Openness, Schema};
use paytp_rail::{RailAdapter, RailError, RailRef};

use crate::channel::{
    chain_terms_fingerprint, ChainSnapshot, ChannelDriver, ChannelError, OpenOutcome,
};

// Control-object type octets (F5-a).
const T_CHANNEL_OPEN: u8 = 0x01;
const T_CHANNEL_ACK: u8 = 0x02;
const T_CHECKPOINT_REQUEST: u8 = 0x03;
const T_CHECKPOINT: u8 = 0x04;
const T_FUNDING_PROOF: u8 = 0x05;
const T_SETTLEMENT_PROPOSE: u8 = 0x06;
const T_SETTLEMENT_PROOF: u8 = 0x07;
const T_SETTLEMENT_CONFIRMED: u8 = 0x08;
const T_CLOSE: u8 = 0x09;
const T_ACK_REQUEST: u8 = 0x0A;
/// `PREPAY_DRAW_COMPLETED` (F5-o) — merchant→payer, emitted by [`Carriage::run_prepay_interim_draw`]
/// as a control-plane response a halted payer obtains on its next contact (not inbound-routed here).
#[allow(dead_code)]
const T_PREPAY_DRAW_COMPLETED: u8 = 0x0B;

/// Per-round cap on distinct countersigned-proposal hashes retained (Defect D).
const MAX_PROPOSAL_HASHES: usize = 64;
/// Per-round cap on settlement proofs retained as deferred-verification evidence.
const MAX_PROOFS: usize = 64;

/// One in-flight interim round the plain-close drain (F6-n(d)) resolves, with the inputs to a
/// **rail-authoritative** funded query: `(CKPT_REF, E_r, P, draw_ref)`.
type DrainRound = ([u8; 32], Vec<(u8, BigUint)>, Option<u128>, Option<String>);

/// A carriage-layer rejection.
///
/// **Error-taxonomy discipline (F6-b / §5.4):** every *pre-authentication* failure
/// — an unknown channel (a channel's terms are "nobody's business"), a bad
/// signature, or a slice MAC failure — collapses to the single generic
/// [`CarriageError::Rejected`], so an unauthenticated sender can never distinguish
/// "channel exists" from "signature wrong" and learns no channel state. Only a
/// *post-authentication* outcome (a MAC-valid slice hitting a bound) draws a
/// specific, actionable error, because only a MAC holder can reach it.
/// The outcome of claiming a canonical rail reference on a money path ([`Carriage::consume_ref`]).
/// `#[must_use]` so no caller can silently drop it — a discarded outcome is exactly how the
/// settlement net leg double-credited (C1-2) and how a storage failure masqueraded as a duplicate
/// on the funding path (C1-3).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsumeOutcome {
    /// This is the FIRST consumption of the reference (durably recorded, or the single-process
    /// first) — the caller performs the gated credit/fold exactly this once.
    First,
    /// The reference was ALREADY consumed (another replica, a restart-race, or a replay). The
    /// caller MUST NOT re-credit — acknowledge idempotently.
    Duplicate,
    /// The durable store FAILED to record the consumption (a write/sync error). Nothing was
    /// consumed and nothing credited — the caller MUST reject/retry (the on-rail transfer is
    /// recoverable), never ack success. Only reachable with a durable store attached.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarriageError {
    /// Empty body, or a type octet outside `0x01..=0x0A` (F5-a).
    UnknownType,
    /// A message posted to the wrong resource — `ACK_REQUEST` on `/channel`, or a
    /// `/channel` control object on `/ack` (retrieval is `/ack`-only, F5.1).
    Misrouted,
    /// The message body failed to parse or validate (F1). Structural, pre-auth.
    Malformed,
    /// The uniform pre-authentication rejection (F6-b): unknown channel, bad
    /// signature, replayed funding, or slice MAC failure — indistinguishable so no
    /// unauthenticated sender learns channel state.
    Rejected,
    /// A recognized control object whose full exchange is not driven in this
    /// profile (checkpoint / settlement rounds — the codecs exist; the exchange
    /// state machine is future wiring).
    Unsupported,
    /// Post-auth: a MAC-valid slice at/below the checkpoint floor or already
    /// accounted (`PAYTP_SEQ_INVALID`, F6-b step 4).
    SeqInvalid,
    /// Post-auth: a MAC-valid slice would breach the mode's balance bound
    /// (`PAYTP_WINDOW_EXCEEDED`, F6-b step 5) — fund or settle to release.
    WindowExceeded,
    /// Post-auth: a MAC-valid slice would push unevidenced value past `E`
    /// (`PAYTP_EVIDENCE_REQUIRED`, F6-b step 5) — a checkpoint releases it.
    EvidenceRequired,
    /// A slice on a `SETTLING`/`CLOSED` channel — meters nothing (F6.1).
    Closed,
    /// A `CHECKPOINT_REQUEST` whose proposed metering does not recompute against the
    /// merchant's books (`PAYTP_STATE_MISMATCH`, F6.3) — the answer carries the
    /// merchant's own checkpoint when it holds one.
    StateMismatch(Option<Vec<u8>>),
}

impl std::fmt::Display for CarriageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CarriageError {}

/// What a dispatched request returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A type-octet-framed control message to return (e.g. `0x02 ‖ CHANNEL_ACK`).
    Message(Vec<u8>),
    /// Accepted with no message body (funding credited, close acknowledged, batch
    /// metered — a slice drop is declared by the next checkpoint, not the response).
    Accepted,
}

/// The construction profile (F5-m). A **proof** carriage is built with a rail + a durable one-decision
/// store (both mandatory, via [`Carriage::proof`]); it can never take the rail-less funding-mint path
/// or run an in-memory replay guard. A **demo** carriage ([`Carriage::demo`], feature-gated out of a
/// proof build) is the permissive virtual-rail build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    #[cfg(any(test, feature = "demo"))]
    Demo,
    Proof,
}

/// Why a proof carriage could not be constructed (F5-m — fail closed at startup). All are
/// misconfiguration, never a runtime money outcome.
#[derive(Debug)]
pub enum ConfigError {
    /// The durable F5-m store could not be replayed into the driver (a corrupt `chopen:` record).
    Retention(ChannelError),
    /// The durable one-decision log is corrupt and could not be replayed into the carriage guards.
    DecisionLog,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Retention(e) => Some(e),
            ConfigError::DecisionLog => None,
        }
    }
}

/// The merchant channel-plane carriage: the establishment driver plus one metering
/// [`ChannelState`] per open channel.
pub struct Carriage {
    /// The construction profile — `Proof` (rail + durable store mandatory) or `Demo`. On a `Proof`
    /// carriage the rail-less funding-mint branch and the in-memory-guard branch are unreachable by
    /// construction; a fail-closed backstop rejects them anyway (defense-in-depth).
    profile: Profile,
    driver: ChannelDriver,
    channels: HashMap<[u8; 8], ChannelState>,
    /// The operative (last countersigned) checkpoint per channel (F6.3) — its
    /// reference (the anchor a `CLOSE`/round must name) plus the metering snapshot
    /// (`CUM_TOTAL`, per-role `ACCRUALS`) a settlement round reconciles against (F6-f).
    operative: HashMap<[u8; 8], Operative>,
    /// Per-channel settlement ledger (F6-f): the completed rounds' cumulative settled
    /// meed (per role), net legs, and credited funding — the "settled" side the
    /// round's owed position subtracts from the operative checkpoint's "metered" side.
    ledger: HashMap<[u8; 8], Ledger>,
    /// The creditor's one-decision record per settlement round `(CHANNEL_ID, CKPT_REF)`
    /// (F6.5): the countersigned round's **terms** fingerprint and the set of
    /// proposal hashes it has countersigned (a retry grows `CREDITED`, changing the
    /// hash but not the terms). A second proposal with *different* terms is refused.
    rounds: HashMap<([u8; 8], [u8; 32]), RoundDecision>,
    /// The `DENOM`-rail adapter used to verify funding + settlement legs on-chain
    /// (F6.4/F6.5). `None` is the documented spike interim: without a rail the merchant
    /// cannot verify a transfer reached its pointer/finality, so funding credit and
    /// `CONFIRMED` fall back to the signature-only path (§C — a launch build MUST set
    /// a rail via [`Carriage::with_rail`]).
    rail: Option<Box<dyn RailAdapter>>,
    /// Consumed funding references, keyed on the **canonical `TX_REF`** and recorded
    /// **globally — across all of the merchant's channels** (F6.4 GAP-FILL F6-d).
    /// The key excludes the attacker-controlled `FUNDING_PROOF.RAIL` string (the
    /// connected adapter, not `fp.rail`, is the rail; `ref_target` reads it), so a
    /// mutated-rail replay cannot re-credit one transfer. Both the on-rail bind
    /// (`memo == stored AUTH_HASH`, `on_funding`) and this global one-decision are
    /// load-bearing: the bind closes cross-channel gift-theft, global-once closes
    /// same-channel replay + cross-channel double-credit. Canonicalizing `TX_REF`
    /// to one transfer event is the rail-adapter contract (F6-d step 3 / F5-n).
    consumed_funding: std::collections::HashSet<String>,
    /// Per-channel `established_at` (F6.6): a chained successor inherits its
    /// predecessor's value (via the ChainSnapshot), so it propagates unchanged across the
    /// chain — chaining never resets the `TH_TIME` settlement clock (no infinite-chain
    /// settlement evasion). Recorded at open, read into the snapshot at a chain-intent close.
    channel_established_at: HashMap<[u8; 8], u64>,
    /// The **one durable close disposition** per channel (F6.6) — *where the
    /// terminal position goes*, read by three DISTINCT predicates (`resolve_chain_tip`,
    /// `bars_new_round`, `funding_admissible`), never one conflated `contains_key`. "Chain
    /// intent is **not a waiver**" (§6.4): a chain-intent close stays `Pending` (deposit
    /// refundable, late funding creditable) until a successor is accepted (`Committed` —
    /// irrevocable, float rolled forward) **or** the payer reclaims via a plain close
    /// (`Reconciled` — settles on its own books: deposit refunded, final round admitted). A
    /// single check-and-set record — refund XOR successor-import, each exactly once — replaces
    /// the old scattered `chain_closed` + `already_closing` state that trapped the deposit when
    /// no successor came (F6-f) and stranded a late predecessor-bound funding leg. In-process
    /// `&mut self` makes the CAS trivial; its TERMINAL transitions
    /// (`Committed`/`Reconciled`) are mirrored to the durable [`Carriage::decisions`] store and
    /// replayed at startup, so the exactly-once decision survives a restart.
    chain_state: HashMap<[u8; 8], ChainState>,
    /// A **chained successor's imported evidenced basis** (F6.6) — the cumulative consumed position,
    /// the predecessor's final checkpoint reference, and the imported accruals — for a successor
    /// that lives in no `operative` entry of its own (it signed no checkpoint). At `on_close` the
    /// reconciliation basis is `operative` ELSE this imported basis ELSE a fresh **birth**: without
    /// it an imported successor's plain-close refund would read `0` and return the whole deposit,
    /// losing the imported consumption (a chained successor is **not** a fresh birth), AND its
    /// outstanding imported carve would never be drawn to the instance (the merchant pocketing it).
    /// Set once at chained import; a later own checkpoint supersedes it via `operative`.
    imported_basis: HashMap<[u8; 8], ImportedBasis>,
    /// The **durable one-decision store** backing the channel-plane exactly-once
    /// guards this carriage keeps in memory: a funding reference is credited once
    /// (`consumed_funding`), and a channel's TERMINAL close disposition (successor-import XOR
    /// refund) is set once (`chain_state`). The in-memory maps are the working cache; THIS store is
    /// the durable authority they are replayed from at [`Carriage::proof`], so the
    /// decisions survive a merchant restart and hold across whatever serves the traffic (the
    /// deferral the `chain_state` / refund comments name "the durable store"). `None`
    /// keeps the pure in-memory build (single process, no restart durability). Held behind an `Arc`
    /// so ONE store backs every carriage replica that serves the channel (the F4.4 "across whatever
    /// serves the traffic" property) — its atomic `decide` is then the cross-replica CAS gate.
    decisions: Option<Arc<dyn OneDecisionStore>>,
}

/// Durable one-decision key namespaces: a consumed funding reference (F6-d global
/// once) and a channel's terminal close disposition. Distinct prefixes so one store holds both.
const FUND_NS: &[u8] = b"fund:";
const DISP_NS: &[u8] = b"disp:";
/// A close refund RESERVED (crash-safe): recorded BEFORE `release_keyed` submits, so the
/// merchant's durable intent precedes the on-chain effect — a crash in the window replays as
/// reserved and re-attempts the SAME keyed release (rail dedups), never losing or doubling it.
const RFND_NS: &[u8] = b"rfnd:";
/// The canonical rail reference of a reserved refund's release — persisted so a restart can poll
/// THAT release's finality (recover-and-poll) instead of blindly re-submitting a fresh one.
const RREF_NS: &[u8] = b"rref:";

fn fund_key(canonical_ref: &str) -> Vec<u8> {
    [FUND_NS, canonical_ref.as_bytes()].concat()
}

fn disp_key(cid: &[u8; 8]) -> Vec<u8> {
    [DISP_NS, &cid[..]].concat()
}

/// The refund one-decision key: the close basis `(CHANNEL_ID, refund-basis CKPT_REF)` — the same key
/// the rail's `release_keyed` dedups on, so the merchant reserve and the rail dedup agree.
fn refund_reserve_key(cid: &[u8; 8], ckpt_ref: &[u8; 32]) -> Vec<u8> {
    [RFND_NS, &cid[..], &ckpt_ref[..]].concat()
}

fn refund_ref_key(cid: &[u8; 8], ckpt_ref: &[u8; 32]) -> Vec<u8> {
    [RREF_NS, &cid[..], &ckpt_ref[..]].concat()
}

/// Encode a **terminal** close disposition for the durable store. `Pending` is revocable and is
/// never recorded (a restart that loses it simply re-derives it from the next close/import).
fn encode_disp(state: &ChainState) -> Vec<u8> {
    match state {
        ChainState::Committed { successor } => [&[0x01u8][..], &successor[..]].concat(),
        ChainState::Reconciled { pending_draw: None } => vec![0x02],
        ChainState::Reconciled {
            pending_draw: Some((ckpt, p)),
        } => [&[0x03u8][..], &ckpt[..], &p.to_be_bytes()[..]].concat(),
        ChainState::Pending => Vec::new(),
    }
}

/// Decode a durable disposition record (`None` on a malformed/unknown tag). EXACT length per tag —
/// a complete record with **trailing garbage** is rejected, so a proof replay fails closed on a
/// corrupt disposition rather than accepting a truncated/padded value: e.g.
/// a `0x02 ‖ garbage` must not silently decode as `Reconciled{None}`, losing a pending carve draw.
fn decode_disp(bytes: &[u8]) -> Option<ChainState> {
    match bytes.first()? {
        0x01 if bytes.len() == 9 => Some(ChainState::Committed {
            successor: <[u8; 8]>::try_from(bytes.get(1..9)?).ok()?,
        }),
        0x02 if bytes.len() == 1 => Some(ChainState::Reconciled { pending_draw: None }),
        0x03 if bytes.len() == 49 => {
            let ckpt = <[u8; 32]>::try_from(bytes.get(1..33)?).ok()?;
            let p = u128::from_be_bytes(<[u8; 16]>::try_from(bytes.get(33..49)?).ok()?);
            Some(ChainState::Reconciled {
                pending_draw: Some((ckpt, p)),
            })
        }
        _ => None,
    }
}

/// The one durable **close disposition** per channel (F6-f/F6.5): where this channel's terminal
/// position goes. Answered by three *distinct* predicates — chain routing (`resolve_chain_tip`),
/// whether a new settlement round is barred (`bars_new_round`), and funding admissibility
/// (`funding_admissible`) — NEVER conflated into a single `contains_key` (the over-broad
/// guard). (Named `ChainState` for history; it is the close disposition, of which two variants
/// are chaining and one is not.)
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainState {
    /// Chain intent expressed at close; the position is chainable but the deposit is still
    /// **refundable** (a plain `CLOSE` reclaims it) and late funding still **creditable**.
    /// Revocable — no successor has imported yet. **Bars a new settlement round** (the
    /// successor settles the imported obligation — F6-i).
    Pending,
    /// A successor imported the position (consumed the chain ref). **Irrevocable**: the float
    /// rolled forward, so a later reclaim is refused and a late predecessor-bound funding leg
    /// credits the successor (`resolve_chain_tip`). **Bars a new settlement round.**
    Committed { successor: [u8; 8] },
    /// A **plain (reconciling) close**: this channel settles on its **own** books — no
    /// successor may import (F6.6 clause (d)), the deposit refunded here (prepay), the **final
    /// settlement round admitted** (postpay — F6-i does NOT bar it, only the chaining states do).
    /// `pending_draw` is the prepay close carve draw owed to the instance, **pinned once at the
    /// FIRST close** to `(named CKPT_REF, target_p)` — the SAME evidenced basis as the refund (an own
    /// operative checkpoint, or the imported checkpoint for a chained successor that signed none of
    /// its own), so a checkpoint completing later in `Settling` can NEVER move the draw's basis or
    /// amount (the double-draw a dynamic re-read would open). It makes the draw **retryable, never a
    /// terminal silent leak**: `Some((ckpt, target_p))` = a draw is still owed (a transient rail
    /// failure leaves it pending; a replay/retry close re-attempts — the watermark advance's idempotent
    /// 0-delta (`Ok`, never re-drawing) backs exactly-once); `None` = drawn, or none owed (postpay / zero carve /
    /// converted-deferred / birth).
    Reconciled {
        pending_draw: Option<([u8; 32], u128)>,
    },
}

/// A chained successor's imported **evidenced basis** (F6.6) — the cumulative consumed position,
/// the predecessor's final checkpoint reference, and the imported per-role accruals — recorded at
/// import for a successor that signs no operative checkpoint of its own. `on_close` reconciles the
/// prepay refund against `cum` and draws the outstanding imported carve against `(ckpt_ref,
/// accruals)` — never against LIVE metering (F6-k), which a merchant could inflate by forging
/// slices to short the payer's refund and over-pay the instance.
#[derive(Clone)]
struct ImportedBasis {
    cum: u128,
    ckpt_ref: [u8; 32],
    accruals: Vec<(u8, BigUint)>,
    /// The imported cumulative settled meed per role (F6-f `opening_settled_r`) — what the
    /// PREDECESSOR already funded to the instance (under its own channel's watermark). The Option W
    /// own-cumulative target subtracts THIS (not the running `settled_r = imported + own`), so a
    /// chained successor's fresh per-channel `funded_p` funds only its OWN carve `floor((accrued −
    /// imported_settled) / 1e4)` — the v4 altitude fix. Empty for a first-generation channel (no
    /// `imported_basis` entry at all → `imported_settled = 0`).
    opening_settled_r: Vec<(u8, BigUint)>,
}

impl Carriage {
    /// The common field init (all maps empty, no rail, no store). The constructor sets the profile.
    fn empty(driver: ChannelDriver, profile: Profile) -> Self {
        Carriage {
            profile,
            driver,
            channels: HashMap::new(),
            operative: HashMap::new(),
            ledger: HashMap::new(),
            rounds: HashMap::new(),
            consumed_funding: std::collections::HashSet::new(),
            rail: None,
            channel_established_at: HashMap::new(),
            chain_state: HashMap::new(),
            imported_basis: HashMap::new(),
            decisions: None,
        }
    }

    /// **Demo / virtual carriage** — rail optional (the signature-only interim), in-memory guards
    /// allowed. Feature-gated OUT of a proof build (F5-m): a proof/production build cannot even NAME
    /// it, so the rail-less mint path is not compilable there. Use [`Carriage::proof`] for a
    /// money deployment.
    #[cfg(any(test, feature = "demo"))]
    pub fn demo(driver: ChannelDriver) -> Self {
        Self::empty(driver, Profile::Demo)
    }

    /// **Proof carriage** (F5-m) — rail + a durable one-decision store are REQUIRED (fail closed at
    /// startup, never a comment). The SAME `Arc` store backs the driver's F5-m tombstones AND the
    /// carriage guards (funding / disposition / refund), so every exactly-once decision survives a
    /// restart and holds across whatever serves the traffic (F4.4). The sealed [`DurableOneDecision`]
    /// bound means an in-memory store *cannot* be passed — construction-proof, not a runtime boolean
    /// an operator could subvert. A corrupt durable log fails the open
    /// (never silently forgets a decision → never double-acts).
    ///
    /// Single-active-owner: the reference WAL is restart-durable but not a cross-process CAS;
    /// multi-replica needs the linearizable DB profile (ASYNC-1).
    pub fn proof<D>(
        mut driver: ChannelDriver,
        rail: Box<dyn RailAdapter>,
        decisions: Arc<D>,
    ) -> Result<Self, ConfigError>
    where
        D: DurableOneDecision + 'static,
    {
        let store: Arc<dyn OneDecisionStore> = decisions;
        // Install + replay the SAME store into the driver (F5-m tombstones), fail-closed on corrupt.
        driver
            .attach_decisions(store.clone())
            .map_err(ConfigError::Retention)?;
        let mut c = Self::empty(driver, Profile::Proof);
        c.rail = Some(rail);
        c.replay_guards(store, true)?;
        Ok(c)
    }

    /// Replay the durable log into the carriage guard maps (consumed funding refs + terminal close
    /// dispositions), then install the store as the durable authority. In `strict` mode (a proof
    /// build) a complete-but-corrupt `fund:`/`disp:` record FAILS closed (`ConfigError::DecisionLog`),
    /// never silently skipped — a forgotten disposition would re-refund /
    /// re-import. Lenient mode (demo) tolerates it.
    fn replay_guards(
        &mut self,
        store: Arc<dyn OneDecisionStore>,
        strict: bool,
    ) -> Result<(), ConfigError> {
        for (key, val) in store.entries() {
            if let Some(canonical) = key.strip_prefix(FUND_NS) {
                // A `fund:` record's value is ALWAYS empty (the canonical ref is the key); a
                // non-empty value, or a non-UTF-8 ref, is corruption → fail closed in a proof build
                // (never silently consume a ref from a corrupt record).
                match String::from_utf8(canonical.to_vec()) {
                    Ok(s) if val.is_empty() => {
                        self.consumed_funding.insert(s);
                    }
                    _ if strict => return Err(ConfigError::DecisionLog),
                    _ => {}
                }
            } else if let Some(cid_bytes) = key.strip_prefix(DISP_NS) {
                match (<[u8; 8]>::try_from(cid_bytes), decode_disp(&val)) {
                    (Ok(cid), Some(state)) => {
                        self.chain_state.insert(cid, state);
                    }
                    _ if strict => return Err(ConfigError::DecisionLog),
                    _ => {}
                }
            }
            // `chopen:` (driver F5-m), `rfnd:`/`rref:` (refund reserves, consulted via `store.get`)
            // are not replayed into a guard map here.
        }
        self.decisions = Some(store);
        Ok(())
    }

    /// Install the durable one-decision store and REPLAY it into the in-memory guard maps (the demo
    /// builder form — lenient). A proof build uses [`Carriage::proof`] (strict, fail-closed).
    #[cfg(any(test, feature = "demo"))]
    pub fn with_decisions(mut self, store: Arc<dyn OneDecisionStore>) -> Self {
        let _ = self.replay_guards(store, false);
        self
    }

    /// Has this canonical rail reference already been consumed (F6-d global once)? Reads the working
    /// set, which [`Carriage::proof`] restored from the durable store at startup.
    fn ref_consumed(&self, canonical_ref: &str) -> bool {
        self.consumed_funding.contains(canonical_ref)
    }

    /// Mark a canonical rail reference consumed (F6-d global once). When a durable store backs the
    /// carriage its atomic `decide` is the authority **across replicas AND restart** (the store
    /// is the CAS gate, not a side log); without one the in-memory set
    /// is the single-process gate. Returns [`ConsumeOutcome::First`] on the first consumption,
    /// [`ConsumeOutcome::Duplicate`] if it was already consumed (caller MUST NOT re-credit), or
    /// [`ConsumeOutcome::Failed`] if the durable store could not record it (caller MUST reject/retry
    /// — nothing consumed). The fast-path cache is updated on First/Duplicate; on **Failed** it is
    /// deliberately left untouched so a retry against a recovered store can still consume-and-credit
    /// exactly once (a burned in-memory ref would strand the deposit — C1-3).
    fn consume_ref(&mut self, canonical_ref: String) -> ConsumeOutcome {
        match &self.decisions {
            Some(store) => match store.decide(&fund_key(&canonical_ref), b"") {
                Decision::Fresh => {
                    self.consumed_funding.insert(canonical_ref);
                    ConsumeOutcome::First
                }
                Decision::AlreadyDecided(_) => {
                    self.consumed_funding.insert(canonical_ref);
                    ConsumeOutcome::Duplicate
                }
                Decision::Failed => ConsumeOutcome::Failed,
            },
            // No durable store: the in-memory set is the single-process gate and cannot fail.
            None => {
                if self.consumed_funding.insert(canonical_ref) {
                    ConsumeOutcome::First
                } else {
                    ConsumeOutcome::Duplicate
                }
            }
        }
    }

    /// Record a channel's TERMINAL close disposition durably (mirrors the `chain_state` insert), so
    /// a restart replays it and the exactly-once close side effects (refund / import) never repeat.
    /// Returns the durable [`Decision`] so the caller can **fail closed on `Failed`** (a durable write
    /// error) rather than proceed as if it recorded (`record_disposition`
    /// must not silently ignore its result). `Fresh` with no store (demo). The refund/import the
    /// disposition gates is itself idempotent (keyed release / one-decision import), so a caller that
    /// rejects on `Failed` and is retried converges without double-acting.
    #[must_use]
    fn record_disposition(&self, cid: &[u8; 8], state: &ChainState) -> Decision {
        match &self.decisions {
            Some(store) => store.decide(&disp_key(cid), &encode_disp(state)),
            None => Decision::Fresh,
        }
    }

    /// Follow `Committed` chain links from `cid` to the **live tip** — the channel that now
    /// carries this position (a chain may pass through several imports). A funding leg bound
    /// to a chain-committed predecessor credits the tip, never the frozen predecessor
    /// (the imported-predecessor credit path). Bounded by the number
    /// of channels; a `Pending`/`Reconciled`/absent link is the tip.
    fn resolve_chain_tip(&self, cid: [u8; 8]) -> [u8; 8] {
        let mut cur = cid;
        // Guard against a pathological cycle (cannot occur — a successor id is fresh — but
        // never loop unboundedly on in-memory state).
        for _ in 0..self.chain_state.len() + 1 {
            match self.chain_state.get(&cur) {
                Some(ChainState::Committed { successor }) => cur = *successor,
                _ => break,
            }
        }
        cur
    }

    /// **Predicate Q2 — does the close disposition bar a NEW settlement round?** (F6-i, scoped.)
    /// A round is barred ONLY while the channel may still hand its position to a successor —
    /// the chaining dispositions `Pending`/`Committed`, whose obligation the *successor* settles
    /// (a round here would strand its predecessor-memo-bound legs). A plain-closed (`Reconciled`)
    /// or still-`OPEN` channel settles on its **own** books, so it MUST still admit the final
    /// round (F6.5 "a round MUST begin at close"). This is the fix: the old guard barred
    /// **any** disposition (`contains_key`), sweeping `Reconciled` in and locking out the final
    /// round (prepay carve never drawn / postpay final round stranded).
    fn bars_new_round(&self, cid: &[u8; 8]) -> bool {
        matches!(
            self.chain_state.get(cid),
            Some(ChainState::Pending | ChainState::Committed { .. })
        )
    }

    /// **Predicate Q1 (admissibility) — may a funding leg credit `cid` NOW?** (F6.4), mode-aware.
    /// The caller routes a `Committed` predecessor to its tip first (`resolve_chain_tip`), so
    /// this judges the *target*:
    /// - **Postpay**: creditable in any live phase (Open/Paused/Settling), regardless of a
    ///   plain-close `Reconciled` disposition — funding pays down the outstanding merchant-net
    ///   and **floors at 0** (F6.4), so a late transfer either reduces a real standing debt or
    ///   credits 0 (harmless, never over-credits). Closes the postpay strand and the
    ///   not-yet-wired implicit-close cell (a Settling channel with no disposition).
    /// - **Prepay**: creditable only while the deposit is still **live** — never after a plain
    ///   close (`Reconciled`: the deposit was reconciled/refunded here), and never a `Committed`
    ///   link (the tip carries it). A late prepay deposit post-reconcile is a payer ordering
    ///   error, recovered off-protocol — never stranded on a dead channel.
    ///
    /// A key-erased `Closed` channel (not reached in this RI — `close()` is unwired) is never
    /// creditable; fail-closed regardless.
    fn funding_admissible(&self, cid: &[u8; 8]) -> bool {
        let Some(status) = self.channels.get(cid).map(|s| s.status()) else {
            return false; // unknown channel
        };
        if status == Status::Closed {
            return false;
        }
        match self.channels.get(cid).map(|s| s.mode()) {
            // Postpay funding floors at merchant-net (harmless in any live phase); never credit a
            // frozen `Committed` link directly — the caller resolves the tip first.
            Some(Mode::Postpay) => !matches!(
                self.chain_state.get(cid),
                Some(ChainState::Committed { .. })
            ),
            // Prepay deposit: only while still returnable (not reconciled, not committed).
            Some(Mode::Prepay) => !matches!(
                self.chain_state.get(cid),
                Some(ChainState::Reconciled { .. } | ChainState::Committed { .. })
            ),
            None => false,
        }
    }

    /// Attach the `DENOM`-rail adapter so funding + settlement legs are verified on-chain
    /// (F6.4/F6.5) — the demo builder form. A proof build passes the rail to [`Carriage::proof`]
    /// (mandatory); this feature-gated builder is the demo/virtual path.
    #[cfg(any(test, feature = "demo"))]
    pub fn with_rail(mut self, rail: Box<dyn RailAdapter>) -> Self {
        self.rail = Some(rail);
        self
    }

    /// Whether reference `r` has reached at least `required` finality on the rail,
    /// compared in the rail's declared total order (F8.1) — never a hard-coded level.
    fn finality_reached(rail: &dyn RailAdapter, r: &RailRef, required: &str) -> bool {
        let levels = rail.caps().finality_levels;
        let idx = |lvl: &str| levels.iter().position(|l| l == lvl);
        match (rail.finality(r).and_then(|f| idx(&f.level)), idx(required)) {
            (Some(reached), Some(need)) => reached >= need,
            _ => false,
        }
    }

    /// Whether a channel's `fin_meed`/`fin_denom` are BOTH the attached rail's STRONGEST
    /// (irreversible) finality level (F8.1) — the only level at which an obligation may be retired
    /// (`settled_r` fold, prepay draw/drain, refund). `true` when no rail is attached (the
    /// signature-only build has no on-chain finality). Checked at BOTH `on_open` AND every settlement
    /// entry point (`on_settlement_propose`, `run_prepay_interim_draw`) so a rail attached AFTER a
    /// channel opened cannot bypass the guard and fold at a reorg-able level (the primary defense
    /// stays `with_rail`-before-open, this is the fold-time backstop).
    fn finality_is_irreversible(&self, fin_meed: &str, fin_denom: &str) -> bool {
        match self.rail.as_deref().map(|r| r.caps().finality_levels) {
            Some(levels) => levels
                .last()
                .is_some_and(|s| fin_meed == s && fin_denom == s),
            None => true,
        }
    }

    /// The merchant identity key (for a payer building `CHANNEL_AUTH`).
    pub fn merchant_key(&self) -> [u8; 32] {
        self.driver.key()
    }

    /// The X25519 `ENC_KEY` a payer seals the session secret to.
    pub fn enc_key(&self) -> [u8; 32] {
        self.driver.enc_key()
    }

    /// Read access to a channel's metering state (for assertions / reconciliation).
    pub fn state(&self, channel_id: &[u8; 8]) -> Option<&ChannelState> {
        self.channels.get(channel_id)
    }

    /// Split a `/channel` or `/ack` body into `(type_octet, object_bytes)`.
    fn split(body: &[u8]) -> Result<(u8, &[u8]), CarriageError> {
        match body.split_first() {
            Some((&octet, rest)) => Ok((octet, rest)),
            None => Err(CarriageError::UnknownType),
        }
    }

    /// Dispatch a `POST /channel` control object (F5-a). One message per request.
    pub fn channel(&mut self, body: &[u8], now: u64) -> Result<Response, CarriageError> {
        let (octet, obj) = Self::split(body)?;
        match octet {
            T_CHANNEL_OPEN => self.on_open(obj, now),
            T_CHECKPOINT_REQUEST => self.on_checkpoint_request(obj),
            T_FUNDING_PROOF => self.on_funding(obj),
            T_SETTLEMENT_PROPOSE => self.on_settlement_propose(obj),
            T_SETTLEMENT_PROOF => self.on_settlement_proof(obj),
            T_CLOSE => self.on_close(obj),
            // The merchant is the creditor/responder in postpay: it does not receive
            // an inbound CHECKPOINT (0x04) or SETTLEMENT_CONFIRMED (0x08) — it emits
            // those. Recognized, but not an inbound message in this profile.
            T_CHECKPOINT | T_SETTLEMENT_CONFIRMED => Err(CarriageError::Unsupported),
            // Retrieval never rides /channel (F5.1) — it is /ack-only.
            T_ACK_REQUEST => Err(CarriageError::Misrouted),
            // 0x02 CHANNEL_ACK is a response object, never an inbound /channel message.
            T_CHANNEL_ACK => Err(CarriageError::Misrouted),
            _ => Err(CarriageError::UnknownType),
        }
    }

    /// Dispatch a `POST /ack` retrieval (F5.3) — only `ACK_REQUEST` (0x0A).
    pub fn ack(&mut self, body: &[u8], now: u64) -> Result<Response, CarriageError> {
        let (octet, obj) = Self::split(body)?;
        if octet != T_ACK_REQUEST {
            // Any control object other than ACK_REQUEST is misrouted here.
            return Err(CarriageError::Misrouted);
        }
        let req = AckRequest::parse(obj).map_err(|_| CarriageError::Malformed)?;
        match self.driver.serve_ack_request(&req, now) {
            Some(ack) => Ok(Response::Message(framed(
                T_CHANNEL_ACK,
                &ack.encode().map_err(|_| CarriageError::Malformed)?,
            ))),
            None => Err(CarriageError::Rejected),
        }
    }

    /// Dispatch a `POST /batch` metering batch (F5-c): a `BATCH_HEAD` naming one
    /// channel, then F1-j-framed slices, verified under that channel's keys and
    /// accepted atomically (whole-body — any failure meters nothing).
    pub fn batch(&mut self, body: &[u8]) -> Result<Response, CarriageError> {
        // F1-j: the body is a sequence of framed objects. Collect their raw bytes.
        let frames: Vec<Vec<u8>> =
            tlv::parse_frames(body, |_o| Ok(())).map_err(|_| CarriageError::Malformed)?;
        let (head, slice_frames) = frames.split_first().ok_or(CarriageError::Malformed)?;

        // BATCH_HEAD: a closed TLV object with a single 0x00 CHANNEL_ID (8 bytes).
        let head_obj = Object::parse(head).map_err(|_| CarriageError::Malformed)?;
        head_obj
            .validate(&Schema::new(Openness::Closed, &[(0x00, false)]))
            .map_err(|_| CarriageError::Malformed)?;
        let cid: [u8; 8] = head_obj
            .get(0x00)
            .ok_or(CarriageError::Malformed)?
            .value
            .clone()
            .try_into()
            .map_err(|_| CarriageError::Malformed)?;

        // F5-c: a BATCH_HEAD is followed by framed slices — an empty batch (head
        // only) is malformed and MUST NOT be a zero-auth "channel exists" probe.
        if slice_frames.is_empty() {
            return Err(CarriageError::Malformed);
        }
        // Parse every slice BEFORE the channel lookup: a structural (channel-
        // independent) failure is `Malformed` whether or not the channel exists, so
        // it cannot become a pre-auth existence oracle (F6-b — no unauthenticated
        // sender learns channel state).
        let slices: Vec<paytp_core::slice::Slice> = slice_frames
            .iter()
            .map(|b| paytp_core::slice::Slice::parse(b))
            .collect::<Result<_, _>>()
            .map_err(|_| CarriageError::Malformed)?;
        // Unknown channel → the uniform pre-auth rejection (F6-b step 1: a channel's
        // terms are nobody's business), indistinguishable from a later MAC failure.
        let state = self.channels.get_mut(&cid).ok_or(CarriageError::Rejected)?;
        // F1-j whole-body atomicity: accept_batch validates against a tentative state
        // and commits together, or rejects the whole unit with nothing metered. A MAC
        // failure collapses to the generic rejection (no state leak, F6-b step 3); a
        // bound hit — reachable only by a MAC-valid slice — draws its specific error.
        state.accept_batch(&slices).map_err(map_accept_err)?;
        Ok(Response::Accepted)
    }

    fn on_open(&mut self, obj: &[u8], now: u64) -> Result<Response, CarriageError> {
        let open = ChannelOpen::parse(obj).map_err(|_| CarriageError::Malformed)?;
        // **Fold-at-irreversible finality (F8.1).** When a rail is attached, a
        // channel's meed AND net finality MUST both be the rail's STRONGEST declared level — the
        // only IRREVERSIBLE one. Every obligation retirement (the `settled_r` fold in
        // `on_settlement_proof`, the prepay draw/drain, the refund) gates on these levels, so a
        // channel naming a REORG-ABLE level (e.g. "confirmed" on an async rail) would let a payer
        // advance→confirm→proof→FOLD, then reorg the confirmed advance away, leaving `settled_r`
        // over-extinguished and the enablers un-paid. We refuse such a
        // channel at open rather than trust an off-protocol finality choice. On the synchronous
        // rail the strongest level is `"final"` (immediate + irreversible), so a conformant channel
        // is unaffected; the signature-only (no-rail) build skips this (no on-chain finality).
        if !self.finality_is_irreversible(&open.auth.fin_meed, &open.auth.fin_denom) {
            return Err(CarriageError::Rejected);
        }
        // F6.6: a chained open imports the predecessor's CURRENT reconciled
        // position, computed at THIS instant (not frozen at close), so a late funding
        // credited to a `Pending` predecessor is imported verbatim, and the metering is the
        // named checkpoint (F3) with its reference recomputed (F5). `predecessor` is `Copy`.
        let predecessor = open.auth.predecessor;
        if let Some((pred_cid, pred_ref)) = predecessor {
            match self.chain_state.get(&pred_cid) {
                // Pending → recompute the imported position from the predecessor's live state
                // and record it for the driver to import. CLEAR any snapshot a prior (possibly
                // failed) open left FIRST: a recompute that fails the reference match returns
                // `None` and records nothing, so without the clear a STALE snapshot would
                // survive and be imported — e.g. a birth/stillborn predecessor whose
                // deterministic synthetic reference moved after a late funding credit, then a
                // successor naming the OLD reference would import the pre-funding position and
                // strand the late deposit. Clearing then recomputing guarantees the driver
                // imports the CURRENT position or nothing (→ `PAYTP_CHAIN_REJECTED`).
                Some(ChainState::Pending) => {
                    self.driver.remove_chain_snapshot(&(pred_cid, pred_ref));
                    if let Some(snap) = self.compute_chain_snapshot(&pred_cid, &pred_ref) {
                        self.driver
                            .record_chain_snapshot((pred_cid, pred_ref), snap);
                    }
                }
                // Reconciled → the channel plain-closed and settled on its own books (F6.6 clause
                // (d)): reject BEFORE the driver reads any (possibly stale) snapshot, so a
                // reconciled position can never be imported.
                Some(ChainState::Reconciled { .. }) => return Err(CarriageError::Rejected),
                // Committed → fall through: a byte-identical retransmit of the SAME successor
                // gets its stored ACK (F5-m, before the chain check); a DIFFERENT successor
                // naming the consumed ref draws `ChainReplay` in the driver. No fresh snapshot.
                Some(ChainState::Committed { .. }) => {}
                // Absent → never chain-intent-closed, so not chainable; the driver finds no
                // snapshot and rejects (a non-chained open has no `predecessor` and skips this).
                None => {}
            }
        }
        match self
            .driver
            .open_channel(&open, now)
            .map_err(|_| CarriageError::Rejected)?
        {
            OpenOutcome::Established(est) => {
                let ack = est.ack.encode().map_err(|_| CarriageError::Malformed)?;
                let est = *est;
                // A chained open (F6.6) seeds the successor's ledger with the
                // predecessor's imported cumulative openings, so F6-f reconciliation reads
                // `opening_* + Σ own` over the whole chain (a fresh open has no ledger until
                // its first credit). The metering state (imported or fresh) installs next.
                // Capture the imported cumulative settled meed (F6-f `opening_settled_r`) BEFORE it
                // merges into the ledger's running `settled_r` — the Option W own-cumulative target
                // subtracts THIS (imported alone), so a chained successor funds only its own carve.
                let imported_settled_r = est
                    .ledger_openings
                    .as_ref()
                    .map(|o| o.settled_r.clone())
                    .unwrap_or_default();
                if let Some(op) = est.ledger_openings {
                    self.ledger.insert(
                        est.channel_id,
                        Ledger {
                            settled_r: op.settled_r,
                            net_legs_sum: op.net_legs,
                            funding_sum: op.funding,
                            version: 0,
                        },
                    );
                }
                self.channel_established_at
                    .insert(est.channel_id, est.established_at);
                // A chained successor imports a bilaterally-evidenced consumed position that lives
                // in no operative checkpoint of its own; record its imported basis (cumulative
                // consumed, the predecessor's final checkpoint ref, and the imported accruals) so
                // `on_close` reconciles the refund against the imported consumption (not `0` — an
                // imported successor is not a fresh birth) AND draws the outstanding imported carve
                // to the instance (never pockets it). A later own checkpoint supersedes
                // it via `operative`. Read before `est.state` moves into `channels`.
                if let Some((_, pred_ref)) = predecessor {
                    self.imported_basis.insert(
                        est.channel_id,
                        ImportedBasis {
                            cum: est.state.cum_total(),
                            ckpt_ref: pred_ref,
                            accruals: est.state.accruals(),
                            opening_settled_r: imported_settled_r,
                        },
                    );
                }
                self.channels.insert(est.channel_id, est.state);
                // F6-f: a successful chained import is the durable decision — the predecessor's
                // float rolled forward. Mark it `Committed` so the deposit is no longer
                // reclaimable and a late predecessor-bound funding leg credits THIS successor
                // (`resolve_chain_tip`). Reaching `Established` with a `predecessor` means the
                // import succeeded (the driver fail-closes a non-importable chain).
                if let Some((pred_cid, _)) = predecessor {
                    let committed = ChainState::Committed {
                        successor: est.channel_id,
                    };
                    // Durable one-decision: the float rolled forward exactly once — a
                    // restart replays it so the predecessor's deposit is never re-reclaimed. On a
                    // durable-store `Failed` here the chain import is simply not durable — its
                    // successor state AND chain-ref consumption are in-memory too (channel resumption
                    // is ASYNC-1), so on restart the predecessor is reclaimable and no successor
                    // exists: consistent, never a double-import. Proceed in-memory this life (the
                    // result is handled explicitly, not silently ignored).
                    //
                    // ⚠ ASYNC-1 DEBT: the day live channel state IS
                    // restored from a durable ledger, this MUST become a **contingent install** —
                    // reject the successor open (and roll back its in-memory install + chain-ref
                    // consumption) on a `Failed` disposition — else a recovered successor plus a
                    // predecessor whose terminal `Committed` never persisted would double-spend the
                    // float. Safe today ONLY because the successor is in-memory-only. Tracked with the
                    // durable-ledger milestone.
                    let _ = self.record_disposition(&pred_cid, &committed);
                    self.chain_state.insert(pred_cid, committed);
                }
                Ok(Response::Message(framed(T_CHANNEL_ACK, &ack)))
            }
            OpenOutcome::Retransmit(ack) => {
                // A retransmit re-sends the stored ACK and does NOT touch the
                // metering state (F5-m — no slice-plane reset).
                let ack = ack.encode().map_err(|_| CarriageError::Malformed)?;
                Ok(Response::Message(framed(T_CHANNEL_ACK, &ack)))
            }
        }
    }

    fn on_checkpoint_request(&mut self, obj: &[u8]) -> Result<Response, CarriageError> {
        // F5.5: the body is the two-label wrapper `{0x00 PROPOSED, 0x70 SIG(ckpt-req)}`,
        // NOT a bare checkpoint. PROPOSED is the initiator's half-signed checkpoint.
        let request = CheckpointRequest::parse(obj).map_err(|_| CarriageError::Malformed)?;
        // Unknown channel + bad payer signature collapse to the uniform rejection.
        let payer_key = self
            .driver
            .payer_key(&request.proposed.channel_id)
            .ok_or(CarriageError::Rejected)?;
        // Verify BOTH the outer PayTPv1-ckpt-req wrapper signature and the inner
        // PayTPv1-ckpt payer signature — both the initiator's (F5.5).
        request
            .verify(&payer_key)
            .map_err(|_| CarriageError::Rejected)?;
        let proposed = request.proposed;
        let state = self
            .channels
            .get_mut(&proposed.channel_id)
            .ok_or(CarriageError::Rejected)?;

        // F6-c: countersign iff the proposed metering recomputes from our own books.
        if state.recomputes(&proposed) {
            let mut cp = proposed.clone();
            self.driver
                .countersign_checkpoint(&mut cp)
                .map_err(|_| CarriageError::Malformed)?;
            // Commit only the named snapshot (F6-c): advance the floor to the
            // proposal's LAST_SEQ, retaining any newer slice accepted since the proposal
            // was cut (never lost from settlement/chaining), and release the evidence pause.
            state.checkpoint_upto(proposed.last_seq);
            let reference = cp.reference().map_err(|_| CarriageError::Malformed)?;
            // Record the operative checkpoint's reference AND its metering snapshot —
            // a settlement round reconciles its owed position against exactly this
            // `CUM_TOTAL`/`ACCRUALS` (F6-f), not the live (possibly newer) state.
            self.operative.insert(
                proposed.channel_id,
                Operative {
                    ckpt_ref: reference,
                    cum_total: cp.cum_total.clone(),
                    accruals: cp.accruals.clone(),
                },
            );
            Ok(Response::Message(framed(
                T_CHECKPOINT,
                &cp.encode().map_err(|_| CarriageError::Malformed)?,
            )))
        } else {
            // A retry of the checkpoint we already countersigned: once `state.checkpoint()`
            // advanced the floor, the identical CHECKPOINT_REQUEST no longer `recomputes()`,
            // yet the payer (e.g. after a lost ACK) must still recover the receipt. Re-derive
            // the countersigned reference for this proposal — the ed25519 countersign is
            // deterministic, so it reproduces the operative checkpoint byte-for-byte iff the
            // proposal IS that checkpoint — and answer idempotently instead of stalling the
            // receipt exchange (liveness; no value is at stake — CUM_TOTAL/ACCRUALS live
            // on the operative + the F6-f ledger regardless of the receipt).
            if let Some(op_ref) = self.operative.get(&proposed.channel_id).map(|o| o.ckpt_ref) {
                let mut cp = proposed.clone();
                if self.driver.countersign_checkpoint(&mut cp).is_ok()
                    && cp.reference().map(|r| r == op_ref).unwrap_or(false)
                {
                    return Ok(Response::Message(framed(
                        T_CHECKPOINT,
                        &cp.encode().map_err(|_| CarriageError::Malformed)?,
                    )));
                }
            }
            // Otherwise a genuine PAYTP_STATE_MISMATCH (F6.3): the operative reference is
            // recorded and the bytes are recoverable via the standard re-anchor exchange.
            Err(CarriageError::StateMismatch(None))
        }
    }

    /// Recompute a **deterministic** (unity-rate) round's owed legs from the operative
    /// checkpoint's metering minus the ledger's settled side (F6-f): returns
    /// `(meed P if E ≥ 1, per-role E_r, expected net OUTPUTS)`. This is the
    /// creditor's countersign-time economic check — a proposal must match it, so a
    /// debtor cannot understate the round (propose `net = 1` when owed 100, or strip
    /// the meed leg).
    fn recompute_round(&self, cid: &[u8; 8]) -> Result<RecomputedRound, CarriageError> {
        let op = self.operative.get(cid).ok_or(CarriageError::Rejected)?;
        let terms = self
            .driver
            .settlement_terms(cid)
            .ok_or(CarriageError::Rejected)?;
        let led = self.ledger.get(cid);
        let zero = BigUint::from(0u8);
        // Defense-in-depth: a legitimately-countersigned checkpoint has strictly
        // ascending (hence unique) roles; a duplicate would break the per-role
        // subtraction below (subtracting one settled value from two accrual entries).
        for w in op.accruals.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(CarriageError::Rejected);
            }
        }
        let mut accrued: Vec<U256> = Vec::with_capacity(op.accruals.len());
        let mut settled: Vec<U256> = Vec::with_capacity(op.accruals.len());
        for (role, n) in &op.accruals {
            accrued.push(fee::u256_from_biguint(n).map_err(|_| CarriageError::Rejected)?);
            let s = led
                .and_then(|l| l.settled_r.iter().find(|(r, _)| r == role))
                .map(|(_, v)| v)
                .unwrap_or(&zero);
            settled.push(fee::u256_from_biguint(s).map_err(|_| CarriageError::Rejected)?);
        }
        let outstanding = reconcile::outstanding_meed_per_role(&accrued, &settled)
            .map_err(|_| CarriageError::Rejected)?;
        let div = fee::divide_round(
            &outstanding,
            &Rate::new(1, 1).map_err(|_| CarriageError::Rejected)?,
        )
        .map_err(|_| CarriageError::Rejected)?;
        let cum = fee::u256_from_biguint(&op.cum_total).map_err(|_| CarriageError::Rejected)?;
        let net_legs = U256::from(led.map(|l| l.net_legs_sum).unwrap_or(0));
        let funding = U256::from(led.map(|l| l.funding_sum).unwrap_or(0));
        let owed_net = reconcile::outstanding_merchant_net(&cum, &accrued, &net_legs, &funding);

        let meed_amount = if div.leg {
            Some(
                u128::try_from(fee::biguint_from_u256(div.p))
                    .map_err(|_| CarriageError::Rejected)?,
            )
        } else {
            None
        };
        let e_r: Vec<(u8, BigUint)> = op
            .accruals
            .iter()
            .map(|(r, _)| *r)
            .zip(div.e_r.iter().map(|u| fee::biguint_from_u256(*u)))
            .collect();
        let owed_net_big = fee::biguint_from_u256(owed_net);
        let outputs = if owed_net_big > zero {
            vec![Output {
                amount: owed_net_big,
                asset: terms.denom.clone(),
                dest: terms.settle_ptr.clone(),
            }]
        } else {
            Vec::new()
        };
        Ok((meed_amount, e_r, outputs))
    }

    fn on_settlement_propose(&mut self, obj: &[u8]) -> Result<Response, CarriageError> {
        let p = SettlementPropose::parse(obj).map_err(|_| CarriageError::Malformed)?;
        let cid = p.channel_id;
        // Q2 (F6-i, scoped): a NEW settlement round is barred ONLY while the channel may still
        // hand its position to a successor (`Pending`/`Committed` — the successor settles the
        // imported obligation; a round here would strand its predecessor-memo-bound legs and
        // double-pay). A **plain-closed (`Reconciled`)** channel settles on its OWN books and MUST
        // still admit its final round (F6.5 "a round MUST begin at close") — barring it is the
        // lockout (prepay carve never drawn / postpay final round + late funding stranded).
        // A payer wanting to settle instead of chain reclaims via a plain `CLOSE` (→ `Reconciled`,
        // revoking the intent), which then admits the round.
        if self.bars_new_round(&cid) {
            return Err(CarriageError::Rejected);
        }
        // Unknown channel + bad debtor (payer) signature collapse to one rejection.
        let payer_key = self.driver.payer_key(&cid).ok_or(CarriageError::Rejected)?;
        p.verify_payer(&payer_key)
            .map_err(|_| CarriageError::Rejected)?;

        // F5.6/F5-h: a **deterministic** (DENOM = BASELINE_ASSET, net-on-baseline) round is
        // SINGLE-signed — only the debtor's role slot is present, "the other stays absent". The
        // RI is baseline-only (F5-p), so every round it settles is deterministic; reject a
        // proposal carrying the illegal extra `SIG_MERCHANT` slot (default-deny strictness — the
        // codec leaves both slots optional, F5.6, so the driver enforces the mode's cardinality).
        // Left unrejected, `proposal_hash()` (F5-h) would bind the NON-CANONICAL both-signed
        // bytes a strict single-signed verifier never computes. Checked post-auth (no channel
        // existence leak), like the prepay-mode rejection below.
        if p.sig_merchant.is_some() {
            return Err(CarriageError::Rejected);
        }

        // A PREPAY channel is never settled via a payer-proposed round: the merchant is the prepay
        // meed debtor and executes the meed by DRAWING from the deposit (`on_close` / interim
        // rounds), so a payer-signed `SETTLEMENT_PROPOSE` is not a prepay message. Reject it — this
        // also forecloses a payer proposing a redundant meed round on a `Reconciled` prepay
        // channel that would race the merchant's pinned close draw against the same claim record.
        // Postpay (payer = debtor) proceeds. Checked post-auth (no existence leak).
        if self.channels.get(&cid).map(|s| s.mode()) == Some(Mode::Prepay) {
            return Err(CarriageError::Rejected);
        }

        // Fold-at-irreversible backstop: a postpay round folds `settled_r` at
        // `fin_meed` — refuse it if that is not the rail's irreversible level, so a rail attached
        // AFTER a no-rail open (which bypassed the `on_open` guard) cannot fold at a reorg-able level.
        let fin_ok = self
            .driver
            .settlement_terms(&cid)
            .map(|t| self.finality_is_irreversible(&t.fin_meed, &t.fin_denom))
            .unwrap_or(true);
        if !fin_ok {
            return Err(CarriageError::Rejected);
        }

        // F6-l serialization — **the settlement concurrency model**: at most ONE in-flight round
        // per channel. Reject a NEW round (a different `CKPT_REF`) while an earlier round on this
        // channel is still unconfirmed; only that round's RETRY (same `CKPT_REF`, admitted below)
        // continues. This forecloses the overlapping-round races found in the
        // prior "credit the stale leg" model: a stale round's finalized net leg stranded then
        // re-billed; a slow-rail round confirming AFTER its checkpoint was re-settled and
        // over-collecting a *conformant* payer; two rounds each folding one accrual's `E_r` toward
        // the `settled > accrued` brick. With only one round live, it always confirms against an
        // UNMOVED settled position (nothing else confirms under it), so no round is ever staled and
        // none of those states can form. The `ledger_version` staleness bar in `on_settlement_proof`
        // remains the **backstop** should serialization ever be bypassed (a second proof is
        // version-rejected before folding); it does NOT *replace* serialization, and the quiescence
        // guard (`on_close`) deliberately does NOT depend on it. A future
        // concurrency-tolerant build would instead implement F6-f crediting in full.
        if self
            .rounds
            .iter()
            .any(|((c, ck), d)| *c == cid && *ck != p.ckpt_ref && !d.confirmed)
        {
            return Err(CarriageError::Rejected);
        }

        // F6.3/F6.5: the round settles against the channel's operative checkpoint —
        // OR against an already-started round's original CKPT_REF (a retry completes
        // against its own anchor even after a newer checkpoint supersedes, §6.5, so a
        // superseding checkpoint never strands an in-flight round). A **postpay chained
        // successor with no own operative checkpoint** (a nonzero imported stillborn) is
        // rejected here: settling directly against the IMPORTED checkpoint ref is the
        // deferred onward-settlement path. Its recourse is checkpoint-then-settle —
        // the payer countersigns a checkpoint over the imported position (giving an own
        // operative), then proposes against it — so the imported postpay debt is NEVER lost
        // (a §6.4 standing obligation, evidenced, until settled), only settled a round-trip
        // later. (Prepay never reaches here — it is barred above; its imported carve is drawn
        // merchant-side at close against the imported basis, `compute_pending_draw`.)
        let key = (cid, p.ckpt_ref);
        let in_flight = self.rounds.contains_key(&key);
        match self.operative.get(&cid) {
            Some(op) if op.ckpt_ref == p.ckpt_ref => {}
            _ if in_flight => {}
            _ => return Err(CarriageError::Rejected),
        }

        // Validate against the establishment terms (scope the borrow so it drops
        // before the &mut self.rounds access below).
        {
            let terms = self
                .driver
                .settlement_terms(&cid)
                .ok_or(CarriageError::Rejected)?;
            // F5.6 CONVERSION presence: present iff DENOM ≠ BASELINE_ASSET.
            if p.conversion.is_some() != terms.conversion_required {
                return Err(CarriageError::Malformed);
            }
            for o in &p.outputs {
                // F5.6: every OUTPUTS destination MUST be bound at establishment.
                if !terms.bound_dests.iter().any(|d| d == &o.dest) {
                    return Err(CarriageError::Rejected);
                }
                // F5.6: an output moves value in the channel's DENOM — never an
                // attacker-substituted asset to a correct destination. (In this RI the
                // net leg always settles in DENOM; with DENOM = BASELINE_ASSET that is
                // the baseline rail, so DENOM-asset + no CONVERSION ⟹ net-on-baseline,
                // which is exactly F5-h's deterministic condition below.)
                if o.asset != terms.denom {
                    return Err(CarriageError::Rejected);
                }
            }
        }

        // F6.5 one-decision per (CHANNEL_ID, CKPT_REF): refuse a second proposal whose
        // *terms* differ (the two-replica fork); a retry with identical terms (only
        // CREDITED grown) is countersigned. NOTE: validating the rate sits within the
        // establishment RATE_SOURCE/RATE_DEV needs the rate oracle — a documented
        // deferred boundary (§C), like the funding rail check.
        let fp = terms_fingerprint(&p);
        if let Some(d) = self.rounds.get(&key) {
            if d.terms_fp != fp {
                return Err(CarriageError::Rejected);
            }
        }

        // For a NEW round, verify its economics against the operative checkpoint (a
        // retry — same `(CHANNEL_ID, CKPT_REF)`, already terms_fp-checked equal above —
        // reuses the stored verified values, so its own anchor is honoured even after
        // supersession). A **deterministic** round (no `CONVERSION`, unity rate) is
        // fully recomputed: `P`/`EXTINGUISHED`/net-`OUTPUTS` MUST equal what the
        // checkpoint owes (F6-f) — this is what stops an understated round. An
        // off-baseline (`CONVERSION`) round is fail-closed until its rate-scaled economics
        // are pinned (see below).
        let is_new = !self.rounds.contains_key(&key);
        if is_new {
            // The economics are recomputed against the operative checkpoint minus the ledger's
            // current version; the round confirms only if the ledger is still at this version.
            // Serialization (F6-l) is the primary control (at most one in-flight round); this
            // captured `ledger_version` is the **backstop** — should a round ever race a
            // confirm, its proof is rejected stale before folding (`on_settlement_proof`).
            let ledger_version = self.ledger.get(&cid).map(|l| l.version).unwrap_or(0);
            let deterministic = p.conversion.is_none();
            // Off-baseline (DENOM ≠ BASELINE_ASSET) settlement is FAIL-CLOSED (F5-p).
            // Countersigning a converted round needs the rate oracle AND the full rate-scaled
            // meed arithmetic — P↔E↔rate consistency AND canonical per-role attribution
            // (E_r = ⌊E·N_r/N⌋) — none of which is pinned or implemented. Partial validation
            // leaves holes: role-starving under-attribution, P/E/rate
            // inconsistency, and an instance_leg=None zero-progress round that still locks the
            // (CHANNEL_ID, CKPT_REF) one-decision record. So the merchant refuses converted
            // settlement outright rather than emit a durable countersignature over unvalidated
            // numbers. The channel still meters, checkpoints, closes and reclaims; only the
            // on-DENOM settlement round is unavailable, and metered value stays recoverable via
            // close. (Re-enabling off-baseline is a spec task: the oracle + rate arithmetic.)
            if !deterministic {
                return Err(CarriageError::Rejected);
            }
            // A DETERMINISTIC round (unity rate) is fully recomputed: P / EXTINGUISHED / net
            // OUTPUTS MUST equal what the checkpoint owes (F6-f) — this stops an understated round.
            let (meed_amount, e_r, outputs) = self.recompute_round(&cid)?;
            if p.outputs != outputs {
                return Err(CarriageError::Rejected); // net output ≠ owed merchant-net
            }
            // Option W (F6-o): the postpay meed leg's `INSTANCE_LEG.amount` is the channel's
            // OWN-CUMULATIVE watermark target `target_P` (not the per-round carve `P`) — the payer
            // advances `funded_p` to it and the merchant binds the advance fact at proof. The
            // on-chain ΔP = target_P − funded_p is the SAME F6.2 settled-carve delta, so the fragile
            // `E_r` / `settled_r` fold (on_settlement_proof) is UNCHANGED. `target_P` is `Some`
            // exactly when meed is owed (`meed_amount` `Some` ⟹ Σaccrued − imported ≥ 1e4).
            let target_p = match &meed_amount {
                Some(_) => {
                    let accruals = self
                        .operative
                        .get(&cid)
                        .map(|op| op.accruals.clone())
                        .ok_or(CarriageError::Rejected)?;
                    Some(
                        self.cumulative_target_p(&cid, &accruals)
                            .ok_or(CarriageError::Rejected)?,
                    )
                }
                None => None,
            };
            match (&p.instance_leg, target_p) {
                (Some(l), Some(tp)) => {
                    if u128::try_from(l.amount.clone()).ok() != Some(tp) || l.extinguished != e_r {
                        return Err(CarriageError::Rejected); // target_P / E_r ≠ recomputed
                    }
                }
                (None, None) => {} // E = 0: correctly no meed leg
                _ => return Err(CarriageError::Rejected), // leg presence ≠ E ≥ 1
            }
            // A deterministic round is single-signed — the debtor executes it directly (F5-h).
            // (Off-baseline rounds, which alone would be countersigned, are fail-closed above.)
            let response = Response::Accepted;
            let ph = p.proposal_hash().map_err(|_| CarriageError::Malformed)?;
            let mut proposal_hashes = std::collections::HashSet::new();
            proposal_hashes.insert(ph);
            self.rounds.insert(
                key,
                RoundDecision {
                    terms_fp: fp,
                    proposal_hashes,
                    proofs: Vec::new(),
                    outputs,
                    meed_amount,
                    e_r,
                    deterministic,
                    ledger_version,
                    confirmed: false,
                    meed_folded: false,
                    net_folded: false,
                    meed_final_time: None,
                    draw_ref: None,
                    target_p, // Option W: the payer's 0x01 leg advances `funded_p` to this own-cumulative target
                },
            );
            Ok(response)
        } else {
            // Identical-terms retry of a (deterministic) stored round: single-signed Accept,
            // record its hash. (Off-baseline rounds are never stored — fail-closed above.)
            let response = Response::Accepted;
            let ph = p.proposal_hash().map_err(|_| CarriageError::Malformed)?;
            let d = self.rounds.get_mut(&key).expect("round present");
            // Bound retry-signature accumulation: a debtor spamming varied countersigned
            // shapes cannot grow this set without limit (Defect D). Beyond the cap the
            // hash is already-known or the round is over-churned — reject.
            if !d.proposal_hashes.contains(&ph) && d.proposal_hashes.len() >= MAX_PROPOSAL_HASHES {
                return Err(CarriageError::Rejected);
            }
            d.proposal_hashes.insert(ph);
            Ok(response)
        }
    }

    fn on_settlement_proof(&mut self, obj: &[u8]) -> Result<Response, CarriageError> {
        let proof = SettlementProof::parse(obj).map_err(|_| CarriageError::Malformed)?;
        let cid = proof.channel_id;
        // No disposition bar here — correct for BOTH terminal cases (F6.5): (a) a chaining channel
        // (`Pending`/`Committed`) is barred at PROPOSE (`bars_new_round`), so no round exists to
        // prove; (b) a plain-closed (`Reconciled`) channel's FINAL settlement round MUST still
        // confirm here — folding its net leg + drawing its meed (the postpay path). A proof
        // that names no live round idempotently re-emits an already-CONFIRMED receipt (lost-ACK
        // recovery, below) or is rejected. Barring here would deny the final round and that recovery.
        let payer_key = self.driver.payer_key(&cid).ok_or(CarriageError::Rejected)?;
        proof
            .verify_payer(&payer_key)
            .map_err(|_| CarriageError::Rejected)?;
        // The proof must name a round this merchant countersigned (F6.5). Retain it
        // as evidence for the deferred rail-adapter verification (never dropped).
        let round_key = self
            .rounds
            .iter()
            .find(|((c, _), d)| *c == cid && d.proposal_hashes.contains(&proof.proposal_hash))
            .map(|(k, _)| *k);
        let round_key = match round_key {
            Some(k) => k,
            None => return Err(CarriageError::Rejected),
        };
        let ckpt_ref = round_key.1;
        let proposal_hash = proof.proposal_hash;
        // Snapshot the verified round terms (owned, so the &self reads below don't hold
        // a borrow across the &mut ledger/round updates).
        let (deterministic, already_confirmed, outputs, meed_amount, target_p, e_r, ledger_version) = {
            let d = self.rounds.get(&round_key).expect("round present");
            (
                d.deterministic,
                d.confirmed,
                d.outputs.clone(),
                d.meed_amount,
                d.target_p,
                d.e_r.clone(),
                d.ledger_version,
            )
        };

        // Defect B — idempotent re-proof: an already-confirmed **deterministic** round
        // re-emits the SAME CONFIRMED receipt (the debtor may have lost the first),
        // never re-folding the ledger. sign_confirmed is deterministic over
        // (CHANNEL_ID, PROPOSAL_HASH), so the bytes are identical. An off-baseline
        // round never confirms here, so Accepted is its safe idempotent reply.
        if already_confirmed {
            if deterministic {
                let mut c = SettlementConfirmed {
                    channel_id: cid,
                    proposal_hash,
                    sig_payer: None,
                    sig_merchant: None,
                };
                self.driver.sign_confirmed(&mut c);
                return Ok(Response::Message(framed(
                    T_SETTLEMENT_CONFIRMED,
                    &c.encode().map_err(|_| CarriageError::Malformed)?,
                )));
            }
            return Ok(Response::Accepted);
        }

        // CONFIRMED is signed only for a **deterministic**, rail-verified round
        // (off-baseline stays oracle-deferred; no rail → interim). Those non-confirming
        // paths retain the proof as evidence for the deferred verification (F6-f), but
        // the Vec is CAPPED (Defect 1): the deterministic-confirm path folds directly
        // and needs no retention, so a proof flood — which only ever lands on the
        // evidence path — cannot exhaust memory. Beyond the cap, later evidence is
        // dropped (the proof is a claim, not yet a credit; the debtor re-presents when
        // the oracle/rail path is live).
        let rail = match (&self.rail, deterministic) {
            (Some(r), true) => r.as_ref(),
            _ => {
                let d = self.rounds.get_mut(&round_key).expect("round present");
                if d.proofs.len() < MAX_PROOFS {
                    d.proofs.push(proof.clone());
                }
                return Ok(Response::Accepted);
            }
        };

        // BACKSTOP — this round's economics were recomputed against the ledger at
        // `ledger_version`. Serialization (F6-l) already bars a second in-flight round, so under
        // correct serialization this never fires; but should a round ever race a confirm (a
        // serialization bypass / future cross-replica store), the moved ledger version rejects the
        // stale proof **before** folding its `E_r`, so two rounds can never double-count toward the
        // `settled > accrued` brick. Reject; the creditor re-proposes against the current position.
        if self.ledger.get(&cid).map(|l| l.version).unwrap_or(0) != ledger_version {
            return Err(CarriageError::Rejected);
        }
        let terms = self
            .driver
            .settlement_terms(&cid)
            .ok_or(CarriageError::Rejected)?;
        let instance_addr = rail.derive_address(&terms.seed_instance);

        // Correlate every leg's rail record against the round's verified legs, at the
        // required finality, meed-then-net ordered, each TX_REF consumed once.
        let mut meed_time: Option<u64> = None;
        let mut net_times: Vec<u64> = Vec::new();
        let mut matched = vec![false; outputs.len()];
        let mut seen_refs: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Net-leg canonical refs are consumed globally (F6-d/§5.4, C69/C80). The meed
        // leg's ref is NOT consumed here — its claim-record is idempotent by its own
        // (CHANNEL_ID, CKPT_REF, P) key (F4.2) and the `meed_folded` once-guard is the
        // authority (F6-m); consuming it would wrongly reject a later net-completing proof
        // that re-presents the already-folded meed ref.
        let mut net_canonical_refs: Vec<String> = Vec::new();
        for t in &proof.tx_refs {
            let rref = RailRef(t.reference.clone());
            let info = rail.ref_target(&rref).ok_or(CarriageError::Rejected)?;
            // Dedup and consume on the adapter's CANONICAL reference (F6-d step 3),
            // never the caller's spelling — else aliases `T`/`T#0` of one transfer satisfy
            // two legs / credit twice.
            if !seen_refs.insert(info.canonical.clone()) {
                return Err(CarriageError::Rejected); // a transfer may satisfy at most one leg
            }
            match t.leg {
                0x01 => {
                    // Meed leg (Option W, F6-o): exactly one advance to the instance address in
                    // BASELINE_ASSET, at FIN_MEED, moving the channel's per-channel watermark to at
                    // least the round's OWN-CUMULATIVE `target_P`. **The load-bearing check is the
                    // DISTRIBUTION fact `advanced_channel_meed`, not the memo/amount.** The adapter
                    // sets that fact ONLY on the advance kind that ran the F7.3 division to the meed
                    // destinations (the per-channel form of the F6-m closure) — a plain `submit` to the
                    // instance address, even one copying the watermark identifiers, leaves it `None`, so
                    // a non-distributing transfer can never satisfy the leg (the §10.2/F7.3 break
                    // stays closed). The fact binds THIS channel + THIS instance reaching `target_P`, so
                    // it is checkpoint-agnostic BY DESIGN: any advance on this channel that reached
                    // `funded_p ≥ target_P` proves the enablers were paid up to that cumulative position
                    // (the closure — interim and close move the SAME monotone watermark). The
                    // advance's `info.amount` is the DELTA ΔP (not the cumulative `P`), so it is NOT
                    // checked; and the memo is `None` (the fact, not a caller-settable memo, is the bind).
                    let target_p = target_p.ok_or(CarriageError::Rejected)?; // a 0x01 leg with nothing owed → reject
                    let advanced = info.advanced_channel_meed.as_ref().is_some_and(|f| {
                        f.channel_id == cid
                            && f.seed_instance == terms.seed_instance
                            && f.funded_p >= target_p
                    });
                    if meed_time.is_some()
                        || info.to != instance_addr
                        || info.asset != terms.baseline_asset
                        || !advanced
                        || !Self::finality_reached(rail, &rref, &terms.fin_meed)
                    {
                        return Err(CarriageError::Rejected);
                    }
                    meed_time = rail.finality(&rref).map(|f| f.time);
                }
                0x02 => {
                    // Net leg: pays an owed OUTPUT to the settlement pointer in DENOM.
                    // F6-h — the transfer MUST NAME ITS ROUND on the rail: its memo binds
                    // (CHANNEL_ID, CKPT_REF), recomputed and checked here exactly as the
                    // meed leg's memo is checked against its claim-record key (above).
                    // Without it a debtor could name a VICTIM's transfer to the shared
                    // settlement pointer as its own net leg (the net-leg hijack).
                    // This enforces F6-h option (a) — the memo — UNCONDITIONALLY, exactly
                    // as on_funding enforces its AUTH_HASH (F5-n): the RI's only rail is
                    // memo-capable. Option (b), a per-channel-unique settle_ptr for a
                    // memoless rail, is a future adapter's job, not implemented here.
                    let net_memo = settlement_net_memo(&cid, &ckpt_ref);
                    let idx = outputs.iter().enumerate().position(|(i, o)| {
                        !matched[i]
                            && o.dest == info.to
                            && o.asset == info.asset
                            && u128::try_from(o.amount.clone()).ok() == Some(info.amount)
                    });
                    let idx = idx.ok_or(CarriageError::Rejected)?;
                    if info.memo != Some(net_memo)
                        || !Self::finality_reached(rail, &rref, &terms.fin_denom)
                    {
                        return Err(CarriageError::Rejected);
                    }
                    matched[idx] = true;
                    net_canonical_refs.push(info.canonical.clone());
                    if let Some(ft) = rail.finality(&rref).map(|f| f.time) {
                        net_times.push(ft);
                    }
                }
                _ => return Err(CarriageError::Rejected),
            }
        }
        // F6-m — the meed leg and the net leg are credited INDEPENDENTLY (F6-f: "the
        // meed is credited independently of the net leg"). A deterministic round funds
        // meed first (F5-h); if the net leg lags or drops, the finalized meed MUST
        // still be credited now, else a later checkpoint re-charges it (the double-
        // charge). Read the round's partial-fold state — either leg may already be folded
        // by an earlier proof.
        let (already_meed_folded, already_net_folded, prior_meed_time) = {
            let d = self.rounds.get(&round_key).expect("round present");
            (d.meed_folded, d.net_folded, d.meed_final_time)
        };
        let meed_needed = meed_amount.is_some();
        // Fold the meed this proof iff it is owed, not yet folded, and its leg finalized here.
        let fold_meed_now = meed_needed && !already_meed_folded && meed_time.is_some();
        let meed_done = !meed_needed || already_meed_folded || fold_meed_now;
        // The net is complete when every owed OUTPUT is matched on-rail in THIS proof (an
        // E-only round with no net output is net-complete trivially); fold it once.
        let net_complete = matched.iter().all(|m| *m);
        let fold_net_now = !already_net_folded && net_complete && !net_canonical_refs.is_empty();
        let net_done = already_net_folded || net_complete;
        // CONFIRMED is emitted only when BOTH legs are done — and an `E = 0`/`net = 0` round is
        // done with ZERO legs. Compute it here so the progress guard admits a zero-owed round
        // that CONFIRMS with nothing to fold; else it would wedge (stored unconfirmed, F6-l then
        // bars every future round and F6-i bars chain-close).
        let will_confirm = meed_done && net_done;

        // The proof must make progress: fold the meed, complete the net, OR confirm a
        // zero-owed round. A proof that folds nothing AND does not confirm advances nothing.
        if !fold_meed_now && !fold_net_now && !will_confirm {
            return Err(CarriageError::Rejected);
        }
        // F6.4 ordering — a net leg finalizes no earlier than the meed. Compare each net
        // leg's finality against the meed's finalized time: this proof's (`meed_time`),
        // or the time stored when an earlier proof folded it (`prior_meed_time`).
        if fold_net_now {
            match meed_time.or(prior_meed_time) {
                Some(rt) => {
                    if net_times.iter().any(|&nt| nt < rt) {
                        return Err(CarriageError::Rejected); // net finalized before meed (F6.4)
                    }
                }
                // Meed owed but not yet finalized (not folded, not in this proof): the
                // debtor executes meed FIRST (F5-h), so a net leg cannot precede it.
                None if meed_needed => return Err(CarriageError::Rejected),
                None => {} // E = 0 round: no meed leg to order against.
            }
        }

        // Defect C — atomicity: compute EVERY fallible op BEFORE the commit point. The
        // net-legs total, its running sum, and the consume-once check apply only when the
        // net is folded this proof; the meed leg's ref is NOT consumed (its claim-record
        // is idempotent by key F4.2 + `meed_folded`), so a later net-completing proof may
        // re-present it.
        let (net_total, new_net_legs) = if fold_net_now {
            let net_total: u128 = outputs
                .iter()
                .map(|o| u128::try_from(o.amount.clone()).unwrap_or(0))
                .try_fold(0u128, |a, x| a.checked_add(x))
                .ok_or(CarriageError::Rejected)?;
            let cur_net = self.ledger.get(&cid).map(|l| l.net_legs_sum).unwrap_or(0);
            let new_net_legs = cur_net
                .checked_add(net_total)
                .ok_or(CarriageError::Rejected)?;
            for r in &net_canonical_refs {
                if self.ref_consumed(r) {
                    return Err(CarriageError::Rejected); // a net leg's transfer already credited
                }
            }
            (net_total, new_net_legs)
        } else {
            (
                0u128,
                self.ledger.get(&cid).map(|l| l.net_legs_sum).unwrap_or(0),
            )
        };
        // Build+sign+encode the CONFIRMED receipt NOW (encode is fallible) — but only when
        // BOTH legs are done (`will_confirm`, computed above). A meed-only proof folds the
        // meed and returns `Accepted` (the net is still owed; the debtor cannot evade it).
        let confirmed_msg = if will_confirm {
            let mut c = SettlementConfirmed {
                channel_id: cid,
                proposal_hash,
                sig_payer: None,
                sig_merchant: None,
            };
            self.driver.sign_confirmed(&mut c);
            Some(framed(
                T_SETTLEMENT_CONFIRMED,
                &c.encode().map_err(|_| CarriageError::Malformed)?,
            ))
        } else {
            None
        };

        // --- Commit point. `consume_ref` is the durable exactly-once gate; honor its outcome exactly
        // as `on_funding` does — discarding it double-credited the net leg under multi-replica (C1-2).
        // The current propose path emits exactly ONE net output per round, so this loop runs once and
        // is trivially all-or-nothing; the fold below is the only ledger mutation and follows this:
        //  - `First`     → this net leg's transfer is ours to fold exactly once; proceed.
        //  - `Duplicate` → the ref was already consumed (another replica / a restart-race) and the
        //    net credited there — acknowledge idempotently, never re-fold. (Returning `Accepted`
        //    rather than a re-derived SETTLEMENT_CONFIRMED is a deferred multi-replica liveness
        //    nicety, not a value issue — ASYNC-1.)
        //  - `Failed`    → the durable store could not record the consume; reject so the debtor
        //    re-presents — nothing folded, and the on-rail leg is recoverable.
        // FUTURE multi-output rounds MUST NOT keep this per-ref early-return loop: consuming one ref
        // then returning on a later Duplicate/Failed would durably burn the first ref with the round
        // unfolded (a strand). Multi-output settlement needs an
        // atomic multi-key consume, part of the durable-ledger / multi-replica milestone (ASYNC-1).
        // Single-process today, the pre-commit `ref_consumed` check already forces this to `First`.
        if fold_net_now {
            for r in &net_canonical_refs {
                match self.consume_ref(r.clone()) {
                    ConsumeOutcome::First => {}
                    ConsumeOutcome::Duplicate => return Ok(Response::Accepted),
                    ConsumeOutcome::Failed => return Err(CarriageError::Rejected),
                }
            }
        }
        let led = self.ledger.entry(cid).or_default();
        let mut gross_denom_settled: u128 = 0;
        if fold_meed_now {
            // Fold this round's meed `E_r` into `settled_r` (F6-f). The window `B` moves
            // by the non-distributive settled-carve delta floor(ΣE_after/10000) −
            // floor(ΣE_before/10000) (F6.2), NOT a per-round floor. `settled_r` monotonically
            // approaches accrued; the top-of-handler version gate staled this round unless it
            // is the in-flight round (F6-l), so a meed fold cannot push settled_r past
            // accrued (the backstop).
            let sum_e_before: BigUint = led.settled_r.iter().map(|(_, e)| e.clone()).sum();
            for (role, e) in &e_r {
                match led.settled_r.iter_mut().find(|(r, _)| r == role) {
                    Some((_, acc)) => *acc += e,
                    None => led.settled_r.push((*role, e.clone())),
                }
            }
            led.settled_r.sort_by_key(|(r, _)| *r);
            let sum_e_after: BigUint = led.settled_r.iter().map(|(_, e)| e.clone()).sum();
            let carve_delta = (&sum_e_after / 10_000u32) - (&sum_e_before / 10_000u32);
            gross_denom_settled = gross_denom_settled
                .saturating_add(u128::try_from(carve_delta).unwrap_or(u128::MAX));
        }
        if fold_net_now {
            led.net_legs_sum = new_net_legs;
            gross_denom_settled = gross_denom_settled.saturating_add(net_total);
        }
        // A ledger MOVE bumps the version (the backstop stales OTHER in-flight rounds'
        // captured versions); a zero-progress confirm moves nothing, so it does not bump.
        // Persist the (possibly unchanged) version into THIS round's captured version too, so
        // the round's other leg (a later proof) still passes the top-of-handler version gate.
        if fold_meed_now || fold_net_now {
            led.version = led.version.wrapping_add(1);
        }
        let new_version = led.version;
        // Decrease the live flow-control `B` by the gross DENOM settled this proof and re-open
        // a window-paused channel (F6.2/§6.1).
        if gross_denom_settled > 0 {
            if let Some(st) = self.channels.get_mut(&cid) {
                st.apply_settlement_round(gross_denom_settled);
            }
        }
        {
            let d = self.rounds.get_mut(&round_key).expect("round present");
            if fold_meed_now {
                d.meed_folded = true;
                d.meed_final_time = meed_time;
            }
            if fold_net_now {
                d.net_folded = true;
            }
            d.ledger_version = new_version;
            if will_confirm {
                d.confirmed = true;
            }
        }
        match confirmed_msg {
            Some(m) => Ok(Response::Message(m)),
            None => Ok(Response::Accepted),
        }
    }

    fn on_funding(&mut self, obj: &[u8]) -> Result<Response, CarriageError> {
        let fp = FundingProof::parse(obj).map_err(|_| CarriageError::Malformed)?;
        // Q1 routing — where the position actually lives now (admissibility judged below,
        // mode-aware, after the proof is verified against the NAMED predecessor):
        //  - `Committed` → the float rolled forward; **credit the live tip** (the
        //    imported-predecessor credit path), while STILL verifying the proof against the
        //    predecessor it names (its payer key + `AUTH_HASH` + on-rail memo, below).
        //  - `Reconciled` / `Pending` / absent → credit the named channel itself, and
        //    `funding_admissible` then decides: a plain-closed **postpay** channel still credits
        //    (pays down the standing merchant-net, floored — the **postpay strand fix**); a
        //    plain-closed **prepay** channel does not (its deposit is reconciled); a `Pending`
        //    predecessor's late funding lands in its own ledger, imported verbatim when a
        //    successor opens (F6.6 reads the predecessor's CURRENT ledger at import).
        // The canonical `TX_REF` is consumed once globally regardless of the target, so a
        // proof can never credit both the predecessor and the successor.
        let target_cid = match self.chain_state.get(&fp.channel_id) {
            Some(ChainState::Committed { .. }) => self.resolve_chain_tip(fp.channel_id),
            _ => fp.channel_id,
        };
        // Unknown channel, bad signature, and a proof bound to a different channel
        // (wrong AUTH_HASH, §5.4) all collapse to the uniform pre-auth rejection.
        let payer_key = self
            .driver
            .payer_key(&fp.channel_id)
            .ok_or(CarriageError::Rejected)?;
        let auth_hash = self
            .driver
            .auth_hash(&fp.channel_id)
            .ok_or(CarriageError::Rejected)?;
        fp.verify(&payer_key).map_err(|_| CarriageError::Rejected)?;
        if fp.auth_hash != auth_hash {
            return Err(CarriageError::Rejected); // proof presented against another channel
        }
        // Q1 admissibility (mode-aware): a **postpay** target credits in any live phase (funding
        // pays down the standing merchant-net, floored at 0 — harmless; the postpay strand
        // fix), a **prepay** target only while its deposit is still returnable (not `Reconciled`).
        // Reject WITHOUT consuming the reference — the transfer is on-rail and recoverable
        // off-protocol (a payer ordering error, never a theft, F6-d).
        if !self.funding_admissible(&target_cid) {
            return Err(CarriageError::Rejected);
        }
        // On-rail verification (F6.4) when a rail is attached: the transfer must have
        // landed at the channel's settlement pointer, in DENOM, for the amount, and
        // reached the channel-established FIN_DENOM finality — "confirmed" IS this.
        // Its memo binds the tx to THIS channel's AUTH_HASH (the interim channel
        // binding, pending the spec answer), so one rail tx credits exactly one
        // channel: a second channel's proof for the same tx fails the memo check.
        let (credit_amount, canonical_ref) = if let Some(rail) = self.rail.as_deref() {
            let terms = self
                .driver
                .settlement_terms(&fp.channel_id)
                .ok_or(CarriageError::Rejected)?;
            let rref = RailRef(fp.tx_ref.clone());
            let info = rail.ref_target(&rref).ok_or(CarriageError::Rejected)?;
            if info.to != terms.settle_ptr
                || info.asset != terms.denom
                || info.amount < fp.amount
                || info.memo != Some(auth_hash)
                || !Self::finality_reached(rail, &rref, &terms.fin_denom)
            {
                return Err(CarriageError::Rejected);
            }
            // Credit the transfer's ACTUAL on-rail amount; the credited-not-raw clamp
            // below caps it at the debt. Consume on the CANONICAL reference (F6-d step 3)
            // so aliases of one transfer can't double-credit.
            (info.amount, info.canonical.clone())
        } else {
            // No rail attached. On a PROOF carriage this is unreachable (proof() sets a rail, never
            // cleared) — but reject explicitly rather than mint the claimed amount, so no refactor
            // can ever reopen the rail-less mint on a proof money path (fail-closed
            // backstop). The signature-only interim (crediting the claimed amount) is the DEMO path
            // ONLY (a launch build always attaches a rail; §C).
            match self.profile {
                Profile::Proof => return Err(CarriageError::Rejected),
                #[cfg(any(test, feature = "demo"))]
                Profile::Demo => (fp.amount, fp.tx_ref.clone()),
            }
        };
        // Atomicity (mirror of the on_settlement_proof commit discipline): run EVERY
        // fallible check — TX_REF not already consumed, channel present, ledger sum
        // won't overflow — BEFORE any state mutation, so an overflow abort cannot burn
        // a TX_REF or credit the live channel while leaving the F6-f ledger desynced.
        //
        // One-decision replay bar (F6.4/F6-d step 5): the canonical TX_REF is consumed
        // **globally, across all channels** — NOT the attacker-controlled `fp.rail`
        // string (the connected adapter is the rail). Global-once is load-bearing
        // alongside the on-rail memo bind: the bind closes cross-channel gift-theft,
        // global-once closes same-channel replay + cross-channel
        // double-credit.
        if self.ref_consumed(&canonical_ref) {
            return Err(CarriageError::Rejected); // reference already consumed (any channel)
        }
        // The credit lands on `target_cid` — the named channel itself, or the live tip when
        // the named predecessor rolled forward (imported-predecessor credit path). All the
        // reads/writes below use `target_cid`; only the proof VERIFICATION above uses the
        // named channel (whose key + `AUTH_HASH` the transfer's memo binds).
        let state = self
            .channels
            .get(&target_cid)
            .ok_or(CarriageError::Rejected)?;
        // Credited-not-raw is a POSTPAY mechanism (F6.4): postpay funding pays down the
        // outstanding merchant-net and floors there, so a proof records
        // `credited = min(raw, outstanding merchant-net at confirmation)` — the excess of
        // an over-transfer is forfeit and NEVER recorded in Σ funding, so the live `B`
        // and the F6-f ledger subtract the SAME bounded quantity and can never disagree.
        // Merchant-net is ≤ B (B additionally carries the outstanding meed), so an
        // over-transfer can pay merchant-net to 0 while B floors at the still-owed carve.
        // **Prepay** funding is deposit principal, NOT merchant-net debt — a fresh prepay
        // channel has CUM_TOTAL = 0, so this clamp would credit 0 and brick it; prepay
        // credits the full amount (credit_funding subtracts and clamps at −L_prepay).
        let credited = if state.mode() == Mode::Postpay {
            // Outstanding merchant-net = max(0, (CUM_TOTAL − meed_carve) − Σ net legs
            // − Σ prior credited funding); carve = floor(Σ ACCRUALS / 10000) once on the
            // cumulative (F6.5). Live cum_total/accruals is the right basis — funding can
            // precede any checkpoint, and F6-f later subtracts this same credited sum.
            let carve: BigUint = state
                .accruals()
                .into_iter()
                .map(|(_, a)| a)
                .sum::<BigUint>()
                / 10_000u32;
            let carve = u128::try_from(carve).unwrap_or(u128::MAX);
            let cur_net = self
                .ledger
                .get(&target_cid)
                .map(|l| l.net_legs_sum)
                .unwrap_or(0);
            let cur_funding = self
                .ledger
                .get(&target_cid)
                .map(|l| l.funding_sum)
                .unwrap_or(0);
            let outstanding_mn = state
                .cum_total()
                .saturating_sub(carve)
                .saturating_sub(cur_net)
                .saturating_sub(cur_funding);
            credit_amount.min(outstanding_mn)
        } else {
            credit_amount
        };
        let cur_funding = self
            .ledger
            .get(&target_cid)
            .map(|l| l.funding_sum)
            .unwrap_or(0);
        let new_funding = cur_funding
            .checked_add(credited)
            .ok_or(CarriageError::Rejected)?;

        // --- Commit point: no fallible op past here; credit atomically. ---
        // The durable one-decision store is the atomic exactly-once gate. `consume_ref`
        // resolves three ways and each is distinct on the MONEY path:
        //  - `Duplicate` → another replica / a restart-race already consumed this ref and credited
        //    the funding THERE; acknowledge idempotently, never double-credit.
        //  - `Failed`    → the durable store could not record the consumption (a write/sync error);
        //    NOTHING was consumed, so we must NOT credit and must NOT ack success — reject so the
        //    payer re-presents (the on-rail transfer is recoverable, F6-d) and a recovered store
        //    credits it exactly once. Masking this as a duplicate stranded the deposit (C1-3).
        //  - `First`     → proceed to credit below.
        // (Single-process, the `&mut self` serialization makes the first consumption always `First`.)
        match self.consume_ref(canonical_ref) {
            ConsumeOutcome::Duplicate => return Ok(Response::Accepted),
            ConsumeOutcome::Failed => return Err(CarriageError::Rejected),
            ConsumeOutcome::First => {}
        }
        // Confirmed funding credits toward the merchant-net and re-opens a
        // window-paused channel (F6.4); `credited` already floors at merchant-net (postpay),
        // so `B` and the ledger move by the same amount.
        self.channels
            .get_mut(&target_cid)
            .expect("channel present")
            .credit_funding(credited);
        // Record the credited funding in the F6-f ledger (the "settled" side the
        // settlement recompute subtracts).
        let led = self.ledger.entry(target_cid).or_default();
        led.funding_sum = new_funding;
        // F1 — funding does NOT bump `version`. The version-staleness bar exists to
        // stop the cross-round double-fold of `settled_r` (two rounds against distinct
        // checkpoints both folding `E_r` against one accrual → over-extinguish → brick). A
        // *funding* credit is not another round: it pays down merchant-net, which FLOORS at 0
        // (F6.4), so a funding overpayment is the payer's forfeit and can NEVER invalidate a
        // round's economics (funding only *decreases* what is owed; a round proposed before it
        // then over-collects, floored — never under-collects). Bumping the version here instead
        // STRANDED a round whose legs the payer already finalized on-rail (the net leg
        // is paid but never credited → the merchant re-bills it at the next round), AND made a
        // live round with a finalized net leg falsely-stale so the F6-i quiescence guard let a
        // premature chain-close through and stranded the leg (the quiescence-race). A round
        // still re-verifies against a moved ledger the moment ANOTHER round confirms (that path
        // still bumps the version, on_settlement_proof) — the only mover required.
        Ok(Response::Accepted)
    }

    fn on_close(&mut self, obj: &[u8]) -> Result<Response, CarriageError> {
        let close = Close::parse(obj).map_err(|_| CarriageError::Malformed)?;
        // Unknown channel and a bad/foreign signature collapse to one rejection. **This is also the
        // fail-closed point:** the refund / carve draw / terminal disposition
        // below can only be adjudicated against LIVE channel state, which after a restart is gone
        // (channel resumption = ASYNC-1). The driver holds `payer_key` in the same in-memory
        // `retained` as the rest of the live state — restored to a rejecting tombstone, NOT a
        // servable record — so a post-restart CLOSE returns `None` HERE and never reaches a
        // `Reconciled` write it cannot back with a refund (a strand, recoverable evidentiary — never
        // a false-terminal disposition that would bar a later legitimate refund).
        let payer_key = self
            .driver
            .payer_key(&close.channel_id)
            .ok_or(CarriageError::Rejected)?;
        let merchant_key = self.driver.key();
        // F5-l: verifies the channel id + signature; chain intent honored only from
        // the payer. A CLOSE for another channel can never drive this one to SETTLING.
        // `decision.chain_intent` is the AUTHENTICATED (payer-only) chain choice — a
        // merchant-signed close with the wire bit set does NOT count as chaining.
        let decision = close
            .accept(&close.channel_id, &payer_key, &merchant_key)
            .map_err(|_| CarriageError::Rejected)?;
        // F6.3: a CLOSE must name the channel's *operative* checkpoint when one exists
        // (settlement/chaining anchors there); a CLOSE naming a stale/other reference
        // is refused. Before any checkpoint the channel closes from birth (no anchor
        // to match), so a CLOSE is accepted whatever its (conventionally zero) ref.
        // EXCEPTION: an already-`Reconciled` channel accepts a REPLAY close regardless
        // of the operative ref — a checkpoint completing in `Settling` may have advanced the
        // operative PAST the close's pinned basis, so an *exact* replay of the original close would
        // otherwise be rejected here and never reach the pinned-draw RETRY (step 2 below). The replay
        // re-refunds nothing and re-pins nothing (`first_close` is false); it only re-attempts the
        // idempotent pinned draw, so skipping the freshness check is safe.
        let is_reconciled = matches!(
            self.chain_state.get(&close.channel_id),
            Some(ChainState::Reconciled { .. })
        );
        if !is_reconciled {
            if let Some(op) = self.operative.get(&close.channel_id) {
                if close.ckpt_ref != op.ckpt_ref {
                    return Err(CarriageError::Rejected);
                }
            }
        }
        // F6-i: chaining requires a **quiescent** channel — no unconfirmed settlement
        // round may be in flight at a `chain_intent` close. Such a round's predecessor-bound rail
        // legs (memo `(CHANNEL_ID, CKPT_REF)`, F6-h) settle only the predecessor, yet the snapshot
        // rolls the position forward from CONFIRMED rounds only — a round completing *after* the
        // snapshot would strand its paid legs on the predecessor AND leave the successor importing
        // the full obligation (double-pay). Reject; the payer completes (or lets lapse) the round,
        // then chains.
        //
        // Block on **any unconfirmed round** (`!d.confirmed`), NOT a version-refined predicate:
        // under serialization (F6-l) there is at most one in-flight round, always current-version,
        // so the two are equivalent — but `!d.confirmed` is strictly safer and carries **no
        // `ledger_version` dependency**. A version-gated guard (`d.ledger_version == cur_version`)
        // would silently stop blocking if the version ever moved spuriously while a round is
        // unconfirmed → a premature chain-close → a strand; the
        // version machinery is the *backstop* in `on_settlement_proof`, and the quiescence bar
        // must not depend on it. A NON-chain close is unaffected — it reconciles normally.
        // (Residual liveness: an abandoned round holds the channel non-quiescent until the payer
        // completes it or the deferred `SETTLE_TIMEOUT` lapses; a plain close always escapes it.)
        if decision.chain_intent
            && self
                .rounds
                .iter()
                .any(|((c, _), d)| *c == close.channel_id && !d.confirmed)
        {
            return Err(CarriageError::Rejected);
        }
        // F6-f: a prepay channel returns its unconsumed deposit at close — the "one
        // durable choice per final checkpoint" (§6.4). **Chain intent is NOT a waiver:** a
        // `chain_intent` close records only the REVOCABLE intent (`ChainState::Pending`); it
        // does NOT refund and does NOT freeze the position. The deposit stays reclaimable (a
        // later plain CLOSE below returns it — the no-successor deposit trap fix) and late
        // funding stays creditable, until a successor actually imports (`Committed`, at
        // `on_open` — the float then rolls forward irrevocably). No snapshot is frozen here:
        // the successor imports the predecessor's CURRENT reconciled position at open
        // (`compute_chain_snapshot`), so a late funding credited to a `Pending` predecessor is
        // imported verbatim.
        //
        // **The durable close decision lives in `chain_state`, NOT the channel's lifecycle
        // phase.** Refund idempotency (no double-release of the shared `settle_ptr` — the
        // drain) is the `Reconciled` marker, not `status() == Settling`: an implicit
        // connection-drop close (F6-a) moves a channel to `Settling` WITHOUT a refund, so
        // keying idempotency on the phase would TRAP that deposit — a plain CLOSE arriving
        // afterward would see `Settling` and skip the refund. Keying on `chain_state` returns
        // it correctly and still bars the replay double-release.
        let chain_ok = decision.chain_intent
            && self
                .driver
                .settlement_terms(&close.channel_id)
                .map(|t| !t.conversion_required)
                .unwrap_or(false);
        // The prior terminal disposition — consulting the DURABLE store as the authority: a
        // `Committed` (a concurrent/earlier successor import) or `Reconciled` (a
        // pre-restart close) recorded elsewhere bars this close from re-refunding or re-reconciling,
        // even if THIS process's in-memory `chain_state` is fresh (a restart, or a second replica).
        // The keyed release is idempotent, so a true simultaneous race still refunds at most once.
        let prior = self
            .chain_state
            .get(&close.channel_id)
            .cloned()
            .or_else(|| {
                self.decisions
                    .as_ref()
                    .and_then(|s| s.get(&disp_key(&close.channel_id)))
                    .and_then(|v| decode_disp(&v))
            });
        // The reconciliation basis (F6-f / F6-k): the channel's bilaterally-evidenced consumed
        // position — its **own** operative checkpoint's `CUM_TOTAL` if it has one, ELSE the
        // **imported** `CUM_TOTAL` a chained successor opened at (which lives in no operative of
        // its own, `imported_cum`), ELSE `0` for a fresh **birth**. A chained successor is NOT a
        // fresh birth: reading `0` here would over-refund the whole deposit and mis-judge the
        // checkpoint-before-chain guard. Uncheckpointed slices beyond this basis
        // are the merchant's E-risk, borne once at close.
        let basis_cum = self
            .operative
            .get(&close.channel_id)
            .map(|o| u128::try_from(o.cum_total.clone()).unwrap_or(u128::MAX))
            .or_else(|| self.imported_basis.get(&close.channel_id).map(|b| b.cum))
            .unwrap_or(0);
        if chain_ok {
            // F6-k checkpoint-before-chain: a `chain_intent` close is honored only when live
            // metering equals the evidenced basis — no accepted-but-uncheckpointed slice standing
            // beyond it. Otherwise the successor imports the basis and DROPS the uncheckpointed
            // value (prepay: the payer re-spends; postpay: the merchant loses the debt), amplified
            // per chain hop → the `E` bound defeated. Reject; checkpoint the outstanding slices
            // first, then chain.
            let live_cum = self
                .channels
                .get(&close.channel_id)
                .map(|s| s.cum_total())
                .unwrap_or(0);
            if live_cum != basis_cum {
                return Err(CarriageError::Rejected); // uncheckpointed slices — checkpoint first
            }
            // F5-a — chain onward only from an OWN bilateral checkpoint. A channel with no own
            // operative checkpoint but a nonzero metered/imported position (a chained successor
            // that signed none of its own, or a metered-but-unchecked channel) cannot be chained
            // onward: its "final checkpoint" would be an F6-e synthetic one over nonzero imported
            // state, which the RI defers (`compute_chain_snapshot` rejects it). Reject the
            // chain-close **fail-fast** — the payer plain-closes instead (prepay refund against the
            // basis; postpay the debt stands as a §6.4 standing obligation) — rather than record a
            // `Pending` intent no successor can ever consume (don't strand it in a dead
            // Pending). A true **birth** (cum == 0) still chains via its synthetic checkpoint
            // (F6-e): `live_cum == 0`, so this does not fire.
            if !self.operative.contains_key(&close.channel_id) && live_cum != 0 {
                return Err(CarriageError::Rejected); // no own checkpoint + nonzero — onward chaining deferred
            }
            // Record the revocable intent, ONCE. If the durable decision is already made — a
            // `Pending` replay, a `Committed` float, or a `Reconciled` deposit — it is a no-op (you
            // cannot chain a channel already rolled forward or reclaimed).
            if prior.is_none() {
                self.chain_state
                    .insert(close.channel_id, ChainState::Pending);
            }
        } else {
            // Plain (reconciling) CLOSE — this channel settles on its OWN books. Two close legs:
            //  (1) REFUND the prepay unconsumed deposit ONCE (the release is not idempotent — a
            //      replay must not double-release, the drain), on the FIRST plain close only:
            //      `None` (an ordinary first close) or `Pending` (the payer REVOKING a chain intent
            //      and reclaiming). `Committed`/`Reconciled` → already decided, no refund.
            //  (2) DRAW the outstanding prepay meed carve to the instance (step 2 below) —
            //      RETRYABLE, so a transient failure never terminally leaks the enablers' carve.
            let first_close = matches!(prior, None | Some(ChainState::Pending));
            if first_close {
                // F6-f / F6-k: refund against the evidenced `basis_cum`, never live — refunding
                // against live would let a merchant (holding the symmetric slice key) forge slices
                // to inflate the deduction and short the deposit.
                let cum_total = self.channels.get(&close.channel_id).map(|_| basis_cum);
                let funding_sum = self.ledger.get(&close.channel_id).map(|l| l.funding_sum);
                let refund_terms = self
                    .driver
                    .settlement_terms(&close.channel_id)
                    .and_then(|t| {
                        t.refund_ptr
                            .as_ref()
                            .map(|rp| (t.settle_ptr.clone(), rp.clone(), t.denom.clone()))
                    });
                if let (Some(cum), Some(fund), Some((settle_ptr, refund_ptr, denom))) =
                    (cum_total, funding_sum, refund_terms)
                {
                    // Rejects the inconsistency CUM_TOTAL > Σ funding (consumption cannot
                    // exceed a prepay deposit); a well-formed channel refunds the remainder.
                    if let Ok(refund) =
                        reconcile::prepay_unconsumed_deposit(&U256::from(fund), &U256::from(cum))
                    {
                        let refund = u128::try_from(refund).unwrap_or(0);
                        if refund > 0 {
                            if let Some(rail) = self.rail.as_deref() {
                                // Best-effort on a non-custodial rail (§6.4). The durable decision
                                // is consumed regardless of the release outcome (`Reconciled` below):
                                // a failed release leaves a **standing obligation** (the merchant
                                // holds the funds; recover off-protocol), NOT a chainable position
                                // — which would DOUBLE-SPEND (chain the float AND collect the
                                // on-chain refund) — nor a re-releasable one (a
                                // replay close sees `Reconciled`, skips the refund — no double-release).
                                // **Reserve the refund durably BEFORE submitting** (crash-safe
                                // exactly-once). The reserve keyed on `(CHANNEL_ID, close basis)` — the
                                // SAME key the rail's `release_keyed` dedups on — precedes the on-chain
                                // effect, so a crash in/after the submit replays as "refund owed" at
                                // restart (never lost). The release is then ALWAYS attempted (it is
                                // idempotent: `release_keyed` returns the SAME ref and moves nothing on
                                // a retry, F6-f) — the reserve gates nothing here (skipping would strand
                                // a reserved-but-not-yet-released refund). The persisted canonical ref
                                // lets a restart poll THAT release's finality and mark it settled (or
                                // re-submit if it dropped, the rail deduping) rather than re-release
                                // blind. On a replay/restart the terminal `Reconciled` disposition (its
                                // `prior` consults the durable store) makes `first_close` false,
                                // so this block does not re-run at all — the reserve + ref are the
                                // additional safety for the narrow window before that record lands, and
                                // the seam for the async poll-then-settle recovery (S4/S6).
                                if let Some(store) = &self.decisions {
                                    store.decide(
                                        &refund_reserve_key(&close.channel_id, &close.ckpt_ref),
                                        b"",
                                    );
                                }
                                if let Ok(rref) = rail.release_keyed(
                                    close.channel_id,
                                    close.ckpt_ref,
                                    &settle_ptr,
                                    &refund_ptr,
                                    &denom,
                                    refund,
                                ) {
                                    if let Some(store) = &self.decisions {
                                        store.decide(
                                            &refund_ref_key(&close.channel_id, &close.ckpt_ref),
                                            rref.0.as_bytes(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                // The one durable choice: mark `Reconciled` **unconditionally** (whether or not the
                // release succeeded) so a replay never double-releases, no successor imports a
                // reconciled position (F6.6 clause (d) — the double-spend bar), and a late prepay
                // deposit is not credited to this settled channel. **PIN the prepay carve draw HERE**
                // (`compute_pending_draw`) to the SAME evidenced basis as the refund (own operative
                // checkpoint, or the imported checkpoint), so a checkpoint completing later in
                // `Settling` can never move the draw's basis/amount (the double-draw). `None` = none
                // owed (postpay / zero carve / converted / birth); step (2) draws a `Some`. A failed
                // release is a §6.4 standing obligation (recover off-protocol); the disposition is
                // mirrored to the durable store above so a restart never re-refunds.
                // F6-n(d): drain any in-flight interim round FIRST — a drawn round folds into
                // settled_r, an undrawn one is removed — so the pinned carve is the correct
                // residual and no accrual is drawn twice (a checkpoint superseding an unfolded
                // interim round would otherwise let the close recompute and re-draw its carve).
                self.drain_interim_rounds(&close.channel_id);
                let pending_draw = self.compute_pending_draw(&close.channel_id);
                let reconciled = ChainState::Reconciled { pending_draw };
                // Durable one-decision: the terminal reconcile is recorded so a
                // restart replays it — `first_close` is then false and the refund never re-issues.
                if self.record_disposition(&close.channel_id, &reconciled) == Decision::Failed {
                    // Durable-or-fail (F4.4): the terminal disposition could
                    // not be durably recorded → REJECT the close rather than proceed as if it were,
                    // so the client retries against a recovered store. The refund above is idempotent
                    // (keyed release dedups), so the retry re-attempts it without double-releasing.
                    return Err(CarriageError::Rejected);
                }
                self.chain_state.insert(close.channel_id, reconciled);
            }
            // (2) Draw the PINNED prepay carve to the instance (F6.5 / F6-f) while owed — the FIRST
            // close, or a RETRY after a transient failure (the pinned `(CKPT_REF, target_p)` never
            // moves, and the watermark advance's idempotent 0-delta — `Ok`, never re-drawing — backs
            // exactly-once, so re-attempting never double-draws or leaks the enablers' carve). A no-op
            // when `pending_draw` is `None`.
            if matches!(
                self.chain_state.get(&close.channel_id),
                Some(ChainState::Reconciled {
                    pending_draw: Some(_)
                })
            ) {
                self.attempt_prepay_close_draw(&close.channel_id);
            }
        }
        let state = self
            .channels
            .get_mut(&close.channel_id)
            .ok_or(CarriageError::Rejected)?;
        state.begin_settling();
        // Mark the F5-m record terminated so the id is never re-initialized.
        self.driver.terminate(&close.channel_id);
        Ok(Response::Accepted)
    }

    /// Fold a completed prepay **interim** round's `E_r` into the per-channel `settled_r`
    /// (F6-f), idempotently (guarded by the round's `meed_folded`), and mark the round
    /// complete. A prepay interim round is **meed-only**: `B` does NOT move and the window
    /// does NOT re-open (F6-g) — unlike the postpay fold, which also moves `B` by the settled
    /// gross. Bumps the ledger `version` (the backstop). No-op if already folded or absent.
    fn fold_interim_round(
        &mut self,
        cid: &[u8; 8],
        ckpt_ref: &[u8; 32],
        e_r: &[(u8, BigUint)],
        final_time: Option<u64>,
    ) {
        let key = (*cid, *ckpt_ref);
        // Idempotent: a re-run (retry / close drain) never double-folds.
        if self.rounds.get(&key).map(|d| d.meed_folded).unwrap_or(true) {
            return;
        }
        let led = self.ledger.entry(*cid).or_default();
        // settled_r += E_r; stays ≤ accrued because E_r was recomputed as
        // outstanding = accrued − settled_before and E_r ≤ outstanding (F7.3), and
        // one-round-per-CKPT_REF + F6-l serialization bar a concurrent fold.
        for (role, e) in e_r {
            match led.settled_r.iter_mut().find(|(r, _)| r == role) {
                Some((_, acc)) => *acc += e,
                None => led.settled_r.push((*role, e.clone())),
            }
        }
        led.settled_r.sort_by_key(|(r, _)| *r);
        led.version = led.version.wrapping_add(1);
        let v = led.version;
        if let Some(d) = self.rounds.get_mut(&key) {
            d.meed_folded = true;
            d.net_folded = true; // meed-only round: no net leg
            d.confirmed = true;
            d.meed_final_time = final_time;
            d.ledger_version = v;
        }
    }

    /// **F6-n(d)** — at a **plain** close, drain any in-flight interim round on the channel BEFORE
    /// pinning the close carve draw, so the close never double-draws an accrual. **Rail-authoritative:**
    /// a round folds into `settled_r` iff the **rail** shows its claim-record funded
    /// (`funds_claim`, the F6-m recipients-paid fact) — NOT merely that `draw_ref` is set (a local
    /// hint). A funded round is credited (the close then draws only the residual carve); an unfunded
    /// / never-submitted round is removed (the close draws the full carve, once). On the synchronous
    /// rail `draw_ref` tracks `funds_claim` exactly, so this changes no outcome here — it makes the
    /// decision authoritative; a reorg-capable rail's not-yet-final draw at close is the residual
    /// durable-store concern. A chain-close is barred separately by F6-i quiescence,
    /// so this runs only on the plain-close path.
    fn drain_interim_rounds(&mut self, cid: &[u8; 8]) {
        // Scope to PREPAY: interim rounds are prepay-only, and a prepay channel's `self.rounds`
        // holds ONLY interim rounds (payer `SETTLEMENT_PROPOSE` is barred on prepay, F6.5). A
        // POSTPAY channel's in-flight rounds are the payer's settlement rounds — settled by
        // `SETTLEMENT_PROOF`, NEVER drained; draining one (it also has `draw_ref: None`) would
        // strand a funded round and double-pay. Belt-and-braces: `on_close`
        // only reaches the carve path on prepay, but guard here so the drain can never touch a
        // postpay round wherever it is called.
        if self.channels.get(cid).map(|s| s.mode()) != Some(Mode::Prepay) {
            return;
        }
        let Some(seed_instance) = self.driver.settlement_terms(cid).map(|t| t.seed_instance) else {
            return;
        };
        let in_flight: Vec<DrainRound> = self
            .rounds
            .iter()
            .filter(|((c, _), d)| c == cid && !d.confirmed)
            .map(|((_, k), d)| (*k, d.e_r.clone(), d.target_p, d.draw_ref.clone()))
            .collect();
        for (ckpt_ref, e_r, target_p, draw_ref) in in_flight {
            // Rail-authoritative (Option W): did THIS round's advance move the watermark (the
            // recipients paid)? The rail-fact is the `advanced_channel_meed` bind — the watermark
            // reached at least this round's `target_p` on THIS channel — never a state read. A
            // dropped/never-final advance leaves it unfunded, and the drop-then-redraw is harmless:
            // the close draw advances to the higher close target, subsuming this round with no
            // double (the monotone `funded_p`). The rail borrow is scoped so the fold/remove is free.
            let funded = {
                match (target_p, &draw_ref) {
                    (Some(target_p), Some(r)) => self
                        .rail
                        .as_deref()
                        .and_then(|rail| rail.ref_target(&RailRef(r.clone())))
                        .and_then(|info| info.advanced_channel_meed)
                        .map(|f| {
                            f.channel_id == *cid
                                && f.seed_instance == seed_instance
                                && f.funded_p >= target_p
                        })
                        .unwrap_or(false),
                    _ => false, // never submitted (no ref / no target) → funded nothing
                }
            };
            if funded {
                self.fold_interim_round(cid, &ckpt_ref, &e_r, None);
            } else {
                self.rounds.remove(&(*cid, ckpt_ref));
            }
        }
    }

    /// **F6-n — run a prepay interim meed draw** on a live channel, returning the
    /// merchant-signed `PREPAY_DRAW_COMPLETED` (F5-o) a halted payer resumes on, or `None`
    /// when nothing is settleable, a guard fails, or the draw/its finality is not yet
    /// complete (a caller MAY retry — the round stays locked with its pinned `(CKPT_REF, P,
    /// E_r)`, never recomputed). The merchant is the prepay meed debtor (F6.5); this
    /// settles the accrued carve to the instance **from the deposit**, without closing, and
    /// folds `settled_r` only on FIN_MEED finality (rail-authoritative). The four F6-n
    /// rules: (a) lock before the rail draw and retry the locked params; (b) one round per
    /// operative `CKPT_REF`; (c) register in `self.rounds` so F6-l/F6-i govern it; (d) a plain
    /// close drains it first (`on_close`).
    pub fn run_prepay_interim_draw(&mut self, cid: &[u8; 8]) -> Option<PrepayDrawCompleted> {
        // --- Guards ---
        // Prepay only — postpay settles via the payer's round, not a merchant draw.
        if self.channels.get(cid).map(|s| s.mode()) != Some(Mode::Prepay) {
            return None;
        }
        // Live (non-terminal): SETTLING/CLOSED accept no interim draw (F6.1) — the draw exists
        // to clear a halt on a running channel.
        if !matches!(
            self.channels.get(cid).map(|s| s.status()),
            Some(Status::Open | Status::PausedWindow | Status::PausedEvidence)
        ) {
            return None;
        }
        // Deterministic (DENOM = BASELINE_ASSET): off-baseline interim draw needs the rate
        // oracle (deferred, as off-baseline CONFIRMED); `open_channel` rejects off-baseline
        // prepay at establishment, so this is belt-and-braces.
        let (seed_instance, settle_ptr, baseline_asset, baseline_net, fin_meed) = {
            let terms = self.driver.settlement_terms(cid)?;
            if terms.conversion_required {
                return None;
            }
            // Fold-at-irreversible backstop: the interim draw folds `settled_r` at
            // `fin_meed` — refuse to draw if that is not the rail's irreversible level (a rail
            // attached AFTER a no-rail open that bypassed the `on_open` guard).
            if !self.finality_is_irreversible(&terms.fin_meed, &terms.fin_denom) {
                return None;
            }
            // Clone to owned — `terms` borrows `self.driver`, which must be free for the
            // `&mut self` fold below (F6-f: no borrow of self held across the fold).
            (
                terms.seed_instance,
                terms.settle_ptr.clone(),
                terms.baseline_asset.clone(),
                terms.baseline_net.clone(),
                terms.fin_meed.clone(),
            )
        };
        // Rail present — the draw moves value.
        self.rail.as_ref()?;

        // --- Pick the round: retry a locked in-flight interim round, else lock a NEW one. ---
        // (c) The round registers in self.rounds, so F6-l serialization (one in-flight round)
        // and F6-i chain-close quiescence both govern it. A locked, unconfirmed round is this
        // prepay channel's single in-flight round (prepay has no payer-proposed rounds); retry
        // it with its LOCKED params (a), never a recompute.
        let in_flight = self
            .rounds
            .iter()
            .find(|((c, _), d)| c == cid && !d.confirmed)
            .map(|((_, k), d)| (*k, d.target_p, d.e_r.clone()));
        let (ckpt_ref, target_p, e_r) = match in_flight {
            Some((k, Some(target_p), er)) => (k, target_p, er), // RETRY the locked round (a)
            Some((_, None, _)) => return None, // malformed lock (no target_p) — unreachable
            None => {
                // NEW round against the current operative checkpoint.
                let ckpt_ref = self.operative.get(cid)?.ckpt_ref;
                // (b) One round per operative CKPT_REF: a round already keyed here is a completed
                // draw on this checkpoint (the in-flight case is handled above); a second draw needs
                // a FRESH checkpoint (the E cadence forces one). But RE-EMIT its signed notice
                // idempotently (liveness — the postpay CONFIRMED re-emit analogue): the halted
                // wallet resumes on the receipt, so a lost delivery must be re-servable or the payer
                // is stranded. Reconstruct from the confirmed round + rail facts (deterministic
                // claim-id, the retained draw ref), NEVER re-drawing.
                if let Some(d) = self.rounds.get(&(*cid, ckpt_ref)) {
                    if let (true, Some(target_p), Some(tx_ref)) =
                        (d.confirmed, d.target_p, d.draw_ref.clone())
                    {
                        let e_r = d.e_r.clone();
                        let claim_id = claim_record_id(&seed_instance, cid, &ckpt_ref, target_p);
                        let finality_level = self
                            .rail
                            .as_deref()
                            .and_then(|rail| rail.finality(&RailRef(tx_ref.clone())))
                            .map(|f| f.level)
                            .unwrap_or_default();
                        let mut receipt = PrepayDrawCompleted {
                            channel_id: *cid,
                            ckpt_ref,
                            amount: BigUint::from(target_p),
                            extinguished: e_r,
                            claim_record: claim_id,
                            // F5-o/F9.1 0x05 RAIL is the CAIP-2 baseline NETWORK (BASELINE_NET),
                            // not the CAIP-19 `baseline_asset` (which scopes the on-rail meed draw).
                            rail: baseline_net.clone(),
                            tx_ref,
                            finality: finality_level,
                            sig_merchant: None,
                        };
                        self.driver.sign_prepay_draw(&mut receipt);
                        return Some(receipt);
                    }
                    return None;
                }
                // Recompute the round's per-role `E_r` (the postpay creditor's F7.3) for the
                // `settled_r` fold, AND the OWN-CUMULATIVE watermark target for the advance (Option W).
                let (meed_amount, er, _outputs) = self.recompute_round(cid).ok()?;
                let p = meed_amount?; // None ⇒ E = 0 ⇒ nothing settleable ⇒ no-op (before locking)
                let accruals = self.operative.get(cid)?.accruals.clone();
                let target_p = self.cumulative_target_p(cid, &accruals)?; // floor((Σacc − imported)/1e4)
                                                                          // (a) LOCK before the rail draw.
                let ledger_version = self.ledger.get(cid).map(|l| l.version).unwrap_or(0);
                self.rounds.insert(
                    (*cid, ckpt_ref),
                    RoundDecision {
                        terms_fp: sha256(
                            &[&cid[..], &ckpt_ref[..], &target_p.to_be_bytes()].concat(),
                        ),
                        proposal_hashes: std::collections::HashSet::new(),
                        proofs: Vec::new(),
                        outputs: Vec::new(),
                        meed_amount: Some(p),
                        e_r: er.clone(),
                        meed_folded: false,
                        net_folded: true, // meed-only: no net leg to fold
                        meed_final_time: None,
                        deterministic: true,
                        ledger_version,
                        confirmed: false,
                        draw_ref: None,
                        target_p: Some(target_p),
                    },
                );
                (ckpt_ref, target_p, er)
            }
        };

        // --- Draw (or re-check a submitted draw's finality), scoping the rail borrow. ---
        enum DrawStep {
            Ready {
                rref: String,
                final_time: Option<u64>,
                finality_level: String,
            },
            PendingDrawn {
                rref: String,
            },
            Crashed, // advance returned no ref (unreachable: the watermark advance is idempotent)
        }
        let already_drawn = self
            .rounds
            .get(&(*cid, ckpt_ref))
            .and_then(|d| d.draw_ref.clone());
        let step = {
            let rail = self.rail.as_deref()?;
            let rref = match already_drawn {
                Some(r) => Some(RailRef(r)), // (a) re-check the SAME draw — never re-draw
                None => {
                    let addr = rail.derive_address(&seed_instance);
                    // Option W: ADVANCE the per-channel watermark to `target_p` (idempotent by
                    // absolute position — a drop-then-redraw or a close draw at a higher target
                    // moves only the residual, closing the cross-checkpoint double-draw).
                    match rail.advance_channel_meed(
                        Some(&settle_ptr),
                        &addr,
                        *cid,
                        target_p,
                        baseline_asset.clone(),
                    ) {
                        Ok(rref) => Some(rref),
                        // The idempotent advance returns `Ok` (0-delta) rather than `AlreadyFunded`;
                        // kept for parity with the crash branch (never fires for the advance kind).
                        Err(RailError::AlreadyFunded) => None,
                        // Transient (outage / insufficient escrow): the round stays LOCKED in
                        // self.rounds (never recomputed), so a later call retries it; return.
                        Err(_) => return None,
                    }
                }
            };
            match rref {
                Some(rref) => {
                    if Self::finality_reached(rail, &rref, &fin_meed) {
                        DrawStep::Ready {
                            final_time: rail.finality(&rref).map(|f| f.time),
                            finality_level: rail
                                .finality(&rref)
                                .map(|f| f.level)
                                .unwrap_or_default(),
                            rref: rref.0,
                        }
                    } else {
                        DrawStep::PendingDrawn { rref: rref.0 }
                    }
                }
                None => DrawStep::Crashed,
            }
        };

        // --- Commit (rail borrow dropped): store the ref, fold on finality, emit. ---
        match step {
            DrawStep::Ready {
                rref,
                final_time,
                finality_level,
            } => {
                if let Some(d) = self.rounds.get_mut(&(*cid, ckpt_ref)) {
                    d.draw_ref = Some(rref.clone());
                }
                self.fold_interim_round(cid, &ckpt_ref, &e_r, final_time);
                // Option W: the receipt names the cumulative watermark position `target_p` (the
                // wallet checks the advance fact reached it); the claim-record id is the deterministic
                // watermark name at `target_p` (F4.2, retained as the round-naming belt).
                let claim_id = claim_record_id(&seed_instance, cid, &ckpt_ref, target_p);
                let mut receipt = PrepayDrawCompleted {
                    channel_id: *cid,
                    ckpt_ref,
                    amount: BigUint::from(target_p),
                    extinguished: e_r,
                    claim_record: claim_id,
                    // F5-o/F9.1 0x05 RAIL is the CAIP-2 baseline NETWORK (BASELINE_NET), not the
                    // CAIP-19 `baseline_asset` that scoped the on-rail draw (a conformant peer
                    // parses RAIL strictly as CAIP-2). Value-neutral on the v0.1 baseline.
                    rail: baseline_net,
                    tx_ref: rref,
                    finality: finality_level,
                    sig_merchant: None,
                };
                self.driver.sign_prepay_draw(&mut receipt);
                Some(receipt)
            }
            DrawStep::PendingDrawn { rref } => {
                if let Some(d) = self.rounds.get_mut(&(*cid, ckpt_ref)) {
                    d.draw_ref = Some(rref);
                }
                None // draw submitted, finality pending — leave locked, retry when final
            }
            DrawStep::Crashed => {
                // Reached only if an advance returned no ref — UNREACHABLE under Option W: the
                // watermark advance is idempotent by absolute position, so a crash-retry re-advances
                // to the SAME `target_p` and returns `Ok` (a 0-delta no-op), never `AlreadyFunded`.
                // (That idempotency IS the S4 crash-branch fix; the durable one-decision store backs
                // the CLOSE-plane exactly-once, not this draw.) Kept as a fold-safe defensive path:
                // fold conservation-safely (idempotent) so a later close never double-draws; emit no
                // receipt (no ref to verify) — a liveness-only degradation, never a value loss.
                self.fold_interim_round(cid, &ckpt_ref, &e_r, None);
                None
            }
        }
    }

    /// Execute the **pinned** prepay carve draw (F6.5 / F6-f): the merchant is the prepay meed
    /// debtor and advances the per-channel watermark to `target_p` (drawing the residual `ΔP`) **from
    /// the deposit it holds** at `settle_ptr` into the instance's `(CHANNEL_ID, CKPT_REF)` claim record.
    /// Reads the LOCKED `(CKPT_REF, target_p)` from the `Reconciled` disposition — never `self.operative`,
    /// which a checkpoint completing in `Settling` could move (the double-draw a dynamic re-read would
    /// open). On success — `Ok`, including the idempotent 0-delta advance when the watermark already
    /// reached `target_p` — clears the pending draw; a transient rail failure
    /// (an outage, or an insufficient-escrow precondition under the shared `settle_ptr`) or no rail
    /// leaves it pending for a later replay/retry close — never a terminal silent leak of the carve.
    fn attempt_prepay_close_draw(&mut self, cid: &[u8; 8]) {
        let Some(ChainState::Reconciled {
            pending_draw: Some((_ckpt_ref, target_p)),
        }) = self.chain_state.get(cid).cloned()
        else {
            return; // nothing owed (None / not Reconciled)
        };
        let Some(terms) = self.driver.settlement_terms(cid) else {
            return;
        };
        // Best-effort draw from the shared `settle_ptr` to the instance (§6.5). Option W: ADVANCE the
        // per-channel watermark to `target_p` — idempotent by absolute position, so if an interim
        // round already advanced part of it, this moves only the residual (no double). Scope the rail
        // borrow so the `&mut` update below does not conflict.
        let draw_result = self.rail.as_deref().map(|rail| {
            let addr = rail.derive_address(&terms.seed_instance);
            rail.advance_channel_meed(
                Some(&terms.settle_ptr),
                &addr,
                *cid,
                target_p,
                terms.baseline_asset.clone(),
            )
        });
        match draw_result {
            // Advanced (`Ok`) — including the idempotent 0-delta no-op when the watermark already
            // reached `target_p`. (`advance_channel_meed` returns `Ok`, never `AlreadyFunded`; the
            // `AlreadyFunded` arm below is a defensive guard.) The carve reached the instance → clear.
            // Clearing on the advance `Ok` (submit) WITHOUT a `finality_reached` gate is the same
            // tracked async deferral as the drain (`drain_interim_rounds`) and refund paths (see
            // ASYNC-1 / SCOPE.md's real-adapter boundary): on the synchronous `VirtualRail`
            // submit==final so this is exact; a real async/reorg rail's finality gate on the
            // close plane is the tracked durable-store milestone, NOT a v0.1 VirtualRail value loss.
            Some(Ok(_)) | Some(Err(RailError::AlreadyFunded)) => {
                if let Some(ChainState::Reconciled { pending_draw }) = self.chain_state.get_mut(cid)
                {
                    *pending_draw = None;
                }
            }
            // Transient (outage / insufficient escrow) or no rail (the no-rail interim): leave the
            // pinned draw for a retry — never mark it done, never leak the carve.
            _ => {}
        }
    }

    /// The prepay carve draw owed at a reconciling close, PINNED to `(named CKPT_REF, P)` — the
    /// evidenced basis: an own operative checkpoint, ELSE a chained successor's imported checkpoint
    /// (F6.6), ELSE a birth (no accruals → nothing owed). Never LIVE metering (F6-k). Returns `None`
    /// when nothing is owed: not prepay (the postpay payer runs the meed leg), a converted channel
    /// (off-baseline draw deferred — a §6.4 standing obligation), a zero carve, or a birth. Computed
    /// ONCE at the first close and stored, so a later checkpoint cannot move it.
    fn compute_pending_draw(&self, cid: &[u8; 8]) -> Option<([u8; 32], u128)> {
        if self.channels.get(cid).map(|s| s.mode()) != Some(Mode::Prepay) {
            return None; // postpay: the payer runs the meed leg in its final settlement round
        }
        if self.driver.settlement_terms(cid)?.conversion_required {
            return None; // converted: off-baseline draw deferred (standing obligation)
        }
        // The evidenced accruals basis + its CKPT_REF: own operative checkpoint, else the imported
        // checkpoint of a chained successor that signed none of its own. A birth has neither → None.
        let (ckpt_ref, accruals) = if let Some(op) = self.operative.get(cid) {
            (op.ckpt_ref, op.accruals.clone())
        } else if let Some(b) = self.imported_basis.get(cid) {
            (b.ckpt_ref, b.accruals.clone())
        } else {
            return None;
        };
        // Option W: pin the OWN-CUMULATIVE watermark target (not the per-round carve) — the close
        // draw advances `funded_p` to it, subsuming any in-flight interim round idempotently.
        let target_p = self.cumulative_target_p(cid, &accruals)?;
        (target_p > 0).then_some((ckpt_ref, target_p))
    }

    /// The Option W own-cumulative meed **watermark target** `target_P` (DENOM) at a
    /// deterministic (unity) basis: `floor((Σ accruals − Σ imported_opening_settled) / 10 000)` —
    /// the channel's OWN cumulative carve, subtracting ONLY what a predecessor already funded
    /// (`imported_basis.opening_settled_r`; empty → 0 for a first-generation channel), NEVER the
    /// running `settled_r` (= imported + own). Computed via the SAME F7 `outstanding_meed_per_role
    /// → divide_round` the postpay creditor uses, so the on-chain advance `ΔP = target_P − funded_p` is
    /// exactly the F6.2 difference-of-cumulative-floors the B-move already computes (the wide-arithmetic
    /// zone is untouched). `None` on an inconsistent history (duplicate/non-ascending roles) or when
    /// `target_P = 0` (nothing own-accrued to advance — the caller treats it as a no-op).
    fn cumulative_target_p(&self, cid: &[u8; 8], accruals: &[(u8, BigUint)]) -> Option<u128> {
        for w in accruals.windows(2) {
            if w[0].0 >= w[1].0 {
                return None;
            }
        }
        let imported = self.imported_basis.get(cid).map(|b| &b.opening_settled_r);
        let zero = BigUint::from(0u8);
        let mut accrued: Vec<U256> = Vec::with_capacity(accruals.len());
        let mut settled: Vec<U256> = Vec::with_capacity(accruals.len());
        for (role, n) in accruals {
            accrued.push(fee::u256_from_biguint(n).ok()?);
            let s = imported
                .and_then(|v| v.iter().find(|(r, _)| r == role))
                .map(|(_, v)| v)
                .unwrap_or(&zero);
            settled.push(fee::u256_from_biguint(s).ok()?);
        }
        let outstanding = reconcile::outstanding_meed_per_role(&accrued, &settled).ok()?;
        let div = fee::divide_round(&outstanding, &Rate::new(1, 1).ok()?).ok()?;
        if !div.leg {
            return None; // target_P = 0: nothing own-accrued to advance
        }
        u128::try_from(fee::biguint_from_u256(div.p)).ok()
    }

    /// The bounded **reconciliation dust** for a channel (the reconcile-only
    /// resolution): the amount by which the merchant's whole-chain carve
    /// reservation (`outstanding_merchant_net`, `floor(Σaccrued/1e4)`) exceeds the per-channel
    /// watermark actually distributed — precisely `floor(Σaccrued/1e4) − floor(Σimported_settled/1e4)
    /// − target_P`, which is `∈ {0, 1}` per hop by floor superadditivity. It is **0 for a first-
    /// generation channel**, and the accepted ≤1µ/hop §10.2 dust ONLY for a chained successor that
    /// settled meed before chaining (`imported_settled ≠ 0`). The merchant SURFACES this so its
    /// books tie out and the sub-unit is an explicit, attributed, bounded line item rather than a
    /// silent gap: the payer paid this much less than the quote (a bounded payer discount the
    /// merchant absorbs — < 0.00001% at any economically-sensible settlement size). The alternative
    /// "Option A" would instead charge it to the payer by moving the reconciliation carve onto the
    /// per-channel floor, at the cost of realigning the shared paytp-f7 arithmetic (contract + RI) —
    /// **deliberately NOT taken** (RI-only, no contract change).
    pub fn reconciliation_dust(&self, cid: &[u8; 8]) -> u128 {
        let accruals = match self
            .operative
            .get(cid)
            .map(|op| op.accruals.clone())
            .or_else(|| self.imported_basis.get(cid).map(|b| b.accruals.clone()))
        {
            Some(a) => a,
            None => return 0,
        };
        let carve = |rows: &[(u8, BigUint)]| -> u128 {
            let cols: Vec<U256> = rows
                .iter()
                .filter_map(|(_, n)| fee::u256_from_biguint(n).ok())
                .collect();
            u128::try_from(fee::biguint_from_u256(reconcile::meed_carve(&cols))).unwrap_or(0)
        };
        let imported = self
            .imported_basis
            .get(cid)
            .map(|b| carve(&b.opening_settled_r))
            .unwrap_or(0);
        let target_p = self.cumulative_target_p(cid, &accruals).unwrap_or(0);
        carve(&accruals)
            .saturating_sub(imported)
            .saturating_sub(target_p)
    }

    /// Compute the reconciled imported position a successor opens at (F6.6), for the
    /// `Pending` predecessor `cid` whose final checkpoint the successor names `named_ref`.
    /// Computed at **import** (not frozen at close), so a late funding credited to a
    /// `Pending` predecessor is imported verbatim. Returns `None` (→ `PAYTP_CHAIN_REJECTED`)
    /// on any inconsistency. Three findings converge here:
    ///  - **(F3):** metering is the **named checkpoint** — the operative bilateral
    ///    checkpoint (`self.operative`), NOT the live state (uncheckpointed slices within `E`
    ///    are not imported); its reference must equal `named_ref`.
    ///  - **(F5):** for a birth/stillborn predecessor (no operative checkpoint), the
    ///    deterministic **F6-e synthetic-checkpoint reference is RECOMPUTED** (via the one
    ///    canonical `StillbornState` builder) and matched against `named_ref` — never trusting
    ///    a payer-supplied ref.
    ///  - **(F1) interaction:** the imported `B` is the **F6-e reconciled position on the
    ///    same named-checkpoint basis** the settlement path credits against, so the two agree.
    fn compute_chain_snapshot(&self, cid: &[u8; 8], named_ref: &[u8; 32]) -> Option<ChainSnapshot> {
        let ch = self.channels.get(cid)?;
        let payer_key = self.driver.payer_key(cid)?;
        let t = self.driver.settlement_terms(cid)?;
        let established_at = self.channel_established_at.get(cid).copied()?;
        let led = self.ledger.get(cid);
        let opening_settled_r: Vec<(u8, BigUint)> =
            led.map(|l| l.settled_r.clone()).unwrap_or_default();
        let opening_net_legs = led.map(|l| l.net_legs_sum).unwrap_or(0);
        let opening_funding = led.map(|l| l.funding_sum).unwrap_or(0);
        let mode = ch.mode();

        // Metering basis = the NAMED checkpoint (F3), its reference matched to `named_ref`.
        let (cum_total, accruals) = match self.operative.get(cid) {
            Some(op) => {
                if op.ckpt_ref != *named_ref {
                    return None; // successor named a non-final / stale checkpoint
                }
                (
                    u128::try_from(op.cum_total.clone()).ok()?,
                    op.accruals.clone(),
                )
            }
            None => {
                // Birth chaining (F5-a): supported ONLY for a channel with NO metered
                // value — a **funded-but-unmetered** float (typically a prepay deposit) whose
                // connection dropped before any slice landed (the Tier-1 persistence case).
                // Its deterministic F6-e synthetic checkpoint (`cum_total = 0`)
                // is RECOMPUTED here via the one canonical `StillbornState` builder and matched
                // against `named_ref` (never a payer-supplied ref). A channel that
                // metered value but never CHECKPOINTED (`cum_total > 0`, no operative) has no
                // bilateral anchor (F6.6 clause (b)) and cannot chain — it settles/refunds and
                // opens fresh (no value lost: the consumed value is kept, the remainder
                // refunded). Onward-chaining THROUGH a stillborn (imported `cum_total > 0`, no
                // own checkpoint) is likewise deferred (F5-a).
                if ch.cum_total() != 0 {
                    return None;
                }
                let accruals = ch.accruals(); // all-zero for an unmetered channel
                let still = paytp_core::channel::checkpoint::StillbornState {
                    channel_id: *cid,
                    prepay: mode == Mode::Prepay,
                    cum_total: BigUint::from(0u8),
                    accruals: accruals.clone(),
                    settled_sum: BigUint::from(0u8),
                    net_legs_sum: BigUint::from(opening_net_legs),
                    funding_sum: BigUint::from(opening_funding),
                    timestamp: established_at,
                    // v1 does not wire onward-chaining THROUGH a stillborn (a non-zero
                    // `prev_ref`); an unchained stillborn's synthetic checkpoint has none.
                    prev_ref: [0u8; 32],
                };
                let synthetic_ref = still
                    .synthetic_checkpoint()
                    .ok()?
                    .synthetic_reference()
                    .ok()?;
                if synthetic_ref != *named_ref {
                    return None; // recomputed F6-e reference ≠ the payer's named ref
                }
                (0, accruals)
            }
        };

        // Guard: reject an impossible `settled_r > accrued` history before importing;
        // clamp only `B`, never the ledger openings.
        let accrued_u: Vec<U256> = accruals
            .iter()
            .map(|(_, a)| fee::u256_from_biguint(a))
            .collect::<Result<_, _>>()
            .ok()?;
        let settled_u: Vec<U256> = accruals
            .iter()
            .map(|(role, _)| {
                let s = opening_settled_r
                    .iter()
                    .find(|(r, _)| r == role)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                fee::u256_from_biguint(&s)
            })
            .collect::<Result<_, _>>()
            .ok()?;
        reconcile::outstanding_meed_per_role(&accrued_u, &settled_u).ok()?;

        // Imported B = the F6-e reconciled position on the named-checkpoint basis (F3),
        // clamped to the predecessor's window (an over-deposit's excess is forfeit to the
        // window but still returnable as deposit — F6.4; never rejected).
        let imported_balance = imported_balance_f6e(
            mode,
            cum_total,
            &opening_settled_r,
            opening_net_legs,
            opening_funding,
            ch.bound_lower(),
            ch.bound_upper(),
        );

        let terms_fingerprint = chain_terms_fingerprint(
            mode,
            &t.seed_instance,
            &t.denom,
            &t.baseline_net,
            &t.fin_meed,
            &t.fin_denom,
            t.th_value,
            t.th_time,
        );
        Some(ChainSnapshot {
            cum_total,
            accruals,
            opening_settled_r,
            opening_net_legs,
            opening_funding,
            imported_balance,
            payer_key,
            mode,
            terms_fingerprint,
            established_at,
        })
    }
}

/// The F6-e reconciled imported `B` on the named-checkpoint basis (F3), clamped to the mode
/// window: postpay `CUM − Σfunding − Σnet − floor(ΣE/10000)`; prepay `CUM − Σfunding` =
/// `−(Σfunding − CUM)`. Clamp (never reject) an over-deposit — its excess is forfeit to the
/// window yet returnable as deposit (F6.4). This is the **live opening `B`** for the successor's
/// flow control, and the window clamp is applied ONLY here. It shares the F6-e formula with
/// `StillbornState::synthetic_balance` and equals it exactly **only when the clamp is a no-op**
/// (a non-over-deposit position). On an over-deposit the two diverge: this returns the clamped
/// window bound, whereas the hashed synthetic `BALANCE` uses the exact, UNclamped
/// `synthetic_balance` — the value both parties hash into the checkpoint reference, which must
/// never be clamped or the reference would fork.
fn imported_balance_f6e(
    mode: Mode,
    cum: u128,
    settled_r: &[(u8, BigUint)],
    net_legs: u128,
    funding: u128,
    bound_lower: i128,
    bound_upper: i128,
) -> i128 {
    let settled_carve: u128 =
        u128::try_from(settled_r.iter().map(|(_, e)| e.clone()).sum::<BigUint>() / 10_000u32)
            .unwrap_or(u128::MAX);
    let paid = match mode {
        // Postpay `B` is the gross unsettled (merchant-net + outstanding meed carve).
        Mode::Postpay => funding
            .saturating_add(net_legs)
            .saturating_add(settled_carve),
        // Prepay `B` = consumption − deposit (negative while a deposit stands); the meed
        // is drawn from the deposit, not netted here (F6-f / F6-e prepay form).
        Mode::Prepay => funding,
    };
    // Compute `cum − paid` in the u128 domain FIRST (exact, no wrap), THEN narrow to i128
    // with a sign-preserving saturating conversion, before clamping into the mode's bounds.
    // Both the naive `(cum as i128).saturating_sub(paid as i128)` (correct only while
    // |cum − paid| ≤ i128::MAX — it wraps both operands and relies on the wraps cancelling)
    // and clamping the operands first (which erases a small delta between two ≥ 2¹²⁷
    // operands to 0) are wrong at the u128 edges.
    // Infeasible amounts, but the difference-first form is correct across the whole u128
    // domain: the magnitude `|cum − paid|` is an exact u128, saturated to the i128 range
    // only if it truly exceeds it, keeping the sign.
    let b: i128 = if cum >= paid {
        i128::try_from(cum - paid).unwrap_or(i128::MAX)
    } else {
        i128::try_from(paid - cum).map(|d| -d).unwrap_or(i128::MIN)
    };
    b.clamp(bound_lower, bound_upper)
}

/// A recomputed deterministic round: `(meed P if E ≥ 1, per-role E_r, net OUTPUTS)`.
type RecomputedRound = (Option<u128>, Vec<(u8, BigUint)>, Vec<Output>);

/// The operative checkpoint's reference + metering snapshot (F6.3/F6-f).
struct Operative {
    ckpt_ref: [u8; 32],
    cum_total: BigUint,
    /// Per-role accrued meed numerators, ascending role (the checkpoint's `ACCRUALS`).
    accruals: Vec<(u8, BigUint)>,
}

/// The per-channel settled side of the F6-f reconciliation (completed rounds).
#[derive(Default)]
struct Ledger {
    /// Σ `E_r` per role across completed rounds (ascending role).
    settled_r: Vec<(u8, BigUint)>,
    /// Σ net-leg DENOM value across completed rounds.
    net_legs_sum: u128,
    /// Σ credited funding (DENOM µ-units).
    funding_sum: u128,
    /// Optimistic-concurrency version: bumped on every **confirmed round** (NOT on a funding
    /// credit — F1). Serialization (F6-l) is the primary concurrency control (at most one
    /// in-flight round per channel), so under it this version never stales anything; it is the
    /// **backstop** — should a round ever race a confirm (a serialization bypass), the moved
    /// version rejects the second stale proof before it folds `E_r`, barring the overlapping-round
    /// double-count. The quiescence guard (`on_close`) deliberately does NOT read this (a stray
    /// bump must not be able to silently unblock a chain-close).
    version: u64,
}

/// The creditor's one-decision record for a settlement round (F6.5), populated after
/// the round's economics are verified against the operative checkpoint at propose time.
struct RoundDecision {
    /// Fingerprint of the round's economic **terms** (all but `CREDITED`/signatures)
    /// — a second proposal with a different fingerprint for the same round is refused.
    terms_fp: [u8; 32],
    /// Proposal hashes this merchant has countersigned for the round (a retry grows
    /// `CREDITED`, so the hash changes across retries with identical terms).
    proposal_hashes: std::collections::HashSet<[u8; 32]>,
    /// The debtor's `SETTLEMENT_PROOF`s for this round, retained as evidence (F6-f).
    proofs: Vec<SettlementProof>,
    /// The round's verified net `OUTPUTS` — each matched by a net leg before CONFIRMED.
    outputs: Vec<Output>,
    /// The round's aggregate meed `P` (verified `= INSTANCE_LEG.AMOUNT`), or `None`
    /// for an `E = 0` round with no meed leg.
    meed_amount: Option<u128>,
    /// The round's verified per-role extinguished `E_r` (ascending role) — folded into
    /// the ledger's `settled_r` when the **meed leg** finalizes (F6-f: the meed is
    /// credited **independently of the net leg**, F6-m2), not only at full CONFIRMED.
    e_r: Vec<(u8, BigUint)>,
    /// F6-m: the meed leg's `E_r` has been folded into `settled_r`. The **authority** for
    /// "already folded" (idempotency): a later full proof settles the net leg / emits
    /// CONFIRMED without re-folding `E_r`. Set the first time the meed claim-record
    /// finalizes on-rail for this round (a deterministic round funds meed first, F5-h,
    /// and the net leg may lag / drop — the round must still credit the finalized meed).
    meed_folded: bool,
    /// F6-m: the round's net leg(s) have been folded into `net_legs_sum` (all `outputs`
    /// matched on-rail). Tracked independently of `meed_folded` so either leg may
    /// finalize first; CONFIRMED is emitted once BOTH are done (or `E = 0` → no meed).
    net_folded: bool,
    /// F6-m: the meed leg's finalized on-rail time, retained so a *later* net-only proof
    /// can still enforce the F6.4 ordering (net finalizes no earlier than meed) even
    /// though the meed leg is not re-presented in that proof.
    meed_final_time: Option<u64>,
    /// `true` for a deterministic (unity-rate, `DENOM = BASELINE_ASSET`) round whose
    /// economics were **recomputed and verified** against the operative checkpoint at
    /// propose time — only these are CONFIRMED on-rail. An off-baseline round's rate
    /// verification needs the oracle (deferred), so its CONFIRMED stays deferred.
    deterministic: bool,
    /// The channel ledger's `version` when this round's economics were verified. Its
    /// proof confirms only if the ledger is still at this version (optimistic
    /// concurrency — a round that raced another confirmed round is stale and rejected).
    ledger_version: u64,
    /// Whether the round has already been CONFIRMED (its `E_r`/net folded into the
    /// ledger) — a re-proof re-emits the same receipt without double-counting.
    confirmed: bool,
    /// F6-n prepay interim round only: the rail reference of the merchant's advance once
    /// it has been submitted (`advance_channel_meed` returned `Ok`), retained so a
    /// finality-lagging retry re-checks the SAME advance's finality without re-drawing
    /// (the lock-before-draw discipline; the watermark is idempotent by absolute position).
    /// `None` for a postpay round and for an interim round whose advance has not yet landed.
    draw_ref: Option<String>,
    /// **Option W (F6-o):** the round's own-cumulative meed **watermark target** `target_P =
    /// floor((Σ accruals − imported_settled) / 1e4)` — the cumulative position `funded_p` is advanced
    /// to (the draw / leg is `advance_channel_meed(…, target_P)`, idempotent by absolute position).
    /// **Prepay:** the `amount` the `PREPAY_DRAW_COMPLETED` receipt carries + the wallet checks against
    /// its own metering (the merchant draws). **Postpay:** the `INSTANCE_LEG.amount` the payer's 0x01
    /// leg must reach — the merchant binds the advance fact (`funded_p ≥ target_P`) at proof rather
    /// than a per-round claim record. `None` only for an `E = 0` round (nothing owed → no meed leg).
    target_p: Option<u128>,
}

/// A fingerprint over a `SETTLEMENT_PROPOSE`'s **terms** — `OUTPUTS`, the
/// `INSTANCE_LEG` `AMOUNT`/`EXTINGUISHED`, and `CONVERSION` — deliberately
/// **excluding `CREDITED`** (which grows across a round's retries, F6.5) and the
/// signatures. Two proposals with the same fingerprint are the same round's terms.
fn terms_fingerprint(p: &SettlementPropose) -> [u8; 32] {
    fn put(b: &mut Vec<u8>, x: &[u8]) {
        b.extend_from_slice(&(x.len() as u32).to_be_bytes());
        b.extend_from_slice(x);
    }
    let mut b = Vec::new();
    b.extend_from_slice(&p.channel_id);
    b.extend_from_slice(&p.ckpt_ref);
    b.extend_from_slice(&(p.outputs.len() as u32).to_be_bytes());
    for o in &p.outputs {
        put(&mut b, &tlv::encode_uint_biguint(&o.amount));
        put(&mut b, o.asset.as_bytes());
        put(&mut b, o.dest.as_bytes());
    }
    match &p.instance_leg {
        Some(l) => {
            b.push(1);
            put(&mut b, &tlv::encode_uint_biguint(&l.amount));
            b.extend_from_slice(&(l.extinguished.len() as u32).to_be_bytes());
            for (role, e) in &l.extinguished {
                b.push(*role);
                put(&mut b, &tlv::encode_uint_biguint(e));
            }
            // CREDITED excluded on purpose — it grows across retries (F6.5).
        }
        None => b.push(0),
    }
    match &p.conversion {
        Some(c) => {
            b.push(1);
            put(&mut b, c.rate.as_bytes());
            b.extend_from_slice(&c.rate_time.to_be_bytes());
            b.extend_from_slice(&c.rate_exp.to_be_bytes());
            b.extend_from_slice(&c.rate_grace.to_be_bytes());
        }
        None => b.push(0),
    }
    sha256(&b)
}

/// Map a slice-acceptance failure to the carriage taxonomy (F6-b): a MAC failure is
/// the generic pre-auth rejection (no state leak); a bound hit — reachable only by a
/// MAC-valid slice, hence an authenticated sender — draws its specific error.
fn map_accept_err(e: paytp_core::channel::state::AcceptError) -> CarriageError {
    use paytp_core::channel::state::AcceptError::*;
    match e {
        BadMac => CarriageError::Rejected,
        SeqInvalid => CarriageError::SeqInvalid,
        WindowExceeded => CarriageError::WindowExceeded,
        EvidenceRequired => CarriageError::EvidenceRequired,
        NotOpen => CarriageError::Closed,
    }
}

/// `type-octet ‖ object bytes` (F5-a).
fn framed(octet: u8, obj: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + obj.len());
    out.push(octet);
    out.extend_from_slice(obj);
    out
}

#[cfg(test)]
mod tests;
