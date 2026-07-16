//! The in-process virtual rail with a native split contract.
//!
//! Programmable finality (a delay after which a ref reaches the `final` level),
//! a deterministic clock (reclaim/contest windows run in test time), and the
//! Tier 0 baseline **split**: a payment to a split address is divided among its
//! configured recipients by the running-`V` rule (F7-d) — each recipient's
//! entitlement is `floor(V × bp / 10 000)`, so a plain-x402 payer that simply
//! pays the split address triggers the division at no extra step (F3-a).

use crate::adapter::{
    AdvancedFact, Finality, RailAdapter, RailCaps, RailError, RailRef, RefInfo, Transfer,
    TransferKind,
};
use crate::instance::{EntryError, EntryStatus, MeedInstance, MeedShare, Payout};
use paytp_core::derive::AddressInputs;
use paytp_core::fee::BP_DENOM;
use paytp_core::tier0::attest::Signed;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn map_entry_err(e: EntryError) -> RailError {
    match e {
        EntryError::Duplicate => RailError::AlreadyFunded,
        EntryError::Lapsed => RailError::Rejected("T_lapse already past"),
        EntryError::ZeroAmount => RailError::Rejected("zero amount"),
        EntryError::NotFound => RailError::Rejected("no such entry"),
        EntryError::Terminal => RailError::Rejected("entry is terminal"),
        EntryError::BadSignature => RailError::Rejected("bad attestation/cancellation"),
        EntryError::Window => RailError::Rejected("window guard"),
    }
}

/// One configured split recipient: a destination and its basis points of the
/// gross. The recipients of a Tier 0 split are the meed destinations plus the
/// merchant (its share is `10 000 − Σ meed bp`), summing to 10 000 (F7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRecipient {
    pub dest: String,
    pub bp: u16,
}

struct SplitState {
    recipients: Vec<SplitRecipient>,
    v_received: u128,
    paid: Vec<u128>,
}

struct Inner {
    clock: u64,
    ledger: HashMap<String, u128>,
    splits: HashMap<String, SplitState>,
    instances: HashMap<String, MeedInstance>,
    refs: HashMap<String, (u64, RefInfo)>, // ref id -> (submit_time, info)
    /// Design A baseline idempotency: payer-presented signed-tx identity → the first
    /// settlement ref. Re-presenting the same authorization returns the same ref and moves no value.
    settle_ids: HashMap<[u8; 32], String>,
    /// Idempotent keyed releases (F6-f close refund): `(CHANNEL_ID, CKPT_REF)` → the first
    /// release's ref, so a replay/retry returns the SAME ref and never double-releases (F6-h).
    release_keys: HashMap<([u8; 8], [u8; 32]), String>,
    finality_delay: u64,
    next_ref: u64,
    outage: bool,
}

/// The in-process rail. `Clone` shares the same underlying state (an `Arc`), so a
/// test/driver can hold a handle to the same rail it hands to a `Carriage` — exactly
/// how a real adapter is a handle to shared external chain state.
#[derive(Clone)]
pub struct VirtualRail {
    inner: Arc<Mutex<Inner>>,
    caps: RailCaps,
}

impl VirtualRail {
    /// A rail where a submitted ref reaches `final` after `finality_delay`
    /// seconds of chain time.
    pub fn new(finality_delay: u64) -> Self {
        VirtualRail {
            inner: Arc::new(Mutex::new(Inner {
                clock: 1_000_000_000,
                ledger: HashMap::new(),
                splits: HashMap::new(),
                instances: HashMap::new(),
                refs: HashMap::new(),
                settle_ids: HashMap::new(),
                release_keys: HashMap::new(),
                finality_delay,
                next_ref: 0,
                outage: false,
            })),
            caps: RailCaps {
                supports_contracts: true,
                finality_levels: vec!["pending".into(), "final".into()],
                // The strongest finality (`final`) is reached `finality_delay` chain-seconds
                // after submit — the same delay `finality()` applies. (`pending` is at submit.)
                finality_delay,
                assets: vec!["virt-usd".into()],
                // Synchronous rail (deterministic clock) — no mempool inclusion race, so the
                // F8-f margin is zero here. A real async adapter declares its own latency.
                inclusion_latency: 0,
            },
        }
    }

    /// Declare a nonzero inclusion latency (F8-f) — for a real async adapter, or to
    /// exercise the merchant's reclaim-margin check in tests.
    pub fn with_inclusion_latency(mut self, secs: u64) -> Self {
        self.caps.inclusion_latency = secs;
        self
    }

    /// Declare the settlement assets this rail supports (`caps().assets`), overriding the
    /// default single demo asset. The wallet's two-leg pre-flight refuses a quote whose net
    /// or meed leg settles in an asset the rail does not route (F4.5 route availability), so
    /// a rail carrying a realistic CAIP-asset two-leg flow must declare those assets here.
    pub fn with_assets(mut self, assets: Vec<String>) -> Self {
        self.caps.assets = assets;
        self
    }

    /// Advance the deterministic clock.
    pub fn advance_clock(&self, secs: u64) {
        self.inner.lock().unwrap().clock += secs;
    }

    /// Inject / clear an outage (submissions revert while set).
    pub fn set_outage(&self, on: bool) {
        self.inner.lock().unwrap().outage = on;
    }

    /// Deploy a baseline split at the address the F4.1 `ADDRESS_INPUTS` derive, **recomputing
    /// and validating the seed from those canonical inputs** and deriving the recipient set from
    /// the SAME inputs — so a caller cannot deploy an *unbound* recipient set at the address.
    /// This mirrors the SVM contract's `deploy_split`
    /// (`contracts/programs/paytp_kit/src/lib.rs`), which does
    /// `require!(derive_seed_split(canonical_bytes) == seed_split)` and then binds the
    /// merchant-net + meed destinations that preimage commits: a `seed` that does not recompute
    /// from `inputs` is **rejected** (`RailError::Rejected`). Closing this on the mock rail is
    /// what lets the public demo *prove* the on-chain seed↔recipients binding (F4-d) rather
    /// than merely assert it; the front-run closure (committing `MERCHANT_NET` in the
    /// seed) is now enforced here, not only on the contract + the wallet's quote re-derivation.
    ///
    /// **First deploy at an address wins** — a later `deploy_split` at the same address is a
    /// no-op, never a silent overwrite (mirrors the contract making an already-initialized split
    /// PDA un-redeployable, so a redeploy cannot clobber a live split's recipients).
    ///
    /// The recipients are the meed destinations (aggregated by destination) plus the merchant at
    /// `10 000 − Σ meed bp` (F7.4), built by [`Self::split_recipients`] from
    /// `inputs.vector` + `inputs.merchant_net`. `inputs.merchant_net` MUST be present (a split
    /// commits its net seat) — [`AddressInputs::seed_split`] enforces it.
    pub fn deploy_split(
        &self,
        seed: &[u8; 32],
        inputs: &AddressInputs,
    ) -> Result<String, RailError> {
        // Recompute the seed from the canonical ADDRESS_INPUTS (F4.1) and reject a mismatch — the
        // mock rail's mirror of the contract's
        // `require!(derive_seed_split(canonical_bytes) == seed_split)`. This is what binds the
        // recipients (derived below from the SAME inputs) to the address: a `seed` naming a
        // different (honest) recipient set can never host these ones (F7.3).
        let expected = inputs.seed_split().map_err(|_| {
            RailError::Rejected("invalid split ADDRESS_INPUTS (missing merchant-net / malformed)")
        })?;
        if *seed != expected {
            return Err(RailError::Rejected(
                "split seed does not recompute from ADDRESS_INPUTS (unbound recipients)",
            ));
        }
        // Derive the recipient set from the SAME inputs that derive the seed (the contract parses
        // the bound destinations out of `canonical_bytes`) — there is no separate caller-supplied
        // recipient set that could desync from the address. `seed_split()` above guaranteed
        // `merchant_net` is present (a split commits its net seat).
        let merchant_net = inputs
            .merchant_net
            .as_deref()
            .expect("seed_split() succeeded, so merchant_net is present (F4.1)");
        let meed: Vec<(String, u16)> = inputs
            .vector
            .iter()
            .map(|e| (e.dest.clone(), e.bp))
            .collect();
        let recipients = Self::split_recipients(&meed, merchant_net)
            .ok_or(RailError::Rejected("meed vector exceeds BP_DENOM"))?;
        Ok(self.deploy_split_raw(seed, recipients))
    }

    /// The address-insertion core shared by [`Self::deploy_split`] (the bound protocol path) and
    /// the test-only [`Self::deploy_split_unchecked`]. First deploy at an address wins.
    fn deploy_split_raw(&self, seed: &[u8; 32], recipients: Vec<SplitRecipient>) -> String {
        let addr = self.derive_address(seed);
        let n = recipients.len();
        let mut inner = self.inner.lock().unwrap();
        inner
            .splits
            .entry(addr.clone())
            .or_insert_with(|| SplitState {
                recipients,
                v_received: 0,
                paid: vec![0u128; n],
            });
        addr
    }

    /// **TEST/DEMO ONLY** — deploy a split from an arbitrary `(seed, recipients)` pair, WITHOUT
    /// binding the recipients to the seed's canonical inputs. This is the low-level rail
    /// primitive the deterministic-mechanics tests/demos use (arbitrary seeds/recipients); it is
    /// `cfg`-gated out of any normal build (`test` or the `test-helpers` feature) so no
    /// value-path caller can reach it — the protocol deploy path is [`Self::deploy_split`], which
    /// recomputes + validates the seed. Never use this where the address must prove it
    /// commits its recipients.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn deploy_split_unchecked(
        &self,
        seed: &[u8; 32],
        recipients: Vec<SplitRecipient>,
    ) -> String {
        self.deploy_split_raw(seed, recipients)
    }

    /// Build the full recipient set for a Tier 0 split: the meed destinations
    /// (aggregated by destination) plus the merchant at `10 000 − Σ meed bp`.
    /// `meed` is `(dest, bp)` per meed-vector entry (§10.1); `merchant_payout`
    /// is where the merchant's 99% lands.
    pub fn split_recipients(
        meed: &[(String, u16)],
        merchant_payout: &str,
    ) -> Option<Vec<SplitRecipient>> {
        // The merchant's share is BP_DENOM − Σ meed bp. A well-formed meed vector's
        // meed sums to MEED_BASE_BP, well within BP_DENOM; reject (→ None) any
        // vector whose meed total exceeds BP_DENOM rather than underflowing the
        // merchant share under a debug-only assert (compiled out in release). This is
        // defense-in-depth at the rail, mirroring `instance.rs` `distribute`'s
        // `bp_total == 0` guard — the caller does not pre-validate the total here. The
        // total is accumulated with checked addition so an oversized slice returns None
        // instead of wrapping; the resulting `merchant_bp` is ≤ BP_DENOM, so the u16
        // conversion never truncates.
        let meed_total = meed
            .iter()
            .try_fold(0u32, |acc, (_, bp)| acc.checked_add(u32::from(*bp)))?;
        let merchant_bp = u16::try_from(BP_DENOM.checked_sub(meed_total)?).ok()?;
        // Aggregate meed bp by destination (two roles may share the fund dest).
        // The `checked_sub(BP_DENOM)` guard above already bounds each subtotal to
        // ≤ meed_total ≤ BP_DENOM ≤ u16::MAX, so this fold cannot overflow here; it
        // still folds with `saturating_add` for uniformity with the sibling aggregation
        // site (`instance::MeedInstance::new`) — belt-and-suspenders should that guard
        // ever be weakened, never a wrap-to-0.
        let mut agg: Vec<(String, u16)> = Vec::new();
        for (dest, bp) in meed {
            match agg.iter_mut().find(|(d, _)| d == dest) {
                Some((_, b)) => *b = b.saturating_add(*bp),
                None => agg.push((dest.clone(), *bp)),
            }
        }
        let mut out: Vec<SplitRecipient> = agg
            .into_iter()
            .map(|(dest, bp)| SplitRecipient { dest, bp })
            .collect();
        out.push(SplitRecipient {
            dest: merchant_payout.to_string(),
            bp: merchant_bp,
        });
        Some(out)
    }

    /// The current balance credited to `addr`.
    pub fn balance(&self, addr: &str) -> u128 {
        *self.inner.lock().unwrap().ledger.get(addr).unwrap_or(&0)
    }

    /// Whether a split is deployed at `addr`.
    pub fn has_split(&self, addr: &str) -> bool {
        self.inner.lock().unwrap().splits.contains_key(addr)
    }

    /// What a submitted ref moved — destination, asset, amount, and the bound
    /// quote nonce (F4.4: the merchant confirms rail arrival itself).
    pub fn ref_target(&self, r: &RailRef) -> Option<RefInfo> {
        self.inner
            .lock()
            .unwrap()
            .refs
            .get(&r.0)
            .map(|(_, info)| info.clone())
    }

    // --- Meed instance / entry machine (F4.3) ---

    /// Deploy a meed instance at the address the F4.1 `ADDRESS_INPUTS` derive, bound to the
    /// `inputs.merchant_key` with the meed division carried by `inputs.vector` (F4.1).
    /// Counterfactual: the funding wallet deploys before first use (§5.6).
    ///
    /// **Seed↔recipients binding enforced (closes the mock-fidelity boundary).** Like
    /// the on-chain kit, this **recomputes** `derive_seed_instance(canonical_bytes)` from `inputs`
    /// and **rejects** a `seed` that does not match (`RailError::Rejected`), then binds the
    /// merchant key + meed destinations that same preimage commits. A rogue recipient set derives
    /// a *different* address, so "front-running with the honest preimage only deploys the honest
    /// instance" now holds on this rail too — not only on the real kit
    /// (`contracts/programs/paytp_kit`) + the wallet's quote re-derivation. Consequently a
    /// settlement `0x01` leg's `funds_claim` fact (F6-m) — which proves *a distributing
    /// claim-record funding executed at the derived instance address* — is anchored to an
    /// instance whose destinations are provably the establishment-bound ones. (The separate
    /// non-distributing-forge closure — a plain transfer can never SET `funds_claim` — is
    /// unchanged.) A launch build still settles against the real contract, never this mock rail.
    pub fn deploy_instance(
        &self,
        seed: &[u8; 32],
        inputs: &AddressInputs,
    ) -> Result<String, RailError> {
        // Recompute the seed from the canonical ADDRESS_INPUTS (F4.1) and reject a mismatch — the
        // mock rail's mirror of the kit's
        // `require!(derive_seed_instance(canonical_bytes) == seed_instance)`. This binds the
        // merchant key + meed destinations (taken below from the SAME inputs) to the address, so a
        // rogue recipient set cannot occupy the honest instance PDA (`seed_instance()` also
        // rejects an instance form that carries a merchant-net seat).
        let expected = inputs.seed_instance().map_err(|_| {
            RailError::Rejected(
                "invalid instance ADDRESS_INPUTS (unexpected merchant-net / malformed)",
            )
        })?;
        if *seed != expected {
            return Err(RailError::Rejected(
                "instance seed does not recompute from ADDRESS_INPUTS (unbound recipients)",
            ));
        }
        // Bind the meed division from the SAME inputs that derive the seed (the contract parses
        // the destination accounts out of `canonical_bytes`). `MeedInstance::new` aggregates by
        // destination (F7.3), so raw per-role entries are fine here.
        let meed: Vec<MeedShare> = inputs
            .vector
            .iter()
            .map(|e| MeedShare {
                dest: e.dest.clone(),
                bp: e.bp,
            })
            .collect();
        Ok(self.deploy_instance_raw(seed, inputs.merchant_key, meed))
    }

    /// The instance-insertion core shared by [`Self::deploy_instance`] (the bound protocol path)
    /// and the test-only [`Self::deploy_instance_unchecked`]. Idempotent: the instance is
    /// counterfactual and address-deterministic — re-deploying MUST NOT wipe an existing
    /// instance's entries / claim-records / residue (all quotes with the same inputs share one
    /// instance).
    fn deploy_instance_raw(
        &self,
        seed: &[u8; 32],
        merchant_key: [u8; 32],
        meed: Vec<MeedShare>,
    ) -> String {
        let addr = self.derive_address(seed);
        self.inner
            .lock()
            .unwrap()
            .instances
            .entry(addr.clone())
            .or_insert_with(|| MeedInstance::new(merchant_key, meed, *seed));
        addr
    }

    /// **TEST/DEMO ONLY** — deploy an instance from an arbitrary `(seed, merchant_key, meed)`
    /// triple, WITHOUT binding them to the seed's canonical inputs. The low-level rail primitive
    /// the deterministic-mechanics tests use (arbitrary seeds); `cfg`-gated out of any normal
    /// build (`test` or the `test-helpers` feature) so no value-path caller can reach it — the
    /// protocol deploy path is [`Self::deploy_instance`], which recomputes + validates the seed
    /// (F7.3). Never use this where the address must prove it commits its recipients.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn deploy_instance_unchecked(
        &self,
        seed: &[u8; 32],
        merchant_key: [u8; 32],
        meed: Vec<MeedShare>,
    ) -> String {
        self.deploy_instance_raw(seed, merchant_key, meed)
    }

    pub fn has_instance(&self, addr: &str) -> bool {
        self.inner.lock().unwrap().instances.contains_key(addr)
    }

    /// The state of a purchase entry, if the instance and entry exist.
    pub fn entry_status(&self, addr: &str, entry_id: &[u8; 32]) -> Option<EntryStatus> {
        self.inner
            .lock()
            .unwrap()
            .instances
            .get(addr)
            .and_then(|i| i.status(entry_id))
    }

    /// `T_exec` of an open reclaim on an entry (F4.4 margin check), if open.
    pub fn reclaim_exec_time(&self, addr: &str, entry_id: &[u8; 32]) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .instances
            .get(addr)
            .and_then(|i| i.reclaim_exec_time(entry_id))
    }

    fn record_ref(inner: &mut Inner, mut info: RefInfo) -> RailRef {
        let id = format!("virt-ref:{}", inner.next_ref);
        inner.next_ref += 1;
        let now = inner.clock;
        // The stored id IS the canonical reference (VirtualRail is 1:1 — no aliasing);
        // callers pass an empty `canonical` and it is set here (F6-d step 3).
        info.canonical = id.clone();
        inner.refs.insert(id.clone(), (now, info));
        RailRef(id)
    }

    /// The escrow-release core, run with the rail lock ALREADY HELD (`inner`). Shared by the plain
    /// [`RailAdapter::release`] (lock → call) and the idempotent [`RailAdapter::release_keyed`]
    /// (lock → key check → call → key insert, all under ONE acquisition), so the keyed release's
    /// check-release-insert is ATOMIC. Splitting it across lock drops (the earlier shape) let two
    /// concurrent same-key callers both observe the key absent and both release, double-draining
    /// the shared escrow — F6-h idempotency requires the WHOLE sequence be atomic.
    fn release_locked(
        inner: &mut Inner,
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        if inner.outage {
            return Err(RailError::Outage);
        }
        // Source-debit guard: a release can never mint value or overdraw the escrow.
        let bal = inner.ledger.get(from).copied().unwrap_or(0);
        if amount == 0 || amount > bal {
            return Err(RailError::Rejected(
                "insufficient escrow balance for release",
            ));
        }
        *inner
            .ledger
            .get_mut(from)
            .expect("balance >= amount > 0 implies the entry exists") -= amount;
        // The unconsumed deposit lands at the payer's refund pointer (a plain payout address,
        // never a split); credit it directly, mirroring `submit`'s plain path. Saturating credit:
        // never PANIC after the source was already debited above (non-atomic under
        // overflow-checks). Infeasible at ≈2^128 for real amounts.
        let bal = inner.ledger.entry(to.to_string()).or_insert(0);
        *bal = bal.saturating_add(amount);
        Ok(Self::record_ref(
            inner,
            RefInfo {
                to: to.to_string(),
                asset: asset.to_string(),
                amount,
                memo: None,
                funds_entry: None,
                funds_claim: None, // an escrow release, not a claim-record funding (F6-m)
                advanced_channel_meed: None, // an escrow release advances no watermark (F6-o)
                canonical: String::new(), // set by record_ref
            },
        ))
    }

    fn apply_payouts(inner: &mut Inner, payouts: Vec<Payout>) {
        for p in payouts {
            let bal = inner.ledger.entry(p.dest).or_insert(0);
            // Saturating: a debit-then-credit (draw/release) must not PANIC on the credit
            // after the source was already debited (overflow-checks on). Infeasible for
            // real amounts (≈2^128), but a panic mid-op would leave no atomic rollback.
            *bal = bal.saturating_add(p.amount);
        }
    }

    /// Fund a purchase entry at an instance (F4.3). The instance **derives** the
    /// `entry_id` from the funding parameters (F4-c); returns `(ref, entry_id)`.
    /// The ref binds to that entry so the merchant can tie the finality proof to
    /// the specific derived entry (F4.4).
    #[allow(clippy::too_many_arguments)]
    pub fn fund_entry(
        &self,
        addr: &str,
        nonce: [u8; 32],
        amount: u128,
        refund_ptr: String,
        t_open: u64,
        t_lapse: u64,
        contest: u64,
        asset: String,
    ) -> Result<(RailRef, [u8; 32]), RailError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.outage {
            return Err(RailError::Outage);
        }
        let now = inner.clock;
        let entry_id = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.fund_entry(nonce, amount, refund_ptr, t_open, t_lapse, contest, now)
                .map_err(map_entry_err)?
        };
        let rref = Self::record_ref(
            &mut inner,
            RefInfo {
                to: addr.to_string(),
                asset,
                amount,
                memo: Some(nonce),
                funds_entry: Some(entry_id),
                funds_claim: None, // an entry funding, not a channel claim-record (F6-m)
                advanced_channel_meed: None, // a Tier 0 entry funding, not a watermark advance (F6-o)
                canonical: String::new(),    // set by record_ref
            },
        );
        Ok((rref, entry_id))
    }

    /// Post an attestation to an entry (F4.3), distributing to recipients.
    pub fn attest_entry(
        &self,
        addr: &str,
        entry_id: [u8; 32],
        signed: &Signed,
    ) -> Result<(), RailError> {
        let mut inner = self.inner.lock().unwrap();
        let payouts = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.attest(entry_id, signed).map_err(map_entry_err)?
        };
        Self::apply_payouts(&mut inner, payouts);
        Ok(())
    }

    /// Post a cancellation to an entry (F4.3), refunding the payer.
    pub fn cancel_entry(
        &self,
        addr: &str,
        entry_id: [u8; 32],
        signed: &Signed,
    ) -> Result<(), RailError> {
        let mut inner = self.inner.lock().unwrap();
        let payouts = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.cancel(entry_id, signed).map_err(map_entry_err)?
        };
        Self::apply_payouts(&mut inner, payouts);
        Ok(())
    }

    /// Open reclaim on an entry (F4.3).
    pub fn open_reclaim(&self, addr: &str, entry_id: [u8; 32]) -> Result<(), RailError> {
        let mut inner = self.inner.lock().unwrap();
        let now = inner.clock;
        let inst = inner
            .instances
            .get_mut(addr)
            .ok_or(RailError::NoSuchAccount)?;
        inst.open_reclaim(entry_id, now).map_err(map_entry_err)
    }

    /// Execute reclaim on an entry (F4.3), refunding the payer after `T_exec`.
    pub fn execute_reclaim(&self, addr: &str, entry_id: [u8; 32]) -> Result<(), RailError> {
        let mut inner = self.inner.lock().unwrap();
        let now = inner.clock;
        let payouts = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.execute_reclaim(entry_id, now).map_err(map_entry_err)?
        };
        Self::apply_payouts(&mut inner, payouts);
        Ok(())
    }

    /// Claim a lapsed entry (F4.3), distributing to recipients.
    pub fn claim_lapsed(&self, addr: &str, entry_id: [u8; 32]) -> Result<(), RailError> {
        let mut inner = self.inner.lock().unwrap();
        let now = inner.clock;
        let payouts = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.claim_lapsed(entry_id, now).map_err(map_entry_err)?
        };
        Self::apply_payouts(&mut inner, payouts);
        Ok(())
    }

    /// Batch execute-reclaim (F4.3): entry ids only, each checked under the
    /// single-entry rules; per-entry results.
    pub fn batch_execute_reclaim(
        &self,
        addr: &str,
        entry_ids: &[[u8; 32]],
    ) -> Vec<Result<(), RailError>> {
        entry_ids
            .iter()
            .map(|id| self.execute_reclaim(addr, *id))
            .collect()
    }

    /// Batch claim-lapsed (F4.3): entry ids only; per-entry results.
    pub fn batch_claim_lapsed(
        &self,
        addr: &str,
        entry_ids: &[[u8; 32]],
    ) -> Vec<Result<(), RailError>> {
        entry_ids
            .iter()
            .map(|id| self.claim_lapsed(addr, *id))
            .collect()
    }

    /// Fund a channel claim-record (F4.2) — the instance derives the key from
    /// `(channel_id, ckpt_ref, P)`; windowless, immediately distributed. Returns
    /// `(ref, derived key)`. A **fresh** credit — the meed `P` is created into the
    /// distribution (postpay: the payer's own transfer executes the leg; or a test).
    pub fn fund_claim_record(
        &self,
        addr: &str,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        amount: u128,
        asset: String,
    ) -> Result<(RailRef, [u8; 32]), RailError> {
        self.fund_claim_record_impl(None, addr, channel_id, ckpt_ref, amount, asset)
    }

    /// DRAW a prepay channel's meed leg **FROM** the held deposit at `from`
    /// (`settle_ptr`) rather than a fresh credit — F6-f: in prepay the merchant is the
    /// debtor and executes the meed from the deposit it holds. The escrow is debited
    /// by `P` before distributing, so value conserves (the deposit funds the meed,
    /// it is never minted) and an overdraw is rejected.
    pub fn draw_claim_record(
        &self,
        from: &str,
        addr: &str,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        amount: u128,
        asset: String,
    ) -> Result<(RailRef, [u8; 32]), RailError> {
        self.fund_claim_record_impl(Some(from), addr, channel_id, ckpt_ref, amount, asset)
    }

    fn fund_claim_record_impl(
        &self,
        from: Option<&str>,
        addr: &str,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        amount: u128,
        asset: String,
    ) -> Result<(RailRef, [u8; 32]), RailError> {
        let mut inner = self.inner.lock().unwrap();
        // No funding during a rail outage — consistent with fund_entry/submit, so an
        // outage-created ref can't later satisfy the settlement meed predicate (F6-m gate).
        if inner.outage {
            return Err(RailError::Outage);
        }
        // DUPLICATE-CLAIM check BEFORE the escrow-balance check (F6-f). A retry after a
        // successful draw finds the escrow already debited by `P`; an escrow-first order
        // returns `Rejected(insufficient escrow)` — which a caller MUST retry — instead of the
        // idempotent `AlreadyFunded` the record's existence warrants, wedging the prepay
        // close-draw (`attempt_prepay_close_draw` never clears `pending_draw`). Existence is
        // the authoritative exactly-once signal; the escrow gates only a genuinely-NEW draw.
        // Read-only, so no state mutation precedes the escrow verification below. A MISSING
        // instance is NOT diagnosed here (no claim record can exist without one): skip the peek
        // and let the escrow check + the `get_mut(addr).ok_or(NoSuchAccount)` commit path below
        // report it exactly as before — so this reorder changes the result in precisely the
        // duplicate-claim case, nothing else.
        if let Some(inst) = inner.instances.get(addr) {
            if inst.claim_record_funded(channel_id, ckpt_ref, amount) {
                return Err(RailError::AlreadyFunded);
            }
        }
        // Prepay draw (F6-f): VERIFY the escrow can cover `P` before any state mutation —
        // the deposit funds the meed, it is never minted and never overdrawn. The
        // actual debit is deferred to the commit point below so no fallible op sits
        // between it and the distribution (mirrors the carriage atomicity discipline).
        if let Some(src) = from {
            let bal = inner.ledger.get(src).copied().unwrap_or(0);
            // `amount == 0` guarded too: it makes `bal >= amount > 0`, so the source
            // entry provably exists and the debit's `get_mut().expect()` cannot fire.
            // (A P = 0 round funds no leg, so a zero draw is degenerate regardless.)
            if amount == 0 || amount > bal {
                return Err(RailError::Rejected(
                    "insufficient escrow balance for meed draw",
                ));
            }
        }
        let (key, payouts) = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.fund_claim_record(channel_id, ckpt_ref, amount)
                .map_err(map_entry_err)?
        };
        // Commit point: the escrow balance was verified above and the lock held
        // throughout, so this debit cannot fail; it and the distribution below apply
        // together (the deposit funds the meed, it is never minted).
        if let Some(src) = from {
            *inner
                .ledger
                .get_mut(src)
                .expect("escrow balance verified above") -= amount;
        }
        Self::apply_payouts(&mut inner, payouts);
        let rref = Self::record_ref(
            &mut inner,
            RefInfo {
                to: addr.to_string(),
                asset,
                amount,
                // The claim-record key NAMES the round (memo), continuity for F6-m and the
                // net-leg-symmetric round bind. But naming is not distribution: the memo is
                // caller-settable (`submit` copies any bytes), so it cannot be the security
                // check. `funds_claim` is the load-bearing DISTRIBUTION fact (F6-m): set here —
                // and ONLY here, on the path that actually ran `fund_claim_record` +
                // `apply_payouts` (the F7-d division to the recipients above) — so the
                // settlement `0x01` leg confirms against a genuinely-distributed record, never
                // a plain transfer that merely carries the key. A non-distributing `submit`
                // leaves `funds_claim` None and can never satisfy the leg.
                memo: Some(key),
                funds_entry: None,
                funds_claim: Some(key),
                advanced_channel_meed: None, // the per-round claim path, not the watermark advance
                canonical: String::new(),    // set by record_ref
            },
        );
        Ok((rref, key))
    }

    fn distribute(state: &mut SplitState, ledger: &mut HashMap<String, u128>) {
        // F7-d running-V distribution: entitlement = floor(V × bp / 10000),
        // computed in BigUint (V × bp can exceed u128 for a large V).
        let v = num_bigint::BigUint::from(state.v_received);
        let denom = num_bigint::BigUint::from(BP_DENOM);
        for (i, r) in state.recipients.iter().enumerate() {
            let ent = (&v * num_bigint::BigUint::from(r.bp)) / &denom;
            let entitlement = u128::try_from(ent).expect("entitlement <= V < 2^128");
            let claimable = entitlement - state.paid[i];
            if claimable > 0 {
                *ledger.entry(r.dest.clone()).or_insert(0) += claimable;
                state.paid[i] = entitlement;
            }
        }
    }

    fn record_payment(inner: &mut Inner, transfer: Transfer) -> Result<RailRef, RailError> {
        match transfer.kind {
            TransferKind::Payment => {
                if inner.splits.contains_key(&transfer.to) {
                    // Fund the split and distribute (auto — anyone can pay it). REJECT a payment
                    // that would overflow the running V rather than silently saturating it (which
                    // would drop the excess unit — value loss): money math never wraps silently
                    // (Cargo.toml `profile.release.overflow-checks`). Unreachable with real amounts
                    // (V ≤ the total supply ≤ u128::MAX), so no conformant flow is affected; this
                    // is defense-in-depth mirroring `split_recipients`' reject-on-overflow.
                    let mut state = inner.splits.remove(&transfer.to).unwrap();
                    match state.v_received.checked_add(transfer.amount) {
                        Some(v) => state.v_received = v,
                        None => {
                            // Put the split back untouched — the rejected payment moved nothing.
                            inner.splits.insert(transfer.to.clone(), state);
                            return Err(RailError::Rejected(
                                "split payment would overflow running V",
                            ));
                        }
                    }
                    VirtualRail::distribute(&mut state, &mut inner.ledger);
                    inner.splits.insert(transfer.to.clone(), state);
                } else {
                    // A plain address (a meed/merchant payout or an EOA).
                    *inner.ledger.entry(transfer.to.clone()).or_insert(0) += transfer.amount;
                }
                Ok(Self::record_ref(
                    inner,
                    RefInfo {
                        to: transfer.to,
                        asset: transfer.asset,
                        amount: transfer.amount,
                        memo: transfer.memo,
                        funds_entry: None,
                        // A plain transfer distributes nothing — even a memo copying a
                        // claim key funds no record, so the settlement meed leg can
                        // never confirm against it (F6-m).
                        funds_claim: None,
                        advanced_channel_meed: None, // a plain transfer advances no watermark (F6-o)
                        canonical: String::new(),    // set by record_ref
                    },
                ))
            }
        }
    }
}

impl RailAdapter for VirtualRail {
    fn caps(&self) -> RailCaps {
        self.caps.clone()
    }

    fn derive_address(&self, seed: &[u8; 32]) -> String {
        // Deterministic, reproducible: address = f(seed). The real invariant is
        // `address = f(SHA-256(ADDRESS_INPUTS))` (§11.2); here the seed already
        // IS that hash, so we render it directly.
        let hex: String = seed[..16].iter().map(|b| format!("{b:02x}")).collect();
        format!("virt:0x{hex}")
    }

    fn submit(&self, transfer: Transfer) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.outage {
            return Err(RailError::Outage);
        }
        Self::record_payment(&mut inner, transfer)
    }

    fn settle(&self, transfer: Transfer, settle_id: [u8; 32]) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.settle_ids.get(&settle_id) {
            return Ok(RailRef(existing.clone()));
        }
        if inner.outage {
            return Err(RailError::Outage);
        }
        let rref = Self::record_payment(&mut inner, transfer)?;
        inner.settle_ids.insert(settle_id, rref.0.clone());
        Ok(rref)
    }

    fn release(
        &self,
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        let mut inner = self.inner.lock().unwrap();
        Self::release_locked(&mut inner, from, to, asset, amount)
    }

    fn release_keyed(
        &self,
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        from: &str,
        to: &str,
        asset: &str,
        amount: u128,
    ) -> Result<RailRef, RailError> {
        // Hold the lock across the WHOLE check-release-insert so the keyed idempotency (F6-h) is
        // ATOMIC: two concurrent same-key calls cannot both observe the key absent and both
        // release (the TOCTOU double-drain). The earlier shape dropped the lock between the check
        // and the release, so under contention an interleaved second `get` slipped through.
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner.release_keys.get(&(channel_id, ckpt_ref)) {
            // Idempotent: this (CHANNEL_ID, basis) already released — return the SAME ref and
            // move nothing, so a replay/retry/restart never double-releases the refund (F6-h).
            return Ok(RailRef(existing.clone()));
        }
        let rref = Self::release_locked(&mut inner, from, to, asset, amount)?;
        inner
            .release_keys
            .insert((channel_id, ckpt_ref), rref.0.clone());
        Ok(rref)
    }

    fn advance_channel_meed(
        &self,
        from: Option<&str>,
        addr: &str,
        channel_id: [u8; 8],
        target_p: u128,
        asset: String,
    ) -> Result<RailRef, RailError> {
        // Synchronous VirtualRail: the value moves + the fact is set at SUBMIT (finality
        // is a co-reporting label). The async rail defers both to finalization.
        let mut inner = self.inner.lock().unwrap();
        if inner.outage {
            return Err(RailError::Outage);
        }
        // Read the instance bind + current watermark; delta = target − funded (own-cumulative).
        let (seed_instance, funded_before) = {
            let inst = inner.instances.get(addr).ok_or(RailError::NoSuchAccount)?;
            (inst.seed_instance(), inst.channel_funded_p(&channel_id))
        };
        let delta = target_p.saturating_sub(funded_before);
        // Prepay draw sources the DELTA from the deposit (F6-f): verify escrow cover BEFORE
        // any mutation — the deposit funds the meed, never minted, never overdrawn. A
        // 0-delta (idempotent) advance debits nothing and needs no escrow.
        if let Some(src) = from {
            if delta > 0 {
                let bal = inner.ledger.get(src).copied().unwrap_or(0);
                if delta > bal {
                    return Err(RailError::Rejected(
                        "insufficient escrow balance for meed advance",
                    ));
                }
            }
        }
        // Advance the per-channel watermark (idempotent; 0-delta → empty payouts).
        let (funded_after, delta2, payouts) = {
            let inst = inner
                .instances
                .get_mut(addr)
                .ok_or(RailError::NoSuchAccount)?;
            inst.advance_channel_meed(channel_id, target_p)
        };
        // Commit point: escrow verified above and the lock held throughout, so this debit
        // cannot fail; it and the distribution apply together (the deposit funds the meed).
        if let Some(src) = from {
            if delta2 > 0 {
                *inner
                    .ledger
                    .get_mut(src)
                    .expect("escrow balance verified above") -= delta2;
            }
        }
        Self::apply_payouts(&mut inner, payouts);
        let rref = Self::record_ref(
            &mut inner,
            RefInfo {
                to: addr.to_string(),
                asset: asset.clone(),
                amount: delta2,
                memo: None,
                funds_entry: None,
                funds_claim: None,
                // The DISTRIBUTION fact (F6-o): set here, and ONLY here, on the path that ran
                // `advance_channel_meed` + `apply_payouts` (the F7.3 division to the
                // recipients). A plain `submit` leaves it None and can never satisfy the leg —
                // the per-channel form of the F6-m closure. A 0-delta re-advance still reports
                // the fact (funded_p unchanged), so an idempotent retry is value-safe.
                advanced_channel_meed: Some(AdvancedFact {
                    channel_id,
                    seed_instance,
                    funded_p: funded_after,
                    delta: delta2,
                    asset,
                }),
                canonical: String::new(), // set by record_ref
            },
        );
        Ok(rref)
    }

    fn finality(&self, r: &RailRef) -> Option<Finality> {
        let inner = self.inner.lock().unwrap();
        let (submit_time, _) = inner.refs.get(&r.0)?;
        let reached = *submit_time + inner.finality_delay;
        if inner.clock >= reached {
            Some(Finality {
                level: "final".into(),
                time: reached,
            })
        } else {
            Some(Finality {
                level: "pending".into(),
                time: *submit_time,
            })
        }
    }

    fn ref_target(&self, r: &RailRef) -> Option<RefInfo> {
        // Delegate to the inherent method (fully qualified to avoid self-recursion).
        VirtualRail::ref_target(self, r)
    }

    fn chain_time(&self) -> u64 {
        self.inner.lock().unwrap().clock
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::derive::{AddressInputs, MeedVectorEntry};

    /// A schema-0x01 split's canonical `ADDRESS_INPUTS`, parameterized by the IL (`0x10`)
    /// destination so a test can build an *honest* set and an *evil* one that differs only in
    /// where the IL share lands (a stolen meed seat).
    fn split_inputs(il_dest: &str) -> AddressInputs {
        AddressInputs {
            merchant_key: [0x11; 32],
            asset: "virt-usd".into(),
            schema: 1,
            vector: vec![
                MeedVectorEntry {
                    role: 0x10,
                    bp: 50,
                    dest: il_dest.into(),
                },
                MeedVectorEntry {
                    role: 0x11,
                    bp: 10,
                    dest: "os-fund".into(),
                },
                MeedVectorEntry {
                    role: 0x12,
                    bp: 30,
                    dest: "wallet".into(),
                },
                MeedVectorEntry {
                    role: 0x13,
                    bp: 10,
                    dest: "dev-fund".into(),
                },
            ],
            contract: 1,
            merchant_net: Some("merchant".into()),
        }
    }

    /// **F7.3 repro — the split front-run / unbound-recipient closure on the mock rail.**
    /// The bound `deploy_split` MUST recompute the seed from `ADDRESS_INPUTS` and REJECT a seed
    /// that does not bind the recipients it is asked to deploy — so a demo/caller cannot deploy a
    /// recipient set the address does not commit (the guarantee the SVM contract enforces via
    /// `require!(derive_seed_split(canonical_bytes) == seed_split)`).
    #[test]
    fn deploy_split_rejects_seed_that_does_not_bind_recipients() {
        let rail = VirtualRail::new(0);
        let honest = split_inputs("il"); // IL share → the honest IL fund
        let evil = split_inputs("attacker"); // IL share → the attacker (a stolen meed seat)
        let honest_seed = honest.seed_split().unwrap();
        // The honest address the payer would be quoted (`payTo`) commits the honest recipients.
        assert_ne!(
            honest_seed,
            evil.seed_split().unwrap(),
            "a different recipient set MUST derive a different seed (else nothing binds)"
        );

        // ATTACK: deploy the EVIL recipients at the HONEST address (the seed the payer pays).
        // The seed does not recompute from the evil inputs → REJECTED (the closure).
        let attack = rail.deploy_split(&honest_seed, &evil);
        assert!(
            matches!(attack, Err(RailError::Rejected(_))),
            "a wrong-recipient seed must be rejected at deploy, got {attack:?}"
        );
        // Nothing was deployed at the honest address by the rejected attack.
        assert!(!rail.has_split(&rail.derive_address(&honest_seed)));

        // The honest deploy (seed recomputes from its own inputs) succeeds and binds the honest
        // recipients: paying the split credits the honest IL fund, never the attacker.
        let addr = rail.deploy_split(&honest_seed, &honest).unwrap();
        rail.submit(Transfer {
            to: addr,
            asset: "virt-usd".into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        assert_eq!(
            rail.balance("il"),
            5_000,
            "the honest IL fund is paid its 50 bp"
        );
        assert_eq!(
            rail.balance("attacker"),
            0,
            "the attacker is never a bound recipient"
        );
    }

    /// **F7.3 repro — the instance sibling.** The bound `deploy_instance` MUST recompute the
    /// seed from `ADDRESS_INPUTS` and REJECT a seed that does not bind the meed destinations it is
    /// asked to deploy (mirrors the kit's `derive_seed_instance(canonical_bytes) == seed_instance`).
    #[test]
    fn deploy_instance_rejects_seed_that_does_not_bind_recipients() {
        let rail = VirtualRail::new(0);
        // The instance form carries no merchant seat (F4.1), so `merchant_net` is absent.
        let honest = AddressInputs {
            merchant_net: None,
            ..split_inputs("il")
        };
        let evil = AddressInputs {
            merchant_net: None,
            ..split_inputs("attacker")
        };
        let honest_seed = honest.seed_instance().unwrap();
        assert_ne!(honest_seed, evil.seed_instance().unwrap());

        // ATTACK: deploy the EVIL meed at the HONEST instance address → REJECTED.
        let attack = rail.deploy_instance(&honest_seed, &evil);
        assert!(
            matches!(attack, Err(RailError::Rejected(_))),
            "a wrong-recipient instance seed must be rejected at deploy, got {attack:?}"
        );
        assert!(!rail.has_instance(&rail.derive_address(&honest_seed)));

        // The honest deploy succeeds and binds the honest meed destinations.
        let addr = rail.deploy_instance(&honest_seed, &honest).unwrap();
        rail.fund_claim_record(&addr, [0u8; 8], [0u8; 32], 1_000_000, "virt-usd".into())
            .unwrap();
        assert_eq!(
            rail.balance("il"),
            500_000,
            "the honest IL fund is paid its 50 bp"
        );
        assert_eq!(
            rail.balance("attacker"),
            0,
            "the attacker is never a bound recipient"
        );
    }

    #[test]
    fn batch_claim_lapsed_over_multiple_entries() {
        // Two funded entries lapse; a batch claim distributes both (entry-ids only).
        let rail = VirtualRail::new(1);
        let seed = [0x07u8; 32];
        let addr = rail.deploy_instance_unchecked(
            &seed,
            [0x55; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 50,
                },
            ],
        );
        let (_, e1) = rail
            .fund_entry(
                &addr,
                [0xa1; 32],
                1000,
                "r".into(),
                1_000_000_100,
                1_000_000_200,
                30,
                "a".into(),
            )
            .unwrap();
        let (_, e2) = rail
            .fund_entry(
                &addr,
                [0xa2; 32],
                1000,
                "r".into(),
                1_000_000_100,
                1_000_000_200,
                30,
                "a".into(),
            )
            .unwrap();
        rail.advance_clock(300); // past T_lapse
        let results = rail.batch_claim_lapsed(&addr, &[e1, e2]);
        assert!(results.iter().all(|r| r.is_ok()));
        // Each entry (1000) split 50/50 → il and wallet each 500 + 500 = 1000.
        assert_eq!(rail.balance("il"), 1000);
        assert_eq!(rail.balance("wallet"), 1000);
    }

    #[test]
    fn split_divides_schema_01_correctly() {
        // §10.1 example scaled: V = 1_000_000 → merchant 990000 (99%),
        // IL 5000, OS→fund 1000, wallet 3000, fund 1000 (fund total 2000).
        let rail = VirtualRail::new(2);
        let seed = [0x01u8; 32];
        let meed = vec![
            ("il".to_string(), 50u16),
            ("fund".to_string(), 10), // OS → fund
            ("wallet".to_string(), 30),
            ("fund".to_string(), 10), // dev fund
        ];
        let recips = VirtualRail::split_recipients(&meed, "merchant").expect("valid vector");
        let addr = rail.deploy_split_unchecked(&seed, recips);
        rail.submit(Transfer {
            to: addr.clone(),
            asset: "virt-usd".into(),
            amount: 1_000_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        assert_eq!(rail.balance("merchant"), 990_000);
        assert_eq!(rail.balance("il"), 5_000);
        assert_eq!(rail.balance("wallet"), 3_000);
        assert_eq!(rail.balance("fund"), 2_000); // OS 1000 + dev fund 1000
                                                 // Conservation.
        assert_eq!(
            rail.balance("merchant")
                + rail.balance("il")
                + rail.balance("wallet")
                + rail.balance("fund"),
            1_000_000
        );
    }

    #[test]
    fn split_recipients_rejects_meed_over_bp_denom() {
        // A meed vector whose meed exceeds 100% (BP_DENOM) is rejected rather than
        // underflowing the merchant share — the schema check rejects such a vector
        // upstream, so this is the rail's defense-in-depth (regression for the
        // u16-underflow residual). 9000 + 2000 = 11000 bp > 10 000.
        let over = vec![("il".to_string(), 9000u16), ("fund".to_string(), 2000u16)];
        assert!(VirtualRail::split_recipients(&over, "merchant").is_none());
        // Exactly 100% meed leaves the merchant a zero share, but does not underflow.
        let full = vec![("il".to_string(), 10_000u16)];
        let recips = VirtualRail::split_recipients(&full, "merchant").expect("valid");
        assert_eq!(recips.iter().find(|r| r.dest == "merchant").unwrap().bp, 0);
        // The normal schema-0x01 100-bp path is unchanged: merchant keeps 9900 bp.
        let ok = vec![
            ("il".to_string(), 50u16),
            ("fund".to_string(), 10),
            ("wallet".to_string(), 30),
            ("fund".to_string(), 10),
        ];
        let recips = VirtualRail::split_recipients(&ok, "merchant").expect("valid");
        assert_eq!(
            recips.iter().find(|r| r.dest == "merchant").unwrap().bp,
            9900
        );
    }

    #[test]
    fn release_debits_source_and_credits_dest_conserving() {
        // The escrow-release primitive (C1 of the prepay close-refund): moving the
        // unconsumed deposit from settle_ptr to refund_ptr must DEBIT the source, not
        // mint — the sibling of `submit`, which only credits.
        let rail = VirtualRail::new(0);
        // Seed an escrow balance the way prepay funding lands at settle_ptr.
        rail.submit(Transfer {
            to: "escrow".into(),
            asset: "virt-usd".into(),
            amount: 1_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        assert_eq!(rail.balance("escrow"), 1_000);
        // Release part of it to the payer's refund pointer.
        rail.release("escrow", "refund-ptr", "virt-usd", 300)
            .unwrap();
        assert_eq!(rail.balance("escrow"), 700); // debited
        assert_eq!(rail.balance("refund-ptr"), 300); // credited
        assert_eq!(rail.balance("escrow") + rail.balance("refund-ptr"), 1_000); // conserved
                                                                                // Cannot overdraw the escrow, and a rejected release moves nothing.
        assert!(matches!(
            rail.release("escrow", "refund-ptr", "virt-usd", 701),
            Err(RailError::Rejected(_))
        ));
        assert_eq!(rail.balance("escrow"), 700);
        // A zero release is rejected, not a silent no-op that records a 0-ref.
        assert!(matches!(
            rail.release("escrow", "refund-ptr", "virt-usd", 0),
            Err(RailError::Rejected(_))
        ));
    }

    #[test]
    fn draw_claim_record_debits_escrow_and_distributes_conserving() {
        // C2 of the prepay close-refund: the merchant draws the meed leg FROM the
        // held deposit (settle_ptr) to the recipients — debiting the escrow, never
        // minting (F6-f: in prepay the merchant is the debtor). Contrast plain
        // fund_claim_record, which credits a fresh P (postpay/test).
        let rail = VirtualRail::new(0);
        let instance = rail.deploy_instance_unchecked(
            &[0x77u8; 32],
            [0x88; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 30,
                },
                MeedShare {
                    dest: "fund".into(),
                    bp: 20,
                },
            ],
        );
        // The prepay deposit sits at settle_ptr (where funding lands it).
        rail.submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: 10_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        // Draw a meed P = 10_000 µ-units from the deposit → recipients.
        rail.draw_claim_record(
            "settle-ptr",
            &instance,
            [0; 8],
            [0; 32],
            10_000,
            "virt-usd".into(),
        )
        .unwrap();
        // Escrow debited by exactly P; recipients credited by P (50/30/20); no mint.
        assert_eq!(rail.balance("settle-ptr"), 0);
        assert_eq!(rail.balance("il"), 5_000);
        assert_eq!(rail.balance("wallet"), 3_000);
        assert_eq!(rail.balance("fund"), 2_000);
        assert_eq!(
            rail.balance("il") + rail.balance("wallet") + rail.balance("fund"),
            10_000
        );
        // A draw cannot overdraw the escrow, and a rejected draw moves nothing.
        rail.submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: 100,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        assert!(matches!(
            rail.draw_claim_record(
                "settle-ptr",
                &instance,
                [1; 8],
                [1; 32],
                500,
                "virt-usd".into()
            ),
            Err(RailError::Rejected(_))
        ));
        assert_eq!(rail.balance("settle-ptr"), 100);
    }

    #[test]
    fn duplicate_draw_is_alreadyfunded_even_when_escrow_now_insufficient() {
        // the prepay close-draw MUST be idempotent (F6-f "retryable,
        // exactly-once via `Duplicate`"). The FIRST successful draw debits the escrow by
        // `P`, so a retry — a crash / lost-ack between the rail draw and the carriage
        // clearing `pending_draw`, then an idempotent close retransmit re-attempting the
        // pinned draw — finds the escrow short of `P`. The DUPLICATE-CLAIM check MUST run
        // BEFORE the escrow-balance check so the retry returns the idempotent
        // `AlreadyFunded` (the record already landed), NOT `Rejected("insufficient
        // escrow")` — which `attempt_prepay_close_draw` treats (correctly, per the
        // AlreadyFunded/Rejected contract) as a transient failure to retry, wedging the
        // close forever. Escrow-first ordering is the bug this repro pins.
        let rail = VirtualRail::new(0);
        let instance = rail.deploy_instance_unchecked(
            &[0x77u8; 32],
            [0x88; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 30,
                },
                MeedShare {
                    dest: "fund".into(),
                    bp: 20,
                },
            ],
        );
        // Fund the escrow with EXACTLY one draw's worth of `P`.
        rail.submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: 10_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        // First draw succeeds: escrow → 0, recipients credited `P` (50/30/20).
        rail.draw_claim_record(
            "settle-ptr",
            &instance,
            [0; 8],
            [0; 32],
            10_000,
            "virt-usd".into(),
        )
        .unwrap();
        assert_eq!(rail.balance("settle-ptr"), 0);
        // Retry the SAME (channel, ckpt, P) draw against the now-empty escrow. The claim
        // record already landed, so this is idempotent: it MUST be AlreadyFunded, never
        // Rejected(insufficient escrow).
        assert_eq!(
            rail.draw_claim_record(
                "settle-ptr",
                &instance,
                [0; 8],
                [0; 32],
                10_000,
                "virt-usd".into()
            ),
            Err(RailError::AlreadyFunded)
        );
        // The retry moved NOTHING — recipients paid once, escrow debited once.
        assert_eq!(rail.balance("settle-ptr"), 0);
        assert_eq!(rail.balance("il"), 5_000);
        assert_eq!(rail.balance("wallet"), 3_000);
        assert_eq!(rail.balance("fund"), 2_000);
    }

    #[test]
    fn prefund_then_draw_pays_enablers_exactly_once_escrow_untouched() {
        // an adversary (or the merchant itself) front-runs the
        // prepay close by funding the claim record directly; the merchant's close draw then sees
        // it already funded and returns `AlreadyFunded` WITHOUT debiting the deposit. This pins the
        // load-bearing invariant: the enablers are paid `P` **exactly once** (never doubled, never
        // shorted — the USP holds), and the draw is idempotent. Two facts it documents:
        //   (1) the pre-existing `fund_claim_record` **mint** (a fresh credit, no source debit) is
        //       the `VirtualRail` mock-fidelity boundary — the real kit requires the funder to
        //       actually deposit+distribute `P` and reverts the honest draw as duplicate, so the
        //       "merchant pockets `P` for free" does not exist on-chain (a launch build never
        //       settles here).
        //   (2) this is the escrow-SUFFICIENT duplicate case, which the earlier code handled
        //       IDENTICALLY (`AlreadyFunded` via the instance `Duplicate` guard, debit skipped) —
        //       so the reorder neither introduces nor widens it. No honest party loses: the
        //       enablers are whole, and a prepay payer's refund is computed against the checkpoint,
        //       independent of who funded the carve.
        let rail = VirtualRail::new(0);
        let instance = rail.deploy_instance_unchecked(
            &[0x77u8; 32],
            [0x88; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 30,
                },
                MeedShare {
                    dest: "fund".into(),
                    bp: 20,
                },
            ],
        );
        // The merchant holds the prepay deposit's consumed portion at settle_ptr (>= P: SUFFICIENT).
        rail.submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: 10_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        // Attacker FRONT-RUNS: funds the claim record directly (a fresh credit — the mock mint).
        rail.fund_claim_record(&instance, [0; 8], [0; 32], 10_000, "virt-usd".into())
            .unwrap();
        let enablers = |r: &VirtualRail| r.balance("il") + r.balance("wallet") + r.balance("fund");
        assert_eq!(enablers(&rail), 10_000, "enablers paid P by the front-run");
        // Merchant's close draw: escrow is SUFFICIENT (10_000 >= P), yet the record exists → the
        // draw is the idempotent `AlreadyFunded` and does NOT debit settle_ptr.
        assert_eq!(
            rail.draw_claim_record(
                "settle-ptr",
                &instance,
                [0; 8],
                [0; 32],
                10_000,
                "virt-usd".into()
            ),
            Err(RailError::AlreadyFunded)
        );
        // The enablers were paid P EXACTLY ONCE (not 2P — no double-distribution); settle_ptr is
        // untouched (the merchant holds it — on a real chain it was the funder, not an honest
        // party, who paid the enablers; the USP "carve reaches the enablers once" holds).
        assert_eq!(
            enablers(&rail),
            10_000,
            "enablers paid exactly once, never doubled"
        );
        assert_eq!(
            rail.balance("settle-ptr"),
            10_000,
            "escrow untouched (draw idempotent)"
        );
    }

    #[test]
    fn finality_reached_after_delay() {
        let rail = VirtualRail::new(5);
        let r = rail
            .submit(Transfer {
                to: "eoa".into(),
                asset: "virt-usd".into(),
                amount: 10,
                kind: TransferKind::Payment,
                memo: None,
            })
            .unwrap();
        assert_eq!(rail.finality(&r).unwrap().level, "pending");
        rail.advance_clock(5);
        assert_eq!(rail.finality(&r).unwrap().level, "final");
    }

    #[test]
    fn outage_reverts_submit() {
        let rail = VirtualRail::new(1);
        rail.set_outage(true);
        assert_eq!(
            rail.submit(Transfer {
                to: "x".into(),
                asset: "virt-usd".into(),
                amount: 1,
                kind: TransferKind::Payment,
                memo: None,
            }),
            Err(RailError::Outage)
        );
    }

    #[test]
    fn outage_reverts_fund_claim_record() {
        // F6-m gate: fund_claim_record must respect the outage guard like fund_entry/submit,
        // so an outage-created ref can never satisfy the settlement meed predicate.
        let rail = VirtualRail::new(1);
        let inst = rail.deploy_instance_unchecked(
            &[0x11; 32],
            [0x22; 32],
            vec![MeedShare {
                dest: "il".into(),
                bp: 100,
            }],
        );
        rail.set_outage(true);
        assert_eq!(
            rail.fund_claim_record(&inst, [0; 8], [0; 32], 1_000, "virt-usd".into()),
            Err(RailError::Outage)
        );
    }

    #[test]
    fn funds_claim_set_only_by_distributing_kind() {
        use paytp_core::derive::claim_record_id;
        // F6-m — `funds_claim` (the settlement meed leg's load-bearing fact) is set ONLY by
        // the claim-record FUNDING kind (which runs the F7-d division), never by a plain transfer
        // that merely copies the rail-public key into its memo.
        let rail = VirtualRail::new(0);
        let seed = [0x33u8; 32];
        let inst = rail.deploy_instance_unchecked(
            &seed,
            [0x44; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 60,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 40,
                },
            ],
        );
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];
        let ckpt = [0xcd; 32];
        let key = claim_record_id(&seed, &cid, &ckpt, 1_000);

        // (a) Genuine postpay funding distributes to the recipients AND sets funds_claim = Some(key).
        let (r_fund, k) = rail
            .fund_claim_record(&inst, cid, ckpt, 1_000, "virt-usd".into())
            .unwrap();
        assert_eq!(k, key);
        assert!(
            rail.balance("il") + rail.balance("wallet") > 0,
            "the genuine funding must distribute to the recipients"
        );
        assert_eq!(rail.ref_target(&r_fund).unwrap().funds_claim, Some(key));

        // (b) Prepay draw is also a distributing kind → funds_claim set to its own key.
        rail.submit(Transfer {
            to: "escrow".into(),
            asset: "virt-usd".into(),
            amount: 1_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        let (r_draw, _) = rail
            .draw_claim_record(
                "escrow",
                &inst,
                [9; 8],
                [0xef; 32],
                1_000,
                "virt-usd".into(),
            )
            .unwrap();
        assert_eq!(
            rail.ref_target(&r_draw).unwrap().funds_claim,
            Some(claim_record_id(&seed, &[9; 8], &[0xef; 32], 1_000))
        );

        // (c) The forge: a PLAIN submit to the instance address carrying the SAME key as its memo
        // distributes NOTHING and leaves funds_claim None — the attack the 0x01 check rejects.
        let before = rail.balance("il") + rail.balance("wallet");
        let r_plain = rail
            .submit(Transfer {
                to: inst.clone(),
                asset: "virt-usd".into(),
                amount: 1_000,
                kind: TransferKind::Payment,
                memo: Some(key),
            })
            .unwrap();
        let info = rail.ref_target(&r_plain).unwrap();
        assert_eq!(info.memo, Some(key), "the memo is forgeable...");
        assert_eq!(
            info.funds_claim, None,
            "...but the distribution fact is not"
        );
        assert_eq!(
            rail.balance("il") + rail.balance("wallet"),
            before,
            "the plain transfer paid no recipient"
        );

        // (d) release and fund_entry are not claim-record fundings → funds_claim None.
        rail.submit(Transfer {
            to: "src".into(),
            asset: "virt-usd".into(),
            amount: 500,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        let r_rel = rail.release("src", "dst", "virt-usd", 100).unwrap();
        assert_eq!(rail.ref_target(&r_rel).unwrap().funds_claim, None);
        let (r_entry, _) = rail
            .fund_entry(
                &inst,
                [0xa5; 32],
                100,
                "refund".into(),
                1_000_000_100,
                1_000_000_200,
                30,
                "virt-usd".into(),
            )
            .unwrap();
        assert_eq!(rail.ref_target(&r_entry).unwrap().funds_claim, None);
    }

    #[test]
    fn advance_channel_meed_debits_delta_sets_fact_and_is_idempotent() {
        // Option W (F6-o) on the sync rail: an advance sources the DELTA from the deposit,
        // distributes per role, and sets the `advanced_channel_meed` fact (funded_p +
        // delta + channel + instance). An interim-then-close advance moves only the residual;
        // a re-advance is a 0-delta no-op (the #1 anti-double-draw), the fact still proving
        // the watermark. Conservation: escrow debited by exactly funded_p; recipients get it.
        let rail = VirtualRail::new(0);
        let seed = [0x77u8; 32];
        let instance = rail.deploy_instance_unchecked(
            &seed,
            [0x88; 32],
            vec![
                MeedShare {
                    dest: "il".into(),
                    bp: 50,
                },
                MeedShare {
                    dest: "wallet".into(),
                    bp: 30,
                },
                MeedShare {
                    dest: "fund".into(),
                    bp: 20,
                },
            ],
        );
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];
        rail.submit(Transfer {
            to: "settle-ptr".into(),
            asset: "virt-usd".into(),
            amount: 10_000,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        // Interim advance to W1 = 4000: delta 4000 debited, recipients get 50/30/20 of 4000.
        let r1 = rail
            .advance_channel_meed(Some("settle-ptr"), &instance, cid, 4_000, "virt-usd".into())
            .unwrap();
        let f1 = rail.ref_target(&r1).unwrap().advanced_channel_meed.unwrap();
        assert_eq!(
            (f1.channel_id, f1.seed_instance, f1.funded_p, f1.delta),
            (cid, seed, 4_000, 4_000)
        );
        assert_eq!(rail.balance("settle-ptr"), 6_000);
        assert_eq!(rail.balance("il"), 2_000);
        // Close advance to W2 = 10000: only the 6000 residual moves.
        let r2 = rail
            .advance_channel_meed(
                Some("settle-ptr"),
                &instance,
                cid,
                10_000,
                "virt-usd".into(),
            )
            .unwrap();
        let f2 = rail.ref_target(&r2).unwrap().advanced_channel_meed.unwrap();
        assert_eq!((f2.funded_p, f2.delta), (10_000, 6_000));
        assert_eq!(rail.balance("settle-ptr"), 0);
        // Recipients hold exactly the cumulative carve; escrow fully drained (conserves).
        assert_eq!(
            rail.balance("il") + rail.balance("wallet") + rail.balance("fund"),
            10_000
        );
        assert_eq!(rail.balance("il"), 5_000);
        // Idempotent re-advance to the SAME target: 0-delta no-op, no further debit, fact still set.
        let r3 = rail
            .advance_channel_meed(
                Some("settle-ptr"),
                &instance,
                cid,
                10_000,
                "virt-usd".into(),
            )
            .unwrap();
        let f3 = rail.ref_target(&r3).unwrap().advanced_channel_meed.unwrap();
        assert_eq!((f3.funded_p, f3.delta), (10_000, 0));
        assert_eq!(
            rail.balance("il") + rail.balance("wallet") + rail.balance("fund"),
            10_000
        );
        // A plain submit to the instance address leaves `advanced_channel_meed` None
        // (the per-channel non-distributing forge is closed, F6-o).
        let plain = rail
            .submit(Transfer {
                to: instance.clone(),
                asset: "virt-usd".into(),
                amount: 500,
                kind: TransferKind::Payment,
                memo: None,
            })
            .unwrap();
        assert_eq!(rail.ref_target(&plain).unwrap().advanced_channel_meed, None);
    }

    #[test]
    fn settle_idempotent_returns_same_ref_and_credits_once() {
        let rail = VirtualRail::new(0);
        let transfer = Transfer {
            to: "merchant".into(),
            asset: "virt-usd".into(),
            amount: 1_000,
            kind: TransferKind::Payment,
            memo: None,
        };
        let r1 = rail.settle(transfer.clone(), [0x5e; 32]).unwrap();
        let r2 = rail.settle(transfer, [0x5e; 32]).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(rail.balance("merchant"), 1_000);
        assert_eq!(rail.ref_target(&r1).unwrap().canonical, r1.0);
    }

    #[test]
    fn release_keyed_is_atomic_under_concurrency_no_double_release() {
        // REPRO (release_keyed TOCTOU double-release).
        // `release_keyed` advertises idempotency (F6-h): the FIRST call for a
        // `(CHANNEL_ID, CKPT_REF)` key moves value; every later call returns that SAME ref and
        // "moves nothing", so a replay/retry/crash-restart never double-releases the shared
        // settle_ptr. The implementation checked `release_keys` under the lock, DROPPED the
        // lock, called `release` (which re-locks), then re-locked to insert the key — so the
        // check-release-insert was NOT atomic. Two concurrent same-key calls could BOTH observe
        // the key absent and BOTH perform a real `release`, double-draining the escrow.
        // VirtualRail is `Clone` over one `Arc<Mutex<Inner>>`, so concurrent calls are intended.
        //
        // The spec-correct outcome is EXACTLY ONE release, no matter how many callers race the
        // key. `settle-ptr` is seeded with N×amount so a double-release manifests as value loss
        // (every racing release succeeds) rather than the extra ones merely erroring on the
        // balance guard. N contending threads (not 2) defeat mutex "barging": under N-way
        // contention the lock hand-off interleaves a second `get` before the winner's `insert`.
        let cid = [9u8; 8];
        let ckpt = [0xab; 32];
        let amount = 6_000u128;
        const N: u128 = 16;
        for _ in 0..300 {
            let rail = VirtualRail::new(0);
            rail.submit(Transfer {
                to: "settle-ptr".into(),
                asset: "virt-usd".into(),
                amount: N * amount,
                kind: TransferKind::Payment,
                memo: None,
            })
            .unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(N as usize));
            let handles: Vec<_> = (0..N)
                .map(|_| {
                    let rail = rail.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        rail.release_keyed(cid, ckpt, "settle-ptr", "refund", "virt-usd", amount)
                    })
                })
                .collect();
            let refs: Vec<RailRef> = handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap().expect(
                        "release_keyed must be idempotent — a duplicate key returns the SAME ref, \
                         never an error",
                    )
                })
                .collect();
            // Exactly one release of value: refund credited `amount` once (never more), escrow
            // debited once. A double-release drains the escrow more than once for one close key.
            assert_eq!(
                rail.balance("refund"),
                amount,
                "double-release: refund credited more than once for one close key"
            );
            assert_eq!(
                rail.balance("settle-ptr"),
                (N - 1) * amount,
                "double-release: escrow drained more than once"
            );
            assert!(
                refs.iter().all(|r| *r == refs[0]),
                "keyed release must return the SAME ref for a duplicate key"
            );
        }
    }

    #[test]
    fn split_v_received_overflow_is_rejected_not_silently_saturated() {
        // REPRO (u128 split-saturation value loss).
        // `record_payment`'s split branch accumulated the running V with `v_received
        // .saturating_add`. An adversarial review posited value loss: pay `u128::MAX`, then pay `1`; V
        // saturates at MAX, the 2nd unit distributes to NOBODY, yet a ref records `amount=1` and
        // the merchant would honor it. Two facts this pins:
        //   (1) FALSE POSITIVE for real value loss — the premise is UNREACHABLE under value
        //       conservation. V reaches u128::MAX only if the ENTIRE u128 value supply sits in
        //       ONE split, leaving nothing to fund a "second" unit; the only way to construct it
        //       is the mock's MINTING plain `submit` (credit with NO source debit — the
        //       documented mock-fidelity boundary), never a real source-debited rail whose total
        //       supply is itself ≤ u128::MAX.
        //   (2) Even so, silently saturating a MONEY accumulator violates the repo's money-math
        //       rule ("never wrap silently", Cargo.toml `profile.release.overflow-checks`). So
        //       `record_payment` now REJECTS a split payment that would overflow V (fail-closed)
        //       rather than eat the unit — matching `split_recipients`' reject-on-overflow. No
        //       conformant flow reaches this (real amounts ≪ 2^128); the value can no longer
        //       vanish silently.
        let rail = VirtualRail::new(0);
        let recips = VirtualRail::split_recipients(&[("il".to_string(), 100u16)], "merchant")
            .expect("valid vector");
        let addr = rail.deploy_split_unchecked(&[0x01u8; 32], recips);
        // First payment: V 0 → u128::MAX (no overflow), distributing the whole "supply".
        rail.submit(Transfer {
            to: addr.clone(),
            asset: "virt-usd".into(),
            amount: u128::MAX,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
        let distributed = rail.balance("merchant") + rail.balance("il");
        // A second unit would overflow V. Pre-fix this silently saturated (returned Ok, dropped
        // the unit — the value-loss that review flagged); it must now be REJECTED fail-closed.
        let second = rail.submit(Transfer {
            to: addr.clone(),
            asset: "virt-usd".into(),
            amount: 1,
            kind: TransferKind::Payment,
            memo: None,
        });
        assert!(
            matches!(second, Err(RailError::Rejected(_))),
            "a split payment overflowing V must be rejected, got {second:?}"
        );
        // Conservation: the rejected submit moved nothing — the distribution is unchanged.
        assert_eq!(rail.balance("merchant") + rail.balance("il"), distributed);
    }
}
