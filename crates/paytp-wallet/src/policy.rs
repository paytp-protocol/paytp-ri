//! `WalletPolicy` — all spending authority (§7.2, §10.4, Part 1b).
//!
//! Every value-moving action the wallet takes passes a policy gate first: paying
//! a quote, opening a channel, streaming a slice, and deciding whether to keep
//! streaming when a meed round is overdue. The trait also carries the pure §10.3
//! **path-selection** hook (`select_path`) — choosing among offered payment paths
//! on the payer's total cost, honoring operator policy over the wallet's own meed.
//! The trait is the substitution boundary: an interaction layer MUST allow the
//! operator to select an external wallet (§10.4), so the wallet is behind this trait
//! and never bundled — M7's substitution test drives a *second* implementation
//! through the same methods.
//!
//! The v0.1 [`StaticPolicy`] is a static budget + explicit-consent model. It is
//! deliberately pure (no interior mutability): running-budget accounting across
//! transactions is the caller's concern; a policy decides one action at a time.

use paytp_core::tier0::quote::Quote;

/// A per-action spend decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approve,
    /// Denied, with a static reason for the audit trail / caller error.
    Deny(&'static str),
}

impl Decision {
    pub fn is_approved(&self) -> bool {
        matches!(self, Decision::Approve)
    }
}

/// The wallet's answer when a meed settlement round is overdue on a prepay
/// channel (F6.5 conformant halt): a conformant wallet stops streaming until the
/// round settles, rather than keep accruing unpaid meed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltOrContinue {
    Halt,
    Continue,
}

/// The channel parameters a policy weighs at open time — the subset of
/// `CHANNEL_AUTH` that bears on spend authority (§7.2). Built by the wallet from
/// the terms it is about to sign.
#[derive(Debug, Clone)]
pub struct ChannelTerms {
    pub denom: String,
    /// The channel spend ceiling `L` (postpay credit limit / prepay deposit limit).
    pub limit_l: u128,
    /// The unevidenced-value cap `E`.
    pub limit_e: u128,
    pub th_value: u128,
    pub th_time: u64,
    /// `true` = prepay (deposit-before-consume), `false` = postpay.
    pub prepay: bool,
}

/// A candidate payment path the wallet selects among (§10.3). **Every field comes from a source
/// the wallet TRUSTS** — the merchant-SIGNED offer (price, folded into `cost`), a trusted
/// rate/oracle (the rail/gas/conversion part of `cost`), and the signed `MEED_VECTOR`
/// (`meed_share_bp`) — **NEVER** a figure the untrusted interaction layer asserts. That is the
/// whole point of putting selection behind the wallet boundary: if the cost inputs came from the
/// IL, the IL could spoof a path cheap to steer the wallet into the IL's own meed-maximal choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCandidate {
    /// Opaque path/offer identifier (e.g. the offer's index in the signed quote).
    pub id: u32,
    /// The payer's TOTAL cost for this path (price + rail/gas/conversion), µ-units, from the
    /// trusted source(s).
    pub cost: u128,
    /// The meed share (basis points) the SELECTING software earns on this path, from the signed
    /// `MEED_VECTOR` (`0` for a non-PayTP path that earns nothing). Carried for DISCLOSURE only —
    /// the selection rule NEVER optimizes for it (§10.3: serve the payer, not own meed).
    pub meed_share_bp: u16,
}

/// The wallet's §10.3 selection outcome + the disclosure it must surface (the "disclose the share
/// it earns" / "surface a costlier choice with its reason" obligations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSelection {
    /// The chosen path's id.
    pub chosen: u32,
    /// The chosen path's payer total cost.
    pub cost: u128,
    /// The minimum available payer total cost among the offered, non-excluded paths — the
    /// cost-minimal benchmark the payer is entitled to.
    pub cost_minimal: u128,
    /// `cost − cost_minimal`: the payer delta a costlier operator-authorized choice DISCLOSES
    /// (`0` when the cost-minimal path was chosen). §10.3 — preferring a costlier (e.g. PayTP) path
    /// is legitimate only under explicit operator policy, and the delta is always disclosed.
    pub cost_delta: u128,
    /// The meed share (bp) the software earns on the CHOSEN path — the §10.3 "disclose the share it
    /// earns" obligation, surfaced from the signed `MEED_VECTOR`.
    pub meed_share_bp: u16,
    /// Why this path was chosen — the audit/disclosure basis.
    pub reason: SelectReason,
}

/// Why the wallet chose a path (§10.3 audit trail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectReason {
    /// The cost-minimal path among the offered set — the default, payer-first outcome.
    CostMinimal,
    /// A costlier path the OPERATOR policy explicitly authorized; `cost_delta` discloses the excess.
    OperatorAuthorizedCostlier,
}

/// The §10.3 selection core, shared by the [`WalletPolicy::select_path`] default and any policy that
/// carries operator preferences. Among `candidates` not in `excluded`, pick the **cost-minimal** path
/// (ties broken by the lowest `id`, so selection is deterministic); but if `authorized_costlier` names
/// an offered, non-excluded, strictly-costlier path, pick THAT and disclose the delta. The meed share
/// is NEVER an input to the choice — only carried through for disclosure. Returns `None` iff no path is
/// selectable (empty set, or every path excluded by operator policy).
pub fn select_cost_minimal(
    candidates: &[PathCandidate],
    excluded: &[u32],
    authorized_costlier: Option<u32>,
) -> Option<PathSelection> {
    // The cheapest offered, non-excluded path — the payer's entitlement. Tie-break on `id` so the
    // result is deterministic and never silently meed-driven.
    let cheapest = candidates
        .iter()
        .filter(|c| !excluded.contains(&c.id))
        .min_by(|a, b| a.cost.cmp(&b.cost).then(a.id.cmp(&b.id)))?;
    let cost_minimal = cheapest.cost;
    // An operator-authorized costlier path is honored only if it is actually offered, not excluded,
    // and strictly costlier than the minimum (otherwise it IS the cost-minimal choice).
    let chosen = authorized_costlier
        .and_then(|id| {
            candidates
                .iter()
                .find(|c| c.id == id && !excluded.contains(&c.id) && c.cost > cost_minimal)
        })
        .unwrap_or(cheapest);
    let cost_delta = chosen.cost - cost_minimal;
    let reason = if cost_delta > 0 {
        SelectReason::OperatorAuthorizedCostlier
    } else {
        SelectReason::CostMinimal
    };
    Some(PathSelection {
        chosen: chosen.id,
        cost: chosen.cost,
        cost_minimal,
        cost_delta,
        meed_share_bp: chosen.meed_share_bp,
        reason,
    })
}

/// All spending authority (Part 1b). Implementations decide; the wallet enforces.
pub trait WalletPolicy {
    /// Budget/consent for a Tier 0 payment. `amount` is the quote's settlement
    /// amount in µ-units; `asset` its CAIP asset id.
    fn approve_quote(&self, q: &Quote, amount: u128, asset: &str) -> Decision;
    /// Limits `L`/`E`/`TH` selection for a channel open.
    fn approve_channel(&self, terms: &ChannelTerms) -> Decision;
    /// Stream flow control: approve a slice of `amt` µ-units on channel `ch`.
    fn approve_slice(&self, ch: [u8; 8], amt: u64) -> Decision;
    /// The F6.5 conformant halt on an overdue meed round.
    fn on_overdue_meed(&self, ch: [u8; 8]) -> HaltOrContinue;
    /// §10.3 path selection: choose among candidate paths on the payer's TOTAL COST (from trusted
    /// sources), honoring operator policy over the wallet's own meed. **PURE** — immutable operator
    /// preferences may live in the policy object (like this policy's consent/limits), never a running
    /// store. Returns `None` iff no path is selectable. The DEFAULT is the payer-first rule with NO
    /// operator preferences: strictly the cost-minimal path (never the meed-maximal one).
    fn select_path(&self, candidates: &[PathCandidate]) -> Option<PathSelection> {
        select_cost_minimal(candidates, &[], None)
    }
}

/// The v0.1 static budget + explicit-consent policy.
///
/// Approves a Tier 0 payment iff consent is granted, the asset is on the
/// allowlist, and the amount is within that asset's budget. Approves a channel iff
/// its denom is allowlisted and its `L` is within THAT denom's budget. Approves a
/// slice iff within `per_slice_limit`. Halts on an overdue meed round (the
/// conformant default).
#[derive(Debug, Clone)]
pub struct StaticPolicy {
    pub consent: bool,
    /// Allowlisted assets, each with its OWN per-transaction budget. A single scalar limit
    /// cannot be shared across assets of different decimal scales (a limit sized for an
    /// 18-decimal asset would authorise a catastrophic spend of a 6-decimal one), so the
    /// budget is per asset.
    pub asset_limits: Vec<(String, u128)>,
    pub per_slice_limit: u64,
    /// §10.3 operator selection preference: path ids the operator EXCLUDES/deprioritizes — never
    /// selected, even where they earn the wallet more meed. Empty by default (payer-first
    /// cost-minimal). Immutable operator config, like the budgets — the policy stays pure/stateless.
    pub excluded_paths: Vec<u32>,
    /// §10.3 operator selection preference: a path id the operator explicitly AUTHORIZES even if
    /// costlier than the cost-minimal one (the delta is disclosed). `None` by default. Immutable.
    pub authorized_costlier: Option<u32>,
}

impl StaticPolicy {
    /// A permissive-within-limits default for a single asset.
    pub fn new(asset: impl Into<String>, per_tx_limit: u128) -> Self {
        Self::new_multi([(asset.into(), per_tx_limit)])
    }

    /// A permissive-within-limits default over several allowlisted assets, each with its
    /// own per-transaction budget — e.g. a two-leg payer funds value in BOTH the net asset
    /// and the protocol baseline asset (the meed leg), which are different assets/scales,
    /// so each carries its own limit.
    pub fn new_multi(asset_limits: impl IntoIterator<Item = (impl Into<String>, u128)>) -> Self {
        let asset_limits: Vec<(String, u128)> = asset_limits
            .into_iter()
            .map(|(a, l)| (a.into(), l))
            .collect();
        // The slice ceiling is a coarse per-slice cap = the largest per-asset budget;
        // cumulative channel spend is bounded per-denom by `approve_channel` + the channel
        // state, so this loose ceiling is not itself a drain vector.
        let max = asset_limits.iter().map(|(_, l)| *l).max().unwrap_or(0);
        StaticPolicy {
            consent: true,
            asset_limits,
            per_slice_limit: max.min(u64::MAX as u128) as u64,
            excluded_paths: Vec::new(),
            authorized_costlier: None,
        }
    }

    /// Set the §10.3 operator preference: path ids to EXCLUDE/deprioritize (never selected).
    /// Immutable builder — returns the configured policy (the policy itself stays pure).
    pub fn with_excluded_paths(mut self, ids: impl IntoIterator<Item = u32>) -> Self {
        self.excluded_paths = ids.into_iter().collect();
        self
    }

    /// Set the §10.3 operator preference: a path id explicitly AUTHORIZED even if costlier than the
    /// cost-minimal one (the delta is disclosed on selection).
    pub fn with_authorized_costlier(mut self, id: u32) -> Self {
        self.authorized_costlier = Some(id);
        self
    }

    /// The per-transaction budget for `asset`, if it is allowlisted.
    fn limit_for(&self, asset: &str) -> Option<u128> {
        self.asset_limits
            .iter()
            .find(|(a, _)| a == asset)
            .map(|(_, l)| *l)
    }
}

impl WalletPolicy for StaticPolicy {
    fn approve_quote(&self, _q: &Quote, amount: u128, asset: &str) -> Decision {
        if !self.consent {
            return Decision::Deny("no operator consent");
        }
        match self.limit_for(asset) {
            None => Decision::Deny("asset not on allowlist"),
            Some(limit) if amount > limit => Decision::Deny("amount over per-transaction budget"),
            Some(_) => Decision::Approve,
        }
    }

    fn approve_channel(&self, terms: &ChannelTerms) -> Decision {
        if !self.consent {
            return Decision::Deny("no operator consent");
        }
        match self.limit_for(&terms.denom) {
            None => Decision::Deny("channel denom not on allowlist"),
            // Gate against THIS denom's budget — not a global max across all assets, or a
            // low-limit denom could open a channel up to a high-limit asset's budget.
            Some(limit) if terms.limit_l > limit => Decision::Deny("channel limit over budget"),
            Some(_) => Decision::Approve,
        }
    }

    fn approve_slice(&self, _ch: [u8; 8], amt: u64) -> Decision {
        if amt > self.per_slice_limit {
            return Decision::Deny("slice over per-slice limit");
        }
        Decision::Approve
    }

    fn on_overdue_meed(&self, _ch: [u8; 8]) -> HaltOrContinue {
        HaltOrContinue::Halt
    }

    /// §10.3 selection under this operator's immutable preferences: cost-minimal among the offered,
    /// non-`excluded_paths` paths, unless `authorized_costlier` names a costlier one (delta disclosed).
    /// Pure — reads only the immutable policy config, never a running store.
    fn select_path(&self, candidates: &[PathCandidate]) -> Option<PathSelection> {
        select_cost_minimal(candidates, &self.excluded_paths, self.authorized_costlier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::tier0::quote::Quote;

    fn dummy_quote() -> Quote {
        Quote {
            v: "1".into(),
            resource: "https://x/y".into(),
            nonce: [1; 32],
            exp: 0,
            idem: vec![],
            schema: 1,
            contract: 1,
            registry: 5,
            baseline: "eip155:1".into(),
            grace: 0,
            retry: 0,
            vector: vec![],
            offers: vec![],
            signature: None,
        }
    }

    #[test]
    fn static_policy_budget_asset_and_consent() {
        let p = StaticPolicy::new("eip155:1/native", 1_000_000);
        let q = dummy_quote();
        // Within budget + right asset + consent → approve.
        assert_eq!(
            p.approve_quote(&q, 1_000_000, "eip155:1/native"),
            Decision::Approve
        );
        // Over budget → deny.
        assert!(matches!(
            p.approve_quote(&q, 1_000_001, "eip155:1/native"),
            Decision::Deny(_)
        ));
        // Wrong asset → deny.
        assert!(matches!(
            p.approve_quote(&q, 10, "eip155:1/OTHER"),
            Decision::Deny(_)
        ));
        // No consent → deny everything.
        let mut nc = p.clone();
        nc.consent = false;
        assert!(matches!(
            nc.approve_quote(&q, 1, "eip155:1/native"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn static_policy_channel_and_slice_and_halt() {
        let p = StaticPolicy::new("sol/usdc", 1_000_000);
        let ok = ChannelTerms {
            denom: "sol/usdc".into(),
            limit_l: 500_000,
            limit_e: 100_000,
            th_value: 1000,
            th_time: 60,
            prepay: true,
        };
        assert_eq!(p.approve_channel(&ok), Decision::Approve);
        let over = ChannelTerms {
            limit_l: 2_000_000,
            ..ok.clone()
        };
        assert!(matches!(p.approve_channel(&over), Decision::Deny(_)));
        let wrong_denom = ChannelTerms {
            denom: "sol/other".into(),
            ..ok
        };
        assert!(matches!(p.approve_channel(&wrong_denom), Decision::Deny(_)));
        assert_eq!(p.approve_slice([0; 8], 1_000), Decision::Approve);
        assert!(matches!(
            p.approve_slice([0; 8], u64::MAX),
            Decision::Deny(_)
        ));
        // The conformant default halts on an overdue meed round (F6.5).
        assert_eq!(p.on_overdue_meed([0; 8]), HaltOrContinue::Halt);
    }

    #[test]
    fn select_path_default_is_cost_minimal_and_deterministic() {
        // The DEFAULT hook (no operator preferences) serves the payer: strictly cost-minimal, never
        // the meed-maximal path, with a deterministic lowest-id tie-break.
        let p = StaticPolicy::new("x", 1);
        // Cost-minimal wins even though the pricier path earns the wallet more meed.
        let c = [
            PathCandidate {
                id: 0,
                cost: 200,
                meed_share_bp: 30,
            },
            PathCandidate {
                id: 1,
                cost: 100,
                meed_share_bp: 0,
            },
        ];
        let sel = p.select_path(&c).unwrap();
        assert_eq!((sel.chosen, sel.cost, sel.cost_delta), (1, 100, 0));
        assert_eq!(sel.reason, SelectReason::CostMinimal);
        // Equal cost → deterministic lowest-id tie-break (never silently meed-driven).
        let tie = [
            PathCandidate {
                id: 7,
                cost: 100,
                meed_share_bp: 0,
            },
            PathCandidate {
                id: 3,
                cost: 100,
                meed_share_bp: 30,
            },
        ];
        assert_eq!(p.select_path(&tie).unwrap().chosen, 3);
        // Empty offer set → no selection.
        assert!(p.select_path(&[]).is_none());
    }

    #[test]
    fn select_path_authorized_costlier_must_be_offered_and_strictly_costlier() {
        let c = [
            PathCandidate {
                id: 0,
                cost: 100,
                meed_share_bp: 0,
            },
            PathCandidate {
                id: 1,
                cost: 150,
                meed_share_bp: 30,
            },
        ];
        // Authorizing a costlier OFFERED path selects it and discloses the delta.
        let sel = StaticPolicy::new("x", 1)
            .with_authorized_costlier(1)
            .select_path(&c)
            .unwrap();
        assert_eq!(
            (sel.chosen, sel.cost_delta, sel.reason),
            (1, 50, SelectReason::OperatorAuthorizedCostlier)
        );
        // Authorizing a path that is NOT costlier (or not offered) falls back to cost-minimal.
        let noop = StaticPolicy::new("x", 1)
            .with_authorized_costlier(0) // 0 is already the cheapest
            .select_path(&c)
            .unwrap();
        assert_eq!(
            (noop.chosen, noop.cost_delta, noop.reason),
            (0, 0, SelectReason::CostMinimal)
        );
        let absent = StaticPolicy::new("x", 1)
            .with_authorized_costlier(99) // not in the offer set
            .select_path(&c)
            .unwrap();
        assert_eq!(
            absent.chosen, 0,
            "an authorized path not in the offer set is ignored"
        );
    }

    #[test]
    fn multi_asset_channel_gated_by_denom_not_max() {
        // Regression: a multi-asset policy must gate a channel
        // against ITS denom's budget, not the max across assets — else a low-limit denom
        // could open a channel up to a high-limit asset's budget.
        let p = StaticPolicy::new_multi([("usdc", 1_000_000u128), ("eth", 1_000_000_000_000u128)]);
        let low = ChannelTerms {
            denom: "usdc".into(),
            limit_l: 2_000_000, // > usdc budget (1M), < eth budget
            limit_e: 0,
            th_value: 0,
            th_time: 0,
            prepay: true,
        };
        assert!(matches!(p.approve_channel(&low), Decision::Deny(_)));
        // Within its own denom's budget → approved.
        let ok = ChannelTerms {
            limit_l: 500_000,
            ..low
        };
        assert_eq!(p.approve_channel(&ok), Decision::Approve);
    }
}
