//! v0.1 governance constants (**§10.1 / F9.5 GAP-FILL F9-e**).
//!
//! These are the release-pinned trust anchors that live *outside* F1–F10's prose
//! but are part of conformance (F9-e). Two classes:
//!
//! - **Fixed design constants** — the schema `0x01` role ids and basis points
//!   (§10.1), and the 100/150 bp base/cap. These are real and final.
//! - **Release-bound values** — the Development Fund destination and the
//!   Foundation registry key. F9-e is explicit that F1–F10 *alone* cannot yield
//!   byte-identical addresses: the fund destination "is not a spec value any more
//!   than the registry key is." They are pinned at the reference implementation's
//!   first release. Until then this module carries **clearly-marked
//!   placeholders** — a build MUST NOT ship these to a real rail.
//!
//! Beyond the sentinel *strings*, [`ensure_governance_ready`] is a **fail-closed
//! guard** wired into the governed value path ([`crate::registry`] resolution and
//! [`crate::tier0`] governed-vector validation): a non-demo/proof build (the
//! `demo-governance` feature off) **refuses** to run a value decision while these
//! placeholders are still in place, so they are impossible to confuse with real
//! governance wiring.

/// Schema ids.
pub const SCHEMA_V0_1: u32 = 0x01;

/// Base role ids (§10.1). Decimal display "16"–"19" (F3-b).
pub const ROLE_INTERACTION_LAYER: u8 = 0x10;
pub const ROLE_OS: u8 = 0x11;
pub const ROLE_WALLET: u8 = 0x12;
pub const ROLE_DEV_FUND: u8 = 0x13;

/// The schema `0x01` base share schedule (§10.1): `(role_id, bp)`, ascending
/// role id, summing to exactly 100 bp. Fixed design constant.
pub const SCHEMA_01_ROLES: &[(u8, u16)] = &[
    (ROLE_INTERACTION_LAYER, 50),
    (ROLE_OS, 10),
    (ROLE_WALLET, 30),
    (ROLE_DEV_FUND, 10),
];

/// Every schema allocates exactly 100 bp to the base roles (§10.1).
pub const MEED_BASE_BP: u16 = 100;
/// The protocol's hard cap: 150 bp, the extra 50 reserved for opt-in service
/// roles (§10.1).
pub const MEED_CAP_BP: u16 = 150;

/// **PLACEHOLDER — release-bound (F9-e), NOT a real address.** The schema-pinned
/// Development Fund destination (§10.1). A CAIP-10 pointer so it is baseline-
/// payable and passes [`crate::pointer::Pointer::parse`]; the account text is an
/// obvious sentinel so it can never be mistaken for a live address.
pub const DEV_FUND_DEST_PLACEHOLDER: &str = "eip155:0:PLACEHOLDER-release-bound-dev-fund";

/// **PLACEHOLDER — release-bound (F9-e), NOT a real address.** The **independent
/// open-source fund** destination (§10.1) that an **absent or unlisted OS** share
/// routes to — a destination **outside the PayTP Foundation's control** (the Linux
/// Foundation to start, changeable only by governance to another independent
/// steward), **distinct from the Development Fund**. Routing an absent OS here,
/// not to the Dev Fund, is the neutrality mechanism (§10.5): no registry decision
/// changes the Foundation's income. Pinned in releases as a **second ship-together
/// constant** beside the Dev Fund destination (F9-e). A CAIP-10 pointer
/// (baseline-payable); the account text is an obvious sentinel.
pub const INDEPENDENT_OS_FUND_DEST_PLACEHOLDER: &str =
    "eip155:0:PLACEHOLDER-release-bound-independent-os-fund";

/// **PLACEHOLDER — release-bound (F9-c/F9-e), NOT a real key.** The Foundation
/// registry key (§10.5). Conformance tests inject their own test key; this exists
/// only so the shape is named. All-`0x11` is a recognizable non-key.
pub const FOUNDATION_REGISTRY_KEY_PLACEHOLDER: [u8; 32] = [0x11; 32];

/// The contract-kit version this RI targets (§5.6, `ADDRESS_INPUTS.CONTRACT`).
pub const CONTRACT_VERSION_V0_1: u32 = 0x01;

/// Cross-party clock-skew allowance (F8.2, `SKEW`): 300 s.
pub const SKEW_SECS: u64 = 300;
/// Delivery-latency allowance for timestamped requests (F8.2, `LATENCY`): 300 s.
/// The `CHANNEL_AUTH`/`ACK_REQUEST` acceptance window is `|now − TIMESTAMP| ≤
/// SKEW + LATENCY` (±600 s total).
pub const LATENCY_SECS: u64 = 300;

/// Whether `role` is one of the schema `0x01` base roles.
pub fn is_base_role(role: u8) -> bool {
    SCHEMA_01_ROLES.iter().any(|&(r, _)| r == role)
}

/// The base bp for a schema-`0x01` role, if any.
pub fn base_bp(role: u8) -> Option<u16> {
    SCHEMA_01_ROLES
        .iter()
        .find(|&&(r, _)| r == role)
        .map(|&(_, bp)| bp)
}

/// Whether the governance destinations this build ships are still the release-bound
/// **PLACEHOLDER** sentinels (F9-e), rather than real addresses substituted at a
/// release. True for this reference implementation, which ships only placeholders.
///
/// This is the runtime fact the fail-closed guard keys on: it stays correct even for
/// a fork that swaps in real destinations but forgets the feature flag — replacing the
/// sentinels makes this `false`, so [`ensure_governance_ready`] then permits the value
/// path automatically.
pub fn governance_constants_are_placeholders() -> bool {
    DEV_FUND_DEST_PLACEHOLDER.contains("PLACEHOLDER")
        || INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.contains("PLACEHOLDER")
        || FOUNDATION_REGISTRY_KEY_PLACEHOLDER == [0x11; 32]
}

/// **Fail-closed governance guard (F9-e).** A value-decision path calls this before it
/// treats a governed destination (Dev Fund / independent-OS fund) as a real recipient.
///
/// Returns `Ok` iff the build may do so — i.e. **either**:
/// - the governance constants are no longer placeholders (a real deployment substituted
///   real addresses, [`governance_constants_are_placeholders`] is `false`); **or**
/// - the build explicitly opted into running on the placeholders via the
///   **`demo-governance`** feature — the reference implementation's own demos, proofs,
///   and conformance builds, which have no real money at stake. (Workspace CI runs
///   `--all-features`, so the feature is on there.)
///
/// Otherwise it returns [`Error::PlaceholderGovernance`]: a **non-demo build refuses to
/// run the value path while it still carries placeholder governance constants**, so it
/// can never silently settle a governed share to an unspendable sentinel. This is the
/// guard beyond the sentinel *strings* that makes the placeholders impossible to confuse
/// with real governance wiring (§10.1 / F9-e): a real deployment MUST replace them (and
/// leaves `demo-governance` off) before any governed value decision will complete.
#[inline]
pub fn ensure_governance_ready() -> crate::Result<()> {
    if cfg!(feature = "demo-governance") || !governance_constants_are_placeholders() {
        Ok(())
    } else {
        Err(crate::error::Error::PlaceholderGovernance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_01_totals_100_bp() {
        let total: u16 = SCHEMA_01_ROLES.iter().map(|&(_, bp)| bp).sum();
        assert_eq!(total, MEED_BASE_BP);
    }

    const _: () = assert!(MEED_BASE_BP <= MEED_CAP_BP);

    #[test]
    fn roles_are_ascending_and_unique() {
        for w in SCHEMA_01_ROLES.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
    }

    #[test]
    fn dev_fund_placeholder_is_a_valid_caip_pointer() {
        let p = crate::pointer::Pointer::parse(DEV_FUND_DEST_PLACEHOLDER).unwrap();
        assert!(p.is_caip(), "dev fund must be baseline-payable (CAIP)");
    }

    #[test]
    fn independent_os_fund_is_a_distinct_valid_caip_pointer() {
        // The OS-absent fallback (§10.1) is baseline-payable AND a **syntactically
        // distinct** placeholder from the Development Fund — a necessary condition for
        // neutrality (a shared address would let an absent OS enrich the Foundation).
        // That the real destination is an *independent steward outside Foundation
        // control* is a release-bound governance fact (F9-e), not provable at this level.
        let p = crate::pointer::Pointer::parse(INDEPENDENT_OS_FUND_DEST_PLACEHOLDER).unwrap();
        assert!(
            p.is_caip(),
            "independent OS fund must be baseline-payable (CAIP)"
        );
        assert_ne!(
            INDEPENDENT_OS_FUND_DEST_PLACEHOLDER, DEV_FUND_DEST_PLACEHOLDER,
            "the OS fallback must not be the Development Fund (§10.1 neutrality)"
        );
    }

    #[test]
    fn governance_constants_are_still_placeholders() {
        // This reference implementation ships ONLY placeholders (F9-e) — the guard's
        // runtime fact must reflect that, so a non-demo build is fail-closed.
        assert!(governance_constants_are_placeholders());
    }

    #[test]
    fn governance_guard_permits_the_demo_build() {
        // The workspace test build runs with the `demo-governance` feature (CI uses
        // `--all-features`), so the fail-closed guard admits the value path here even
        // though the constants are still placeholders. If this build did NOT enable the
        // feature, `ensure_governance_ready()` would return `Err` (placeholders present),
        // so this passing is itself proof the feature is on. The feature-off refusal path
        // is exercised by a production build, not this suite.
        assert!(ensure_governance_ready().is_ok());
    }
}
