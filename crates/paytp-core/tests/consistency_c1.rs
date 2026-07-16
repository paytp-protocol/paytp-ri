//! Formal-spec ↔ RI consistency repros for governed-meed destination correctness (F9.4).
//! The gap — a shape-valid vector that misroutes a governed destination — is CLOSED by
//! `validate_vector_governed`; the repro below is now GREEN against the fixed RI and asserts
//! the SPEC-CORRECT (reject) outcome for misrouted governed destinations.

use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::registry::SnapshotStore;
use paytp_core::tier0::quote::{MeedEntry, Quote};

/// A schema-0x01 vector with correct roles/bp/total but the GOVERNED destinations redirected
/// to an attacker: 0x13 (Development Fund) and 0x11 (OS) point at attacker CAIP pointers instead
/// of the schema-pinned Dev-Fund constant / a registry-listed-or-independent-fund destination.
fn misrouted_governed_vector() -> Vec<MeedEntry> {
    vec![
        // 0x10 interaction-layer + 0x12 wallet are payer-side (own pointers — legitimately free).
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:0xInteractionLayer".into(),
        },
        // 0x11 OS: MUST be registry-listed or the independent-OS-fund pinned constant (F9.4/F5-o).
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: "eip155:1:0xAttackerStealsTheOsShare".into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: "eip155:1:0xWallet".into(),
        },
        // 0x13 Development Fund: MUST equal the schema's pinned constant (F5-o "the 0x13
        // Development Fund destination is the schema's pinned constant").
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: "eip155:1:0xAttackerStealsTheDevFund".into(),
        },
    ]
}

/// A conformant schema-0x01 vector: 0x11 OS → the independent-OS-fund fallback (§10.1), 0x13 →
/// the schema-pinned Dev-Fund constant, 0x10/0x12 → payer-side pointers (freedom).
fn conformant_fallback_vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:il".into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: "eip155:1:wallet".into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

fn quote_with_vector(vector: Vec<MeedEntry>) -> Quote {
    Quote {
        v: "1".into(),
        resource: "https://example/resource".into(),
        nonce: [1; 32],
        exp: 0,
        idem: vec![],
        schema: 1,
        contract: 1,
        registry: 5,
        baseline: "eip155:1".into(),
        grace: 0,
        retry: 0,
        vector,
        offers: vec![],
        signature: None,
    }
}

/// **F9.4 — governed-meed destination correctness, now ENFORCED.**
/// F5-o: "Before acknowledging a CHANNEL_OPEN the merchant MUST validate its 0x0E VECTOR …
/// Destination correctness … the 0x11 OS destination is a recipient in the registry OR the pinned
/// independent-open-source-fund fallback; the 0x13 Development Fund destination is the schema's
/// pinned constant." The context-free `validate_vector_schema_01` checked role/bp/total/CAIP-*syntax*
/// only; it is replaced by `validate_vector_governed(registry)`, which the compiler forces every
/// value-decision caller onto (merchant receive AND wallet fund/sign AND channel open). A malicious
/// merchant (Tier-0 quote) or interaction layer (CHANNEL_AUTH) can no longer redirect the governed
/// 0x11+0x13 shares (20 bp) to an attacker.
#[test]
fn misrouted_governed_meed_destinations_are_rejected() {
    // No registry needed to reject: 0x13 fails against the pinned Dev-Fund constant, and 0x11's
    // attacker CAIP is neither the independent fund nor a listed recipient (empty store, fail-closed).
    let registry = SnapshotStore::default();
    let q = quote_with_vector(misrouted_governed_vector());
    assert!(
        q.validate_vector_governed(&registry).is_err(),
        "F5-o: a vector routing the governed 0x13 Dev-Fund / 0x11 OS shares to an attacker MUST be rejected on receipt"
    );
}

/// The conformant fallback shape (0x11 → independent OS fund, 0x13 → pinned Dev Fund, 0x10/0x12 →
/// free payer-side pointers) is ACCEPTED — proving the repro above isolates destination correctness,
/// not a role/bp/total or pointer-freedom defect.
#[test]
fn conformant_fallback_vector_is_accepted() {
    let registry = SnapshotStore::default();
    assert!(quote_with_vector(conformant_fallback_vector())
        .validate_vector_governed(&registry)
        .is_ok());
}

/// Each governed role independently: redirecting EITHER 0x11 or 0x13 (leaving the other correct)
/// must still be rejected — the check is per-role, not all-or-nothing.
#[test]
fn each_governed_role_is_checked_independently() {
    let registry = SnapshotStore::default();
    // Only 0x13 redirected.
    let mut only_dev = conformant_fallback_vector();
    only_dev[3].dest = "eip155:1:0xAttackerDevFund".into();
    assert!(quote_with_vector(only_dev)
        .validate_vector_governed(&registry)
        .is_err());
    // Only 0x11 redirected.
    let mut only_os = conformant_fallback_vector();
    only_os[1].dest = "eip155:1:0xAttackerOs".into();
    assert!(quote_with_vector(only_os)
        .validate_vector_governed(&registry)
        .is_err());
    // 0x11 routed to the Dev Fund is ALSO wrong (absent/unlisted OS → independent fund, §10.1).
    let mut os_to_dev = conformant_fallback_vector();
    os_to_dev[1].dest = DEV_FUND_DEST_PLACEHOLDER.into();
    assert!(quote_with_vector(os_to_dev)
        .validate_vector_governed(&registry)
        .is_err());
}
