//! F2.4 host-normalization conformance matrix (the ONE shared normalizer).
//!
//! Covers the cases the publish-readiness plan enumerates for the F2.4 crate:
//! private-suffix, IP-literal, Unicode A-label, and reject (bidi / joiner /
//! disallowed / non-normalized) — plus the non-transitional UTS#46 proof. The
//! two-merchants-unlink / same-merchant-stable KEY properties live with the payer-key
//! derivation (`paytp-wallet` custody), which resolves the scope through this crate.

use paytp_host::{registrable_domain, validate_normalized_host, HostError, PSL_VERSION};

#[test]
fn pinned_psl_version_is_the_vendored_snapshot() {
    // The pin is surfaced so a refresh (a re-key) is a visible, reviewed change.
    assert_eq!(PSL_VERSION, "2026-07-14_09-26-39_UTC");
}

#[test]
fn private_suffix_is_a_registrable_boundary() {
    // PRIVATE-section suffix (`github.io`): two tenants are distinct registrable
    // domains, so they derive distinct payer keys (the unlinkability boundary).
    assert_eq!(
        registrable_domain("alice.github.io").as_deref(),
        Ok("alice.github.io")
    );
    assert_eq!(
        registrable_domain("bob.github.io").as_deref(),
        Ok("bob.github.io")
    );
    assert_ne!(
        registrable_domain("alice.github.io"),
        registrable_domain("bob.github.io")
    );
    // A deeper subdomain of one tenant folds back to that tenant's boundary (stable).
    assert_eq!(
        registrable_domain("www.alice.github.io").as_deref(),
        Ok("alice.github.io")
    );
}

#[test]
fn ip_literal_scopes_to_the_whole_literal() {
    assert_eq!(
        registrable_domain("203.0.113.7").as_deref(),
        Ok("203.0.113.7")
    );
    // No PSL implicit-* collapse: distinct IPs never share a scope (would link them).
    assert_ne!(
        registrable_domain("203.0.113.7"),
        registrable_domain("198.51.100.7")
    );
}

#[test]
fn all_numeric_hosts_never_collapse_in_the_psl() {
    // Regression: STD3-strict IDNA accepts numeric labels, so shortened,
    // 3-part, and out-of-range "IP-like" hosts pass validation but are NOT valid
    // 4-octet IPv4. They MUST scope to the whole host — else the PSL implicit-`*` rule
    // collapses distinct ones (`10.0.1`/`11.0.1` → `0.1`; `1.2.3`/`9.2.3` → `2.3`;
    // `999.999.999.999`/`111.999.999.999` → `999.999`) and links two merchants.
    // Decimal, shortened, out-of-range, single-integer AND mixed-radix (hex/octal) IP
    // literals — a real TLD is never numeric/hex, so every one scopes to the whole host.
    for h in [
        "10.0.1",
        "1.2.3",
        "999.999.999.999",
        "42",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "0xaa.0xbb.0xcc.0xdd",
    ] {
        assert_eq!(
            registrable_domain(h).as_deref(),
            Ok(h),
            "whole-host scope for {h}"
        );
    }
    assert_ne!(registrable_domain("10.0.1"), registrable_domain("11.0.1"));
    assert_ne!(registrable_domain("1.2.3"), registrable_domain("9.2.3"));
    // The hex-literal repro: distinct hex IPs must NOT collapse to `0.1`.
    assert_ne!(
        registrable_domain("0x7f.0.0.1"),
        registrable_domain("0x80.0.0.1")
    );
    assert_ne!(
        registrable_domain("0xaa.0xbb.0xcc.0xdd"),
        registrable_domain("0xee.0xbb.0xcc.0xdd")
    );
}

#[test]
fn idn_psl_rules_match_the_non_transitional_host() {
    // Regression: the PSL rules are A-label-normalized with the SAME
    // non-transitional idna 1.x processing as the host, so an IDN host resolves against
    // an IDN PSL rule instead of falling through to a broader implicit-`*` domain. `рф`
    // (`xn--p1ai`) is a real ICANN suffix; a subdomain under it must fold to eTLD+1
    // there, and a payer at two `.рф` merchants stays unlinkable (distinct eTLD+1).
    let a = registrable_domain("shop.xn--p1ai"); // shop.рф — shop IS the eTLD+1 head
    assert_eq!(a.as_deref(), Ok("shop.xn--p1ai"));
    assert_ne!(
        registrable_domain("alice.xn--p1ai"),
        registrable_domain("bob.xn--p1ai")
    );
}

#[test]
fn unicode_a_label_is_accepted_and_resolved() {
    // A valid IDN A-label (Punycode) host is already F2.4-normalized: accepted, and
    // its registrable domain resolves through the same normalizer + PSL.
    assert_eq!(validate_normalized_host("xn--mnchen-3ya.de"), Ok(())); // münchen.de
    assert_eq!(
        registrable_domain("shop.xn--mnchen-3ya.de").as_deref(),
        Ok("xn--mnchen-3ya.de")
    );
    // NON-TRANSITIONAL UTS#46: `faß.de` maps to `xn--fa-hia.de` (ß kept), never the
    // transitional `fass.de` — so the A-label that IS the non-transitional form is
    // accepted (proving the processing mode).
    assert_eq!(validate_normalized_host("xn--fa-hia.de"), Ok(()));
}

#[test]
fn raw_u_label_is_rejected_never_repaired() {
    // F2.4 rule 1: a received host is rejected, never repaired. A raw U-label is NOT
    // silently converted to its A-label.
    assert_eq!(
        validate_normalized_host("münchen.de"),
        Err(HostError::NotNormalized)
    );
    assert_eq!(
        registrable_domain("münchen.de"),
        Err(HostError::NotNormalized)
    );
}

#[test]
fn invalid_a_label_is_rejected() {
    // Invalid Punycode payload → rejected.
    assert_eq!(
        validate_normalized_host("xn--a.example"),
        Err(HostError::NotNormalized)
    );
    // Well-formed Punycode that DECODES to an invalid UTS#46 label → rejected (the
    // decoded-label validity check, not just Punycode syntax).
    assert_eq!(
        registrable_domain("xn--a9at.example"),
        Err(HostError::NotNormalized)
    );
}

#[test]
fn bidi_and_joiner_violating_labels_are_rejected() {
    // A label mixing an RTL script with a Latin letter (a UTS#46 CheckBidi failure)
    // is not a valid normalized host.
    assert_eq!(
        validate_normalized_host("\u{0627}a.example"),
        Err(HostError::NotNormalized)
    );
    // A bare ZWNJ (U+200C) outside a valid joining context (CheckJoiners / ContextJ)
    // is rejected.
    assert_eq!(
        validate_normalized_host("a\u{200C}b.example"),
        Err(HostError::NotNormalized)
    );
}

#[test]
fn disallowed_ascii_and_case_are_rejected() {
    // STD3: underscore disallowed in an origin host.
    assert_eq!(
        validate_normalized_host("a_b.example.com"),
        Err(HostError::NotNormalized)
    );
    // Mixed case not repaired.
    assert_eq!(
        validate_normalized_host("Example.com"),
        Err(HostError::NotNormalized)
    );
    // Empty / trailing-dot.
    assert_eq!(validate_normalized_host(""), Err(HostError::Empty));
    assert_eq!(
        validate_normalized_host("example.com."),
        Err(HostError::NotNormalized)
    );
}

#[test]
fn same_normalizer_both_call_sites() {
    // The invariant the crate exists to guarantee: every host the scope resolver
    // accepts, the artifact validator accepts, and vice-versa (identical front gate).
    for h in [
        "api.example.com",
        "xn--mnchen-3ya.de",
        "203.0.113.7",
        "a.b.co.uk",
    ] {
        assert_eq!(
            validate_normalized_host(h).is_ok(),
            registrable_domain(h).is_ok(),
            "{h}"
        );
    }
    for bad in ["Example.com", "münchen.de", "a_b.c", "xn--a.example", ""] {
        assert_eq!(
            validate_normalized_host(bad).is_ok(),
            registrable_domain(bad).is_ok(),
            "{bad}"
        );
    }
}
