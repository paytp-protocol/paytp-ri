//! **F2.4 host normalization — the ONE shared normalizer** used by both the
//! artifact `HOST` validation (`paytp-core` channel establishment) and the payer-key
//! derivation scope (`paytp-wallet` custody). Having a single implementation is the
//! whole point: the registrable domain the wallet scopes its key to is resolved by
//! the *same* function that validates the artifact host, so the two can never
//! disagree (never a lowercase-only URL parse on one side and full IDNA on the other).
//!
//! Two pinned data sources back this crate, both bumped only as deliberate,
//! documented version changes:
//! - **UTS#46 (Unicode) table** — the pinned `idna` crate (`=1.1.0`) and its ICU4X
//!   data. `idna` performs **non-transitional** UTS#46 processing with **STD3** ASCII
//!   rules and the **bidi + joiner (ContextJ)** checks — exactly the F2.4 label rules.
//! - **Public Suffix List** — a vendored, dated snapshot (`data/public_suffix_list.dat`,
//!   see [`psl::PSL_VERSION`]) resolving the registrable domain (eTLD+1), private
//!   section included.
//!
//! **F2.4 rule: a received host MUST already be the normalized form — an IDNA
//! A-label, ASCII, lowercase — and is _rejected, never repaired_** (F1.1 rule 5 /
//! F2.4 rule 1). So [`validate_normalized_host`] accepts a host **iff** it is already
//! the canonical UTS#46 ASCII output for itself; a U-label, mixed case, or otherwise
//! non-canonical host is rejected, not rewritten. [`registrable_domain`] applies the
//! identical validation before resolving the eTLD+1, so the wallet only ever scopes
//! to a host the artifact validator would also accept.

mod psl;

pub use psl::PSL_VERSION;

/// Why a host failed F2.4 normalization/validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The host was empty.
    Empty,
    /// The host is not already in F2.4-normalized form — it is not a valid UTS#46
    /// (non-transitional, STD3, bidi/joiner) A-label, ASCII, lowercase host, or it
    /// would need repair to reach that form (which F2.4 forbids: reject, never repair).
    NotNormalized,
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for HostError {}

/// The UTS#46 (non-transitional) + STD3 + Punycode + bidi/joiner canonical ASCII
/// form of `host`, or `None` if `host` is not a valid domain under those rules.
/// `idna::domain_to_ascii_strict` is `beStrict=true`: `AsciiDenyList::STD3`,
/// `Hyphens::Check`, `DnsLength::Verify`, non-transitional (the only mode in idna 1.x).
fn uts46_ascii(host: &str) -> Option<String> {
    idna::domain_to_ascii_strict(host).ok()
}

/// Validate that `host` is **already** the F2.4-normalized form (IDNA A-label,
/// ASCII, lowercase) — rejecting, never repairing (F2.4 rule 1). This is the artifact
/// `HOST` check: it enforces the full UTS#46/STD3/bidi/joiner label rules by requiring
/// `host` to equal its own canonical UTS#46 ASCII output, so a non-canonical host
/// (U-label, mixed case, invalid Punycode, disallowed/bidi/joiner-violating label,
/// out-of-range DNS length) fails.
pub fn validate_normalized_host(host: &str) -> Result<(), HostError> {
    if host.is_empty() {
        return Err(HostError::Empty);
    }
    match uts46_ascii(host) {
        // Already canonical (idempotent under UTS#46 ToASCII) ⇒ a valid normalized
        // host. Any difference means it was not pre-normalized ⇒ reject, never repair.
        Some(ascii) if ascii == host => Ok(()),
        _ => Err(HostError::NotNormalized),
    }
}

/// Whether `host`'s rightmost label is a **plausible top-level domain** — the only
/// hosts that HAVE a registrable domain. Every real TLD is all-ASCII-alphabetic
/// (`com`, `co.uk`'s `uk`, `google`) or an IDN A-label (`xn--…`, e.g. `xn--p1ai`);
/// NONE is numeric or hex. So a host whose TLD is anything else is an **IP literal in
/// some radix** (dotted decimal `127.0.0.1`, hex `0x7f.0.0.1`, octal `0177.0.0.1`,
/// shortened `10.0.1`, out-of-range `999.999.999.999`) or otherwise malformed — it has
/// no registrable domain and MUST scope to the WHOLE host. Checking the TLD (not "all
/// labels numeric") is what catches the mixed-radix IP forms that slip past an
/// all-digits net: `0x7f.0.0.1` & `0x80.0.0.1` would otherwise both
/// resolve to `0.1` under the PSL implicit-`*` rule and share a scope. (Cross-*merchant*
/// unlinkability holds regardless — the scope also binds `merchant_key`, F1-f — so this
/// closes the finer same-key/multi-host sub-scoping, not a cross-merchant break.)
fn has_plausible_tld(host: &str) -> bool {
    let tld = host.rsplit('.').next().unwrap_or(host);
    !tld.is_empty() && (tld.bytes().all(|b| b.is_ascii_alphabetic()) || tld.starts_with("xn--"))
}

/// The **registrable domain** (eTLD+1) of a merchant `host`, the payer-key
/// unlinkability scope (F1-f/F2.3). `host` is first validated by
/// [`validate_normalized_host`] (same F2.4 rules as the artifact `HOST`), then
/// resolved against the pinned PSL (private section included). A host whose rightmost
/// label is not a plausible TLD (an IP literal in any radix, or malformed) and a host
/// that is *itself* a public suffix both map to the **whole host** — a defined, stable,
/// collision-free scope (never a PSL implicit-`*` collapse of two distinct hosts).
pub fn registrable_domain(host: &str) -> Result<String, HostError> {
    validate_normalized_host(host)?;
    if !has_plausible_tld(host) {
        return Ok(host.to_string());
    }
    Ok(psl::registrable_domain(host).unwrap_or_else(|| host.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_an_already_normalized_ascii_host() {
        assert_eq!(validate_normalized_host("api.example.com"), Ok(()));
        assert_eq!(validate_normalized_host("example.co.uk"), Ok(()));
        // A valid A-label (Punycode) host is already normalized.
        assert_eq!(validate_normalized_host("xn--bcher-kva.example"), Ok(()));
    }

    #[test]
    fn rejects_non_normalized_hosts_never_repairs() {
        assert_eq!(validate_normalized_host(""), Err(HostError::Empty));
        // Mixed case is not repaired to lowercase — rejected (F2.4 rule 1).
        assert_eq!(
            validate_normalized_host("API.example.com"),
            Err(HostError::NotNormalized)
        );
        // A raw U-label is not converted to its A-label — rejected.
        assert_eq!(
            validate_normalized_host("bücher.example"),
            Err(HostError::NotNormalized)
        );
        // A trailing dot (root) is not stripped — rejected (DnsLength::Verify).
        assert_eq!(
            validate_normalized_host("example.com."),
            Err(HostError::NotNormalized)
        );
        // STD3: underscores are disallowed in an origin host.
        assert_eq!(
            validate_normalized_host("a_b.example.com"),
            Err(HostError::NotNormalized)
        );
    }

    #[test]
    fn registrable_domain_uses_the_same_validation() {
        // A host the artifact validator rejects, the scope resolver rejects too — the
        // whole point of the one shared normalizer.
        assert_eq!(
            registrable_domain("API.example.com"),
            Err(HostError::NotNormalized)
        );
        assert_eq!(
            registrable_domain("bücher.example"),
            Err(HostError::NotNormalized)
        );
    }

    #[test]
    fn registrable_domain_resolves_etld_plus_one() {
        assert_eq!(
            registrable_domain("api.example.com").as_deref(),
            Ok("example.com")
        );
        assert_eq!(
            registrable_domain("www.shop.example.com").as_deref(),
            Ok("example.com")
        );
        // Multi-level ICANN suffix.
        assert_eq!(
            registrable_domain("a.example.co.uk").as_deref(),
            Ok("example.co.uk")
        );
    }

    #[test]
    fn ipv4_literal_scopes_to_the_whole_host_no_collision() {
        assert_eq!(registrable_domain("192.0.2.1").as_deref(), Ok("192.0.2.1"));
        // Distinct IPs stay distinct (the PSL implicit-* collapse would have linked these).
        assert_ne!(registrable_domain("1.2.3.4"), registrable_domain("9.2.3.4"));
    }

    #[test]
    fn public_suffix_host_scopes_to_the_whole_host() {
        // A host that is itself a public suffix has no eTLD+1 → whole host, stable.
        assert_eq!(registrable_domain("co.uk").as_deref(), Ok("co.uk"));
    }
}
