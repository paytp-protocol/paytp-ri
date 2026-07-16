//! Public Suffix List matcher (registrable domain / eTLD+1).
//!
//! The **data is vendored and pinned** (`data/public_suffix_list.dat`, the Mozilla
//! PSL, MPL-2.0) — see [`PSL_VERSION`]. Pinning the snapshot is what makes the
//! payer-key scope (F1-f unlinkability) reproducible: the same host resolves to the
//! same registrable domain across builds, so the derived key is stable. Refreshing
//! the list is a deliberate data-version bump, never a silent float.
//!
//! Both PSL sections are loaded and **both are treated as public suffixes** — the
//! "include private domains" mode. So a private-section suffix such as `github.io`
//! is a public suffix: `foo.github.io` has registrable domain `foo.github.io`, not
//! `github.io`. Scoping the payer key to the private-section boundary is what keeps
//! two tenants of one hosting provider unlinkable from each other.
//!
//! The algorithm is the canonical PSL one (<https://publicsuffix.org/list/>):
//! exception (`!`) rules win; otherwise the matching rule with the most labels
//! prevails; wildcard (`*`) labels match exactly one label; with no matching rule
//! the prevailing rule is the implicit `*` (the rightmost label is the suffix).

use std::collections::HashSet;
use std::sync::OnceLock;

/// The pinned PSL snapshot version (the `// VERSION:` line of the vendored file).
/// Bumping the vendored `data/public_suffix_list.dat` MUST bump this too.
pub const PSL_VERSION: &str = "2026-07-14_09-26-39_UTC";

/// The vendored, pinned PSL, embedded at compile time (no runtime file I/O — the
/// data ships inside the binary, so a deployment cannot diverge from the pin).
const PSL_DATA: &str = include_str!("../data/public_suffix_list.dat");

/// The parsed rule sets, all label-strings in **A-label (ASCII, Punycode) form** so
/// they compare directly against a [`crate::normalize_host`]-normalized host.
struct Psl {
    /// Normal rules, e.g. `com`, `co.uk` (the full suffix string).
    rules: HashSet<String>,
    /// Wildcard rules `*.X`, stored as the `X` part (the wildcard consumes exactly
    /// one host label to the left of `X`).
    wildcards: HashSet<String>,
    /// Exception rules `!Y`, stored as the `Y` part; the public suffix of a host
    /// matching `!Y` is `Y` minus its leftmost label.
    exceptions: HashSet<String>,
}

static PSL: OnceLock<Psl> = OnceLock::new();

/// Convert one PSL rule's domain part to A-label form so it matches a normalized
/// host. PSL IDN suffixes are stored as U-labels (e.g. `рф`); a normalized host is
/// an A-label (`xn--p1ai`), so both sides must live in the same space. A rule that
/// will not convert (should not happen for the Mozilla list) is kept verbatim
/// lowercased rather than dropped — fail-safe toward MORE public suffixes (a
/// narrower, never a broader, registrable domain).
fn rule_to_alabel(rule: &str) -> String {
    match idna::domain_to_ascii(rule) {
        Ok(a) => a,
        Err(_) => rule.to_ascii_lowercase(),
    }
}

fn load() -> Psl {
    let mut rules = HashSet::new();
    let mut wildcards = HashSet::new();
    let mut exceptions = HashSet::new();
    for raw in PSL_DATA.lines() {
        let line = raw.trim();
        // Comments (`//`) and blank lines carry no rules; the `===BEGIN PRIVATE
        // DOMAINS===` marker is a comment too, so both sections load as suffixes.
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        // A rule ends at the first whitespace (defensive; the list has none trailing).
        let rule = line.split_whitespace().next().unwrap_or(line);
        if let Some(exc) = rule.strip_prefix('!') {
            exceptions.insert(rule_to_alabel(exc));
        } else if let Some(wild) = rule.strip_prefix("*.") {
            wildcards.insert(rule_to_alabel(wild));
        } else {
            rules.insert(rule_to_alabel(rule));
        }
    }
    Psl {
        rules,
        wildcards,
        exceptions,
    }
}

fn psl() -> &'static Psl {
    PSL.get_or_init(load)
}

/// The number of trailing labels that form the **public suffix** (eTLD) of
/// `labels` (the host split on `.`), per the canonical PSL algorithm. Always `≥ 1`
/// (the implicit `*` rule) and `≤ labels.len()`.
fn public_suffix_len(labels: &[&str]) -> usize {
    let p = psl();
    let n = labels.len();
    // Exception rules take priority over every other rule (checked longest-suffix
    // first). `!Y` → the public suffix is `Y` minus its leftmost label.
    for i in 0..n {
        let candidate = labels[i..].join(".");
        if p.exceptions.contains(&candidate) {
            return (n - i) - 1;
        }
    }
    // Otherwise the matching rule with the MOST labels prevails.
    let mut best = 0usize;
    for i in 0..n {
        let candidate = labels[i..].join(".");
        if p.rules.contains(&candidate) {
            best = best.max(n - i);
        }
        // A wildcard `*.X` matches when the labels to the RIGHT of one consumed
        // label equal `X`; the match then spans `n - i` labels (the consumed label
        // plus `X`). Requires a label at `i` for the `*` to consume, so `i < n-1`.
        if i + 1 < n {
            let rest = labels[(i + 1)..].join(".");
            if p.wildcards.contains(&rest) {
                best = best.max(n - i);
            }
        }
    }
    // No rule matched → the implicit `*` rule: the rightmost label is the suffix.
    best.max(1)
}

/// The registrable domain (public suffix + one more label) of an already
/// [`crate::normalize_host`]-normalized `host`, or `None` when the host **is** a
/// public suffix (no label to the left of the eTLD) — a degenerate scope the caller
/// handles (it falls back to the whole host). `host` must be lowercase ASCII with no
/// leading/trailing/empty labels (guaranteed by the normalizer).
pub(crate) fn registrable_domain(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    let ps = public_suffix_len(&labels);
    // eTLD+1 needs at least one label beyond the public suffix.
    if n <= ps {
        return None;
    }
    Some(labels[(n - ps - 1)..].join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_list_parses_into_all_three_rule_kinds() {
        let p = psl();
        // Sanity floor: the real Mozilla list has thousands of normal rules, plus
        // wildcards and exceptions — a truncated/empty vendored file fails here.
        assert!(p.rules.len() > 5000, "rules = {}", p.rules.len());
        assert!(!p.wildcards.is_empty());
        assert!(!p.exceptions.is_empty());
        // Spot-check canonical members of each kind.
        assert!(p.rules.contains("com"));
        assert!(p.rules.contains("co.uk"));
    }

    #[test]
    fn simple_two_label_tld() {
        assert_eq!(
            registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("a.b.example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn multi_level_icann_suffix() {
        // `co.uk` is a listed public suffix → eTLD+1 keeps three labels.
        assert_eq!(
            registrable_domain("shop.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("example.co.uk").as_deref(),
            Some("example.co.uk")
        );
    }

    #[test]
    fn private_section_suffix_is_a_boundary() {
        // `github.io` is in the PRIVATE section; "include private domains" mode makes
        // it a public suffix, so two GitHub Pages tenants are distinct registrable
        // domains (the unlinkability boundary the payer-key scope rides on).
        assert_eq!(
            registrable_domain("alice.github.io").as_deref(),
            Some("alice.github.io")
        );
        assert_eq!(
            registrable_domain("bob.github.io").as_deref(),
            Some("bob.github.io")
        );
        assert_ne!(
            registrable_domain("alice.github.io"),
            registrable_domain("bob.github.io")
        );
    }

    #[test]
    fn wildcard_and_exception_rules() {
        // The classic pair from the PSL spec examples. `*.ck` is a wildcard public
        // suffix, and `!www.ck` is the exception that makes `www.ck` registrable.
        // A wildcard host that IS the (2-label) suffix has no registrable domain.
        assert_eq!(registrable_domain("foo.ck"), None);
        assert_eq!(
            registrable_domain("something.foo.ck").as_deref(),
            Some("something.foo.ck")
        );
        // The exception: `www.ck`'s public suffix collapses back to `ck`.
        assert_eq!(registrable_domain("www.ck").as_deref(), Some("www.ck"));
    }

    #[test]
    fn host_that_is_itself_a_public_suffix_has_no_registrable_domain() {
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("co.uk"), None);
    }

    #[test]
    fn unknown_tld_uses_the_implicit_wildcard_rule() {
        // No rule matches `.example-tld-not-in-psl` → implicit `*` → rightmost label
        // is the suffix → eTLD+1 is the last two labels.
        assert_eq!(
            registrable_domain("a.b.some-nonexistent-tld-zzz").as_deref(),
            Some("b.some-nonexistent-tld-zzz")
        );
    }
}
