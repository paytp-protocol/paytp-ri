//! Destination pointers (**DECISION F9-a**, formalizing §5.4/§10.1).
//!
//! A destination pointer names where money lands (`MEED_VECTOR` destinations, the
//! refund pointer, the settlement pointer). It is exactly one of two disjoint
//! forms, distinguished by whether it begins `x-`:
//!
//! - **CAIP-10** — `namespace:reference:account` (three colon components; a
//!   parser splits on the first two colons only). Used for every CAIP rail, so
//!   for every meed/baseline destination (the instance is an on-chain
//!   contract, F4.1/F5.2).
//! - **Adapter** — `x-<rail>:<account>` (`x-` exactly once, at the start; split
//!   on the first colon only). The `DENOM`-rail form for custodial / instant-
//!   bank / Lightning channel rails (§6.2/§11.1).
//!
//! Equality is **byte equality** after F1-g validation — nothing is case-folded
//! or normalized (F1's validation-never-transformation rule).

use crate::error::{Error, Result};
use crate::tlv::validate_text;

/// Maximum pointer length in bytes (F9.1).
pub const MAX_POINTER_LEN: usize = 512;

/// A validated destination pointer. The original bytes are retained verbatim
/// (equality is byte equality); the parsed components are offered for callers
/// that need the rail/account split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    /// `namespace:reference:account` (F9.1 CAIP-10 form).
    Caip {
        raw: String,
        namespace: String,
        reference: String,
        account: String,
    },
    /// `x-<rail>:<account>` (F9.1 adapter form).
    Adapter {
        raw: String,
        /// The full adapter rail id including its `x-` prefix.
        rail_id: String,
        account: String,
    },
}

fn matches(s: &str, pred: impl Fn(u8) -> bool) -> bool {
    !s.is_empty() && s.bytes().all(pred)
}

// `^[a-z0-9]{3,8}$`
fn is_caip_namespace(s: &str) -> bool {
    (3..=8).contains(&s.len()) && matches(s, |b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

// `^[A-Za-z0-9._%\-]{1,N}$`
fn is_account(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && matches(s, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'-')
        })
}

// `^x-[a-z0-9\-]{1,32}$` — the whole rail id including `x-`. The `x-` prefix appears
// **exactly once** (F9, 09-registry-snapshot.md: "never `x-x-…`"), so a rest that itself
// begins `x-` is rejected — matching [`Pointer::parse`]'s own `x-x-` guard.
fn is_adapter_rail(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("x-") else {
        return false;
    };
    if rest.starts_with("x-") {
        return false; // double `x-x-` prefix
    }
    (1..=32).contains(&rest.len())
        && matches(rest, |b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
        })
}

/// An F9.1 **rail identifier** for a funding/settlement rail: a CAIP-2 chain id
/// (`eip155:1`) OR an adapter rail id (`x-<rail>`, no account). This is the
/// vocabulary of `FUNDING_PROOF.RAIL` and a `CREDITED`/`PREPAY_DRAW` leg's rail
/// (F5.4/F5.6/F5-o) — the *rail's identity*, not a destination pointer, so it
/// carries no `:account` (a CAIP-10 pointer's account) tail.
pub fn is_rail_id(s: &str) -> bool {
    is_caip2(s) || is_adapter_rail(s)
}

// A CAIP-19 asset **reference** tail after the `<chain>/`: either the strict
// `asset_namespace:asset_reference` form (`erc20:0x…`, `slip44:60`), or the bare
// `asset_reference` the RI's canonical vectors use (`eip155:1/native`,
// `solana:dev/usdc`). Charset per CAIP-19: `[-.%a-zA-Z0-9]{1,128}` — note `_` is NOT a
// CAIP-19 asset-reference character (unlike a CAIP-2 reference / CAIP-10 account).
fn is_asset_reference(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && matches(s, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'%' | b'-')
        })
}

fn is_asset_tail(tail: &str) -> bool {
    match tail.split_once(':') {
        Some((ns, r)) => {
            (3..=8).contains(&ns.len())
                && matches(ns, |b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                })
                && is_asset_reference(r)
        }
        None => is_asset_reference(tail),
    }
}

/// A CAIP-19 asset **type** id: `<caip2-chain>/<asset-tail>` — e.g.
/// `eip155:1/erc20:0x6b17…`, `eip155:1/native`, `solana:dev/usdc`. This is the
/// asset vocabulary of a channel `DENOM` (on a CAIP rail) and `BASELINE_ASSET`
/// (F5.2). The token-id form (`…/<token_id>`) is not modeled: a channel
/// settlement denomination is fungible.
pub fn is_caip19_asset(s: &str) -> bool {
    match s.split_once('/') {
        Some((chain, tail)) => is_caip2(chain) && is_asset_tail(tail),
        None => false,
    }
}

/// A channel **asset identifier** (F5.2 `DENOM` / `BASELINE_ASSET`): a CAIP-19
/// asset **type** (`is_caip19_asset`, `<caip2>/<asset-tail>`). `DENOM` additionally
/// accepts the F9.1 adapter (`x-`) form for a non-CAIP rail (§6.2/§11.1);
/// `BASELINE_ASSET` is CAIP-19-only (`allow_adapter = false`) — the baseline never
/// takes the adapter form (F5.2). The CAIP-10 **account** form (`chain:account`, a
/// [`Pointer::Caip`]) is an *account*, not an asset, and is **rejected** for both:
/// F5.2 scopes these fields to CAIP-19, and `BASELINE_ASSET` feeds the F4.1
/// instance-address derivation, so accepting an account-form here would split a
/// signed `CHANNEL_AUTH` against a strict F5.2 peer. A bare token (`"usd"`) or any
/// non-CAIP text is rejected.
pub fn is_asset_id(s: &str, allow_adapter: bool) -> bool {
    if is_caip19_asset(s) {
        return true;
    }
    // Not a CAIP-19 asset type: the only other accepted form is the F9.1 adapter
    // (`x-`) DENOM form. A CAIP-10 account (`Pointer::Caip`) is NOT an asset id.
    allow_adapter && matches!(Pointer::parse(s), Ok(Pointer::Adapter { .. }))
}

/// A CAIP-2 chain identifier (F3-f): `namespace:reference`. Per the F9 grammar
/// (09-registry-snapshot.md), `namespace` is `^[a-z0-9]{3,8}$` (**no hyphen** — so an
/// `x-` adapter id never parses as CAIP-2, keeping the two forms disjoint) and
/// `reference` is `^[A-Za-z0-9._%\-]{1,128}$` (the same charset as a CAIP-10 account —
/// it admits `_`, e.g. `starknet:SN_GOERLI`). This is the vocabulary of an offer's
/// `accept.network`, the quote's `baseline` (F3-c/F3-f), `BASELINE_NET`, and a rail id;
/// it is DISTINCT from the CAIP-10 [`Pointer`] destination form, which additionally
/// carries an `:account`. A literal sentinel like `"baseline"` (no colon) is not CAIP-2
/// and is rejected (F3-h).
pub fn is_caip2(s: &str) -> bool {
    let Some((namespace, reference)) = s.split_once(':') else {
        return false;
    };
    if reference.contains(':') {
        return false; // exactly one colon: a chain id, never a CAIP-10 account
    }
    is_caip_namespace(namespace) && is_account(reference, 128)
}

impl Pointer {
    /// Parse and validate a pointer (F9.1). Rejects anything matching neither
    /// form, over-length, or failing F1-g text rules.
    pub fn parse(s: &str) -> Result<Pointer> {
        if s.len() > MAX_POINTER_LEN {
            return Err(Error::FieldDomain);
        }
        validate_text(s.as_bytes())?; // F1-g: UTF-8, no controls/NUL/BOM, NFC
        if s.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(Error::JsonGrammar); // no whitespace
        }
        if s.starts_with("x-") {
            // Adapter: split on the FIRST colon only.
            let (rail_id, account) = s.split_once(':').ok_or(Error::JsonGrammar)?;
            if !is_adapter_rail(rail_id) || !is_account(account, 256) {
                return Err(Error::JsonGrammar);
            }
            // `x-` appears exactly once (rail matches x-[a-z0-9-], so no second x-
            // there; the account cannot start x- because it has no colon and is
            // its own charset — but guard the whole-pointer "x-x-" case).
            if s.starts_with("x-x-") {
                return Err(Error::JsonGrammar);
            }
            Ok(Pointer::Adapter {
                raw: s.to_string(),
                rail_id: rail_id.to_string(),
                account: account.to_string(),
            })
        } else {
            // CAIP-10: split on the FIRST TWO colons only.
            let mut it = s.splitn(3, ':');
            let namespace = it.next().unwrap_or("");
            let reference = it.next().ok_or(Error::JsonGrammar)?;
            let account = it.next().ok_or(Error::JsonGrammar)?;
            if account.contains(':') {
                return Err(Error::JsonGrammar); // account carries no further colon
            }
            if !is_caip_namespace(namespace)
                || !is_account(reference, 128)
                || !is_account(account, 128)
            {
                return Err(Error::JsonGrammar);
            }
            Ok(Pointer::Caip {
                raw: s.to_string(),
                namespace: namespace.to_string(),
                reference: reference.to_string(),
                account: account.to_string(),
            })
        }
    }

    /// The verbatim pointer bytes (equality is over these).
    pub fn as_str(&self) -> &str {
        match self {
            Pointer::Caip { raw, .. } | Pointer::Adapter { raw, .. } => raw,
        }
    }

    /// Whether this is the CAIP (baseline-payable) form.
    pub fn is_caip(&self) -> bool {
        matches!(self, Pointer::Caip { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_caip_and_adapter() {
        // F10.3: accept a 3-component CAIP-10 and an x- adapter pointer.
        let c = Pointer::parse("eip155:1:0xAbC123").unwrap();
        assert!(c.is_caip());
        let s = Pointer::parse("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:9WzD...acct").is_ok();
        assert!(s);
        let a = Pointer::parse("x-stripe:acct_123").unwrap();
        assert!(!a.is_caip());
        if let Pointer::Adapter {
            rail_id, account, ..
        } = a
        {
            assert_eq!(rail_id, "x-stripe");
            assert_eq!(account, "acct_123");
        }
    }

    #[test]
    fn caip2_chain_ids() {
        // F3-f / F9: CAIP-2 chain ids for `network` / `baseline` / `BASELINE_NET` / rail.
        assert!(is_caip2("eip155:1"));
        assert!(is_caip2("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
        assert!(is_caip2("bip122:000000000019d6689c085ae165831e93"));
        // F9 reference charset `[A-Za-z0-9._%\-]{1,128}` admits `_` (e.g. Starknet testnet)
        // and is up to 128 chars — NOT the narrower official-CAIP-2 32/`[-a-zA-Z0-9]`.
        assert!(is_caip2("starknet:SN_GOERLI"));
        assert!(is_caip2(&format!("eip155:{}", "a".repeat(33))));
        // Not CAIP-2: the pre-F3-h sentinel (no colon), a CAIP-10 destination (two colons),
        // uppercase namespace, empty parts, a hyphenated (`x-` adapter) namespace, over-length.
        assert!(!is_caip2("baseline"));
        assert!(!is_caip2("eip155:1:0xabc"));
        assert!(!is_caip2("EIP155:1"));
        assert!(!is_caip2("eip155:"));
        assert!(!is_caip2(":1"));
        assert!(!is_caip2("x-stripe:usd")); // F9: no CAIP namespace begins `x-` (adapter form)
        assert!(!is_caip2(&format!("eip155:{}", "a".repeat(129)))); // reference > 128
    }

    #[test]
    fn reject_malformed() {
        // F10.3: reject a 4-colon CAIP-10, an adapter id without x-, x-x-…,
        // over-length, control/whitespace-bearing.
        assert!(Pointer::parse("eip155:1:0x:extra").is_err()); // account has a colon (4 colons)
        assert!(Pointer::parse("stripe:acct_1").is_err()); // adapter-shaped but no x-  → CAIP parse, namespace "stripe" ok but only 2 comps
        assert!(Pointer::parse("x-x-stripe:acct").is_err()); // double x-
        assert!(Pointer::parse("eip155:1").is_err()); // only 2 components
        assert!(Pointer::parse("eip155:1: acct").is_err()); // whitespace
        assert!(Pointer::parse(&format!("eip155:1:{}", "a".repeat(600))).is_err()); // over length
        assert!(Pointer::parse("EIP155:1:0x").is_err()); // uppercase namespace
    }

    #[test]
    fn asset_ids_and_rail_ids() {
        // F5.2 asset ids: only CAIP-19 asset **types** are accepted; a bare token /
        // non-CAIP text is rejected.
        for ok in [
            "solana:dev/usdc",
            "eip155:1/eur",
            "eip155:1/native",
            "eip155:1/erc20:0x6b175474e89094c44da98b954eedeac495271d0f",
        ] {
            assert!(is_asset_id(ok, false), "asset id must be accepted: {ok}");
        }
        for bad in [
            "usd",
            "usdc",
            "sol/usdc",
            "not-caip2",
            "",
            "eip155:1/",
            "eip155:1/erc20:foo_bar", // `_` is not a CAIP-19 asset-reference character
            // F5.2: the CAIP-10 **account** form (`chain:account`, three
            // colon components — an *account*, not an asset) is NOT a CAIP-19 asset id
            // and MUST be rejected for both DENOM and BASELINE_ASSET (allow_adapter
            // makes no difference — it is not the `x-` adapter form either).
            "eip155:1:0xUSDC",
        ] {
            assert!(!is_asset_id(bad, false), "asset id must be rejected: {bad}");
            assert!(
                !is_asset_id(bad, true),
                "asset id must be rejected even for DENOM (allow_adapter): {bad}"
            );
        }
        // DENOM allows the adapter form; BASELINE_ASSET (allow_adapter=false) does not.
        assert!(is_asset_id("x-stripe:usd", true));
        assert!(!is_asset_id("x-stripe:usd", false));

        // F9.1 rail ids: CAIP-2 or an adapter rail id (no account tail).
        for ok in ["eip155:1", "solana:dev", "x-stripe", "x-lightning"] {
            assert!(is_rail_id(ok), "rail id must be accepted: {ok}");
        }
        // Rejected: a CAIP-10 account (two colons); too-short-to-be-CAIP-2 `r`; an adapter
        // *pointer* carrying an account (`x-stripe:usd` — a rail id has no account); a double
        // `x-x-` prefix; whitespace / empty.
        for bad in [
            "r",
            "eip155:1:0xabc",
            "x-stripe:usd",
            "x-x-stripe",
            "not a rail",
            "",
        ] {
            assert!(!is_rail_id(bad), "rail id must be rejected: {bad}");
        }
    }

    #[test]
    fn equality_is_byte_equality_no_casefold() {
        // Two valid casings of the "same" account are NOT equal (F9.1 hazard).
        let a = Pointer::parse("eip155:1:0xAbCd").unwrap();
        let b = Pointer::parse("eip155:1:0xabcd").unwrap();
        assert_ne!(a, b);
        assert_ne!(a.as_str(), b.as_str());
    }
}
