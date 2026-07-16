//! Key custody — the spend boundary (§5.5/F2.3).
//!
//! The wallet's private authority lives here and nowhere else: every signature the
//! payer makes (channel `CHANNEL_AUTH`, `CLOSE`, `ACK_REQUEST`, `FUNDING_PROOF`, and
//! the slice-MAC key schedule) derives from the custody root. In v0.1 the root is an
//! in-memory 32-byte seed; a production wallet backs the same boundary with an HSM /
//! platform secure element (the OS role, §10.1) — the seam is that callers never see
//! the root, only the operations below.
//!
//! **Per-(merchant, registrable-domain) scoping (F1-f/F2.3 — unlinkability MUST).**
//! The payer identity is derived **per counterparty scope**, not once globally:
//!
//! ```text
//! payer_sk(scope) = HKDF-SHA256(
//!     ikm  = root,
//!     info = "PayTPv1-payer-scope-v2" ‖ merchant_key(32) ‖ len16(domain) ‖ domain )
//! ```
//!
//! where `domain` is the merchant's **registrable domain** (eTLD+1) resolved by the
//! ONE shared F2.4 normalizer ([`paytp_host::registrable_domain`]) — the *same*
//! function that validates the artifact `HOST`, so the scope can never disagree with
//! the host the channel authenticated against. Two different merchants (or the same
//! key on two different registrable domains) therefore see **different** `payer_key`s
//! and cannot link a payer across them; the same `(merchant, domain)` is stable, so a
//! returning payer keeps one identity there. The KDF shape is F1-f RECOMMENDED; the
//! unlinkability *property* it delivers is the normative MUST (F2.3).
//!
//! **Derivation version / re-key (`-v2`).** The retired v0.1 derivation was one global
//! key, `HKDF(root, info="PayTPv1-payer")` — no merchant/domain input. Scoping is an
//! **intended re-key**: for a given root, the payer key a wallet now presents differs
//! from the old global one. That is by design (it closes the linkability gap), and
//! it is not wire/spec drift — F1-f/F2.3 pin the unlinkability *property*, not the KDF
//! bytes, and no conformance vector derives `payer_key` from a root. The `-v2` label in
//! the `info` is the version marker: a future derivation change bumps it (never silent).

use paytp_core::crypto;
use zeroize::Zeroizing;

/// The versioned domain-separation label for the scoped payer-key derivation. The
/// `-v2` marks the re-key away from the retired global v0.1 derivation
/// (`PayTPv1-payer`); bump it on any future derivation change so the version is
/// explicit, never silent.
const PAYER_SCOPE_LABEL: &[u8] = b"PayTPv1-payer-scope-v2";

/// The counterparty scope a payer key is derived under (F1-f/F2.3): the merchant
/// identity key **and** its registrable domain. Two scopes differing in either field
/// derive independent, unlinkable payer identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayerScope {
    /// The merchant identity key (`merchant_key`, F1.6) the channel binds to.
    pub merchant_key: [u8; 32],
    /// The merchant's registrable domain (eTLD+1), already resolved through the F2.4
    /// normalizer. Constructed via [`PayerScope::resolve`] so it is never a raw,
    /// unnormalized host.
    pub registrable_domain: String,
}

impl PayerScope {
    /// Resolve the scope from the merchant identity + the merchant's F2.4 `HOST` (the
    /// artifact host, already normalized when the artifact was accepted). The
    /// registrable domain is resolved by the ONE shared normalizer, so it matches the
    /// artifact validation exactly. Fails closed on a host that is not a valid
    /// normalized F2.4 host (the wallet will not open a channel it cannot scope).
    pub fn resolve(
        merchant_key: [u8; 32],
        merchant_host: &str,
    ) -> Result<Self, paytp_host::HostError> {
        Ok(PayerScope {
            merchant_key,
            registrable_domain: paytp_host::registrable_domain(merchant_host)?,
        })
    }

    /// The HKDF `info` preimage for this scope. `merchant_key` is fixed-width and the
    /// domain is length-prefixed, so no two distinct scopes share an `info`.
    fn derivation_info(&self) -> Vec<u8> {
        let domain = self.registrable_domain.as_bytes();
        let mut info = Vec::with_capacity(PAYER_SCOPE_LABEL.len() + 32 + 2 + domain.len());
        info.extend_from_slice(PAYER_SCOPE_LABEL);
        info.extend_from_slice(&self.merchant_key);
        // Registrable domains are ≤ 253 bytes (DNS), so u16 length is ample.
        info.extend_from_slice(&(domain.len() as u16).to_be_bytes());
        info.extend_from_slice(domain);
        info
    }
}

/// The custody boundary. Holds the wallet **root** seed; the root and every derived
/// scoped seed are **never** exported — external callers get only public keys and
/// completed signatures. (`with_signing_key` is crate-private so no caller outside
/// this crate can copy a scalar via `|sk| *sk`; in v0.1 the root is in memory, a
/// production wallet backs the identical boundary with an HSM / secure element.)
pub struct Custody {
    /// The wallet root (32-byte seed). Private to the module — the spend boundary.
    /// Zeroized on drop; scoped signing seeds are derived on demand and never stored.
    root: Zeroizing<[u8; 32]>,
}

impl Custody {
    /// Build a wallet from a root seed.
    pub fn from_root(root: &[u8; 32]) -> Self {
        Custody {
            root: Zeroizing::new(*root),
        }
    }

    /// Derive the per-scope Ed25519 signing seed (F1-f). Returned in a `Zeroizing`
    /// wrapper and used transiently — the scoped seed is never stored, so the spend
    /// boundary widens no further than the root already held here.
    fn scoped_sk(&self, scope: &PayerScope) -> Zeroizing<[u8; 32]> {
        let okm = crypto::hkdf_sha256(&*self.root, None, &scope.derivation_info(), 32);
        let mut sk = Zeroizing::new([0u8; 32]);
        sk.copy_from_slice(&okm);
        sk
    }

    /// The payer's public identity key (`payer_key`, F1.6/F2.5) **for `scope`** — the
    /// public half of the spend boundary, safe to publish. Different scopes yield
    /// different, unlinkable keys.
    pub fn payer_key(&self, scope: &PayerScope) -> [u8; 32] {
        crypto::ed25519_public(&self.scoped_sk(scope))
    }

    /// Sign a message under the scoped payer key. The only way a caller obtains a
    /// payer signature — the raw key never leaves custody. Callers hand the bytes the
    /// wire object commits (each establish/settle object domain-separates its own).
    pub fn sign(&self, scope: &PayerScope, msg: &[u8]) -> [u8; 64] {
        crypto::ed25519_sign(&self.scoped_sk(scope), msg)
    }

    /// Run a closure with the scoped payer signing key, for the paytp-core object APIs
    /// that take `&[u8; 32]` and domain-separate internally (`ChannelAuth::sign`,
    /// `Close::sign`, …). **Crate-private:** only this crate's `execute`/`channel`
    /// modules call it, so no external caller can extract the seed with `|sk| *sk`; the
    /// raw scalar never crosses the crate boundary. (A hardware-backed custody would
    /// replace this with typed sign-this-object operations; the paytp-core object APIs
    /// currently need the raw seed, so this seam stays internal.)
    pub(crate) fn with_signing_key<T>(
        &self,
        scope: &PayerScope,
        f: impl FnOnce(&[u8; 32]) -> T,
    ) -> T {
        f(&self.scoped_sk(scope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(merchant_key: [u8; 32], domain: &str) -> PayerScope {
        PayerScope {
            merchant_key,
            registrable_domain: domain.to_string(),
        }
    }

    #[test]
    fn derivation_is_deterministic_and_root_separated() {
        let s = scope([0xAA; 32], "example.com");
        let a1 = Custody::from_root(&[0x11; 32]);
        let a2 = Custody::from_root(&[0x11; 32]);
        let b = Custody::from_root(&[0x22; 32]);
        // Same root + same scope → same identity; different root → different (F1-f).
        assert_eq!(a1.payer_key(&s), a2.payer_key(&s));
        assert_ne!(a1.payer_key(&s), b.payer_key(&s));
    }

    #[test]
    fn payer_key_is_unlinkable_across_merchant_or_domain() {
        // The F1-f/F2.3 unlinkability MUST: one root, but two different merchants — or
        // the same merchant key on two different registrable domains — derive DIFFERENT
        // payer keys, so a payer cannot be linked across them.
        let c = Custody::from_root(&[0x11; 32]);
        let mk_a = [0xA1; 32];
        let mk_b = [0xB2; 32];
        let k_a = c.payer_key(&scope(mk_a, "alice-merchant.com"));
        let k_b = c.payer_key(&scope(mk_b, "bob-merchant.com"));
        // Different merchant → different key.
        assert_ne!(k_a, k_b);
        // Same merchant KEY, different registrable domain → different key.
        let k_a_other_domain = c.payer_key(&scope(mk_a, "alice-merchant.org"));
        assert_ne!(k_a, k_a_other_domain);
        // Same merchant, different DOMAIN spelling that resolves to the same eTLD+1 is
        // the caller's (scope holds an already-resolved domain); here the scope itself
        // is the identity input, and it is stable:
        let k_a_again = c.payer_key(&scope(mk_a, "alice-merchant.com"));
        assert_eq!(k_a, k_a_again);
    }

    #[test]
    fn scoped_derivation_differs_from_the_retired_global_v1() {
        // The intended re-key: the scoped v2 key is NOT the retired global v0.1 key
        // `HKDF(root, info="PayTPv1-payer")`. This documents the migration executably —
        // deriving scoped keys is a deliberate identity change, not accidental drift.
        let root = [0x11; 32];
        let c = Custody::from_root(&root);
        let global_v1 = {
            let sk = crypto::hkdf_sha256(&root, None, b"PayTPv1-payer", 32);
            let mut s = [0u8; 32];
            s.copy_from_slice(&sk);
            crypto::ed25519_public(&s)
        };
        let scoped_v2 = c.payer_key(&scope([0xAA; 32], "example.com"));
        assert_ne!(scoped_v2, global_v1);
    }

    #[test]
    fn signs_verifiably_under_the_scoped_payer_key() {
        let c = Custody::from_root(&[0x33; 32]);
        let s = scope([0xCC; 32], "example.com");
        let sig = c.sign(&s, b"hello");
        assert!(crypto::ed25519_verify_strict(&c.payer_key(&s), b"hello", &sig).is_ok());
        assert!(crypto::ed25519_verify_strict(&c.payer_key(&s), b"tampered", &sig).is_err());
        // A signature made under a DIFFERENT scope does not verify under this scope's key.
        let other = scope([0xDD; 32], "example.com");
        assert!(crypto::ed25519_verify_strict(&c.payer_key(&other), b"hello", &sig).is_err());
    }

    #[test]
    fn resolve_scopes_through_the_shared_normalizer() {
        // Subdomains of one merchant fold to one registrable domain → one stable key
        // (same-merchant stability); a bad host fails closed.
        let mk = [0xAA; 32];
        let a = PayerScope::resolve(mk, "api.shop.example.com").unwrap();
        let b = PayerScope::resolve(mk, "www.example.com").unwrap();
        assert_eq!(a.registrable_domain, "example.com");
        assert_eq!(a, b);
        assert!(PayerScope::resolve(mk, "NOT-normalized.example.com").is_err());
    }
}
