//! Control-endpoint cache discipline (**F2.6 / §5.2 / F1.1 carriage**).
//!
//! PayTP header fields are sensitive. Quote-bearing `402`s and PayTP-authenticated
//! responses MUST carry `Cache-Control: no-store`, and responses MUST `Vary` on
//! **both** the PayTP capability header and the `PayTP-Roles` header — the quote
//! is built from the role entries, so it must never be cache-served across
//! differing role headers (a cross-role cache-poisoning surface, §5.2).
//!
//! Without a live HTTP stack (that lands with the axum profile at M3), this
//! models the response headers a conformant merchant emits and a caching
//! intermediary that enforces them, so the discipline is testable now.

/// The request header a client sets to advertise PayTP support (§5.1/§8.4).
pub const CAPABILITY_HEADER: &str = "PayTP";
/// The request header carrying asserted roles (F3.3).
pub const ROLES_HEADER: &str = "PayTP-Roles";

/// The response headers a conformant merchant attaches to a PayTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeaders {
    /// `Cache-Control` value, if any (`no-store` for sensitive responses).
    pub cache_control: Option<String>,
    /// The header names this response varies on.
    pub vary: Vec<String>,
}

impl ResponseHeaders {
    /// Headers for a quote-bearing `402` (§5.2): `no-store`, `Vary` on capability
    /// AND role headers.
    pub fn quote_402() -> Self {
        ResponseHeaders {
            cache_control: Some("no-store".into()),
            vary: vec![CAPABILITY_HEADER.into(), ROLES_HEADER.into()],
        }
    }

    /// Headers for a PayTP-authenticated response (a receipt-bearing settlement
    /// response): `no-store`, same `Vary` (§5.2, F2-i).
    pub fn authenticated() -> Self {
        Self::quote_402()
    }

    pub fn is_no_store(&self) -> bool {
        self.cache_control.as_deref() == Some("no-store")
    }

    /// A cacheable response that still Varies on both PayTP headers (for tests).
    #[cfg(test)]
    fn default_uncached() -> Self {
        ResponseHeaders {
            cache_control: None,
            vary: vec![CAPABILITY_HEADER.into(), ROLES_HEADER.into()],
        }
    }
}

/// A caching intermediary between payer and merchant that honors HTTP caching
/// semantics — used by the conformance suite to assert the §5.2 discipline.
#[derive(Default)]
pub struct CacheSim {
    entries: std::collections::HashMap<String, (ResponseHeaders, String)>,
    /// Count of times a request was served from cache (for assertions).
    pub hits: usize,
    pub misses: usize,
}

impl CacheSim {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cache key: the URL plus the values of exactly the `Vary` headers the
    /// stored response named (so a response never crosses a varying header).
    fn key(url: &str, vary: &[String], cap: &str, roles: &str) -> String {
        let mut k = url.to_string();
        for h in vary {
            let v = if h == CAPABILITY_HEADER {
                cap
            } else if h == ROLES_HEADER {
                roles
            } else {
                ""
            };
            k.push('\u{1f}');
            k.push_str(h);
            k.push('=');
            k.push_str(v);
        }
        k
    }

    /// Fetch through the cache: return a cached body when a valid entry exists,
    /// else call `produce`, store it iff cacheable (not `no-store`), and return.
    pub fn fetch(
        &mut self,
        url: &str,
        cap: &str,
        roles: &str,
        produce: impl FnOnce() -> (ResponseHeaders, String),
    ) -> String {
        // A cached entry is keyed by the Vary headers it declared, so an entry
        // matches only when this request's Vary-header values reproduce its key.
        let candidate_keys: Vec<String> = self
            .entries
            .iter()
            .filter_map(|(k, (h, _))| {
                let expect = Self::key(url, &h.vary, cap, roles);
                if *k == expect {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        if let Some(k) = candidate_keys.first() {
            self.hits += 1;
            return self.entries[k].1.clone();
        }
        self.misses += 1;
        let (headers, body) = produce();
        if !headers.is_no_store() {
            let k = Self::key(url, &headers.vary, cap, roles);
            self.entries.insert(k, (headers, body.clone()));
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_402_is_no_store_and_varies_on_both_headers() {
        let h = ResponseHeaders::quote_402();
        assert!(h.is_no_store());
        assert!(h.vary.contains(&CAPABILITY_HEADER.to_string()));
        assert!(h.vary.contains(&ROLES_HEADER.to_string()));
    }

    #[test]
    fn no_store_quote_is_never_cached() {
        let mut cache = CacheSim::new();
        let url = "https://api.example/resource";
        let mut built = 0;
        let mut produce = || {
            built += 1;
            (ResponseHeaders::quote_402(), format!("quote-{built}"))
        };
        let a = cache.fetch(url, "1", "roles-A", &mut produce);
        let b = cache.fetch(url, "1", "roles-A", &mut produce);
        // Both requests hit the origin (no-store → never cached), fresh each time.
        assert_eq!(a, "quote-1");
        assert_eq!(b, "quote-2");
        assert_eq!(cache.misses, 2);
        assert_eq!(cache.hits, 0);
    }

    #[test]
    fn cross_role_poisoning_prevented() {
        // Even a hypothetically-cacheable response Varies on PayTP-Roles, so a
        // quote built for roles-A is never served to a roles-B request.
        let mut cache = CacheSim::new();
        let url = "https://api.example/resource";
        // A cacheable (non-sensitive) response that still Varies on both headers.
        let cacheable = || {
            (
                ResponseHeaders {
                    cache_control: None,
                    vary: vec![CAPABILITY_HEADER.into(), ROLES_HEADER.into()],
                },
                "body-for-roles-A".to_string(),
            )
        };
        let a = cache.fetch(url, "1", "roles-A", cacheable);
        assert_eq!(a, "body-for-roles-A");
        // A different role header is a cache MISS (keyed separately) — no poison.
        let b = cache.fetch(url, "1", "roles-B", || {
            (
                ResponseHeaders {
                    cache_control: None,
                    vary: vec![CAPABILITY_HEADER.into(), ROLES_HEADER.into()],
                },
                "body-for-roles-B".to_string(),
            )
        });
        assert_eq!(b, "body-for-roles-B");
        // Same role header again → served from cache.
        let a2 = cache.fetch(url, "1", "roles-A", || {
            (ResponseHeaders::default_uncached(), "SHOULD-NOT-RUN".into())
        });
        assert_eq!(a2, "body-for-roles-A");
        assert_eq!(cache.hits, 1);
    }
}
