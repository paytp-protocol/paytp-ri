//! The x402 **V2** envelope (F3.1) — the transport-and-scheme-independent types
//! a plain x402 client and facilitator exchange, and PayTP's placement inside
//! them.
//!
//! **PayTP defines none of these** (F3.1): x402 defines `PaymentRequired`,
//! `PaymentRequirements`, `PaymentPayload`, `SettlementResponse`; PayTP defines
//! only the `paytp` member carried in x402's `extensions` mechanism, and the
//! client's copy-back of it in the `PaymentPayload`. This module models the x402
//! V2 shapes (verified against the x402-foundation/coinbase V2 specification,
//! `specs/x402-specification-v2.md`, 2025-12-09) so the RI can emit a **real**
//! x402 V2 `402` a plain, PayTP-unaware client completes, and a PayTP-aware
//! client additionally round-trips the `paytp` extension.
//!
//! Two JSON regimes meet here and MUST NOT be conflated (F3-a):
//! - The **x402 envelope** is plain JSON in *x402's own types* — a field x402
//!   encodes as a number stays a number (`x402Version`, `maxTimeoutSeconds`);
//!   `amount`/`asset`/`payTo` are x402 strings. It is serialized with a normal
//!   JSON serializer (`serde_json`), **not** PayTP's JCS/F1-c string-numeric
//!   rule (F1.2 scope note).
//! - The inner **`paytp` object** (the signed quote, the receipt) stays a PayTP
//!   object: JCS, F1-c string-numeric, Ed25519 over `PayTPv1-reqs`/`-receipt`.
//!   It is embedded verbatim as a nested JSON value under the `paytp` extension;
//!   the merchant re-verifies its signature over the JCS form of the echoed copy
//!   (F3.4), so incidental re-serialization by the transport is harmless.

use crate::error::{Error, Result};
use crate::jcs::StrictValue;
use crate::tier0::quote::{Offer, Quote};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The x402 protocol version this RI **emits** (F3-j): the **shipped**
/// `x402@1.2.0` tooling is V1-protocol-shaped, and the "plain x402 client pays
/// the split" USP only works against tooling that exists today — so the RI emits
/// V1 (the x402 V2 doc is the forward target). The shipped top-level requires the
/// literal `1`.
pub const X402_VERSION: u8 = 1;

/// The extension identifier PayTP registers in x402's `extensions` map (F3-i).
pub const PAYTP_EXTENSION_KEY: &str = "paytp";

/// `ResourceInfo` — the protected resource. In the shipped x402 V1 shape the
/// resource lives **inside each requirement** (`resource`/`description`/
/// `mimeType`); this optional top-level copy is emitted for convenience only, and
/// a PayTP wallet MUST NOT depend on it (F3-j rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A single **shipped x402 V1** `PaymentRequirements` — one acceptable payment
/// method, verified against `x402@1.2.0`'s `PaymentRequirementsSchema`. For a
/// PayTP **baseline** offer this is the mirror (F3-a): `payTo` **is** the
/// re-derived split address (F3-h), so a plain x402 client pays it directly
/// and the meed divides on-chain. The mirror is **hybrid** (F3-j rule 1): it
/// carries x402's live vocabulary (**named** `network`, `maxAmountRequired`,
/// per-req `resource`) even though the signed `paytp` object's own ids stay CAIP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    /// x402 **named** network (F3-j rule 1), e.g. `"solana-devnet"`, `"base"` —
    /// NOT CAIP-2. A baseline wallet maps it back to CAIP-2 (F3-j rule 2/3).
    pub network: String,
    /// Atomic token units, decimal string (the shipped field name).
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: String,
    /// Token mint / contract address, or ISO-4217 code for fiat.
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// The resource this requirement prices (shipped V1: per-requirement). A
    /// PayTP wallet checks it == the signed `paytp.resource` (F3-j rule 4).
    pub resource: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Max seconds allowed to complete payment — an x402 **number**.
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    /// Scheme-specific data (for example exact-svm `feePayer`). PayTP baseline
    /// redemption does not rely on exact-svm `extra.memo`; nonce/ref binding is
    /// enforced by the merchant's durable consumed-settlement record. **Object-typed** —
    /// a present non-object (incl. an explicit `null`) is refused at parse; an absent
    /// field maps to `None`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_extra"
    )]
    pub extra: Option<serde_json::Map<String, Value>>,
}

/// Deserialize `extra`: an absent field is `None` (via `default`); a present
/// field MUST be a JSON object — `null`, string, number, array all rejected
/// (x402 V2 §5.1.2 "object"). Called only when the field is present.
fn de_extra<'de, D>(d: D) -> std::result::Result<Option<serde_json::Map<String, Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Value::deserialize(d)? {
        Value::Object(m) => Ok(Some(m)),
        _ => Err(serde::de::Error::custom("x402 `extra` must be an object")),
    }
}

/// The shipped x402 V1 `PaymentRequired` body a resource server returns on a
/// payment-required signal: `x402Version` (the literal `1`), `accepts`, and the
/// PayTP `extensions` where the signed `paytp` object rides (F3-i).
///
/// **Note on `extensions` (verified against `x402@1.2.0`):** the shipped
/// top-level schema *validates* a body carrying `extensions` but **strips it on
/// parse** — so a PayTP-aware client reads the `paytp` object from the **raw**
/// 402 bytes (it does not rely on the x402 schema to preserve it); the durable,
/// schema-retained slot is `accepts[i].extra` (available if a future F3 revision
/// moves the embedding there). A plain client ignores both.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentRequired {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional top-level resource (shipped V1 has no *required* top-level
    /// resource; the resource is per-requirement). Not emitted by default; a
    /// PayTP wallet MUST NOT depend on it (F3-j rule 4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepts: Vec<PaymentRequirements>,
    /// The x402 extensions map: `{ "paytp": { "info": …, "schema": … } }` (F3-i).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

/// The x402 V2 `PaymentPayload` (§5.2.1) a client returns to authorize a
/// payment. A PayTP-aware client echoes the `paytp` extension back here,
/// member-preserved (F3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// The `PaymentRequirements` the client chose to pay (§5.2.2).
    pub accepted: PaymentRequirements,
    /// Scheme-specific authorization (exact-EVM: signature+authorization;
    /// exact-SVM: `{ "transaction": <base64 partially-signed tx> }`).
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

impl PaymentRequirements {
    /// Convert to a PayTP [`StrictValue`] — the form the mirror is stored as
    /// **inside** the signed `paytp` quote (F3-a). Round-trips exactly through
    /// x402's own JSON types (`maxTimeoutSeconds` a number, the rest strings).
    pub fn to_strict(&self) -> Result<StrictValue> {
        let v = serde_json::to_value(self).map_err(|_| Error::JsonMalformed)?;
        value_to_strict(&v)
    }

    /// Rebuild a `PaymentRequirements` from a stored mirror (the offer's
    /// `accept`). The inverse of [`to_strict`] — used to check `accepts[i]`
    /// equals the mirror the merchant signed (F3-a).
    pub fn from_strict(sv: &StrictValue) -> Result<PaymentRequirements> {
        let v = strict_to_value(sv)?;
        serde_json::from_value(v).map_err(|_| Error::JsonMalformed)
    }
}

impl PaymentRequired {
    /// Serialize to x402 JSON (plain JSON, x402's own types).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("x402 PaymentRequired serializes")
    }

    /// Parse a shipped-x402-V1 `PaymentRequired` body and check the invariants a
    /// plain client relies on: version `== 1`, a non-empty `accepts`, and each
    /// requirement carrying a `resource` (per-requirement in V1).
    pub fn parse(json: &str) -> Result<PaymentRequired> {
        // Reject duplicate members anywhere in the raw 402 body (F1.2) — including inside the
        // embedded paytp.info object — BEFORE the last-wins serde parse could collapse a
        // duplicate in the SIGNED paytp object (a cross-parser split the spec forbids).
        // Fail closed on ANY parse_strict error (a duplicate, or a body that pairs a duplicate
        // with an anomaly parse_strict reports first): the strict parser must validate the
        // whole body, not just the subset serde's typed shape models.
        crate::jcs::parse_strict(json)?;
        let pr: PaymentRequired = serde_json::from_str(json).map_err(|_| Error::JsonMalformed)?;
        if pr.x402_version != X402_VERSION {
            return Err(Error::FieldDomain);
        }
        if pr.accepts.is_empty() || pr.accepts.iter().any(|a| a.resource.is_empty()) {
            return Err(Error::MissingField);
        }
        Ok(pr)
    }

    /// The signed `paytp` quote object carried under the `paytp` extension's
    /// `info`, as JSON text ready for [`crate::tier0::quote::Quote::parse_verify`].
    /// Returns `None` for a plain (PayTP-unaware) `PaymentRequired`.
    ///
    /// Embedding (F3.1, **flagged for ratification**): `extensions.paytp.info`
    /// **is** the signed `paytp` object directly (its own members
    /// `v`/`nonce`/…/`signature`); `extensions.paytp.schema` is its JSON Schema.
    pub fn paytp_info_json(&self) -> Option<String> {
        let info = self
            .extensions
            .as_ref()?
            .get(PAYTP_EXTENSION_KEY)?
            .get("info")?;
        Some(info.to_string())
    }

    /// The **F3-a mirror check**: the subset of `accepts[]` a conformant PayTP
    /// client MAY execute as PayTP payments — those an offer in the **verified**
    /// signed `quote` mirrors. Returns `(index, &offer)` pairs.
    ///
    /// An `accepts` entry no signed offer mirrors, or one whose mirror differs in
    /// any member the shipped x402 schema models (`payTo`, `maxAmountRequired`,
    /// `asset`, `network`, `resource`, `maxTimeoutSeconds`, `extra` — a proxy that
    /// rewrote any of these in the outer envelope) is **excluded**; the client
    /// MUST NOT apply PayTP execution (split re-derivation, nonce binding, receipt)
    /// to it, though it MAY still complete it as a plain x402 payment (F3-a).
    ///
    /// **The load-bearing guarantee (why this is safe):** a matched client pays
    /// the **signed** terms from the returned `offer.accept`, **never the outer
    /// `accepts[i]`**. Comparison is over the typed (schema-modeled) fields, so an
    /// *unmodeled* extra member a proxy appends to the outer entry is dropped by
    /// the parser and does not change the match — but it is **inert**: it cannot
    /// alter `payTo`/amount/asset/etc (those are modeled and must match the signed
    /// mirror), and the client pays the signed mirror regardless. No proxy edit of
    /// a *meaningful* field survives (it breaks the modeled-field equality), so no
    /// wrong-terms payment is possible; the F3-a scope (client protection) holds.
    ///
    /// `quote` MUST already be signature-verified (via
    /// [`Quote::parse_verify`] over [`paytp_info_json`]); this only enforces the
    /// accept↔mirror equality.
    pub fn paytp_mirrored_accepts<'a>(&'a self, quote: &'a Quote) -> Vec<(usize, &'a Offer)> {
        let mut out = Vec::new();
        for (i, entry) in self.accepts.iter().enumerate() {
            if let Some(offer) = quote.offers.iter().find(|o| {
                PaymentRequirements::from_strict(&o.accept)
                    .map(|m| &m == entry)
                    .unwrap_or(false)
            }) {
                out.push((i, offer));
            }
        }
        out
    }
}

impl PaymentPayload {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("x402 PaymentPayload serializes")
    }

    pub fn parse(json: &str) -> Result<PaymentPayload> {
        // Reject duplicate members anywhere in the raw payload (F1.2), including the echoed
        // paytp.info — same cross-parser-split closure as PaymentRequired::parse; fail closed
        // on ANY parse_strict error, not just JsonDuplicateMember.
        crate::jcs::parse_strict(json)?;
        let pp: PaymentPayload = serde_json::from_str(json).map_err(|_| Error::JsonMalformed)?;
        if pp.x402_version != X402_VERSION {
            return Err(Error::FieldDomain);
        }
        Ok(pp)
    }

    /// The echoed signed `paytp` object (F3.4), as JSON text for re-verification.
    pub fn paytp_info_json(&self) -> Option<String> {
        let info = self
            .extensions
            .as_ref()?
            .get(PAYTP_EXTENSION_KEY)?
            .get("info")?;
        Some(info.to_string())
    }
}

/// Build the x402 V2 `extensions` value carrying a signed `paytp` object under
/// the `paytp` key: `{ "paytp": { "info": <paytp object>, "schema": <schema> } }`.
///
/// `paytp_object` is the signed quote as a JSON value (its JCS bytes parsed).
/// The `schema` is the JSON Schema advertising the extension's shape (x402 V2
/// §5.1.2 requires both `info` and `schema`).
pub fn paytp_extension(paytp_object: Value, schema: Value) -> Value {
    let mut ext = serde_json::Map::new();
    let mut inner = serde_json::Map::new();
    inner.insert("info".to_string(), paytp_object);
    inner.insert("schema".to_string(), schema);
    ext.insert(PAYTP_EXTENSION_KEY.to_string(), Value::Object(inner));
    Value::Object(ext)
}

// ---------------------------------------------------------------------------
// StrictValue <-> serde_json::Value bridge
//
// The x402 envelope is serde_json; the PayTP mirror is StrictValue. The bridge
// is exact because `to_jcs` emits `Number` bare and `String` quoted, so a
// StrictValue round-trips through valid JSON and back.
// ---------------------------------------------------------------------------

/// serde_json → StrictValue. Numbers are carried as their exact source text
/// (StrictValue::Number(String)); this is what the mirror preserves (F3-a).
pub fn value_to_strict(v: &Value) -> Result<StrictValue> {
    Ok(match v {
        Value::Null => StrictValue::Null,
        Value::Bool(b) => StrictValue::Bool(*b),
        // Canonicalize numbers **identically to the StrictValue Deserialize
        // path** (`jcs`, visit_i64/u64/f64 → the primitive's `to_string`), so a
        // mirror built here and one re-parsed from the wire agree byte-for-byte
        // — else a float `extra` (e.g. `1.0`) would sign as "1.0" but re-parse
        // as "1" and false-reject the merchant's own quote.
        Value::Number(n) => {
            let s = if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else if let Some(f) = n.as_f64() {
                f.to_string()
            } else {
                return Err(Error::JsonMalformed);
            };
            StrictValue::Number(s)
        }
        Value::String(s) => StrictValue::String(s.clone()),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(value_to_strict(it)?);
            }
            StrictValue::Array(out)
        }
        Value::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, val) in map {
                out.push((k.clone(), value_to_strict(val)?));
            }
            StrictValue::Object(out)
        }
    })
}

/// StrictValue → serde_json, via the canonical JCS bytes (numbers emitted bare).
/// Fallible: a caller-constructed `StrictValue::Number` holding a non-canonical
/// numeric string (e.g. `"01"`) yields invalid JSON and is rejected rather than
/// panicking. For values parsed from the wire this never errors.
pub fn strict_to_value(sv: &StrictValue) -> Result<Value> {
    let bytes = crate::jcs::to_jcs(sv);
    serde_json::from_slice(&bytes).map_err(|_| Error::JsonMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_reqs() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "solana-devnet".into(), // x402 named network (F3-j)
            max_amount_required: "1000000".into(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            pay_to: "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4".into(),
            resource: "https://api.example/data".into(),
            description: "Premium data".into(),
            mime_type: "application/json".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    #[test]
    fn payment_required_is_shipped_v1_shape() {
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            error: None,
            resource: None,
            accepts: vec![sample_reqs()],
            extensions: None,
        };
        let json = String::from_utf8(pr.to_json()).unwrap();
        // Shipped V1: x402Version literal 1, maxAmountRequired string, per-req
        // resource, named network, no required top-level resource.
        assert!(json.contains("\"x402Version\":1"));
        assert!(json.contains("\"maxTimeoutSeconds\":60"));
        assert!(json.contains("\"maxAmountRequired\":\"1000000\""));
        assert!(json.contains("\"network\":\"solana-devnet\""));
        assert!(!json.contains("\"amount\"")); // no V2 `amount`
        let back = PaymentRequired::parse(&json).unwrap();
        assert_eq!(back, pr);
    }

    #[test]
    fn mirror_bridge_is_exact() {
        // A PaymentRequirements → StrictValue (the stored mirror) → back is the
        // identity, so accepts[i] and the signed mirror are provably equal.
        let reqs = sample_reqs();
        let mirror = reqs.to_strict().unwrap();
        let back = PaymentRequirements::from_strict(&mirror).unwrap();
        assert_eq!(reqs, back);
        // The number field survives as a number through the bridge.
        let v = strict_to_value(&mirror).unwrap();
        assert!(v.get("maxTimeoutSeconds").unwrap().is_number());
        assert!(v.get("maxAmountRequired").unwrap().is_string());
    }

    fn v1_body(extra_snippet: &str) -> String {
        format!(
            r#"{{"x402Version":1,"accepts":[{{"scheme":"exact","network":"solana-devnet",
            "maxAmountRequired":"1","asset":"a","payTo":"p","resource":"https://x/y",
            "description":"","mimeType":"application/json","maxTimeoutSeconds":60{extra_snippet}}}]}}"#
        )
    }

    #[test]
    fn non_object_extra_is_rejected_at_parse() {
        // `extra` is object-typed; a bare string / explicit null is refused.
        assert!(PaymentRequired::parse(&v1_body(",\"extra\":\"not-an-object\"")).is_err());
        assert!(PaymentRequired::parse(&v1_body(",\"extra\":null")).is_err());
        // An absent extra is fine (maps to None).
        assert!(PaymentRequired::parse(&v1_body("")).unwrap().accepts[0]
            .extra
            .is_none());
    }

    #[test]
    fn float_extra_number_canonicalizes_like_the_wire() {
        // A float in `extra` must stringify the SAME on the build path
        // (value_to_strict) and the wire re-parse path (jcs Deserialize), else a
        // merchant's own quote false-rejects.
        let mut extra = serde_json::Map::new();
        extra.insert("p".into(), serde_json::json!(1.0));
        let mut reqs = sample_reqs();
        reqs.extra = Some(extra);
        let mirror = reqs.to_strict().unwrap();
        // Canonical JCS bytes must be **stable** across a build→jcs→parse→jcs
        // round-trip (what signature verification depends on). Order-insensitive:
        // JCS sorts keys, so compare bytes, not the order-sensitive StrictValue.
        let bytes1 = crate::jcs::to_jcs(&mirror);
        let via_wire = crate::jcs::parse_strict(std::str::from_utf8(&bytes1).unwrap()).unwrap();
        let bytes2 = crate::jcs::to_jcs(&via_wire);
        assert_eq!(bytes1, bytes2);
        // And the float stringified to the integer form ("1", not "1.0").
        assert!(std::str::from_utf8(&bytes1).unwrap().contains("\"p\":1"));
    }

    #[test]
    fn strict_to_value_rejects_noncanonical_number() {
        // A caller-built malformed number is an error, not a panic (the LOW fix).
        assert!(strict_to_value(&StrictValue::Number("01".into())).is_err());
        assert!(PaymentRequirements::from_strict(&StrictValue::Number("01".into())).is_err());
    }

    #[test]
    fn version_and_shape_rejects() {
        // A V2-versioned body is rejected (the RI emits/accepts the shipped V1).
        let mut bad = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: None,
            accepts: vec![sample_reqs()],
            extensions: None,
        };
        let json = String::from_utf8(bad.to_json()).unwrap();
        assert_eq!(PaymentRequired::parse(&json), Err(Error::FieldDomain));
        bad.x402_version = 1;
        bad.accepts.clear();
        let json = String::from_utf8(bad.to_json()).unwrap();
        assert_eq!(PaymentRequired::parse(&json), Err(Error::MissingField));
    }

    #[test]
    fn paytp_extension_embeds_info_and_schema() {
        let paytp_obj = serde_json::json!({"v":"1","nonce":"AAA","signature":"BBB"});
        let schema = serde_json::json!({"type":"object"});
        let ext = paytp_extension(paytp_obj.clone(), schema);
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            error: None,
            resource: None,
            accepts: vec![sample_reqs()],
            extensions: Some(ext),
        };
        let json = String::from_utf8(pr.to_json()).unwrap();
        let back = PaymentRequired::parse(&json).unwrap();
        let info = back.paytp_info_json().unwrap();
        // The info round-trips to the same paytp object.
        let parsed: Value = serde_json::from_str(&info).unwrap();
        assert_eq!(parsed, paytp_obj);
    }

    #[test]
    fn duplicate_member_in_paytp_info_is_rejected() {
        // F1: a duplicate member inside the embedded, SIGNED paytp.info object must be
        // rejected at the 402 parse — not silently collapsed last-wins before the
        // dup-rejecting verifier ever sees the original bytes.
        let paytp_obj = serde_json::json!({"v":"1","nonce":"AAA","signature":"BBB"});
        let schema = serde_json::json!({"type":"object"});
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            error: None,
            resource: None,
            accepts: vec![sample_reqs()],
            extensions: Some(paytp_extension(paytp_obj, schema)),
        };
        let json = String::from_utf8(pr.to_json()).unwrap();
        assert!(PaymentRequired::parse(&json).is_ok()); // the clean body parses
                                                        // Inject a duplicate member into the signed info object.
        let dup = json.replacen(r#""nonce":"AAA""#, r#""nonce":"AAA","nonce":"EVIL""#, 1);
        assert_ne!(dup, json);
        assert_eq!(
            PaymentRequired::parse(&dup),
            Err(Error::JsonDuplicateMember)
        );
    }

    #[test]
    fn plain_payment_required_has_no_paytp() {
        let pr = PaymentRequired {
            x402_version: X402_VERSION,
            error: None,
            resource: None,
            accepts: vec![sample_reqs()],
            extensions: None,
        };
        assert!(pr.paytp_info_json().is_none());
    }
}
