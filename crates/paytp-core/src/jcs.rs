//! Canonical JSON for Tier 0 (**F1.2 / GAP-FILL F1-c**, formalizing §5.2/§5.6).
//!
//! The `paytp` extension and its signed sub-objects use **JCS (RFC 8785)**. Two
//! rules F1 fixes on top:
//!
//! - **Duplicate members are rejected anywhere in the parsed document** (F1.2) —
//!   the enclosing x402 envelope included, before any object is extracted, so a
//!   first-wins/last-wins parser split cannot verify two different signed
//!   objects from the same bytes.
//! - **Every PayTP-native numeric/timestamp/opaque value is a JSON string** with
//!   a fixed, **anchored** grammar (`^…$`) (F1-c). This closes the
//!   `"1"`/`"01"`/`"1.0"` ambiguity. Mirrored x402 values keep x402's own JSON
//!   types (F1.2 scope note) and are out of M0 scope (they land with M1's quote).

use crate::error::{Error, Result};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

// ---------------------------------------------------------------------------
// F1-c anchored grammars
// ---------------------------------------------------------------------------

/// Anchored unsigned-integer grammar `^(0|[1-9][0-9]*)$` (F1-c): no leading
/// zero, no sign, no point, no exponent, no whitespace.
pub fn validate_uint_string(s: &str) -> Result<()> {
    let ok = match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [first, rest @ ..] => {
            (b'1'..=b'9').contains(first) && rest.iter().all(|b| b.is_ascii_digit())
        }
    };
    if ok {
        Ok(())
    } else {
        Err(Error::JsonGrammar)
    }
}

/// Anchored signed-integer grammar `^-?(0|[1-9][0-9]*)$` with no `-0` (F1-c).
pub fn validate_sint_string(s: &str) -> Result<()> {
    if let Some(mag) = s.strip_prefix('-') {
        if mag == "0" {
            return Err(Error::JsonGrammar); // no -0
        }
        validate_uint_string(mag)
    } else {
        validate_uint_string(s)
    }
}

/// Anchored Base64url-unpadded grammar (F1-c): the alphabet `A–Z a–z 0–9 - _`,
/// no `=` padding, non-empty. Widths are field-specific (F3/F4).
pub fn validate_base64url_unpadded(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::JsonGrammar);
    }
    let ok = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(Error::JsonGrammar)
    }
}

// ---------------------------------------------------------------------------
// Duplicate-member-rejecting parse
// ---------------------------------------------------------------------------

/// A parsed JSON value that has been checked for duplicate members at every
/// object level (F1.2). Member order is preserved as written (JCS re-sorts on
/// serialization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictValue {
    Null,
    Bool(bool),
    /// A JSON number, kept as its canonical textual form. PayTP-native objects
    /// carry none of these (F1-c); they appear only in x402 mirrors (M1).
    Number(String),
    String(String),
    Array(Vec<StrictValue>),
    /// Object members in document order, guaranteed duplicate-free.
    Object(Vec<(String, StrictValue)>),
}

const DUP_MSG: &str = "paytp-duplicate-member";

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Null)
            }
            fn visit_none<E>(self) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Null)
            }
            fn visit_bool<E>(self, b: bool) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Number(n.to_string()))
            }
            fn visit_u64<E>(self, n: u64) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Number(n.to_string()))
            }
            fn visit_f64<E>(self, n: f64) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::Number(n.to_string()))
            }
            fn visit_str<E>(self, s: &str) -> std::result::Result<StrictValue, E> {
                Ok(StrictValue::String(s.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<StrictValue, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<StrictValue>()? {
                    out.push(v);
                }
                Ok(StrictValue::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<StrictValue, A::Error> {
                let mut out: Vec<(String, StrictValue)> = Vec::new();
                // O(1)-amortized duplicate detection (a HashSet, not an O(n) scan of `out`) so
                // an adversarial object with many members cannot force O(n^2) work.
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                while let Some(k) = map.next_key::<String>()? {
                    if !seen.insert(k.clone()) {
                        return Err(de::Error::custom(DUP_MSG)); // duplicate member
                    }
                    let v = map.next_value::<StrictValue>()?;
                    out.push((k, v));
                }
                Ok(StrictValue::Object(out))
            }
        }
        d.deserialize_any(V)
    }
}

/// Parse a JSON document, rejecting duplicate members anywhere (F1.2).
pub fn parse_strict(text: &str) -> Result<StrictValue> {
    match serde_json::from_str::<StrictValue>(text) {
        Ok(v) => Ok(v),
        Err(e) if e.to_string().contains(DUP_MSG) => Err(Error::JsonDuplicateMember),
        Err(_) => Err(Error::JsonMalformed),
    }
}

// ---------------------------------------------------------------------------
// JCS canonical serialization (RFC 8785 key ordering)
// ---------------------------------------------------------------------------

/// Serialize to canonical JCS bytes (RFC 8785): object members sorted by UTF-16
/// code units, minimal separators, no insignificant whitespace.
///
/// M0 scope: PayTP-native objects carry no raw JSON numbers (all string-encoded,
/// F1-c), so number canonicalization is passed through unchanged. Full
/// ECMAScript number canonicalization for x402 mirrors is exercised/confirmed
/// with M1's quote objects.
pub fn to_jcs(value: &StrictValue) -> Vec<u8> {
    let mut out = String::new();
    write_jcs(value, &mut out);
    out.into_bytes()
}

fn write_jcs(value: &StrictValue, out: &mut String) {
    match value {
        StrictValue::Null => out.push_str("null"),
        StrictValue::Bool(true) => out.push_str("true"),
        StrictValue::Bool(false) => out.push_str("false"),
        StrictValue::Number(n) => out.push_str(n),
        StrictValue::String(s) => write_json_string(s, out),
        StrictValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out);
            }
            out.push(']');
        }
        StrictValue::Object(members) => {
            let mut sorted: Vec<&(String, StrictValue)> = members.iter().collect();
            sorted.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_jcs(v, out);
            }
            out.push('}');
        }
    }
}

/// RFC 8785 §3.2.3 string escaping (the JSON minimal-escape set).
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by their UTF-16 code-unit sequences (RFC 8785 ordering).
fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_grammar() {
        // F10.3: reject "01", "1.0", " 1"; accept "0", "1", "1000".
        for good in ["0", "1", "1000", "9999999999"] {
            assert!(validate_uint_string(good).is_ok(), "{good}");
        }
        for bad in ["01", "1.0", " 1", "1 ", "-1", "", "1e3", "+1", "00"] {
            assert!(validate_uint_string(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sint_grammar() {
        // F10.3: reject "-0".
        assert!(validate_sint_string("-1").is_ok());
        assert!(validate_sint_string("0").is_ok());
        assert!(validate_sint_string("-0").is_err());
        assert!(validate_sint_string("01").is_err());
    }

    #[test]
    fn duplicate_members_rejected_anywhere() {
        // Top level.
        assert_eq!(
            parse_strict(r#"{"a":1,"a":2}"#),
            Err(Error::JsonDuplicateMember)
        );
        // Nested (the enclosing-envelope case: a duplicate deep in the document).
        assert_eq!(
            parse_strict(r#"{"outer":{"b":1,"b":2}}"#),
            Err(Error::JsonDuplicateMember)
        );
        // Inside an array element.
        assert_eq!(
            parse_strict(r#"[{"x":1,"x":2}]"#),
            Err(Error::JsonDuplicateMember)
        );
        // A clean document parses.
        assert!(parse_strict(r#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn jcs_sorts_keys_by_utf16() {
        let v = parse_strict(r#"{"b":"2","a":"1","c":"3"}"#).unwrap();
        assert_eq!(to_jcs(&v), br#"{"a":"1","b":"2","c":"3"}"#.to_vec());
    }

    #[test]
    fn jcs_no_whitespace_and_escapes() {
        let v = parse_strict("{\"k\": \"a\\nb\" }").unwrap();
        assert_eq!(to_jcs(&v), br#"{"k":"a\nb"}"#.to_vec());
    }
}
