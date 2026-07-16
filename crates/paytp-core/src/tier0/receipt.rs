//! The Tier 0 receipt (**F3.4**, formalizing §5.6 step 4).
//!
//! Inside the `PAYMENT-RESPONSE` settlement response, the merchant-signed
//! receipt over the challenge tuple and payment references. JSON per F1.2,
//! signed under `PayTPv1-receipt`. The purchaser's durable evidence for exactly
//! this purchase.

use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::jcs::{self, StrictValue};
use crate::{crypto, tier0::quote};

/// One settled leg (F3.4 `paid`): `{leg, network, ref}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidLeg {
    /// `"split"` (baseline), or `"meed"` / `"net"` (two-leg).
    pub leg: String,
    pub network: String,
    /// The rail transaction reference as the adapter binds it (§11.1).
    pub reference: String,
}

/// A parsed / constructed receipt (F3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub nonce: [u8; 32],
    pub idem: Vec<u8>,
    pub resource: String,
    /// The completed offer's mirror — which option was paid.
    pub accept: StrictValue,
    /// Exactly one `split` (baseline), or `meed` then `net` (two-leg).
    pub paid: Vec<PaidLeg>,
    /// Two-leg only: the meed entry identifier (32 bytes).
    pub entry: Option<[u8; 32]>,
    pub ts: u64,
    pub signature: Option<[u8; 64]>,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::JsonGrammar)
}

fn sv(s: impl Into<String>) -> StrictValue {
    StrictValue::String(s.into())
}

impl Receipt {
    fn to_value(&self, include_sig: bool) -> StrictValue {
        let paid = StrictValue::Array(
            self.paid
                .iter()
                .map(|p| {
                    StrictValue::Object(vec![
                        ("leg".into(), sv(&p.leg)),
                        ("network".into(), sv(&p.network)),
                        ("ref".into(), sv(&p.reference)),
                    ])
                })
                .collect(),
        );
        let mut members = vec![
            ("v".into(), sv("1")),
            ("nonce".into(), sv(b64(&self.nonce))),
            ("idem".into(), sv(b64(&self.idem))),
            ("resource".into(), sv(&self.resource)),
            ("accept".into(), self.accept.clone()),
            ("paid".into(), paid),
        ];
        if let Some(e) = &self.entry {
            members.push(("entry".into(), sv(b64(e))));
        }
        members.push(("ts".into(), sv(self.ts.to_string())));
        if include_sig {
            if let Some(sig) = &self.signature {
                members.push(("signature".into(), sv(b64(sig))));
            }
        }
        StrictValue::Object(members)
    }

    fn covered_bytes(&self) -> Vec<u8> {
        covered(DomainLabel::Receipt, &jcs::to_jcs(&self.to_value(false)))
    }

    /// Sign with the merchant identity key.
    pub fn sign(&mut self, merchant_sk: &[u8; 32]) {
        self.signature = Some(crypto::ed25519_sign(merchant_sk, &self.covered_bytes()));
    }

    pub fn to_json(&self) -> Vec<u8> {
        jcs::to_jcs(&self.to_value(true))
    }

    /// Validate `paid[]` shape (F3.4): exactly one `split`, or exactly
    /// `meed` then `net`; no duplicates, no extras.
    fn validate_paid(paid: &[PaidLeg]) -> Result<()> {
        let legs: Vec<&str> = paid.iter().map(|p| p.leg.as_str()).collect();
        match legs.as_slice() {
            ["split"] => Ok(()),
            ["meed", "net"] => Ok(()),
            _ => Err(Error::CountMismatch),
        }
    }

    /// Parse and verify the receipt under the merchant key.
    pub fn parse_verify(json: &str, merchant_pk: &[u8; 32]) -> Result<Receipt> {
        let value = jcs::parse_strict(json)?;
        let StrictValue::Object(members) = &value else {
            return Err(Error::JsonMalformed);
        };
        // F1.2/F1.3 (as `Quote::parse_verify`): reconstruct COVERED from **what arrived** —
        // the received object minus its `signature` member — never from a typed re-encoding
        // that would silently drop unknown members. So any appended / dropped / overwritten
        // member changes COVERED and **fails closed** (the F3.4 member-preserved rule), not
        // just the `entry`-specific check below. Exactly one `signature` member (parse_strict
        // already rejects document-wide duplicates per F1.2; make the invariant explicit).
        if members.iter().filter(|(k, _)| k == "signature").count() != 1 {
            return Err(Error::MissingField);
        }
        let signature: [u8; 64] = match members.iter().find(|(k, _)| k == "signature") {
            Some((_, StrictValue::String(s))) => {
                b64d(s)?.try_into().map_err(|_| Error::WrongWidth)?
            }
            _ => return Err(Error::MissingField),
        };
        let unsigned: Vec<(String, StrictValue)> = members
            .iter()
            .filter(|(k, _)| k != "signature")
            .cloned()
            .collect();
        let covered_bytes = covered(
            DomainLabel::Receipt,
            &jcs::to_jcs(&StrictValue::Object(unsigned)),
        );
        crypto::ed25519_verify_strict(merchant_pk, &covered_bytes, &signature)?;
        // Verified over the received bytes; now parse the typed view (its per-field
        // strictness — the `entry` type/iff rule below — is defense-in-depth over the
        // whole-object verify above).
        let get = |k: &str| members.iter().find(|(m, _)| m == k).map(|(_, v)| v);
        let get_str = |k: &str| -> Result<String> {
            match get(k) {
                Some(StrictValue::String(s)) => Ok(s.clone()),
                _ => Err(Error::MissingField),
            }
        };
        if get_str("v")? != "1" {
            return Err(Error::FieldDomain);
        }
        let nonce: [u8; 32] = b64d(&get_str("nonce")?)?
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let paid = match get("paid") {
            Some(StrictValue::Array(items)) => {
                let mut out = Vec::new();
                for it in items {
                    let StrictValue::Object(m) = it else {
                        return Err(Error::JsonMalformed);
                    };
                    let f = |k: &str| -> Result<String> {
                        match m.iter().find(|(x, _)| x == k) {
                            Some((_, StrictValue::String(s))) => Ok(s.clone()),
                            _ => Err(Error::MissingField),
                        }
                    };
                    out.push(PaidLeg {
                        leg: f("leg")?,
                        network: f("network")?,
                        reference: f("ref")?,
                    });
                }
                out
            }
            _ => return Err(Error::MissingField),
        };
        Self::validate_paid(&paid)?;
        let entry = match get("entry") {
            Some(StrictValue::String(s)) => {
                Some(b64d(s)?.try_into().map_err(|_| Error::WrongWidth)?)
            }
            // A present-but-non-string `entry` (`{}`, `null`, a number) is malformed —
            // NOT silently "absent". Treating it as absent would let an injected
            // `"entry": {}` ride on a valid entryless signature (a raw-wire/verified-view
            // mismatch), since the reconstructed COVERED omits the member.
            Some(_) => return Err(Error::UnexpectedType),
            None => None,
        };
        // F3.4: `entry` (the meed entry identifier) is REQUIRED on a two-leg receipt
        // (`paid = [meed, net]`) and MUST be absent on a baseline (`[split]`) one. The
        // paid shape is already validated to one of those two by `validate_paid`.
        let is_two_leg = paid.iter().map(|p| p.leg.as_str()).eq(["meed", "net"]);
        if is_two_leg && entry.is_none() {
            return Err(Error::MissingField); // two-leg evidence missing `entry`
        }
        if !is_two_leg && entry.is_some() {
            return Err(Error::UnexpectedType); // `entry` only on a two-leg receipt
        }
        let ts_s = get_str("ts")?;
        jcs::validate_uint_string(&ts_s)?;
        Ok(Receipt {
            nonce,
            idem: b64d(&get_str("idem")?)?,
            resource: get_str("resource")?,
            accept: get("accept").cloned().ok_or(Error::MissingField)?,
            paid,
            entry,
            ts: ts_s.parse().map_err(|_| Error::JsonGrammar)?,
            signature: Some(signature),
        })
    }

    /// A baseline (split) receipt bound to a consumed quote.
    pub fn baseline(
        q: &quote::Quote,
        accept: StrictValue,
        network: &str,
        split_ref: &str,
        ts: u64,
    ) -> Receipt {
        Receipt {
            nonce: q.nonce,
            idem: q.idem.clone(),
            resource: q.resource.clone(),
            accept,
            paid: vec![PaidLeg {
                leg: "split".into(),
                network: network.into(),
                reference: split_ref.into(),
            }],
            entry: None,
            ts,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_receipt_roundtrip() {
        let sk = [0x77u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let accept = StrictValue::Object(vec![("network".into(), sv("eip155:1"))]);
        let mut r = Receipt {
            nonce: [0x22; 32],
            idem: b"idem".to_vec(),
            resource: "https://api.example/r".into(),
            accept,
            paid: vec![PaidLeg {
                leg: "split".into(),
                network: "eip155:1".into(),
                reference: "0xabc".into(),
            }],
            entry: None,
            ts: 1_700_000_000,
            signature: None,
        };
        r.sign(&sk);
        let json = String::from_utf8(r.to_json()).unwrap();
        assert_eq!(Receipt::parse_verify(&json, &pk).unwrap().nonce, r.nonce);
    }

    #[test]
    fn two_leg_receipt_requires_entry() {
        // Tier-1 ③ / F3.4: `entry` is present iff `paid` is the two-leg shape.
        let sk = [0x77u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let accept = StrictValue::Object(vec![("network".into(), sv("eip155:1"))]);
        let two_leg_paid = vec![
            PaidLeg {
                leg: "meed".into(),
                network: "eip155:1".into(),
                reference: "0xm".into(),
            },
            PaidLeg {
                leg: "net".into(),
                network: "eip155:1".into(),
                reference: "0xn".into(),
            },
        ];
        // A two-leg receipt WITHOUT entry: signed over the entry-less value, so the
        // rejection fires on the F3.4 evidence rule (which precedes the signature check).
        let mut missing = Receipt {
            nonce: [0x22; 32],
            idem: b"idem".to_vec(),
            resource: "https://api.example/r".into(),
            accept: accept.clone(),
            paid: two_leg_paid.clone(),
            entry: None,
            ts: 1_700_000_000,
            signature: None,
        };
        missing.sign(&sk);
        let json = String::from_utf8(missing.to_json()).unwrap();
        assert!(
            Receipt::parse_verify(&json, &pk).is_err(),
            "a two-leg receipt missing `entry` must be rejected"
        );

        // The same receipt WITH entry round-trips.
        let mut ok = missing.clone();
        ok.entry = Some([0x33; 32]);
        ok.signature = None;
        ok.sign(&sk);
        let json = String::from_utf8(ok.to_json()).unwrap();
        assert!(
            Receipt::parse_verify(&json, &pk).is_ok(),
            "a two-leg receipt with `entry` is accepted"
        );

        // A baseline (split) receipt carrying an `entry` is rejected (entry is two-leg-only).
        let mut baseline_with_entry = Receipt {
            nonce: [0x22; 32],
            idem: b"idem".to_vec(),
            resource: "https://api.example/r".into(),
            accept,
            paid: vec![PaidLeg {
                leg: "split".into(),
                network: "eip155:1".into(),
                reference: "0xs".into(),
            }],
            entry: Some([0x44; 32]),
            ts: 1_700_000_000,
            signature: None,
        };
        baseline_with_entry.sign(&sk);
        let json = String::from_utf8(baseline_with_entry.to_json()).unwrap();
        assert!(
            Receipt::parse_verify(&json, &pk).is_err(),
            "a baseline receipt carrying `entry` must be rejected"
        );
        // (An INJECTED non-string `entry` on a signed receipt is caught by the
        // whole-object F1.3 verify — see `appended_top_level_member_fails_closed`. The
        // `Some(_)` type guard in `parse_verify` is documented defense-in-depth over it.)
    }

    #[test]
    fn appended_top_level_member_fails_closed() {
        // F1.2/F1.3: a valid signed receipt with ANY appended top-level
        // member must fail closed — verification is over the received object minus
        // `signature`, not a typed reconstruction that would drop unknown members.
        let sk = [0x77u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut r = Receipt {
            nonce: [0x22; 32],
            idem: b"idem".to_vec(),
            resource: "https://api.example/r".into(),
            accept: StrictValue::Object(vec![("network".into(), sv("eip155:1"))]),
            paid: vec![PaidLeg {
                leg: "split".into(),
                network: "eip155:1".into(),
                reference: "0xabc".into(),
            }],
            entry: None,
            ts: 1_700_000_000,
            signature: None,
        };
        r.sign(&sk);
        // Unmodified round-trips.
        let json = String::from_utf8(r.to_json()).unwrap();
        assert!(Receipt::parse_verify(&json, &pk).is_ok());
        // Inject an arbitrary top-level member and keep the original signature.
        let StrictValue::Object(mut members) = jcs::parse_strict(&json).unwrap() else {
            panic!("receipt is an object");
        };
        members.push(("zzz_appended".into(), StrictValue::Object(vec![])));
        let injected = String::from_utf8(jcs::to_jcs(&StrictValue::Object(members))).unwrap();
        assert!(
            Receipt::parse_verify(&injected, &pk).is_err(),
            "an appended top-level member must fail closed (F1.3)"
        );
    }

    #[test]
    fn reject_bad_paid_shapes() {
        assert!(Receipt::validate_paid(&[]).is_err());
        assert!(Receipt::validate_paid(&[PaidLeg {
            leg: "net".into(),
            network: "n".into(),
            reference: "r".into()
        }])
        .is_err());
        assert!(Receipt::validate_paid(&[
            PaidLeg {
                leg: "split".into(),
                network: "n".into(),
                reference: "r".into()
            },
            PaidLeg {
                leg: "split".into(),
                network: "n".into(),
                reference: "r".into()
            },
        ])
        .is_err());
        assert!(Receipt::validate_paid(&[PaidLeg {
            leg: "split".into(),
            network: "n".into(),
            reference: "r".into()
        }])
        .is_ok());
    }
}
