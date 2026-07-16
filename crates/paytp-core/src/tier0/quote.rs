//! The `paytp` quote extension (**F3.2**, formalizing §5.6 step 1) and the
//! mirror rule (**DECISION F3-a**).
//!
//! JSON per F1.2 (JCS, every numeric a string under F1-c, duplicate members
//! rejected). The merchant signs the object under `PayTPv1-reqs`; the client
//! re-verifies that signature and re-derives addresses from the signed bytes.
//!
//! M1 scope: the baseline (split) path in full — construction, signing,
//! validation, and split-address re-derivation (F4.1). The two-leg `twoLeg`
//! terms land with M2; the struct carries them as optional.

use crate::derive::{AddressInputs, MeedVectorEntry};
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::jcs::{self, StrictValue};
use crate::registry::SnapshotStore;
use crate::{consts, crypto};

/// A single `MEED_VECTOR` entry (F3.2 `vector` member): `{role, bp, dest}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeedEntry {
    pub role: u8,
    pub bp: u16,
    pub dest: String,
}

/// A PayTP-priced offer (F3.2 `offers`): the mirrored accepts entry plus the
/// finality it must reach. A baseline offer is the one carrying no `twoLeg`
/// (F3-a/F3-h); its `accept.network` is the CAIP-2 baseline rail (the quote's
/// `baseline`), never a sentinel value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The verbatim mirror of the x402 accepts entry (F3-a) — its JSON value.
    pub accept: StrictValue,
    /// The baseline offer's required finality token (REQUIRED for baseline).
    pub finality: Option<String>,
    /// The merchant's **net (~99%) destination** for the baseline split. A
    /// baseline-payable F9/CAIP pointer, REQUIRED for a baseline offer and committed
    /// in the split's `ADDRESS_INPUTS` (F4.1 `0x05`) so the split address binds the
    /// net seat; MUST be absent on a two-leg offer (its net leg pays `accept.payTo`
    /// directly, no split). Enforced by [`Quote::validate_tier0`].
    pub merchant_net: Option<String>,
    /// The two-leg terms (non-baseline; M2). Carried opaquely for now.
    pub two_leg: Option<StrictValue>,
}

/// A parsed / constructed `paytp` quote (F3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub v: String,
    pub resource: String,
    /// 32-byte challenge nonce (carried Base64url on the wire, raw here).
    pub nonce: [u8; 32],
    pub exp: u64,
    pub idem: Vec<u8>,
    pub schema: u32,
    pub contract: u32,
    pub registry: u32,
    pub baseline: String,
    pub grace: u64,
    pub retry: u64,
    pub vector: Vec<MeedEntry>,
    pub offers: Vec<Offer>,
    /// The 64-byte Ed25519 merchant signature (set by [`Quote::sign`]).
    pub signature: Option<[u8; 64]>,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::JsonGrammar)
}

fn sv_str(s: impl Into<String>) -> StrictValue {
    StrictValue::String(s.into())
}

/// Validate the **shape** of a schema-`0x01` meed vector (§10.1): exactly the base roles,
/// ascending, each at its fixed bp, total 100 bp (F3.2 cardinality), every dest a
/// baseline-payable CAIP pointer. **Shape only** — it does NOT check governed destination
/// *correctness* (that `0x11` is registry-listed-or-fund, that `0x13` is the pinned Dev-Fund
/// constant). That is [`validate_governed_destinations`], and the two are wired together in the
/// only public value-decision entry points, [`Quote::validate_vector_governed`] and
/// [`ChannelAuth::validate_vector_governed`], so a caller can never get shape without governed
/// correctness (F5-o). `pub(crate)`: not a value-decision path on its own.
pub(crate) fn validate_shape_schema_01<'a>(
    schema: u32,
    vector: impl ExactSizeIterator<Item = (u8, u16, &'a str)>,
) -> Result<()> {
    if schema != consts::SCHEMA_V0_1 {
        return Err(Error::FieldDomain);
    }
    let expected = consts::SCHEMA_01_ROLES;
    if vector.len() != expected.len() {
        return Err(Error::CountMismatch); // exact cardinality (F3.2)
    }
    let mut total: u16 = 0;
    for ((role, bp, dest), &(exp_role, exp_bp)) in vector.zip(expected.iter()) {
        if role != exp_role || bp != exp_bp {
            return Err(Error::FieldDomain);
        }
        // F3.2/F9.1: baseline destinations are CAIP-throughout — a vector dest must be
        // baseline-payable (never the adapter form).
        if !crate::pointer::Pointer::parse(dest)?.is_caip() {
            return Err(Error::JsonGrammar);
        }
        total += bp;
    }
    if total != consts::MEED_BASE_BP {
        return Err(Error::FieldDomain);
    }
    Ok(())
}

/// Validate **governed destination correctness** of a schema-`0x01` meed vector against the
/// registry version the vector names (**F5-o "Destination correctness" / F9.4 step 2/3**). This
/// is the check that was missing — the shape check alone let a wrong-but-valid-CAIP governed
/// destination through, so a merchant (Tier-0 quote) or interaction layer (`CHANNEL_AUTH`) could
/// redirect the governed `0x11`+`0x13` shares to an attacker and the RI accepted it.
///
/// - **`0x13` Development Fund** → MUST equal the schema's pinned constant
///   (`consts::DEV_FUND_DEST_PLACEHOLDER`); a fixed seat, no assertion (F9.4 / F9-e).
/// - **`0x11` OS** → set-membership via [`SnapshotStore::os_destination_accepted`]: the pinned
///   independent-OS-fund fallback OR a recipient listed at `named_version`. Requires the caller's
///   registry (fail-closed without it — an empty store accepts only the fallback).
/// - **`0x10`/`0x12` payer-side** → **pointer freedom** (F5-o: "the merchant does NOT pin
///   `0x10`/`0x12`"). Their baseline-payability is checked by [`validate_shape_schema_01`]; their
///   *fallback* correctness (unasserted → Dev Fund, F9.4 step 3) would need the `PayTP-Roles`
///   assertion context, which **no receive-side caller holds** — so it is deliberately NOT
///   asserted here (plan step 4 scope-limit; the payer-side layers defend themselves in-line, §10.3).
pub(crate) fn validate_governed_destinations<'a>(
    named_version: u32,
    vector: impl Iterator<Item = (u8, &'a str)>,
    registry: &SnapshotStore,
) -> Result<()> {
    // Fail-closed governance guard (F9-e): the `0x13` arm below is checked against the
    // release-bound Dev-Fund PLACEHOLDER (and `0x11` against the independent-OS-fund
    // PLACEHOLDER via `os_destination_accepted`). A non-demo build refuses to run this
    // value decision while those sentinels stand in for real governance addresses.
    crate::consts::ensure_governance_ready()?;
    for (role, dest) in vector {
        match role {
            consts::ROLE_OS => registry.os_destination_accepted(named_version, dest)?,
            // 0x13 Development Fund MUST equal the schema-pinned Dev-Fund constant (F9.4) —
            // the guard fires only on a WRONG destination.
            consts::ROLE_DEV_FUND if dest != consts::DEV_FUND_DEST_PLACEHOLDER => {
                return Err(Error::FieldDomain);
            }
            // 0x10 interaction-layer / 0x12 wallet: pointer freedom on the *governed* check —
            // their self-defense is [`validate_payer_side_destinations`], applied by the asserting
            // party itself with its OWN expected pointer (the wallet for 0x12, the IL for 0x10),
            // which the governed check cannot do without that party's PayTP-Roles/config context.
            // A correct 0x13 destination also lands here (the guard above only matches a wrong one).
            _ => {}
        }
    }
    Ok(())
}

/// What a party expects a payer-side (`0x10`/`0x12`) meed destination to be, when it
/// defends its OWN share (F5-o "defend yourself in-line" / F9.4 step 3). The asserting
/// party — the wallet for `0x12`, the interaction layer for `0x10` — is the only one
/// that holds this; the shared governed check ([`validate_governed_destinations`])
/// deliberately cannot, which is why `0x10`/`0x12` are pointer-free there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedDest<'a> {
    /// The party asserted this role to `dest` — the vector entry MUST equal it.
    Asserted(&'a str),
    /// The party asserts **no** share for this role — the vector entry MUST be the
    /// Dev-Fund fallback (F9.4 step 3: an unasserted `0x10`/`0x12` routes to the Dev
    /// Fund). This is what forecloses a silent bypass of the fallback.
    Unasserted,
    /// No assertion context is held for this role at this call site, so it is **not**
    /// checked (an explicit scope-limit — never a silent skip). A caller uses this only
    /// for a role that is some *other* party's to defend (e.g. the wallet leaves `0x10`
    /// `Unchecked`; the IL defends its own `0x10` in its own code).
    Unchecked,
}

impl ExpectedDest<'_> {
    /// Check one payer-side destination against this expectation.
    fn check(&self, dest: &str) -> Result<()> {
        let want = match self {
            ExpectedDest::Unchecked => return Ok(()),
            ExpectedDest::Asserted(addr) => *addr,
            ExpectedDest::Unasserted => consts::DEV_FUND_DEST_PLACEHOLDER,
        };
        if dest == want {
            Ok(())
        } else {
            Err(Error::FieldDomain)
        }
    }

    /// Whether this expectation REQUIRES the role to be PRESENT in the vector. An
    /// `Asserted`/`Unasserted` party expects a specific routing for its share, so a
    /// vector that OMITS that role is a bypass — rejected, not silently accepted (the
    /// "0x10 absent" gap). `Unchecked` (not this party's role) imposes
    /// no presence requirement.
    fn requires_presence(&self) -> bool {
        !matches!(self, ExpectedDest::Unchecked)
    }
}

/// Payer-side self-defense for the `0x10` (interaction layer) and `0x12` (wallet) meed
/// shares (**F5-o "defend yourself in-line" / F9.4 step 3**). Unlike the governed
/// `0x11`/`0x13` roles — pinned to registry/constant and checkable by any receiver —
/// `0x10`/`0x12` are *pointer-free* on the wire, so the ONLY party that can catch a
/// misroute is the one whose share it is, comparing the vector entry against the
/// pointer **it** asserted (or the Dev-Fund fallback if it asserted none). A hostile
/// merchant (Tier-0 quote) or interaction layer (Tier-1 `CHANNEL_AUTH`) that reroutes
/// the wallet's `0x12` (or the IL's `0x10`) to itself is caught here **before** the
/// wallet signs or pays — conservation still held (100 bp total), but the share would
/// have gone to the attacker instead of its rightful, asserting owner.
pub(crate) fn validate_payer_side_destinations<'a>(
    vector: impl Iterator<Item = (u8, &'a str)>,
    il: ExpectedDest,
    wallet: ExpectedDest,
) -> Result<()> {
    let mut seen_il = false;
    let mut seen_wallet = false;
    for (role, dest) in vector {
        match role {
            consts::ROLE_INTERACTION_LAYER => {
                seen_il = true;
                il.check(dest)?;
            }
            consts::ROLE_WALLET => {
                seen_wallet = true;
                wallet.check(dest)?;
            }
            _ => {}
        }
    }
    // A party that expects a specific routing (Asserted/Unasserted) but whose role is
    // ABSENT from the vector has had its share silently dropped — reject (a defended
    // caller's assertion is not honored). Unchecked roles impose no presence rule.
    if (il.requires_presence() && !seen_il) || (wallet.requires_presence() && !seen_wallet) {
        return Err(Error::FieldDomain);
    }
    Ok(())
}

impl Quote {
    /// Build the canonical JSON value (with or without the `signature` member).
    fn to_value(&self, include_sig: bool) -> StrictValue {
        let vector = StrictValue::Array(
            self.vector
                .iter()
                .map(|e| {
                    StrictValue::Object(vec![
                        ("role".into(), sv_str(e.role.to_string())),
                        ("bp".into(), sv_str(e.bp.to_string())),
                        ("dest".into(), sv_str(e.dest.clone())),
                    ])
                })
                .collect(),
        );
        let offers = StrictValue::Array(
            self.offers
                .iter()
                .map(|o| {
                    let mut members = vec![("accept".into(), o.accept.clone())];
                    if let Some(f) = &o.finality {
                        members.push(("finality".into(), sv_str(f.clone())));
                    }
                    // A baseline offer carries the merchant's net (~99%) destination,
                    // signed here so it is committed in the split derivation (F4.1 0x05).
                    if let Some(mn) = &o.merchant_net {
                        members.push(("merchantNet".into(), sv_str(mn.clone())));
                    }
                    if let Some(tl) = &o.two_leg {
                        members.push(("twoLeg".into(), tl.clone()));
                    }
                    StrictValue::Object(members)
                })
                .collect(),
        );
        let mut members = vec![
            ("v".into(), sv_str(&self.v)),
            ("resource".into(), sv_str(&self.resource)),
            ("nonce".into(), sv_str(b64(&self.nonce))),
            ("exp".into(), sv_str(self.exp.to_string())),
            ("idem".into(), sv_str(b64(&self.idem))),
            ("schema".into(), sv_str(self.schema.to_string())),
            ("contract".into(), sv_str(self.contract.to_string())),
            ("registry".into(), sv_str(self.registry.to_string())),
            ("baseline".into(), sv_str(&self.baseline)),
            ("grace".into(), sv_str(self.grace.to_string())),
            ("retry".into(), sv_str(self.retry.to_string())),
            ("vector".into(), vector),
            ("offers".into(), offers),
        ];
        if include_sig {
            if let Some(sig) = &self.signature {
                members.push(("signature".into(), sv_str(b64(sig))));
            }
        }
        StrictValue::Object(members)
    }

    /// The covered bytes for the merchant signature: `PayTPv1-reqs ‖ 0x00 ‖ JCS`
    /// of the object with `signature` absent (F1.2/F1.3).
    fn covered_bytes(&self) -> Vec<u8> {
        let jcs_bytes = jcs::to_jcs(&self.to_value(false));
        covered(DomainLabel::Reqs, &jcs_bytes)
    }

    /// Sign the quote with the merchant identity key (sets `signature`).
    pub fn sign(&mut self, merchant_sk: &[u8; 32]) {
        let sig = crypto::ed25519_sign(merchant_sk, &self.covered_bytes());
        self.signature = Some(sig);
    }

    /// Serialize to canonical JCS JSON (signature included).
    pub fn to_json(&self) -> Vec<u8> {
        jcs::to_jcs(&self.to_value(true))
    }

    /// Parse a `paytp` object from JSON and **verify the merchant signature**
    /// (F3.4: the merchant re-verifies its own signature; a client verifies the
    /// merchant's). Rejects duplicate members anywhere (F1.2) and malformed
    /// grammars (F1-c). Returns the parsed quote on success.
    pub fn parse_verify(json: &str, merchant_pk: &[u8; 32]) -> Result<Quote> {
        let value = jcs::parse_strict(json)?;
        let obj = as_object(&value)?;
        // F3-i / F1.2 / F1.3: reconstruct COVERED from **what arrived** — the
        // received object minus its `signature` member — never from a typed
        // re-encoding that would silently drop unknown members. So any
        // appended / dropped / overwritten member changes COVERED and **fails
        // closed** (the F3.4 "member-preserved and nothing appended" rule).
        // Exactly one `signature` member (defense-in-depth: `parse_strict`
        // already rejects duplicates document-wide per F1.2, but the strip below
        // removes *all* matches, so make the single-signature invariant explicit
        // here rather than silently depending on the parser).
        if obj.iter().filter(|(k, _)| k == "signature").count() != 1 {
            return Err(Error::MissingField);
        }
        let sig: [u8; 64] = match obj.iter().find(|(k, _)| k == "signature") {
            Some((_, StrictValue::String(s))) => {
                b64_decode(s)?.try_into().map_err(|_| Error::WrongWidth)?
            }
            _ => return Err(Error::MissingField),
        };
        let unsigned: Vec<(String, StrictValue)> = obj
            .iter()
            .filter(|(k, _)| k != "signature")
            .cloned()
            .collect();
        let covered_bytes = covered(
            DomainLabel::Reqs,
            &jcs::to_jcs(&StrictValue::Object(unsigned)),
        );
        crypto::ed25519_verify_strict(merchant_pk, &covered_bytes, &sig)?;
        // Verified over the received bytes; now parse the typed view.
        Quote::from_members(obj)
    }

    fn from_members(members: &[(String, StrictValue)]) -> Result<Quote> {
        let get = |k: &str| members.iter().find(|(m, _)| m == k).map(|(_, v)| v);
        let get_str = |k: &str| -> Result<String> {
            match get(k) {
                Some(StrictValue::String(s)) => Ok(s.clone()),
                _ => Err(Error::MissingField),
            }
        };
        let get_uint = |k: &str| -> Result<u64> {
            let s = get_str(k)?;
            jcs::validate_uint_string(&s)?;
            s.parse::<u64>().map_err(|_| Error::JsonGrammar)
        };
        // Fields the RI acts on as `u32` MUST reject a signed value that would
        // truncate (`4294967297` → `1`) — else the verified bytes and the
        // acted-upon value diverge (schema/address derivation).
        let get_u32 = |k: &str| -> Result<u32> {
            u32::try_from(get_uint(k)?).map_err(|_| Error::FieldDomain)
        };
        // F3-g: every Tier 0 time quantity is ≤ 2^53 − 1, so the F8 derived
        // windows (exp+grace, …) cannot overflow.
        const MAX_TIME: u64 = (1u64 << 53) - 1;
        let get_time = |k: &str| -> Result<u64> {
            let v = get_uint(k)?;
            if v > MAX_TIME {
                return Err(Error::FieldDomain);
            }
            Ok(v)
        };

        let v = get_str("v")?;
        if v != "1" {
            return Err(Error::FieldDomain);
        }
        let nonce_b = b64_decode(&get_str("nonce")?)?;
        let nonce: [u8; 32] = nonce_b.try_into().map_err(|_| Error::WrongWidth)?;
        let idem = b64_decode(&get_str("idem")?)?;
        if idem.is_empty() || idem.len() > 64 {
            return Err(Error::FieldDomain);
        }

        let vector = match get("vector") {
            Some(StrictValue::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    let m = as_object(it)?;
                    let f = |k: &str| -> Result<String> {
                        match m.iter().find(|(x, _)| x == k) {
                            Some((_, StrictValue::String(s))) => Ok(s.clone()),
                            _ => Err(Error::MissingField),
                        }
                    };
                    let role_s = f("role")?;
                    let bp_s = f("bp")?;
                    jcs::validate_uint_string(&role_s)?;
                    jcs::validate_uint_string(&bp_s)?;
                    out.push(MeedEntry {
                        role: role_s.parse::<u8>().map_err(|_| Error::JsonGrammar)?,
                        bp: bp_s.parse::<u16>().map_err(|_| Error::JsonGrammar)?,
                        dest: f("dest")?,
                    });
                }
                out
            }
            _ => return Err(Error::MissingField),
        };

        let offers = match get("offers") {
            Some(StrictValue::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    let m = as_object(it)?;
                    let accept = m
                        .iter()
                        .find(|(x, _)| x == "accept")
                        .map(|(_, v)| v.clone())
                        .ok_or(Error::MissingField)?;
                    let finality = match m.iter().find(|(x, _)| x == "finality") {
                        Some((_, StrictValue::String(s))) => Some(s.clone()),
                        Some(_) => return Err(Error::JsonGrammar),
                        None => None,
                    };
                    // F4.1: the merchant's net (~99%) destination for a baseline split.
                    let merchant_net = match m.iter().find(|(x, _)| x == "merchantNet") {
                        Some((_, StrictValue::String(s))) => Some(s.clone()),
                        Some(_) => return Err(Error::JsonGrammar),
                        None => None,
                    };
                    let two_leg = m
                        .iter()
                        .find(|(x, _)| x == "twoLeg")
                        .map(|(_, v)| v.clone());
                    out.push(Offer {
                        accept,
                        finality,
                        merchant_net,
                        two_leg,
                    });
                }
                out
            }
            _ => return Err(Error::MissingField),
        };

        let signature = match get("signature") {
            Some(StrictValue::String(s)) => {
                let b = b64_decode(s)?;
                Some(b.try_into().map_err(|_| Error::WrongWidth)?)
            }
            _ => None,
        };

        Ok(Quote {
            v,
            resource: get_str("resource")?,
            nonce,
            exp: get_time("exp")?,
            idem,
            schema: get_u32("schema")?,
            contract: get_u32("contract")?,
            registry: get_u32("registry")?,
            baseline: get_str("baseline")?,
            grace: get_time("grace")?,
            retry: get_time("retry")?,
            vector,
            offers,
            signature,
        })
    }

    /// The `ADDRESS_INPUTS` this quote's split/instance derives from (F4.1), built
    /// from the signed members: merchant key, the baseline settlement asset, schema,
    /// the meed vector, and the contract version. `merchant_net` is the split's net
    /// (~99%) destination — `Some` for a **baseline split**, `None` for a
    /// meed **instance** (which has no merchant seat); [`AddressInputs::seed_split`]
    /// requires it present, [`AddressInputs::seed_instance`] requires it absent.
    pub fn address_inputs(
        &self,
        merchant_key: &[u8; 32],
        asset: &str,
        merchant_net: Option<&str>,
    ) -> AddressInputs {
        AddressInputs {
            merchant_key: *merchant_key,
            asset: asset.to_string(),
            schema: self.schema,
            vector: self
                .vector
                .iter()
                .map(|e| MeedVectorEntry {
                    role: e.role,
                    bp: e.bp,
                    dest: e.dest.clone(),
                })
                .collect(),
            contract: self.contract,
            merchant_net: merchant_net.map(|s| s.to_string()),
        }
    }

    /// Re-derive the baseline split address from the signed quote (F4.1) and
    /// confirm it equals `pay_to` — the client's "refuse on `payTo` mismatch"
    /// (§5.6). `merchant_net` is the offer's signed net destination, committed
    /// in the split seed so a substituted net seat derives a different address.
    /// `derive_addr` maps the 32-byte seed to the rail's address string
    /// (the rail adapter's job); the caller supplies it.
    pub fn verify_split_pay_to(
        &self,
        merchant_key: &[u8; 32],
        asset: &str,
        merchant_net: &str,
        pay_to: &str,
        derive_addr: impl Fn(&[u8; 32]) -> String,
    ) -> Result<()> {
        let seed = self
            .address_inputs(merchant_key, asset, Some(merchant_net))
            .seed_split()?;
        if derive_addr(&seed) == pay_to {
            Ok(())
        } else {
            Err(Error::BadSignature) // payTo mismatch → refuse (§5.6)
        }
    }

    /// Validate the meed vector against schema `0x01` **and** governed destination correctness
    /// (**F3.2 / F5-o / F9.4**) — the one public value-decision check a payer applies before paying
    /// (F3 `03-tier0-objects.md:58`, "validate the vector against schema and registry") and a
    /// merchant re-applies on receive. It combines shape ([`validate_shape_schema_01`]:
    /// roles/order/bp/total/CAIP) with destination correctness
    /// ([`validate_governed_destinations`]: `0x13` == the schema-pinned Dev-Fund constant, `0x11`
    /// registry-listed-or-independent-fund against the vector's own named `registry` version). The
    /// caller MUST supply its registry `snapshot` store — there is no context-free value-decision
    /// validator left, so the compiler forces every caller onto this governed path. `0x10`/`0x12`
    /// keep pointer freedom (F5-o: the receiver does not pin them).
    pub fn validate_vector_governed(&self, registry: &SnapshotStore) -> Result<()> {
        validate_shape_schema_01(
            self.schema,
            self.vector.iter().map(|e| (e.role, e.bp, e.dest.as_str())),
        )?;
        validate_governed_destinations(
            self.registry,
            self.vector.iter().map(|e| (e.role, e.dest.as_str())),
            registry,
        )
    }

    /// Payer-side self-defense (**F5-o / F9.4 step 3**): validate the pointer-free
    /// `0x10`/`0x12` shares against the asserting parties' OWN expected pointers, so a
    /// hostile merchant cannot reroute the wallet's `0x12` (or the IL's `0x10`) meed to
    /// itself and have the payer sign/pay it. This is the check the governed validator
    /// structurally cannot do (no receiver holds those parties' assertion context); a
    /// caller passes [`ExpectedDest::Unchecked`] for a role it is not the owner of.
    pub fn validate_payer_side(&self, il: ExpectedDest, wallet: ExpectedDest) -> Result<()> {
        validate_payer_side_destinations(
            self.vector.iter().map(|e| (e.role, e.dest.as_str())),
            il,
            wallet,
        )
    }

    /// **F3-j baseline rail + resource binding.** The shipped x402
    /// envelope encodes `network` as a **named** value (not CAIP-2), so for each
    /// **baseline** offer (no `twoLeg` — rule 2) the wallet:
    /// - maps the mirrored `accept.network` (named) back to CAIP-2 via the
    ///   normative 1:1 table (`x402_net`) — **fail-closed** on an unknown name
    ///   (rule 3) — and requires it to equal `paytp.baseline` (which stays CAIP-2,
    ///   rule 1); and
    /// - requires the mirrored `accept.resource` to equal the signed
    ///   `paytp.resource` (rule 4).
    ///
    /// **Two-leg offers are exempt** (rule 2): a two-leg offer's `network` is its
    /// net leg's rail, which need not be the baseline — the meed instance is
    /// bound to `paytp.baseline` by F4.1 derivation, not the envelope network.
    /// Applying the rail check to them would wrongly reject valid net-on-another-
    /// rail offers.
    pub fn validate_offer_networks(&self) -> Result<()> {
        for offer in &self.offers {
            let accept = as_object(&offer.accept)?;
            let field = |k: &str| -> Option<&str> {
                accept
                    .iter()
                    .find(|(m, _)| m == k)
                    .and_then(|(_, v)| match v {
                        StrictValue::String(s) => Some(s.as_str()),
                        _ => None,
                    })
            };
            // Rule 4 applies to **every** offer (baseline AND two-leg): the
            // requirement's resource == the signed quote resource.
            let resource = field("resource").ok_or(Error::MissingField)?;
            if resource != self.resource {
                return Err(Error::FieldDomain);
            }
            // Rule 2/3 — the named-network → CAIP-2 == baseline rail check — is
            // **baseline offers only**. A two-leg offer's `network` is its net
            // leg's rail (need not be the baseline; the meed instance binds to
            // `paytp.baseline` by F4.1 derivation, not the envelope network).
            if offer.two_leg.is_none() {
                let network = field("network").ok_or(Error::JsonGrammar)?;
                match crate::x402_net::x402_to_caip2(network) {
                    Some(caip2) if caip2 == self.baseline => {}
                    _ => return Err(Error::JsonGrammar),
                }
            }
        }
        Ok(())
    }

    /// A **baseline** offer MUST carry `merchantNet` — the merchant's net
    /// (~99%) destination, committed in the split derivation (F4.1 `0x05`) so the
    /// split address binds the net seat; without it two different net destinations
    /// derive the same split and a front-runner could deploy the split with an
    /// attacker net seat. A **two-leg** offer MUST NOT carry one (its net leg pays
    /// `accept.payTo` directly; there is no split). The value is the merchant's own
    /// receiving pointer (not a protocol-governed meed dest), so the shape check is
    /// presence + well-formed text — its baseline-payability is the merchant's own
    /// concern, and `canonical_bytes` (F1-g) rejects malformed text at derivation.
    pub fn validate_baseline_merchant_net(&self) -> Result<()> {
        for offer in &self.offers {
            match (offer.two_leg.is_some(), &offer.merchant_net) {
                (true, Some(_)) => return Err(Error::FieldDomain), // no split ⇒ no net seat
                (true, None) => {}                                 // two-leg: correct
                (false, Some(mn)) => {
                    crate::tlv::validate_text(mn.as_bytes())?; // committed + well-formed
                }
                (false, None) => return Err(Error::MissingField), // baseline MUST commit it
            }
        }
        Ok(())
    }

    /// The Tier 0 quote checks a payer applies before paying (F3.2/§5.6): the governed
    /// schema-`0x01` meed vector (`validate_vector_governed` — shape AND destination correctness
    /// against the caller-supplied `registry`, F5-o/F9.4), the offer networks
    /// (`validate_offer_networks`), and the baseline `merchantNet` net-seat binding
    /// (`validate_baseline_merchant_net`, F4.1). Baseline replay protection is enforced at
    /// redemption by the merchant's durable consumed-settlement record, not by x402
    /// `extra.memo`. Signature/resource/window checks are separate (F3.4/F5.4).
    pub fn validate_tier0(&self, registry: &SnapshotStore) -> Result<()> {
        self.validate_vector_governed(registry)?;
        self.validate_offer_networks()?;
        self.validate_baseline_merchant_net()
    }
}

fn as_object(v: &StrictValue) -> Result<&[(String, StrictValue)]> {
    match v {
        StrictValue::Object(m) => Ok(m),
        _ => Err(Error::JsonMalformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty registry store — enough to validate a vector whose `0x11` uses the
    /// version-agnostic independent-OS-fund fallback and whose `0x13` is the pinned
    /// Dev-Fund constant (the sample vector). A populated store is built inline where a
    /// test exercises the registry-listed OS arm.
    fn sample_registry() -> SnapshotStore {
        SnapshotStore::default()
    }

    fn sample_quote() -> Quote {
        // Schema 0x01 baseline quote: the OS share (0x11) routed to the **independent
        // open-source fund** fallback (§10.1/F9.4 step 2 — NOT the Dev Fund), the 0x13
        // Development-Fund seat to the schema-pinned Dev-Fund constant.
        let vector = vec![
            MeedEntry {
                role: 0x10,
                bp: 50,
                dest: "eip155:1:0xIL".into(),
            },
            MeedEntry {
                role: 0x11,
                bp: 10,
                dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            },
            MeedEntry {
                role: 0x12,
                bp: 30,
                dest: "eip155:1:0xWallet".into(),
            },
            MeedEntry {
                role: 0x13,
                bp: 10,
                dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
            },
        ];
        let accept = StrictValue::Object(vec![
            ("scheme".into(), sv_str("exact")),
            // The mirror carries the x402 **named** network (maps to `baseline`
            // below via the F3-j table); never CAIP-2 in the envelope, never a
            // sentinel (F3-j).
            ("network".into(), sv_str("base")),
            ("payTo".into(), sv_str("eip155:8453:0xSPLIT")),
            // Rule 4: the requirement's resource == the signed quote resource.
            ("resource".into(), sv_str("https://api.example/resource")),
        ]);
        Quote {
            v: "1".into(),
            resource: "https://api.example/resource".into(),
            nonce: [0x22; 32],
            exp: 2_000_000_000,
            idem: b"idem-key-1".to_vec(),
            schema: 1,
            contract: 1,
            registry: 5,
            baseline: "eip155:8453".into(),
            grace: 300,
            retry: 600,
            vector,
            offers: vec![Offer {
                accept,
                finality: Some("final".into()),
                merchant_net: Some("eip155:8453:0xNET".into()),
                two_leg: None,
            }],
            signature: None,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = [0x55u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut q = sample_quote();
        q.sign(&sk);
        let json = q.to_json();
        let parsed = Quote::parse_verify(std::str::from_utf8(&json).unwrap(), &pk).unwrap();
        assert_eq!(parsed.nonce, q.nonce);
        assert_eq!(parsed.vector, q.vector);
        // Wrong merchant key → reject.
        let other = crypto::ed25519_public(&[0x66u8; 32]);
        assert!(Quote::parse_verify(std::str::from_utf8(&json).unwrap(), &other).is_err());
    }

    #[test]
    fn tamper_breaks_signature() {
        let sk = [0x55u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut q = sample_quote();
        q.sign(&sk);
        let json = String::from_utf8(q.to_json()).unwrap();
        // Flip a destination inside the signed vector.
        let tampered = json.replace("0xWallet", "0xEvilXX");
        assert!(Quote::parse_verify(&tampered, &pk).is_err());
    }

    #[test]
    fn vector_schema_validation() {
        let reg = sample_registry();
        let q = sample_quote();
        assert!(q.validate_vector_governed(&reg).is_ok());
        // Wrong bp → reject (shape).
        let mut bad = sample_quote();
        bad.vector[0].bp = 40;
        assert!(bad.validate_vector_governed(&reg).is_err());
        // Missing a role → wrong cardinality (shape).
        let mut short = sample_quote();
        short.vector.pop();
        assert!(short.validate_vector_governed(&reg).is_err());
    }

    #[test]
    fn payer_side_self_defense_catches_a_misrouted_own_share() {
        // F5-o: the pointer-free `0x10`/`0x12` shares pass the GOVERNED check (they are
        // not registry/constant-pinned), so ONLY the asserting party's own expected-pointer
        // check catches a hostile merchant rerouting them. sample_quote's vector is
        // 0x10=eip155:1:0xIL, 0x12=eip155:1:0xWallet.
        let q = sample_quote();
        let il = "eip155:1:0xIL";
        let wallet = "eip155:1:0xWallet";

        // Correct expectations → OK.
        assert!(q
            .validate_payer_side(ExpectedDest::Asserted(il), ExpectedDest::Asserted(wallet))
            .is_ok());

        // A hostile merchant rerouted the WALLET's 0x12 to itself: the governed check still
        // passes it, but the wallet's own-pointer check REJECTS it (before the wallet would pay).
        let mut evil_wallet = sample_quote();
        evil_wallet.vector[2].dest = "eip155:1:0xMerchantStealsWalletShare".into();
        assert!(evil_wallet
            .validate_vector_governed(&sample_registry())
            .is_ok()); // governed: fine
        assert_eq!(
            evil_wallet
                .validate_payer_side(ExpectedDest::Unchecked, ExpectedDest::Asserted(wallet)),
            Err(Error::FieldDomain) // self-defense: caught
        );

        // A hostile merchant rerouted the IL's 0x10: caught by the IL's own-pointer check.
        let mut evil_il = sample_quote();
        evil_il.vector[0].dest = "eip155:1:0xMerchantStealsIlShare".into();
        assert_eq!(
            evil_il.validate_payer_side(ExpectedDest::Asserted(il), ExpectedDest::Unchecked),
            Err(Error::FieldDomain)
        );
    }

    #[test]
    fn payer_side_unasserted_must_be_dev_fund_and_unchecked_skips() {
        // F9.4 step 3: an UNASSERTED payer-side role MUST route to the Dev Fund — a non-Dev-Fund
        // dest is a bypass of that fallback and is rejected.
        let q = sample_quote(); // 0x12 = eip155:1:0xWallet (a non-Dev-Fund dest)
        assert_eq!(
            q.validate_payer_side(ExpectedDest::Unchecked, ExpectedDest::Unasserted),
            Err(Error::FieldDomain)
        );
        // The same vector with 0x12 routed to the Dev Fund passes the Unasserted expectation.
        let mut to_dev = sample_quote();
        to_dev.vector[2].dest = consts::DEV_FUND_DEST_PLACEHOLDER.into();
        assert!(to_dev
            .validate_payer_side(ExpectedDest::Unchecked, ExpectedDest::Unasserted)
            .is_ok());
        // Unchecked never rejects (an explicit scope-limit, not a silent skip): any 0x10 passes.
        let mut any_il = sample_quote();
        any_il.vector[0].dest = "eip155:1:0xAnything".into();
        assert!(any_il
            .validate_payer_side(
                ExpectedDest::Unchecked,
                ExpectedDest::Asserted("eip155:1:0xWallet")
            )
            .is_ok());
    }

    #[test]
    fn payer_side_asserted_role_must_be_present_gate_med() {
        // "0x10 absent" gap: an Asserted (or Unasserted) party whose role is
        // OMITTED from the vector has had its share silently dropped — reject, never accept.
        let mut no_il = sample_quote();
        no_il.vector.remove(0); // drop the 0x10 entry
        assert_eq!(
            no_il.validate_payer_side(
                ExpectedDest::Asserted("eip155:1:0xIL"),
                ExpectedDest::Unchecked
            ),
            Err(Error::FieldDomain)
        );
        // Unchecked imposes no presence requirement — the same 0x10-less vector passes when
        // 0x10 is not the checking party's role.
        assert!(no_il
            .validate_payer_side(
                ExpectedDest::Unchecked,
                ExpectedDest::Asserted("eip155:1:0xWallet")
            )
            .is_ok());
    }

    #[test]
    fn governed_destination_correctness_is_enforced() {
        // F9.4: shape is fine (roles/bp/total/CAIP) but a GOVERNED destination
        // is redirected to a wrong-but-valid-CAIP attacker pointer → MUST reject.
        let reg = sample_registry();
        // 0x13 Dev-Fund redirected → reject (must equal the schema-pinned constant, F9.4).
        let mut evil_dev = sample_quote();
        evil_dev.vector[3].dest = "eip155:1:0xAttackerStealsTheDevFund".into();
        assert_eq!(
            evil_dev.validate_vector_governed(&reg),
            Err(Error::FieldDomain)
        );
        // 0x11 OS redirected to a non-listed, non-fund CAIP → reject (set-membership, F5-o).
        let mut evil_os = sample_quote();
        evil_os.vector[1].dest = "eip155:1:0xAttackerStealsTheOsShare".into();
        assert_eq!(
            evil_os.validate_vector_governed(&reg),
            Err(Error::FieldDomain)
        );
        // 0x11 routed to the Dev Fund (a valid CAIP, but the WRONG governed fund) → reject:
        // an absent/unlisted OS must route to the INDEPENDENT fund, never the Dev Fund (§10.1).
        let mut os_to_dev = sample_quote();
        os_to_dev.vector[1].dest = consts::DEV_FUND_DEST_PLACEHOLDER.into();
        assert_eq!(
            os_to_dev.validate_vector_governed(&reg),
            Err(Error::FieldDomain)
        );
        // 0x10/0x12 keep pointer freedom — an arbitrary payer-side CAIP pointer is accepted.
        let mut free_payer = sample_quote();
        free_payer.vector[0].dest = "eip155:1:0xSomeOtherInteractionLayer".into();
        free_payer.vector[2].dest = "eip155:1:0xSomeOtherWallet".into();
        assert!(free_payer.validate_vector_governed(&reg).is_ok());
    }

    #[test]
    fn governed_os_registry_listed_destination_is_accepted() {
        // The registry-listed OS arm: with a snapshot listing an OS recipient at the vector's
        // named version, that recipient's canonical destination is an accepted 0x11 (F9.4 step 2).
        use crate::registry::{Kind, Snapshot};
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut snap = Snapshot {
            version: 5,
            kind: Kind::Rotation,
            issued: 1_700_000_000,
            window_floor: 3,
            os_recipients: vec![("apple".into(), "eip155:1:0xApple".into())],
            revoked: vec![],
            rate_sources: vec![],
            sig: [0u8; 64],
        };
        snap.sign(&sk).unwrap();
        let mut store = SnapshotStore::new();
        store.insert(Snapshot::parse_verify(&snap.encode().unwrap(), &pk).unwrap());

        let mut q = sample_quote(); // registry: 5
        q.vector[1].dest = "eip155:1:0xApple".into();
        assert!(q.validate_vector_governed(&store).is_ok());
        // The same listed dest against an EMPTY store (no registry) → reject: a validator cannot
        // confirm a listing it does not hold (fail-closed).
        assert_eq!(
            q.validate_vector_governed(&sample_registry()),
            Err(Error::FieldDomain)
        );
    }

    #[test]
    fn baseline_rail_and_resource_binding() {
        // Good: named network "base" maps to the CAIP-2 baseline eip155:8453, and
        // the mirror's resource == the quote resource (F3-j rules 2/3/4).
        let q = sample_quote();
        assert!(q.validate_offer_networks().is_ok());
        assert!(q.validate_tier0(&sample_registry()).is_ok());

        let base_accept = |network: &str, resource: &str| {
            StrictValue::Object(vec![
                ("scheme".into(), sv_str("exact")),
                ("network".into(), sv_str(network)),
                ("payTo".into(), sv_str("eip155:8453:0xSPLIT")),
                ("resource".into(), sv_str(resource)),
            ])
        };

        // Bad: an unknown x402 network name → fail-closed (rule 3).
        let mut unknown = sample_quote();
        unknown.offers[0].accept = base_accept("not-a-network", "https://api.example/resource");
        assert_eq!(unknown.validate_offer_networks(), Err(Error::JsonGrammar));
        // Bad: a CAIP-2 value in the envelope (should be a NAME) → fail-closed.
        let mut caip = sample_quote();
        caip.offers[0].accept = base_accept("eip155:8453", "https://api.example/resource");
        assert_eq!(caip.validate_offer_networks(), Err(Error::JsonGrammar));
        // Bad: a known name that maps to a DIFFERENT rail than the baseline (rule 2).
        let mut wrong_rail = sample_quote();
        wrong_rail.offers[0].accept = base_accept("solana", "https://api.example/resource");
        assert_eq!(
            wrong_rail.validate_offer_networks(),
            Err(Error::JsonGrammar)
        );
        // Bad: resource mismatch (rule 4).
        let mut wrong_res = sample_quote();
        wrong_res.offers[0].accept = base_accept("base", "https://evil.example/other");
        assert_eq!(wrong_res.validate_offer_networks(), Err(Error::FieldDomain));
        // Bad: a missing network member → invalid.
        let mut missing = sample_quote();
        missing.offers[0].accept = StrictValue::Object(vec![("scheme".into(), sv_str("exact"))]);
        assert!(missing.validate_offer_networks().is_err());
    }

    #[test]
    fn resource_binding_applies_to_two_leg_offers_too() {
        // Rule 4 (resource match) applies to EVERY offer, but the
        // rail check is baseline-only. A two-leg offer (exempt from the rail
        // check, on another rail) with a mismatched resource must still reject.
        let two_leg_offer = |resource: &str| Offer {
            accept: StrictValue::Object(vec![
                ("scheme".into(), sv_str("exact")),
                ("network".into(), sv_str("solana")), // net-leg rail ≠ baseline — exempt
                ("resource".into(), sv_str(resource)),
            ]),
            finality: None,
            merchant_net: None, // two-leg: no split, no merchant-net seat
            two_leg: Some(StrictValue::Object(vec![])), // marks it two-leg
        };
        let mut bad = sample_quote();
        bad.offers.push(two_leg_offer("https://evil.example/other"));
        assert_eq!(bad.validate_offer_networks(), Err(Error::FieldDomain));
        // Matching resource → the two-leg offer passes (rail check skipped).
        let mut good = sample_quote();
        good.offers
            .push(two_leg_offer("https://api.example/resource"));
        assert!(good.validate_offer_networks().is_ok());
    }

    #[test]
    fn baseline_extra_memo_is_not_required() {
        // Baseline quote validity no longer rests on exact-svm `extra.memo`; the
        // merchant's durable consumed-settlement record is the nonce/ref arbiter.
        let q = sample_quote();
        assert!(q.validate_tier0(&sample_registry()).is_ok());

        // Absent extra remains valid.
        let mut absent = sample_quote();
        absent.offers[0].accept = StrictValue::Object(vec![
            ("scheme".into(), sv_str("exact")),
            ("network".into(), sv_str("base")),
            ("payTo".into(), sv_str("eip155:1:0xSPLIT")),
            ("resource".into(), sv_str("https://api.example/resource")),
        ]);
        assert!(absent.validate_tier0(&sample_registry()).is_ok());

        // Caller extra is allowed, but it is not interpreted as the PayTP nonce bind.
        let mut caller_extra = sample_quote();
        caller_extra.offers[0].accept = StrictValue::Object(vec![
            ("scheme".into(), sv_str("exact")),
            ("network".into(), sv_str("base")),
            ("payTo".into(), sv_str("eip155:1:0xSPLIT")),
            ("resource".into(), sv_str("https://api.example/resource")),
            (
                "extra".into(),
                StrictValue::Object(vec![("feePayer".into(), sv_str("payer111"))]),
            ),
        ]);
        assert!(caller_extra.validate_tier0(&sample_registry()).is_ok());
    }

    #[test]
    fn oversized_u32_field_rejected_not_truncated() {
        // A signed `schema` beyond u32 must reject, not truncate to a different
        // acted-upon value. Validly sign a big-schema object
        // (a buggy/malicious merchant could), so the signature passes and only
        // the parser's domain guard stands between it and a truncated schema==1.
        let sk = [0x55u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut q = sample_quote();
        q.signature = None;
        let json = String::from_utf8(q.to_json())
            .unwrap()
            .replace("\"schema\":\"1\"", "\"schema\":\"4294967297\"");
        let unsigned = match jcs::parse_strict(&json).unwrap() {
            StrictValue::Object(m) => m,
            _ => unreachable!(),
        };
        let covered_b = covered(
            DomainLabel::Reqs,
            &jcs::to_jcs(&StrictValue::Object(unsigned.clone())),
        );
        let sig = crypto::ed25519_sign(&sk, &covered_b);
        let mut signed = unsigned;
        signed.push(("signature".into(), sv_str(b64(&sig))));
        let signed_json = String::from_utf8(jcs::to_jcs(&StrictValue::Object(signed))).unwrap();
        assert_eq!(
            Quote::parse_verify(&signed_json, &pk),
            Err(Error::FieldDomain)
        );
    }

    #[test]
    fn appended_member_fails_closed() {
        // F3-i/F3.4: the signed paytp object is re-verified over the RECEIVED
        // bytes; an appended member changes COVERED and fails the signature.
        let sk = [0x55u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut q = sample_quote();
        q.sign(&sk);
        let json = String::from_utf8(q.to_json()).unwrap();
        // Append a top-level member to the signed object (before the final `}`).
        let appended = format!("{},\"zzz_appended\":\"x\"}}", &json[..json.len() - 1]);
        assert!(Quote::parse_verify(&appended, &pk).is_err());
        // A member appended *inside* a nested value (a vector entry) also fails.
        let nested = json.replacen("\"dest\":", "\"zz\":\"x\",\"dest\":", 1);
        assert!(Quote::parse_verify(&nested, &pk).is_err());
    }

    #[test]
    fn split_pay_to_re_derivation() {
        let sk = [0x55u8; 32];
        let mk = crypto::ed25519_public(&sk);
        let q = sample_quote();
        // A deterministic "rail" that renders the seed as hex.
        let derive = |seed: &[u8; 32]| format!("eip155:1:0x{}", hex_short(seed));
        let net = "eip155:8453:0xNET"; // the sample_quote baseline offer's merchantNet
        let inputs = q.address_inputs(&mk, "eip155:1/native", Some(net));
        let seed = inputs.seed_split().unwrap();
        let addr = derive(&seed);
        assert!(q
            .verify_split_pay_to(&mk, "eip155:1/native", net, &addr, derive)
            .is_ok());
        // A different address → refuse.
        assert!(q
            .verify_split_pay_to(
                &mk,
                "eip155:1/native",
                net,
                "eip155:1:0xWRONG",
                |s| format!("eip155:1:0x{}", hex_short(s))
            )
            .is_err());
        // F4.1: a DIFFERENT merchant-net destination derives a DIFFERENT split — the
        // honest `payTo` no longer matches, so the wallet refuses (front-run closure).
        assert!(q
            .verify_split_pay_to(
                &mk,
                "eip155:1/native",
                "eip155:8453:0xATTACKER",
                &addr,
                derive
            )
            .is_err());
    }

    fn hex_short(b: &[u8; 32]) -> String {
        b.iter().take(20).map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn baseline_requires_merchant_net_two_leg_forbids_it() {
        // F3-a: a baseline offer MUST carry `merchantNet`; a two-leg offer MUST NOT.
        let q = sample_quote();
        assert!(q.validate_baseline_merchant_net().is_ok()); // baseline carries it

        // A baseline offer missing it → rejected (the front-run gap is now invalid).
        let mut missing = sample_quote();
        missing.offers[0].merchant_net = None;
        assert!(missing.validate_baseline_merchant_net().is_err());

        // A two-leg offer carrying a spurious `merchantNet` → rejected (no split seat).
        let mut spurious = sample_quote();
        spurious.offers.push(Offer {
            accept: StrictValue::Object(vec![]),
            finality: None,
            merchant_net: Some("eip155:1:0xSPURIOUS".into()),
            two_leg: Some(StrictValue::Object(vec![])),
        });
        assert!(spurious.validate_baseline_merchant_net().is_err());
    }
}
