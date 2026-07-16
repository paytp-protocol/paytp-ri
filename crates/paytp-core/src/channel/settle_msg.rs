//! The F5.6 settlement messages — SETTLEMENT_PROPOSE, SETTLEMENT_PROOF, and
//! SETTLEMENT_CONFIRMED — the wire framing of a settlement round.
//!
//! The round *arithmetic* (P/E/per-role E_r) is [`super::settlement::Round`] /
//! [`crate::fee`]; this module is the on-wire objects that carry it. The signature
//! slots are **role-fixed** (F5-k): 0x70 is always the payer key's, 0x71 the
//! merchant's, whichever party initiates. A deterministic (DENOM = BASELINE_ASSET,
//! net-on-baseline) round is single-signed by the debtor; any other round is
//! both-signed. The codec validates each object's internal structure; the
//! cross-object facts (outputs match establishment-bound destinations, INSTANCE_LEG
//! present iff E >= 1, CONVERSION present iff DENOM != BASELINE_ASSET) are the
//! caller's, set from the channel context.

use crate::crypto::{ed25519_sign, ed25519_verify_strict, sha256};
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::leb128;
use crate::tlv::{self, Field, Object, Openness, Schema};
use num_bigint::BigUint;

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    leb128::encode_into(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn read_lp(b: &[u8]) -> Result<(&[u8], usize)> {
    let (len, n) = leb128::decode(b)?;
    let len = usize::try_from(len).map_err(|_| Error::LengthOverrun)?; // no 32-bit truncation
    let e = n.checked_add(len).ok_or(Error::LengthOverrun)?;
    if e > b.len() {
        return Err(Error::LengthOverrun);
    }
    Ok((&b[n..e], e))
}

fn read_lp_text(b: &[u8]) -> Result<(String, usize)> {
    let (raw, used) = read_lp(b)?;
    tlv::validate_text(raw)?;
    Ok((
        String::from_utf8(raw.to_vec()).map_err(|_| Error::TextControlChar)?,
        used,
    ))
}

fn read_lp_uint(b: &[u8]) -> Result<(BigUint, usize)> {
    let (raw, used) = read_lp(b)?;
    let v = tlv::decode_uint_biguint(raw)?;
    tlv::check_domain(&v, tlv::Domain::Value)?;
    Ok((v, used))
}

fn fixed32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| Error::WrongWidth)
}
fn fixed64(v: &[u8]) -> Result<[u8; 64]> {
    v.try_into().map_err(|_| Error::WrongWidth)
}

// --- OUTPUTS (F5.6) ---

/// One value movement of a round: `amount` of `asset` to `dest`. A zero-amount
/// output is never encoded (an output is a value movement, F5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub amount: BigUint,
    pub asset: String,
    pub dest: String,
}

fn output_item(o: &Output) -> Vec<u8> {
    let mut it = Vec::new();
    push_lp(&mut it, &tlv::encode_uint_biguint(&o.amount));
    push_lp(&mut it, o.asset.as_bytes());
    push_lp(&mut it, o.dest.as_bytes());
    it
}

/// Validate the F5.6 OUTPUTS discipline: every amount non-zero and within the F7-a
/// domain, and items sorted ascending by (dest, asset) with no duplicate — one
/// canonical form. Enforced on both encode and parse.
fn check_outputs(outputs: &[Output]) -> Result<()> {
    for o in outputs {
        if o.amount == BigUint::from(0u8) {
            return Err(Error::FieldDomain);
        }
        tlv::check_domain(&o.amount, tlv::Domain::Value)?;
    }
    for w in outputs.windows(2) {
        if (&w[0].dest, &w[0].asset) >= (&w[1].dest, &w[1].asset) {
            return Err(Error::TypeOrder);
        }
    }
    Ok(())
}

/// Validate an F3-c conversion rate string: a **canonical positive decimal** — an
/// integer part with no leading zeros (`"0"` allowed only before a fractional
/// part), an optional fractional part with no trailing zeros, all ASCII digits, and
/// a value strictly greater than zero. One string per numeric value (F1.1 canonical
/// form), so a signed `CONVERSION` cannot be made malleable. Rejects `"0"`, `"-1.5"`,
/// `"not-a-rate"`, `"01.5"` (leading zero), `"1.50"` (trailing zero), `"1."` (bare
/// dot); accepts `"1"`, `"2.5"`, `"0.5"`, `"100"`. Enforced on both encode and parse.
fn validate_rate(s: &str) -> Result<()> {
    tlv::validate_text(s.as_bytes())?;
    let mut parts = s.split('.');
    let int_part = parts.next().unwrap_or("");
    let frac_part = parts.next();
    if parts.next().is_some() {
        return Err(Error::FieldDomain); // at most one decimal point
    }
    let all_digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(int_part) {
        return Err(Error::FieldDomain);
    }
    // No leading zeros in the integer part ("0" is allowed, e.g. "0.5").
    if int_part.len() > 1 && int_part.starts_with('0') {
        return Err(Error::FieldDomain);
    }
    if let Some(f) = frac_part {
        // A dot requires a non-empty fractional part with no trailing zeros.
        if !all_digits(f) || f.ends_with('0') {
            return Err(Error::FieldDomain);
        }
    }
    if !s.bytes().any(|b| (b'1'..=b'9').contains(&b)) {
        return Err(Error::FieldDomain); // strictly positive: some nonzero digit
    }
    Ok(())
}

// --- INSTANCE_LEG (F5.6) — the aggregate meed leg, present iff E >= 1 ---

/// A prior finalized leg of *this* round (across its own retries only, F6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditedLeg {
    /// 0x01 meed, 0x02 creditor principal.
    pub kind: u8,
    pub rail: String,
    pub reference: String,
    pub finality: String,
}

/// The aggregate leg the round pays to its claim-record (F4.2 key CHANNEL_ID||CKPT_REF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceLeg {
    /// P — the aggregate this round pays (baseline minimum units).
    pub amount: BigUint,
    /// This round's prior finalized legs (retries only), self-identifying.
    pub credited: Vec<CreditedLeg>,
    /// Per-role extinguished numerators E_r (ascending role); sum E_r = E.
    pub extinguished: Vec<(u8, BigUint)>,
}

const L_AMOUNT: u8 = 0x00;
const L_CREDITED: u8 = 0x01;
const L_EXTINGUISHED: u8 = 0x02;

fn instance_leg_schema() -> Schema {
    Schema::new(
        Openness::Closed,
        &[
            (L_AMOUNT, false),
            (L_CREDITED, false),
            (L_EXTINGUISHED, false),
        ],
    )
}

impl InstanceLeg {
    /// A present `INSTANCE_LEG` exists only for a round making extinguishment
    /// progress (`E = ΣE_r ≥ 1`, F5.6): `P > 0`, at least one role in the canonical
    /// list, every `E_r` within domain, the total `E ≥ 1`, `EXTINGUISHED` ascending by
    /// role, `CREDITED` a valid `kind` ascending by `(kind, ref)`. An individual
    /// zero-share role legitimately has `E_r = 0` (F7.3) — only an all-zero vector (no
    /// progress) is rejected. Enforced on both encode and parse.
    fn validate(&self) -> Result<()> {
        if self.amount == BigUint::from(0u8) {
            return Err(Error::FieldDomain); // no zero-value aggregate leg
        }
        tlv::check_domain(&self.amount, tlv::Domain::Value)?;
        if self.extinguished.is_empty() {
            return Err(Error::FieldDomain); // at least one role in the canonical list
        }
        let mut e_total = BigUint::from(0u8);
        for (_, e) in &self.extinguished {
            tlv::check_domain(e, tlv::Domain::Value)?;
            e_total += e;
        }
        if e_total == BigUint::from(0u8) {
            // E = ΣE_r ≥ 1: a present leg makes extinguishment progress. A zero-share role
            // may be 0 (F7.3), but not every role — an all-zero leg is not a real round.
            return Err(Error::FieldDomain);
        }
        for w in self.extinguished.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(Error::TypeOrder); // ascending role, no duplicates
            }
        }
        for c in &self.credited {
            if c.kind != 0x01 && c.kind != 0x02 {
                return Err(Error::FieldDomain);
            }
        }
        for w in self.credited.windows(2) {
            if (w[0].kind, &w[0].reference) >= (w[1].kind, &w[1].reference) {
                return Err(Error::TypeOrder); // ascending by kind, then ref
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let credited_items: Vec<Vec<u8>> = self
            .credited
            .iter()
            .map(|c| {
                let mut it = vec![c.kind];
                push_lp(&mut it, c.rail.as_bytes());
                push_lp(&mut it, c.reference.as_bytes());
                push_lp(&mut it, c.finality.as_bytes());
                it
            })
            .collect();
        let ext_items: Vec<Vec<u8>> = self
            .extinguished
            .iter()
            .map(|(role, e)| {
                let mut it = vec![*role];
                push_lp(&mut it, &tlv::encode_uint_biguint(e));
                it
            })
            .collect();
        let fields = vec![
            Field::new(L_AMOUNT, false, tlv::encode_uint_biguint(&self.amount)),
            Field::new(
                L_CREDITED,
                false,
                tlv::build_count_prefixed(&credited_items),
            ),
            Field::new(L_EXTINGUISHED, false, tlv::build_count_prefixed(&ext_items)),
        ];
        Ok(Object::from_fields(fields)?.encode())
    }

    fn parse(buf: &[u8]) -> Result<InstanceLeg> {
        let obj = Object::parse(buf)?;
        obj.validate(&instance_leg_schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let amount = tlv::decode_uint_biguint(&get(L_AMOUNT)?.value)?;
        tlv::check_domain(&amount, tlv::Domain::Value)?;
        let credited = tlv::parse_count_prefixed(&get(L_CREDITED)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let kind = b[0];
            let (rail, n1) = read_lp_text(&b[1..])?;
            let (reference, n2) = read_lp_text(&b[1 + n1..])?;
            let (finality, n3) = read_lp_text(&b[1 + n1 + n2..])?;
            Ok((
                CreditedLeg {
                    kind,
                    rail,
                    reference,
                    finality,
                },
                1 + n1 + n2 + n3,
            ))
        })?;
        let extinguished = tlv::parse_count_prefixed(&get(L_EXTINGUISHED)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let role = b[0];
            let (e, n) = read_lp_uint(&b[1..])?;
            Ok(((role, e), 1 + n))
        })?;
        let leg = InstanceLeg {
            amount,
            credited,
            extinguished,
        };
        leg.validate()?; // ordering / domain / non-empty, same rules as encode
        Ok(leg)
    }
}

// --- CONVERSION (F5.6) — present iff DENOM != BASELINE_ASSET ---

/// The round's rate agreement (finality levels live in CHANNEL_AUTH, not here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversion {
    /// Decimal rate grammar (F3-c), baseline minimum units per one µ-unit of DENOM.
    pub rate: String,
    pub rate_time: u64,
    pub rate_exp: u64,
    pub rate_grace: u64,
}

const V_RATE: u8 = 0x00;
const V_RATE_TIME: u8 = 0x01;
const V_RATE_EXP: u8 = 0x02;
const V_RATE_GRACE: u8 = 0x03;

fn conversion_schema() -> Schema {
    Schema::new(
        Openness::Closed,
        &[
            (V_RATE, false),
            (V_RATE_TIME, false),
            (V_RATE_EXP, false),
            (V_RATE_GRACE, false),
        ],
    )
}

impl Conversion {
    fn encode(&self) -> Result<Vec<u8>> {
        validate_rate(&self.rate)?;
        let fields = vec![
            Field::new(V_RATE, false, self.rate.as_bytes().to_vec()),
            Field::new(
                V_RATE_TIME,
                false,
                tlv::encode_uint_u128(self.rate_time as u128),
            ),
            Field::new(
                V_RATE_EXP,
                false,
                tlv::encode_uint_u128(self.rate_exp as u128),
            ),
            Field::new(
                V_RATE_GRACE,
                false,
                tlv::encode_uint_u128(self.rate_grace as u128),
            ),
        ];
        Ok(Object::from_fields(fields)?.encode())
    }
    fn parse(buf: &[u8]) -> Result<Conversion> {
        let obj = Object::parse(buf)?;
        obj.validate(&conversion_schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let rate =
            String::from_utf8(get(V_RATE)?.value.clone()).map_err(|_| Error::TextControlChar)?;
        validate_rate(&rate)?;
        Ok(Conversion {
            rate,
            rate_time: tlv::decode_uint_u64(&get(V_RATE_TIME)?.value)?,
            rate_exp: tlv::decode_uint_u64(&get(V_RATE_EXP)?.value)?,
            rate_grace: tlv::decode_uint_u64(&get(V_RATE_GRACE)?.value)?,
        })
    }
}

// --- SETTLEMENT_PROPOSE (F5.6) ---

const P_CHANNEL_ID: u8 = 0x00;
const P_CKPT_REF: u8 = 0x01;
const P_OUTPUTS: u8 = 0x02;
const P_INSTANCE_LEG: u8 = 0x03;
const P_CONVERSION: u8 = 0x04;
const SIG_PAYER: u8 = 0x70;
const SIG_MERCHANT: u8 = 0x71;

/// SETTLEMENT_PROPOSE (F5.6). Role-fixed sig slots (F5-k): 0x70 payer, 0x71
/// merchant. A deterministic round carries only the debtor's slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPropose {
    pub channel_id: [u8; 8],
    pub ckpt_ref: [u8; 32],
    pub outputs: Vec<Output>,
    /// Some iff the round makes extinguishment progress (E >= 1, F7.3).
    pub instance_leg: Option<InstanceLeg>,
    /// Some iff DENOM != BASELINE_ASSET.
    pub conversion: Option<Conversion>,
    pub sig_payer: Option<[u8; 64]>,
    pub sig_merchant: Option<[u8; 64]>,
}

fn propose_schema() -> Schema {
    Schema::new(
        Openness::Closed,
        &[
            (P_CHANNEL_ID, false),
            (P_CKPT_REF, false),
            (P_OUTPUTS, false),
            (P_INSTANCE_LEG, false),
            (P_CONVERSION, false),
            (SIG_PAYER, false),
            (SIG_MERCHANT, false),
        ],
    )
}

impl SettlementPropose {
    fn content_fields(&self) -> Result<Vec<Field>> {
        check_outputs(&self.outputs)?;
        let output_items: Vec<Vec<u8>> = self.outputs.iter().map(output_item).collect();
        let mut fields = vec![
            Field::new(P_CHANNEL_ID, false, self.channel_id.to_vec()),
            Field::new(P_CKPT_REF, false, self.ckpt_ref.to_vec()),
            Field::new(P_OUTPUTS, false, tlv::build_count_prefixed(&output_items)),
        ];
        if let Some(leg) = &self.instance_leg {
            fields.push(Field::new(P_INSTANCE_LEG, false, leg.encode()?));
        }
        if let Some(conv) = &self.conversion {
            fields.push(Field::new(P_CONVERSION, false, conv.encode()?));
        }
        Ok(fields)
    }

    /// The COVERED bytes both role slots sign (PayTPv1-settle-propose).
    pub fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(
            DomainLabel::SettlePropose,
            &Object::from_fields(self.content_fields()?)?.encode(),
        ))
    }

    pub fn sign_payer(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig_payer = Some(ed25519_sign(payer_sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn sign_merchant(&mut self, merchant_sk: &[u8; 32]) -> Result<()> {
        self.sig_merchant = Some(ed25519_sign(merchant_sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn verify_payer(&self, payer_key: &[u8; 32]) -> Result<()> {
        let sig = self.sig_payer.ok_or(Error::MissingField)?;
        ed25519_verify_strict(payer_key, &self.covered_bytes()?, &sig)
    }
    pub fn verify_merchant(&self, merchant_key: &[u8; 32]) -> Result<()> {
        let sig = self.sig_merchant.ok_or(Error::MissingField)?;
        ed25519_verify_strict(merchant_key, &self.covered_bytes()?, &sig)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig_payer {
            fields.push(Field::new(SIG_PAYER, false, s.to_vec()));
        }
        if let Some(s) = self.sig_merchant {
            fields.push(Field::new(SIG_MERCHANT, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }

    /// The round's identifier (F5-h): SHA-256 over the proposal's complete canonical
    /// bytes, whichever signatures it carries. **Completeness is the driver's (F6.5),
    /// not the codec's:** a both-signed round (`DENOM ≠ BASELINE_ASSET`, or a net leg
    /// off the baseline rail) is only the *binding* identifier once countersigned,
    /// but the codec cannot see the mode/rails that decide which signatures a round
    /// needs — so the caller must ensure the round carries the correct signatures
    /// before binding a `PROOF`/`CONFIRMED` to this hash. (An earlier
    /// `conversion`-only guard was removed: it gave false assurance, missing the
    /// net-off-baseline case it cannot detect.)
    pub fn proposal_hash(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.encode()?))
    }

    pub fn parse(buf: &[u8]) -> Result<SettlementPropose> {
        let obj = Object::parse(buf)?;
        obj.validate(&propose_schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let outputs = tlv::parse_count_prefixed(&get(P_OUTPUTS)?.value, |b| {
            let (amount, n1) = read_lp_uint(b)?;
            let (asset, n2) = read_lp_text(&b[n1..])?;
            let (dest, n3) = read_lp_text(&b[n1 + n2..])?;
            Ok((
                Output {
                    amount,
                    asset,
                    dest,
                },
                n1 + n2 + n3,
            ))
        })?;
        check_outputs(&outputs)?;
        Ok(SettlementPropose {
            channel_id: get(P_CHANNEL_ID)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            ckpt_ref: fixed32(&get(P_CKPT_REF)?.value)?,
            outputs,
            instance_leg: obj
                .get(P_INSTANCE_LEG)
                .map(|f| InstanceLeg::parse(&f.value))
                .transpose()?,
            conversion: obj
                .get(P_CONVERSION)
                .map(|f| Conversion::parse(&f.value))
                .transpose()?,
            sig_payer: obj.get(SIG_PAYER).map(|f| fixed64(&f.value)).transpose()?,
            sig_merchant: obj
                .get(SIG_MERCHANT)
                .map(|f| fixed64(&f.value))
                .transpose()?,
        })
    }
}

// --- SETTLEMENT_PROOF (F5.6) — the debtor proves the round's legs finalized ---

/// One finalized transfer of a settled round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRef {
    /// 0x01 meed, 0x02 creditor output.
    pub leg: u8,
    pub reference: String,
    pub finality: String,
}

/// SETTLEMENT_PROOF (F5.6): signed by the debtor in its role slot, PayTPv1-settle-proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementProof {
    pub channel_id: [u8; 8],
    pub proposal_hash: [u8; 32],
    pub tx_refs: Vec<TxRef>,
    pub sig_payer: Option<[u8; 64]>,
    pub sig_merchant: Option<[u8; 64]>,
}

const PR_CHANNEL_ID: u8 = 0x00;
const PR_PROPOSAL_HASH: u8 = 0x01;
const PR_TX_REFS: u8 = 0x02;

impl SettlementProof {
    fn content_fields(&self) -> Result<Vec<Field>> {
        for t in &self.tx_refs {
            if t.leg != 0x01 && t.leg != 0x02 {
                return Err(Error::FieldDomain);
            }
        }
        for w in self.tx_refs.windows(2) {
            if (w[0].leg, &w[0].reference) >= (w[1].leg, &w[1].reference) {
                return Err(Error::TypeOrder);
            }
        }
        let items: Vec<Vec<u8>> = self
            .tx_refs
            .iter()
            .map(|t| {
                let mut it = vec![t.leg];
                push_lp(&mut it, t.reference.as_bytes());
                push_lp(&mut it, t.finality.as_bytes());
                it
            })
            .collect();
        Ok(vec![
            Field::new(PR_CHANNEL_ID, false, self.channel_id.to_vec()),
            Field::new(PR_PROPOSAL_HASH, false, self.proposal_hash.to_vec()),
            Field::new(PR_TX_REFS, false, tlv::build_count_prefixed(&items)),
        ])
    }
    pub fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(
            DomainLabel::SettleProof,
            &Object::from_fields(self.content_fields()?)?.encode(),
        ))
    }
    pub fn sign_payer(&mut self, sk: &[u8; 32]) -> Result<()> {
        self.sig_payer = Some(ed25519_sign(sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn sign_merchant(&mut self, sk: &[u8; 32]) -> Result<()> {
        self.sig_merchant = Some(ed25519_sign(sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn verify_payer(&self, key: &[u8; 32]) -> Result<()> {
        ed25519_verify_strict(
            key,
            &self.covered_bytes()?,
            &self.sig_payer.ok_or(Error::MissingField)?,
        )
    }
    pub fn verify_merchant(&self, key: &[u8; 32]) -> Result<()> {
        ed25519_verify_strict(
            key,
            &self.covered_bytes()?,
            &self.sig_merchant.ok_or(Error::MissingField)?,
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        // A proof is single-signed by the debtor — exactly one role slot present.
        if self.sig_payer.is_some() == self.sig_merchant.is_some() {
            return Err(Error::MissingField);
        }
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig_payer {
            fields.push(Field::new(SIG_PAYER, false, s.to_vec()));
        }
        if let Some(s) = self.sig_merchant {
            fields.push(Field::new(SIG_MERCHANT, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<SettlementProof> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[
                (PR_CHANNEL_ID, false),
                (PR_PROPOSAL_HASH, false),
                (PR_TX_REFS, false),
                (SIG_PAYER, false),
                (SIG_MERCHANT, false),
            ],
        ))?;
        if obj.get(SIG_PAYER).is_some() == obj.get(SIG_MERCHANT).is_some() {
            return Err(Error::MissingField); // exactly one signer (the debtor)
        }
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let tx_refs = tlv::parse_count_prefixed(&get(PR_TX_REFS)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let leg = b[0];
            if leg != 0x01 && leg != 0x02 {
                return Err(Error::FieldDomain);
            }
            let (reference, n1) = read_lp_text(&b[1..])?;
            let (finality, n2) = read_lp_text(&b[1 + n1..])?;
            Ok((
                TxRef {
                    leg,
                    reference,
                    finality,
                },
                1 + n1 + n2,
            ))
        })?;
        for w in tx_refs.windows(2) {
            if (w[0].leg, &w[0].reference) >= (w[1].leg, &w[1].reference) {
                return Err(Error::TypeOrder);
            }
        }
        Ok(SettlementProof {
            channel_id: get(PR_CHANNEL_ID)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            proposal_hash: fixed32(&get(PR_PROPOSAL_HASH)?.value)?,
            tx_refs,
            sig_payer: obj.get(SIG_PAYER).map(|f| fixed64(&f.value)).transpose()?,
            sig_merchant: obj
                .get(SIG_MERCHANT)
                .map(|f| fixed64(&f.value))
                .transpose()?,
        })
    }
}

// --- SETTLEMENT_CONFIRMED (F5.6) — the creditor confirms receipt ---

/// SETTLEMENT_CONFIRMED (F5.6): signed by the creditor in its role slot,
/// PayTPv1-settle-confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementConfirmed {
    pub channel_id: [u8; 8],
    pub proposal_hash: [u8; 32],
    pub sig_payer: Option<[u8; 64]>,
    pub sig_merchant: Option<[u8; 64]>,
}

impl SettlementConfirmed {
    fn content_fields(&self) -> Vec<Field> {
        vec![
            Field::new(0x00, false, self.channel_id.to_vec()),
            Field::new(0x01, false, self.proposal_hash.to_vec()),
        ]
    }
    pub fn covered_bytes(&self) -> Vec<u8> {
        covered(
            DomainLabel::SettleConfirm,
            &Object::from_fields(self.content_fields()).unwrap().encode(),
        )
    }
    pub fn sign_payer(&mut self, sk: &[u8; 32]) {
        self.sig_payer = Some(ed25519_sign(sk, &self.covered_bytes()));
    }
    pub fn sign_merchant(&mut self, sk: &[u8; 32]) {
        self.sig_merchant = Some(ed25519_sign(sk, &self.covered_bytes()));
    }
    pub fn verify_payer(&self, key: &[u8; 32]) -> Result<()> {
        ed25519_verify_strict(
            key,
            &self.covered_bytes(),
            &self.sig_payer.ok_or(Error::MissingField)?,
        )
    }
    pub fn verify_merchant(&self, key: &[u8; 32]) -> Result<()> {
        ed25519_verify_strict(
            key,
            &self.covered_bytes(),
            &self.sig_merchant.ok_or(Error::MissingField)?,
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Confirmed is single-signed by the creditor — exactly one role slot present.
        if self.sig_payer.is_some() == self.sig_merchant.is_some() {
            return Err(Error::MissingField);
        }
        let mut fields = self.content_fields();
        if let Some(s) = self.sig_payer {
            fields.push(Field::new(SIG_PAYER, false, s.to_vec()));
        }
        if let Some(s) = self.sig_merchant {
            fields.push(Field::new(SIG_MERCHANT, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<SettlementConfirmed> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[
                (0x00, false),
                (0x01, false),
                (SIG_PAYER, false),
                (SIG_MERCHANT, false),
            ],
        ))?;
        if obj.get(SIG_PAYER).is_some() == obj.get(SIG_MERCHANT).is_some() {
            return Err(Error::MissingField); // exactly one signer (the creditor)
        }
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        Ok(SettlementConfirmed {
            channel_id: get(0x00)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            proposal_hash: fixed32(&get(0x01)?.value)?,
            sig_payer: obj.get(SIG_PAYER).map(|f| fixed64(&f.value)).transpose()?,
            sig_merchant: obj
                .get(SIG_MERCHANT)
                .map(|f| fixed64(&f.value))
                .transpose()?,
        })
    }
}

// --- PREPAY_DRAW_COMPLETED (GAP-FILL F5-o) — the prepay interim-draw completion notice ---

/// `PREPAY_DRAW_COMPLETED` (F5-o, §6.4): the merchant→payer notice the merchant emits
/// after a prepay **interim meed draw** (F6-n), and the signal a halted conformant
/// wallet resumes on (the F6.5 prepay meed halt). A prepay interim round is the
/// merchant's — the meed *debtor's* — so this is **merchant-single-signed** under its
/// own domain tag `PayTPv1-prepay-draw`, never a creditor-signed `SETTLEMENT_CONFIRMED`.
/// It is **liveness evidence, not settlement authority** (§6.4): the wallet verifies the
/// signature and resumes at once, but credits the round only from the rail — it
/// independently verifies the claim record (`0x04`) was *funded* by the distributing kind
/// (F6-m) with `P` (`0x02`) to the required finality before crediting the round and
/// permitting the next. Single-signer slot is `0x70` (the CHANNEL_ACK/CLOSE convention),
/// not the role-fixed dual-sig `0x70`/`0x71`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepayDrawCompleted {
    pub channel_id: [u8; 8],
    /// The operative checkpoint the draw settled against (F5-f).
    pub ckpt_ref: [u8; 32],
    /// `P` — the aggregate meed drawn (baseline minimum units, F7.2).
    pub amount: BigUint,
    /// Per-role extinguished numerators `E_r` (ascending role); `Σ E_r = E ≥ 1`.
    pub extinguished: Vec<(u8, BigUint)>,
    /// The funded claim-record id (F4.2 `claim_record_id(seed_instance, cid, ckpt_ref, P)`).
    pub claim_record: [u8; 32],
    /// The baseline rail id the draw funded on (F9.1).
    pub rail: String,
    /// The claim-record funding transfer reference.
    pub tx_ref: String,
    /// The finality the leg reached (adapter token; at least `FIN_MEED`).
    pub finality: String,
    pub sig_merchant: Option<[u8; 64]>,
}

const D_CHANNEL_ID: u8 = 0x00;
const D_CKPT_REF: u8 = 0x01;
const D_AMOUNT: u8 = 0x02;
const D_EXTINGUISHED: u8 = 0x03;
const D_CLAIM_RECORD: u8 = 0x04;
const D_RAIL: u8 = 0x05;
const D_TX_REF: u8 = 0x06;
const D_FINALITY: u8 = 0x07;
const D_SIG: u8 = 0x70; // the sole-signer slot (merchant), per CHANNEL_ACK/CLOSE

impl PrepayDrawCompleted {
    /// A well-formed notice: `P > 0`; `E_r` non-empty, ascending by role, with
    /// `Σ E_r ≥ 1` (a draw makes extinguishment progress, F7.3 — an individual
    /// zero-share role may be 0, but not every role); and the rail/reference/finality
    /// present. Enforced on encode and parse.
    fn validate(&self) -> Result<()> {
        if self.amount == BigUint::from(0u8) {
            return Err(Error::FieldDomain); // a real draw pays P ≥ 1
        }
        tlv::check_domain(&self.amount, tlv::Domain::Value)?;
        if self.extinguished.is_empty() {
            return Err(Error::FieldDomain);
        }
        let mut e_total = BigUint::from(0u8);
        for (_, e) in &self.extinguished {
            tlv::check_domain(e, tlv::Domain::Value)?;
            e_total += e;
        }
        if e_total == BigUint::from(0u8) {
            return Err(Error::FieldDomain); // E = ΣE_r ≥ 1
        }
        for w in self.extinguished.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(Error::TypeOrder); // ascending role, no duplicates
            }
        }
        if self.rail.is_empty() || self.tx_ref.is_empty() || self.finality.is_empty() {
            return Err(Error::FieldDomain); // the rail facts the payer verifies must be present
        }
        tlv::validate_text(self.rail.as_bytes())?;
        tlv::validate_text(self.tx_ref.as_bytes())?;
        tlv::validate_text(self.finality.as_bytes())?;
        Ok(())
    }

    fn content_fields(&self) -> Vec<Field> {
        let ext_items: Vec<Vec<u8>> = self
            .extinguished
            .iter()
            .map(|(role, e)| {
                let mut it = vec![*role];
                push_lp(&mut it, &tlv::encode_uint_biguint(e));
                it
            })
            .collect();
        vec![
            Field::new(D_CHANNEL_ID, false, self.channel_id.to_vec()),
            Field::new(D_CKPT_REF, false, self.ckpt_ref.to_vec()),
            Field::new(D_AMOUNT, false, tlv::encode_uint_biguint(&self.amount)),
            Field::new(D_EXTINGUISHED, false, tlv::build_count_prefixed(&ext_items)),
            Field::new(D_CLAIM_RECORD, false, self.claim_record.to_vec()),
            Field::new(D_RAIL, false, self.rail.as_bytes().to_vec()),
            Field::new(D_TX_REF, false, self.tx_ref.as_bytes().to_vec()),
            Field::new(D_FINALITY, false, self.finality.as_bytes().to_vec()),
        ]
    }

    pub fn covered_bytes(&self) -> Vec<u8> {
        covered(
            DomainLabel::PrepayDraw,
            &Object::from_fields(self.content_fields()).unwrap().encode(),
        )
    }

    pub fn sign_merchant(&mut self, sk: &[u8; 32]) {
        self.sig_merchant = Some(ed25519_sign(sk, &self.covered_bytes()));
    }

    pub fn verify_merchant(&self, key: &[u8; 32]) -> Result<()> {
        ed25519_verify_strict(
            key,
            &self.covered_bytes(),
            &self.sig_merchant.ok_or(Error::MissingField)?,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut fields = self.content_fields();
        fields.push(Field::new(
            D_SIG,
            false,
            self.sig_merchant.ok_or(Error::MissingField)?.to_vec(),
        ));
        Ok(Object::from_fields(fields)?.encode())
    }

    pub fn parse(buf: &[u8]) -> Result<PrepayDrawCompleted> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[
                (D_CHANNEL_ID, false),
                (D_CKPT_REF, false),
                (D_AMOUNT, false),
                (D_EXTINGUISHED, false),
                (D_CLAIM_RECORD, false),
                (D_RAIL, false),
                (D_TX_REF, false),
                (D_FINALITY, false),
                (D_SIG, false),
            ],
        ))?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let amount = tlv::decode_uint_biguint(&get(D_AMOUNT)?.value)?;
        let extinguished = tlv::parse_count_prefixed(&get(D_EXTINGUISHED)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let role = b[0];
            let (e, n) = read_lp_uint(&b[1..])?;
            Ok(((role, e), 1 + n))
        })?;
        let msg = PrepayDrawCompleted {
            channel_id: get(D_CHANNEL_ID)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            ckpt_ref: fixed32(&get(D_CKPT_REF)?.value)?,
            amount,
            extinguished,
            claim_record: fixed32(&get(D_CLAIM_RECORD)?.value)?,
            rail: String::from_utf8(get(D_RAIL)?.value.clone())
                .map_err(|_| Error::TextControlChar)?,
            tx_ref: String::from_utf8(get(D_TX_REF)?.value.clone())
                .map_err(|_| Error::TextControlChar)?,
            finality: String::from_utf8(get(D_FINALITY)?.value.clone())
                .map_err(|_| Error::TextControlChar)?,
            sig_merchant: obj.get(D_SIG).map(|f| fixed64(&f.value)).transpose()?,
        };
        msg.validate()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests;
