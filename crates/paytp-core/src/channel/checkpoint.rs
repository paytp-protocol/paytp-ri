//! The bilateral `CHECKPOINT` (**F5.5**, formalizing §6.3) — the channel's
//! *metering* record.
//!
//! It carries `CUM_TOTAL` (gross accepted, monotone) and per-role `ACCRUALS`
//! (accrued meed numerators, monotone) — authoritative for what was **metered**,
//! never for what was **paid** (F6-f: settlement is rail-authoritative). Both
//! signatures cover the identical `COVERED` bytes; the checkpoint **reference**
//! (F5-f) is `SHA-256` over the *complete* bilateral bytes (both signatures
//! included), naming one countersigned instance.

use crate::crypto::sha256;
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::tlv::{self, Field, Object, Openness, Schema};
use num_bigint::BigUint;

const T_CHANNEL_ID: u8 = 0x00;
const T_BALANCE: u8 = 0x01;
const T_CUM_TOTAL: u8 = 0x02;
const T_ACCRUALS: u8 = 0x03;
const T_LAST_SEQ: u8 = 0x04;
const T_RANGES: u8 = 0x05;
const T_TRANSCRIPT: u8 = 0x06;
const T_EVENTS: u8 = 0x07;
const T_TIMESTAMP: u8 = 0x08;
const T_PREV_REF: u8 = 0x09;
const T_SIG_PAYER: u8 = 0x70;
const T_SIG_MERCHANT: u8 = 0x71;

/// One accepted `SEQ` range (inclusive), F5.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub lo: u64,
    pub hi: u64,
}

/// A recorded event reference since the previous checkpoint (F5.5 `EVENTS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `0x01` funding, `0x02` settlement round, `0x03` predecessor import.
    pub kind: u8,
    pub reference: Vec<u8>,
}

/// A `CHECKPOINT` (F5.5). Content plus the two role-fixed signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub channel_id: [u8; 8],
    /// `B`, the live flow-control estimate (signed, F1-b) — NOT authoritative for
    /// what was paid (F6-f).
    pub balance: BigUint,
    pub balance_negative: bool,
    /// `CUM_TOTAL`, gross accepted (monotone) — the authoritative metered principal.
    pub cum_total: BigUint,
    /// `ACCRUALS`, per-role `(role, numerator)` ascending — the metered meed.
    pub accruals: Vec<(u8, BigUint)>,
    pub last_seq: u64,
    pub ranges: Vec<Range>,
    pub transcript: [u8; 32],
    pub events: Vec<Event>,
    pub timestamp: u64,
    pub prev_ref: [u8; 32],
    pub sig_payer: Option<[u8; 64]>,
    pub sig_merchant: Option<[u8; 64]>,
}

fn schema() -> Schema {
    // Closed (F5.5 is the fixed §6.3 statement): reject any unknown field, so a
    // byte-extended checkpoint is rejected at parse — the verifier/reference can
    // never operate on a sanitized object that drops covered content (F5-f/F1-i).
    Schema::new(
        Openness::Closed,
        &[
            (T_CHANNEL_ID, false),
            (T_BALANCE, false),
            (T_CUM_TOTAL, false),
            (T_ACCRUALS, false),
            (T_LAST_SEQ, false),
            (T_RANGES, false),
            (T_TRANSCRIPT, false),
            (T_EVENTS, false),
            (T_TIMESTAMP, false),
            (T_PREV_REF, false),
            (T_SIG_PAYER, false),
            (T_SIG_MERCHANT, false),
        ],
    )
}

impl Checkpoint {
    /// The content fields (all but the two signatures), in canonical order.
    fn content_fields(&self) -> Result<Vec<Field>> {
        // BALANCE: two's-complement signed minimal (F1-b).
        let bal = if self.balance_negative {
            let mag =
                num_bigint::BigInt::from_biguint(num_bigint::Sign::Minus, self.balance.clone());
            tlv::encode_sint(&mag)
        } else {
            tlv::encode_sint(&num_bigint::BigInt::from_biguint(
                num_bigint::Sign::Plus,
                self.balance.clone(),
            ))
        };
        let accruals_items: Vec<Vec<u8>> = self
            .accruals
            .iter()
            .map(|(role, num)| {
                let n = tlv::encode_uint_biguint(num);
                let mut item = vec![*role];
                crate::leb128::encode_into(n.len() as u64, &mut item);
                item.extend_from_slice(&n);
                item
            })
            .collect();
        let range_items: Vec<Vec<u8>> = self
            .ranges
            .iter()
            .map(|r| {
                let mut it = r.lo.to_be_bytes().to_vec();
                it.extend_from_slice(&r.hi.to_be_bytes());
                it
            })
            .collect();
        let event_items: Vec<Vec<u8>> = self
            .events
            .iter()
            .map(|e| {
                let mut it = vec![e.kind];
                crate::leb128::encode_into(e.reference.len() as u64, &mut it);
                it.extend_from_slice(&e.reference);
                it
            })
            .collect();
        Ok(vec![
            Field::new(T_CHANNEL_ID, false, self.channel_id.to_vec()),
            Field::new(T_BALANCE, false, bal),
            Field::new(
                T_CUM_TOTAL,
                false,
                tlv::encode_uint_biguint(&self.cum_total),
            ),
            Field::new(
                T_ACCRUALS,
                false,
                tlv::build_count_prefixed(&accruals_items),
            ),
            Field::new(T_LAST_SEQ, false, self.last_seq.to_be_bytes().to_vec()),
            Field::new(T_RANGES, false, tlv::build_count_prefixed(&range_items)),
            Field::new(T_TRANSCRIPT, false, self.transcript.to_vec()),
            Field::new(T_EVENTS, false, tlv::build_count_prefixed(&event_items)),
            Field::new(
                T_TIMESTAMP,
                false,
                tlv::encode_uint_u128(self.timestamp as u128),
            ),
            Field::new(T_PREV_REF, false, self.prev_ref.to_vec()),
        ])
    }

    /// The `COVERED` bytes both signatures sign (`PayTPv1-ckpt`).
    pub fn covered_bytes(&self) -> Result<Vec<u8>> {
        let obj = Object::from_fields(self.content_fields()?)?;
        Ok(covered(DomainLabel::Ckpt, &obj.encode()))
    }

    pub fn sign_payer(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig_payer = Some(crate::crypto::ed25519_sign(
            payer_sk,
            &self.covered_bytes()?,
        ));
        Ok(())
    }

    pub fn sign_merchant(&mut self, merchant_sk: &[u8; 32]) -> Result<()> {
        self.sig_merchant = Some(crate::crypto::ed25519_sign(
            merchant_sk,
            &self.covered_bytes()?,
        ));
        Ok(())
    }

    /// Verify the payer signature alone (a single-signed `CHECKPOINT_REQUEST`
    /// proposal, F6.3 — the responder checks the proposer signed the state before
    /// recomputing and countersigning).
    pub fn verify_payer(&self, payer_pk: &[u8; 32]) -> Result<()> {
        let sp = self.sig_payer.ok_or(Error::MissingField)?;
        crate::crypto::ed25519_verify_strict(payer_pk, &self.covered_bytes()?, &sp)
    }

    /// Verify both signatures (bilateral) against the two keys.
    pub fn verify_bilateral(&self, payer_pk: &[u8; 32], merchant_pk: &[u8; 32]) -> Result<()> {
        let covered = self.covered_bytes()?;
        let sp = self.sig_payer.ok_or(Error::MissingField)?;
        let sm = self.sig_merchant.ok_or(Error::MissingField)?;
        crate::crypto::ed25519_verify_strict(payer_pk, &covered, &sp)?;
        crate::crypto::ed25519_verify_strict(merchant_pk, &covered, &sm)?;
        Ok(())
    }

    /// The complete canonical bytes (content + present signatures).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(sp) = self.sig_payer {
            fields.push(Field::new(T_SIG_PAYER, false, sp.to_vec()));
        }
        if let Some(sm) = self.sig_merchant {
            fields.push(Field::new(T_SIG_MERCHANT, false, sm.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }

    /// The checkpoint **reference** (GAP-FILL F5-f): `SHA-256` over the complete
    /// bilateral bytes (both signatures included). Only meaningful when bilateral.
    pub fn reference(&self) -> Result<[u8; 32]> {
        if self.sig_payer.is_none() || self.sig_merchant.is_none() {
            return Err(Error::MissingField); // a reference names one countersigned instance
        }
        Ok(sha256(&self.encode()?))
    }

    /// The reference of a **synthetic (stillborn) checkpoint** (GAP-FILL F6-e):
    /// `SHA-256` over the canonical bytes **with no authenticator TLVs present**. A
    /// stillborn channel signs no bilateral checkpoint of its own; both parties instead
    /// construct this deterministically (its authority is the signed `CHANNEL_AUTH`/
    /// `CHANNEL_ACK` pair). It **cannot collide** with a real checkpoint reference —
    /// `reference()` above always hashes bytes that contain both signature TLVs, this
    /// one hashes bytes that contain neither — so a party validating a chain reference
    /// against a stillborn predecessor recomputes exactly this over the unsigned bytes.
    pub fn synthetic_reference(&self) -> Result<[u8; 32]> {
        if self.sig_payer.is_some() || self.sig_merchant.is_some() {
            return Err(Error::MissingField); // a synthetic reference names an unsigned instance
        }
        Ok(sha256(&self.encode()?))
    }

    /// Parse a checkpoint (validates the F5.5 schema; ascending accruals/ranges).
    pub fn parse(buf: &[u8]) -> Result<Checkpoint> {
        let obj = Object::parse(buf)?;
        obj.validate(&schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let channel_id: [u8; 8] = get(T_CHANNEL_ID)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let bal = tlv::decode_sint(&get(T_BALANCE)?.value)?;
        let (balance_negative, balance) = match bal.to_biguint() {
            Some(b) => (false, b),
            None => (true, (-bal).to_biguint().ok_or(Error::NonMinimalSignedInt)?),
        };
        // Value-domain caps (F1-l/F7-a): µ-unit magnitudes ≤ 2¹²⁸ − 1.
        tlv::check_domain(&balance, tlv::Domain::Value)?;
        let cum_total = tlv::decode_uint_biguint(&get(T_CUM_TOTAL)?.value)?;
        tlv::check_domain(&cum_total, tlv::Domain::Value)?;
        let accruals = tlv::parse_count_prefixed(&get(T_ACCRUALS)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let role = b[0];
            let (len, n) = crate::leb128::decode(&b[1..])?;
            let s = 1 + n;
            let e = s.checked_add(len as usize).ok_or(Error::LengthOverrun)?;
            if e > b.len() {
                return Err(Error::LengthOverrun);
            }
            let num = tlv::decode_uint_biguint(&b[s..e])?;
            tlv::check_domain(&num, tlv::Domain::Value)?; // F7-a: accrual ≤ 2¹²⁸ − 1
            Ok(((role, num), e))
        })?;
        for w in accruals.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(Error::TypeOrder); // ascending role, no duplicates
            }
        }
        let last_seq = u64::from_be_bytes(
            get(T_LAST_SEQ)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
        );
        if last_seq > crate::slice::SEQ_MAX {
            return Err(Error::FieldDomain); // F1-e: SEQ never wraps (> 2^63 rejected)
        }
        let ranges = tlv::parse_count_prefixed(&get(T_RANGES)?.value, |b| {
            if b.len() < 16 {
                return Err(Error::CountMismatch);
            }
            let lo = u64::from_be_bytes(b[..8].try_into().unwrap());
            let hi = u64::from_be_bytes(b[8..16].try_into().unwrap());
            if lo > hi {
                return Err(Error::FieldDomain); // lo ≤ hi
            }
            if hi > crate::slice::SEQ_MAX {
                return Err(Error::FieldDomain); // F1-e: SEQ never wraps (> 2^63 rejected)
            }
            Ok((Range { lo, hi }, 16))
        })?;
        // F5.5: ranges ascending, non-overlapping, non-adjacent (adjacent MUST merge).
        // `hi ≤ SEQ_MAX` (checked above) keeps `hi + 1` in range; saturating_add is
        // belt-and-suspenders so a stray u64::MAX can never panic under overflow-checks.
        for w in ranges.windows(2) {
            if w[1].lo <= w[0].hi.saturating_add(1) {
                return Err(Error::TypeOrder);
            }
        }
        let transcript: [u8; 32] = get(T_TRANSCRIPT)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let events = tlv::parse_count_prefixed(&get(T_EVENTS)?.value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let kind = b[0];
            // F5.5: EVENTS.kind ∈ {0x01 funding, 0x02 settlement, 0x03 predecessor}. An
            // undefined kind is rejected at parse (a signed-byte accept/reject divergence
            // otherwise), never carried through on a best-effort audit field.
            if !matches!(kind, 0x01..=0x03) {
                return Err(Error::FieldDomain);
            }
            let (len, n) = crate::leb128::decode(&b[1..])?;
            let s = 1 + n;
            let e = s.checked_add(len as usize).ok_or(Error::LengthOverrun)?;
            if e > b.len() {
                return Err(Error::LengthOverrun);
            }
            Ok((
                Event {
                    kind,
                    reference: b[s..e].to_vec(),
                },
                e,
            ))
        })?;
        // F5.5: events sorted ascending by kind, then reference bytes.
        for w in events.windows(2) {
            if (w[0].kind, &w[0].reference) >= (w[1].kind, &w[1].reference) {
                return Err(Error::TypeOrder);
            }
        }
        let timestamp = tlv::decode_uint_time(&get(T_TIMESTAMP)?.value)?; // F1-l time domain ≤ 2⁵³−1
        let prev_ref: [u8; 32] = get(T_PREV_REF)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let sig_payer = obj
            .get(T_SIG_PAYER)
            .map(|f| f.value.clone().try_into().map_err(|_| Error::WrongWidth))
            .transpose()?;
        let sig_merchant = obj
            .get(T_SIG_MERCHANT)
            .map(|f| f.value.clone().try_into().map_err(|_| Error::WrongWidth))
            .transpose()?;
        Ok(Checkpoint {
            channel_id,
            balance,
            balance_negative,
            cum_total,
            accruals,
            last_seq,
            ranges,
            transcript,
            events,
            timestamp,
            prev_ref,
            sig_payer,
            sig_merchant,
        })
    }
}

// --- CHECKPOINT_REQUEST (F5.5) — the §5.4 two-label construction ---

/// Field types of the `CHECKPOINT_REQUEST` wrapper (F5.5).
const R_PROPOSED: u8 = 0x00;
const R_SIG: u8 = 0x70;

fn request_schema() -> Schema {
    // Closed: the PROPOSED value + the single outer authenticator, nothing else.
    Schema::new(Openness::Closed, &[(R_PROPOSED, false), (R_SIG, false)])
}

/// A `CHECKPOINT_REQUEST` (**F5.5**) — §5.4's **two-label construction**. It wraps a
/// *proposed* [`Checkpoint`] (the initiator's role slot signed under `PayTPv1-ckpt`,
/// the other absent) in its own object signed under `PayTPv1-ckpt-req`:
///
/// - the **inner** `PayTPv1-ckpt` signature is the initiator's half of the eventual
///   bilateral checkpoint, so the responder completes ONE canonical bilateral object
///   by adding its countersignature over the identical covered bytes (never re-signing
///   the initiator's half);
/// - the **outer** `PayTPv1-ckpt-req` signature authenticates the *request act* in a
///   domain **distinct** from a completed checkpoint. `PayTPv1-ckpt` is a byte prefix
///   of `PayTPv1-ckpt-req`; the `0x00` label delimiter (F1-h) makes the two covered
///   prefixes diverge, so a request signature can never be replayed as a checkpoint
///   signature or vice versa (F1.3).
///
/// Both signatures are the initiator's. The bare-checkpoint form the RI carried before
/// (a `0x03 ‖ <half-signed checkpoint>` with no outer wrapper) is **not** interoperable
/// with an F5.5 peer — the wrapper's request-scoped signature is load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRequest {
    /// The proposed checkpoint — the initiator's role slot signed, the other absent (F5.5).
    pub proposed: Checkpoint,
    /// The outer `PayTPv1-ckpt-req` signature over the wrapper (initiator key).
    pub sig: Option<[u8; 64]>,
}

impl CheckpointRequest {
    /// Wrap a proposed (half-signed) checkpoint for the initiator to sign the request.
    pub fn proposing(proposed: Checkpoint) -> CheckpointRequest {
        CheckpointRequest {
            proposed,
            sig: None,
        }
    }

    /// The wrapper's `COVERED` bytes for the outer `PayTPv1-ckpt-req` signature:
    /// `covered(CkptReq, encode({0x00 PROPOSED = <inner checkpoint bytes>}))`. The
    /// PROPOSED value is the inner checkpoint's COMPLETE canonical bytes (its own
    /// payer-slot signature included), so the outer signature binds the exact
    /// half-signed proposal. Canonical parse/encode round-trips (F1.1), so this
    /// reproduces byte-for-byte what the initiator signed.
    pub fn covered_bytes(&self) -> Result<Vec<u8>> {
        let proposed = Field::new(R_PROPOSED, false, self.proposed.encode()?);
        let obj = Object::from_fields(vec![proposed])?;
        Ok(covered(DomainLabel::CkptReq, &obj.encode()))
    }

    /// Sign the outer wrapper with the initiator (payer) key (`PayTPv1-ckpt-req`).
    pub fn sign(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(crate::crypto::ed25519_sign(
            payer_sk,
            &self.covered_bytes()?,
        ));
        Ok(())
    }

    /// Verify a received request under the payer key (F5.5): the inner proposal is a
    /// half-signed checkpoint (payer slot present, merchant **absent** — the responder
    /// is the one who countersigns), the outer `PayTPv1-ckpt-req` wrapper signature is
    /// valid, AND the inner `PayTPv1-ckpt` payer signature is valid. Both are the
    /// initiator's.
    pub fn verify(&self, payer_pk: &[u8; 32]) -> Result<()> {
        // A request carries only the initiator's half; a merchant slot here is illegal.
        if self.proposed.sig_merchant.is_some() {
            return Err(Error::InconsistentProposal);
        }
        let sig = self.sig.ok_or(Error::MissingField)?;
        crate::crypto::ed25519_verify_strict(payer_pk, &self.covered_bytes()?, &sig)?;
        // The inner PayTPv1-ckpt payer slot (the eventual bilateral half).
        self.proposed.verify_payer(payer_pk)
    }

    /// The complete canonical bytes (`0x00 PROPOSED`, then the outer `0x70 SIG`).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = vec![Field::new(R_PROPOSED, false, self.proposed.encode()?)];
        if let Some(sig) = self.sig {
            fields.push(Field::new(R_SIG, false, sig.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }

    /// Parse a `CHECKPOINT_REQUEST` (F5.5 schema; the inner PROPOSED as a checkpoint).
    pub fn parse(buf: &[u8]) -> Result<CheckpointRequest> {
        let obj = Object::parse(buf)?;
        obj.validate(&request_schema())?;
        let proposed = Checkpoint::parse(&obj.get(R_PROPOSED).ok_or(Error::MissingField)?.value)?;
        let sig = obj
            .get(R_SIG)
            .map(|f| f.value.clone().try_into().map_err(|_| Error::WrongWidth))
            .transpose()?;
        Ok(CheckpointRequest { proposed, sig })
    }
}

/// The cumulative state a **stillborn** channel carries through the chain (GAP-FILL
/// F6-e). A stillborn channel ends before signing any bilateral checkpoint of its own,
/// so it presents a *synthetic* checkpoint — constructed deterministically by both
/// parties (its authority is the signed `CHANNEL_AUTH`/`CHANNEL_ACK`) — as the final
/// checkpoint a further successor names. A stillborn accepts **no slices**, so its
/// metering (`cum_total`/`accruals`) equals its predecessor's imported cumulative; but it
/// **can be funded** (funding needs no checkpoint), so `funding_sum` is the predecessor's
/// `opening_funding` **plus** the stillborn's own accepted funding. `settled_sum`
/// (`Σ E`) and `net_legs_sum` pass through unchanged (a stillborn signs no settlement
/// round, which needs a `CKPT_REF`).
#[derive(Debug, Clone)]
pub struct StillbornState {
    /// This stillborn channel's own id (NOT the predecessor's).
    pub channel_id: [u8; 8],
    /// Prepay vs postpay — selects the `BALANCE` formula.
    pub prepay: bool,
    /// `CUM_TOTAL` = predecessor's final metered total (stillborn accepts no slices).
    pub cum_total: BigUint,
    /// `ACCRUALS` = predecessor's final per-role numerators (ascending role).
    pub accruals: Vec<(u8, BigUint)>,
    /// `Σ E` — cumulative settled extinguished numerators (opening_settled summed over
    /// roles). `floor(Σ E / 10 000)` is the DENOM value of *settled* meed.
    pub settled_sum: BigUint,
    /// `Σ(net legs)` — cumulative settled net legs (passes through unchanged).
    pub net_legs_sum: BigUint,
    /// `Σ(credited funding)` — predecessor `opening_funding` + the stillborn's own
    /// accepted funding.
    pub funding_sum: BigUint,
    /// The `CHANNEL_AUTH`'s timestamp (F6-e).
    pub timestamp: u64,
    /// The imported checkpoint's reference (all-zero for an unchained stillborn). A
    /// non-zero value makes this a *chained* stillborn: `EVENTS` then carries the single
    /// predecessor-import event naming it, and this is `PREV_REF`. All-zero = unchained.
    pub prev_ref: [u8; 32],
}

impl StillbornState {
    /// Construct the deterministic synthetic checkpoint (F6-e) — **no signatures**.
    /// `LAST_SEQ = 0`, `RANGES` empty, `TRANSCRIPT` = the stillborn's `head_0`,
    /// `EVENTS` = the import event or empty, `TIMESTAMP` = the auth's, `PREV_REF` = the
    /// imported reference. Its reference is `Checkpoint::synthetic_reference()`.
    pub fn synthetic_checkpoint(&self) -> Result<Checkpoint> {
        let (balance, balance_negative) = self.synthetic_balance()?;
        // EVENTS: exactly the single predecessor-import event (kind `0x03`, F5.5) naming
        // the imported checkpoint, for a chained stillborn (non-zero PREV_REF); empty for
        // an unchained one. Constructed deterministically — never caller-supplied — so two
        // conforming builders cannot diverge on the event bytes and fork the reference.
        let events = if self.prev_ref == [0u8; 32] {
            Vec::new()
        } else {
            vec![Event {
                kind: 0x03,
                reference: self.prev_ref.to_vec(),
            }]
        };
        Ok(Checkpoint {
            channel_id: self.channel_id,
            balance,
            balance_negative,
            cum_total: self.cum_total.clone(),
            accruals: self.accruals.clone(),
            last_seq: 0,
            ranges: Vec::new(),
            transcript: crate::transcript::head_0(&self.channel_id),
            events,
            timestamp: self.timestamp,
            prev_ref: self.prev_ref,
            sig_payer: None,
            sig_merchant: None,
        })
    }

    /// The canonical `BALANCE` integer both parties MUST agree on (it is hashed into
    /// the synthetic reference, so a divergence forks the chain). Postpay uses the
    /// **single canonical form** `CUM_TOTAL − Σ funding − Σ net legs − floor(Σ E /
    /// 10 000)` (signed — an over-funded position is legitimately negative); prepay uses
    /// `−(Σ funding − CUM_TOTAL)` = −(unconsumed deposit). NOT `floor((ΣACCRUALS−ΣE)/
    /// 10 000)`, which is a different integer (floor is non-distributive over subtraction).
    fn synthetic_balance(&self) -> Result<(BigUint, bool)> {
        if self.prepay {
            // −(Σ funding − CUM_TOTAL). Prepay consumption never exceeds the deposit
            // (F6.2 upper bound 0), so funding ≥ cum_total; a violation is inconsistent.
            if self.cum_total > self.funding_sum {
                return Err(Error::InconsistentProposal);
            }
            let mag = &self.funding_sum - &self.cum_total;
            let neg = mag != BigUint::from(0u8);
            Ok((mag, neg))
        } else {
            // Postpay, signed: floor(Σ E / 10 000) is the settled carve (F7.3).
            use num_bigint::{BigInt, Sign};
            let settled_carve = &self.settled_sum / 10_000u32; // BP_DENOM
            let bal: BigInt = BigInt::from(self.cum_total.clone())
                - BigInt::from(self.funding_sum.clone())
                - BigInt::from(self.net_legs_sum.clone())
                - BigInt::from(settled_carve);
            let neg = bal.sign() == Sign::Minus;
            Ok((bal.magnitude().clone(), neg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn sample() -> Checkpoint {
        Checkpoint {
            channel_id: [0, 0, 0, 0, 0, 0, 0, 1],
            balance: BigUint::from(500u32),
            balance_negative: false,
            cum_total: BigUint::from(40000u32),
            accruals: vec![
                (0x10, BigUint::from(20000u32)),
                (0x12, BigUint::from(12000u32)),
            ],
            last_seq: 42,
            ranges: vec![Range { lo: 1, hi: 42 }],
            transcript: crate::transcript::head_0(&[0, 0, 0, 0, 0, 0, 0, 1]),
            events: vec![Event {
                kind: 0x02,
                reference: vec![0xab; 32],
            }],
            timestamp: 1_700_000_000,
            prev_ref: [0u8; 32],
            sig_payer: None,
            sig_merchant: None,
        }
    }

    #[test]
    fn parse_rejects_unknown_event_kind() {
        // F5.5: EVENTS.kind outside {0x01,0x02,0x03} MUST be rejected at
        // parse — a signed checkpoint naming an undefined kind (0x09) does not parse.
        let (psk, msk) = ([1u8; 32], [2u8; 32]);
        let mut cp = sample();
        cp.events = vec![Event {
            kind: 0x09,
            reference: vec![0xcd; 32],
        }];
        cp.sign_payer(&psk).unwrap();
        cp.sign_merchant(&msk).unwrap();
        let bytes = cp.encode().unwrap();
        assert!(
            Checkpoint::parse(&bytes).is_err(),
            "an undefined EVENTS.kind must be rejected at parse"
        );
    }

    #[test]
    fn parse_rejects_timestamp_over_2_53_time_domain() {
        // F1-l: the checkpoint's TIMESTAMP (Unix seconds) is a time field,
        // capped at 2⁵³ − 1 — NOT the raw u64 range. A signed checkpoint with
        // TIMESTAMP = 2⁵³ (a valid u64 the old raw decode accepted) is rejected at parse.
        let (psk, msk) = ([1u8; 32], [2u8; 32]);
        let mut cp = sample();
        cp.timestamp = 1u64 << 53; // 2⁵³ — out of the F1-l time domain
        cp.sign_payer(&psk).unwrap();
        cp.sign_merchant(&msk).unwrap();
        assert!(
            Checkpoint::parse(&cp.encode().unwrap()).is_err(),
            "checkpoint TIMESTAMP = 2^53 must be rejected (F1-l)"
        );
        // The exact boundary 2⁵³ − 1 round-trips.
        let mut ok = sample();
        ok.timestamp = (1u64 << 53) - 1;
        ok.sign_payer(&psk).unwrap();
        ok.sign_merchant(&msk).unwrap();
        assert!(Checkpoint::parse(&ok.encode().unwrap()).is_ok());
    }

    #[test]
    fn sign_encode_parse_reference_roundtrip() {
        let (psk, msk) = ([1u8; 32], [2u8; 32]);
        let (ppk, mpk) = (crypto::ed25519_public(&psk), crypto::ed25519_public(&msk));
        let mut cp = sample();
        cp.sign_payer(&psk).unwrap();
        cp.sign_merchant(&msk).unwrap();
        cp.verify_bilateral(&ppk, &mpk).unwrap();
        let bytes = cp.encode().unwrap();
        let parsed = Checkpoint::parse(&bytes).unwrap();
        assert_eq!(parsed, cp);
        // Reference is over the complete bilateral bytes (both sigs).
        assert_eq!(parsed.reference().unwrap(), cp.reference().unwrap());
        // A single-signed proposal has no reference.
        let mut half = sample();
        half.sign_payer(&psk).unwrap();
        assert!(half.reference().is_err());
    }

    #[test]
    fn oversized_seq_range_rejected_not_overflow_panicked() {
        // RANGES carried no F1-e SEQ cap, so a range hi = u64::MAX reached the
        // non-adjacency check `w[0].hi + 1` → overflow panic — a pre-auth DoS, since
        // Checkpoint::parse runs before any signature check. hi > SEQ_MAX is now rejected
        // at parse, before the adjacency loop can overflow.
        let mut cp = sample();
        cp.ranges = vec![Range {
            lo: 0,
            hi: u64::MAX,
        }];
        assert!(Checkpoint::parse(&cp.encode().unwrap()).is_err());
        // The exact overflow trigger (a huge first range followed by a second) is now
        // rejected at the cap instead of computing u64::MAX + 1 in the adjacency loop.
        let mut cp2 = sample();
        cp2.ranges = vec![
            Range {
                lo: 0,
                hi: u64::MAX,
            },
            Range { lo: 5, hi: 10 },
        ];
        assert!(Checkpoint::parse(&cp2.encode().unwrap()).is_err()); // no panic
                                                                     // last_seq > SEQ_MAX is likewise rejected (closes the #10 root).
        let mut bad_seq = sample();
        bad_seq.last_seq = crate::slice::SEQ_MAX + 1;
        assert!(Checkpoint::parse(&bad_seq.encode().unwrap()).is_err());
    }

    #[test]
    fn negative_balance_roundtrips() {
        let mut cp = sample();
        cp.balance = BigUint::from(300u32);
        cp.balance_negative = true; // −300 (a prepay deposit position)
        cp.sign_payer(&[1u8; 32]).unwrap();
        cp.sign_merchant(&[2u8; 32]).unwrap();
        let parsed = Checkpoint::parse(&cp.encode().unwrap()).unwrap();
        assert!(parsed.balance_negative);
        assert_eq!(parsed.balance, BigUint::from(300u32));
    }

    // --- Stillborn synthetic checkpoint (F6-e) ---

    fn stillborn(prepay: bool) -> StillbornState {
        StillbornState {
            channel_id: [0, 0, 0, 0, 0, 0, 0, 11],
            prepay,
            cum_total: BigUint::from(40000u32),
            accruals: vec![
                (0x10, BigUint::from(25000u32)),
                (0x12, BigUint::from(15000u32)),
            ],
            settled_sum: BigUint::from(33333u32), // ΣE → settled carve floor(33333/10000)=3
            net_legs_sum: BigUint::from(10000u32),
            funding_sum: BigUint::from(5000u32),
            timestamp: 1_700_000_000,
            prev_ref: [0x99; 32],
        }
    }

    #[test]
    fn stillborn_postpay_balance_and_metering_passthrough() {
        let s = stillborn(false);
        let cp = s.synthetic_checkpoint().unwrap();
        // F6-e postpay BALANCE = CUM_TOTAL − Σfunding − Σnet − floor(ΣE/10000)
        //                      = 40000 − 5000 − 10000 − 3 = 24997 (positive).
        // (Non-distributive: settled carve is floor(33333/10000)=3, NOT floor((40000−33333)/10000)=0.)
        assert!(!cp.balance_negative);
        assert_eq!(cp.balance, BigUint::from(24997u32));
        // Metering passes through unchanged (a stillborn accepts no slices).
        assert_eq!(cp.cum_total, s.cum_total);
        assert_eq!(cp.accruals, s.accruals);
        // The synthetic shape: no slices, no sigs, anchored to the import.
        assert_eq!(cp.last_seq, 0);
        assert!(cp.ranges.is_empty());
        assert_eq!(cp.transcript, crate::transcript::head_0(&s.channel_id));
        assert_eq!(cp.prev_ref, s.prev_ref);
        assert_eq!(cp.timestamp, s.timestamp);
        assert!(cp.sig_payer.is_none() && cp.sig_merchant.is_none());
        // EVENTS: the single predecessor-import event (kind 0x03, F5.5) naming the import.
        assert_eq!(
            cp.events,
            vec![Event {
                kind: 0x03,
                reference: s.prev_ref.to_vec()
            }]
        );
    }

    #[test]
    fn stillborn_unchained_has_empty_events_and_zero_prev_ref() {
        // An UNCHAINED stillborn (all-zero PREV_REF) carries empty EVENTS (F6-e).
        let mut s = stillborn(false);
        s.prev_ref = [0u8; 32];
        let cp = s.synthetic_checkpoint().unwrap();
        assert!(cp.events.is_empty());
        assert_eq!(cp.prev_ref, [0u8; 32]);
    }

    #[test]
    fn stillborn_postpay_overfunded_balance_is_negative() {
        let mut s = stillborn(false);
        s.cum_total = BigUint::from(1000u32);
        s.funding_sum = BigUint::from(5000u32);
        s.net_legs_sum = BigUint::from(0u32);
        s.settled_sum = BigUint::from(0u32);
        let cp = s.synthetic_checkpoint().unwrap();
        // 1000 − 5000 = −4000.
        assert!(cp.balance_negative);
        assert_eq!(cp.balance, BigUint::from(4000u32));
    }

    #[test]
    fn stillborn_prepay_balance_is_negative_unconsumed_deposit() {
        let mut s = stillborn(true);
        s.cum_total = BigUint::from(30000u32);
        s.funding_sum = BigUint::from(50000u32);
        let cp = s.synthetic_checkpoint().unwrap();
        // −(Σfunding − CUM_TOTAL) = −(50000 − 30000) = −20000.
        assert!(cp.balance_negative);
        assert_eq!(cp.balance, BigUint::from(20000u32));
        // A fully-consumed prepay deposit reads as 0 (not negative).
        s.cum_total = s.funding_sum.clone();
        let z = s.synthetic_checkpoint().unwrap();
        assert!(!z.balance_negative && z.balance == BigUint::from(0u32));
    }

    #[test]
    fn stillborn_prepay_overconsume_rejected() {
        let mut s = stillborn(true);
        s.cum_total = BigUint::from(50000u32); // consumption > deposit — impossible under F6.2
        s.funding_sum = BigUint::from(30000u32);
        assert!(s.synthetic_checkpoint().is_err());
    }

    #[test]
    fn stillborn_reference_is_deterministic_unsigned_and_never_collides() {
        let s = stillborn(false);
        let cp = s.synthetic_checkpoint().unwrap();
        // Deterministic: both parties construct byte-identical bytes → identical reference.
        let again = s.synthetic_checkpoint().unwrap();
        assert_eq!(cp.encode().unwrap(), again.encode().unwrap());
        assert_eq!(
            cp.synthetic_reference().unwrap(),
            again.synthetic_reference().unwrap()
        );
        // A real bilateral checkpoint over the SAME content hashes different bytes (its
        // bytes carry both signature TLVs), so a stillborn reference can never collide
        // with a real one (F6-e).
        let mut real = cp.clone();
        real.sign_payer(&[1u8; 32]).unwrap();
        real.sign_merchant(&[2u8; 32]).unwrap();
        assert_ne!(cp.synthetic_reference().unwrap(), real.reference().unwrap());
        // synthetic_reference only names an UNSIGNED instance; reference() only a signed one.
        assert!(real.synthetic_reference().is_err());
        assert!(cp.reference().is_err());
    }

    #[test]
    fn stillborn_funding_passthrough_accumulates() {
        // A stillborn's cumulative funding = predecessor opening_funding + its own accepted
        // funding; a further successor imports that exact sum (F6-e funded-stillborn).
        let opening_funding = BigUint::from(5000u32);
        let own_funding = BigUint::from(2000u32);
        let mut s = stillborn(false);
        s.funding_sum = &opening_funding + &own_funding; // 7000 passes through
        let cp = s.synthetic_checkpoint().unwrap();
        // BALANCE reflects the accumulated funding: 40000 − 7000 − 10000 − 3 = 22997.
        assert_eq!(cp.balance, BigUint::from(22997u32));
        assert!(!cp.balance_negative);
    }

    #[test]
    fn accrual_over_domain_rejected() {
        // M1: a checkpoint naming an accrual ≥ 2^128 is rejected (F7-a).
        let mut cp = sample();
        cp.accruals = vec![(0x10, BigUint::from(1u8) << 128u32)];
        cp.sign_payer(&[1u8; 32]).unwrap();
        cp.sign_merchant(&[2u8; 32]).unwrap();
        assert!(Checkpoint::parse(&cp.encode().unwrap()).is_err());
    }

    #[test]
    fn unknown_field_rejected_closed_object() {
        // A byte-extended checkpoint (unknown field 0x0A) is rejected at parse,
        // so verify/reference can never operate on a sanitized object.
        let mut cp = sample();
        cp.sign_payer(&[1u8; 32]).unwrap();
        cp.sign_merchant(&[2u8; 32]).unwrap();
        let bytes = cp.encode().unwrap();
        // Rebuild the object with an extra unknown non-critical field 0x0A.
        let obj = Object::parse(&bytes).unwrap();
        let mut fields = obj.fields().to_vec();
        fields.push(Field::new(0x0A, false, vec![0xff]));
        let extended = Object::from_fields(fields).unwrap().encode();
        assert!(Checkpoint::parse(&extended).is_err());
    }

    #[test]
    fn tamper_breaks_bilateral_verify() {
        let (psk, msk) = ([1u8; 32], [2u8; 32]);
        let (ppk, mpk) = (crypto::ed25519_public(&psk), crypto::ed25519_public(&msk));
        let mut cp = sample();
        cp.sign_payer(&psk).unwrap();
        cp.sign_merchant(&msk).unwrap();
        cp.cum_total = BigUint::from(99999u32); // tamper after signing
        assert!(cp.verify_bilateral(&ppk, &mpk).is_err());
    }

    // --- CHECKPOINT_REQUEST (F5.5) ---

    fn half_signed(psk: &[u8; 32]) -> Checkpoint {
        let mut cp = sample();
        cp.sign_payer(psk).unwrap(); // initiator's role slot only (merchant absent)
        cp
    }

    #[test]
    fn checkpoint_request_roundtrip_and_verify() {
        // F5.5: the wrapped request round-trips and verifies both the outer
        // PayTPv1-ckpt-req wrapper signature and the inner PayTPv1-ckpt payer signature.
        let psk = [1u8; 32];
        let ppk = crypto::ed25519_public(&psk);
        let mut req = CheckpointRequest::proposing(half_signed(&psk));
        req.sign(&psk).unwrap();
        let bytes = req.encode().unwrap();
        let parsed = CheckpointRequest::parse(&bytes).unwrap();
        assert_eq!(parsed, req);
        parsed.verify(&ppk).unwrap();
        // The inner proposal is recoverable and is a half-signed checkpoint the merchant
        // completes into ONE bilateral object (its reference is not yet derivable).
        assert!(parsed.proposed.sig_payer.is_some());
        assert!(parsed.proposed.sig_merchant.is_none());
        assert!(parsed.proposed.reference().is_err());
    }

    #[test]
    fn checkpoint_request_rejects_bare_checkpoint_form() {
        // The pre-fix wire form was a BARE `0x03 ‖ <half-signed checkpoint>`
        // with no wrapper. Parsing those bytes as an F5.5 request fails — the bare
        // checkpoint's extra fields (BALANCE, CUM_TOTAL, …) are not the request schema's
        // {0x00 PROPOSED, 0x70 SIG}. So an F5.5 peer rejects the bare form (and vice versa)
        // — the interop split the fix closes.
        let bare = half_signed(&[1u8; 32]).encode().unwrap();
        assert!(CheckpointRequest::parse(&bare).is_err());
    }

    #[test]
    fn checkpoint_request_verify_rejects_tamper_and_missing_outer_sig() {
        let psk = [1u8; 32];
        let ppk = crypto::ed25519_public(&psk);
        // Missing outer wrapper signature → rejected.
        let unsigned = CheckpointRequest::proposing(half_signed(&psk));
        assert!(unsigned.verify(&ppk).is_err());
        // Tampering the inner proposal after the outer signature breaks the outer sig
        // (the wrapper binds the exact inner bytes).
        let mut req = CheckpointRequest::proposing(half_signed(&psk));
        req.sign(&psk).unwrap();
        req.proposed.cum_total = BigUint::from(99_999u32);
        assert!(req.verify(&ppk).is_err());
    }

    #[test]
    fn checkpoint_request_rejects_merchant_slot_in_proposal() {
        // F5.5: the inner proposal is HALF-signed — the responder countersigns. A request
        // whose inner proposal already carries a merchant slot is rejected.
        let (psk, msk) = ([1u8; 32], [2u8; 32]);
        let ppk = crypto::ed25519_public(&psk);
        let mut cp = sample();
        cp.sign_payer(&psk).unwrap();
        cp.sign_merchant(&msk).unwrap(); // illegal in a request
        let mut req = CheckpointRequest::proposing(cp);
        req.sign(&psk).unwrap();
        assert!(req.verify(&ppk).is_err());
    }

    #[test]
    fn checkpoint_request_outer_sig_is_domain_separated_from_ckpt() {
        // F1.3/F1-h: the outer slot MUST carry a `PayTPv1-ckpt-req` signature, NOT a
        // `PayTPv1-ckpt` one. Placing the inner checkpoint's own (valid) `PayTPv1-ckpt`
        // payer signature into the outer slot fails verification — the two labels are
        // domain-separated, so a checkpoint signature never doubles as a request signature.
        let psk = [1u8; 32];
        let ppk = crypto::ed25519_public(&psk);
        let proposed = half_signed(&psk);
        let ckpt_sig = proposed.sig_payer.unwrap(); // a valid PayTPv1-ckpt signature
        let req = CheckpointRequest {
            proposed,
            sig: Some(ckpt_sig), // wrong domain in the outer slot
        };
        assert!(req.verify(&ppk).is_err());
    }
}
