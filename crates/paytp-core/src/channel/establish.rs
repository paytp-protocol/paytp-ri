//! Channel-establishment wire objects (**F2.2 / F5.2–F5.4**) — the binding
//! artifact, `CHANNEL_AUTH`/`CHANNEL_OPEN`, `CHANNEL_ACK`, `ACK_REQUEST`, and
//! `FUNDING_PROOF`.
//!
//! **Transport-independent binding (Change A):** the `K_session` salt
//! is the public digest `BindSalt = SHA-256(payer_key ‖ merchant_key)`
//! ([`crypto::bind_salt`]), not a TLS exporter. `CHANNEL_AUTH` field `0x11` (the
//! former `CONN_BINDING`) is **RESERVED-UNUSED** — never emitted; its presence is
//! a malformed object (rejected at parse). Merchant authenticity (the artifact +
//! the `CHANNEL_AUTH` signature) and `s` confidentiality (the single-shot HPKE
//! seal) carry the security; the F5-m replay-suppression rule replaces the
//! exporter's former structural replay bar (see `paytp-merchant`).

use crate::consts::SKEW_SECS;
use crate::crypto::{ed25519_sign, ed25519_verify_strict, sha256};
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::pointer::{is_asset_id, is_caip2, is_rail_id, Pointer};
use crate::registry::SnapshotStore;
use crate::tlv::{self, Field, Object, Openness, Schema};

/// A received host MUST already be the F2.4 normalized form — an IDNA A-label,
/// ASCII, lowercase — and is **rejected, never repaired** (F1.1 rule 5 / F2.4
/// rule 1). This routes through the ONE shared normalizer
/// ([`paytp_host::validate_normalized_host`]) — the SAME function the wallet's
/// payer-key scope resolves the registrable domain through — so the full UTS#46
/// (non-transitional) + STD3 + Punycode + bidi/joiner label rules are enforced here,
/// never a lowercase-only byte check that would diverge from the scope resolver.
/// F1-g (`validate_text`: NFC, no BOM/control) is kept first as defense-in-depth on
/// the stored text.
fn validate_host_normalized(host: &str) -> Result<()> {
    tlv::validate_text(host.as_bytes())?;
    paytp_host::validate_normalized_host(host).map_err(|_| Error::FieldDomain)
}

// --- Binding artifact (F2.2) ---

const A_HOST: u8 = 0x00;
const A_CERT_HASH: u8 = 0x01;
const A_ENC_KEY: u8 = 0x02;
const A_NOT_BEFORE: u8 = 0x03;
const A_NOT_AFTER: u8 = 0x04;
const A_SIG: u8 = 0x70;

/// The merchant binding artifact (F2.2): binds the origin host + the TLS leaf
/// certificate the client verified + the merchant's channel-encryption key, signed
/// by the merchant key under `PayTPv1-artifact`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingArtifact {
    pub host: String,
    pub cert_hash: [u8; 32],
    pub enc_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub sig: Option<[u8; 64]>,
}

fn artifact_schema() -> Schema {
    Schema::new(
        Openness::Closed,
        &[
            (A_HOST, false),
            (A_CERT_HASH, false),
            (A_ENC_KEY, false),
            (A_NOT_BEFORE, false),
            (A_NOT_AFTER, false),
            (A_SIG, false),
        ],
    )
}

impl BindingArtifact {
    fn content_fields(&self) -> Result<Vec<Field>> {
        validate_host_normalized(&self.host)?;
        Ok(vec![
            Field::new(A_HOST, false, self.host.as_bytes().to_vec()),
            Field::new(A_CERT_HASH, false, self.cert_hash.to_vec()),
            Field::new(A_ENC_KEY, false, self.enc_key.to_vec()),
            Field::new(
                A_NOT_BEFORE,
                false,
                tlv::encode_uint_u128(self.not_before as u128),
            ),
            Field::new(
                A_NOT_AFTER,
                false,
                tlv::encode_uint_u128(self.not_after as u128),
            ),
        ])
    }

    fn covered_bytes(&self) -> Result<Vec<u8>> {
        let obj = Object::from_fields(self.content_fields()?)?;
        Ok(covered(DomainLabel::Artifact, &obj.encode()))
    }

    pub fn sign(&mut self, merchant_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(merchant_sk, &self.covered_bytes()?));
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig {
            fields.push(Field::new(A_SIG, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }

    pub fn parse(buf: &[u8]) -> Result<BindingArtifact> {
        let obj = Object::parse(buf)?;
        obj.validate(&artifact_schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let host =
            String::from_utf8(get(A_HOST)?.value.clone()).map_err(|_| Error::TextControlChar)?;
        validate_host_normalized(&host)?;
        Ok(BindingArtifact {
            host,
            cert_hash: fixed32(&get(A_CERT_HASH)?.value)?,
            enc_key: fixed32(&get(A_ENC_KEY)?.value)?,
            not_before: tlv::decode_uint_time(&get(A_NOT_BEFORE)?.value)?, // F1-l ≤ 2⁵³−1
            not_after: tlv::decode_uint_time(&get(A_NOT_AFTER)?.value)?,   // F1-l ≤ 2⁵³−1
            sig: obj.get(A_SIG).map(|f| fixed64(&f.value)).transpose()?,
        })
    }

    /// Accept this artifact for an establishing connection (F2.2 fetch/acceptance):
    /// it verifies under `merchant_key`, is **current** at `now` within the F8.2
    /// skew allowance (`NOT_BEFORE − SKEW ≤ now ≤ NOT_AFTER + SKEW`), its
    /// `CERT_HASH` equals the connection's verified leaf cert, and its `HOST`
    /// equals the host the client verified (already F2.4-normalized). Returns the
    /// [`AcceptedBinding`] — the authenticated `(merchant_key, host, enc_key)` triple —
    /// which a wallet MUST use as the ONLY source of those channel-open inputs (so the
    /// payer-key scope host, F1-f, and the sealing key, F2.5, can never be IL-supplied).
    pub fn accept(
        &self,
        merchant_key: &[u8; 32],
        conn_cert_hash: &[u8; 32],
        conn_host: &str,
        now: u64,
    ) -> Result<AcceptedBinding> {
        let sig = self.sig.ok_or(Error::MissingField)?;
        ed25519_verify_strict(merchant_key, &self.covered_bytes()?, &sig)?;
        // Current iff NOT_BEFORE − SKEW ≤ now ≤ NOT_AFTER + SKEW (F8.2), written to
        // avoid unsigned underflow at the window edges.
        if now.saturating_add(SKEW_SECS) < self.not_before
            || now > self.not_after.saturating_add(SKEW_SECS)
        {
            return Err(Error::FieldDomain); // not current
        }
        if &self.cert_hash != conn_cert_hash {
            return Err(Error::BadSignature); // wrong establishing-connection cert
        }
        if self.host != conn_host {
            return Err(Error::BadSignature); // wrong origin host (F2-h)
        }
        Ok(AcceptedBinding {
            merchant_key: *merchant_key,
            host: self.host.clone(),
            enc_key: self.enc_key,
        })
    }
}

/// **Proof that a merchant binding artifact was ACCEPTED** (F2.2): its signature verified
/// under `merchant_key`, its `CERT_HASH` matched the connection's verified leaf cert, and
/// its `HOST` matched the host the client verified — so the `(merchant_key, host, enc_key)`
/// triple is the AUTHENTICATED one. Only [`BindingArtifact::accept`] constructs this (the
/// fields are private), so a channel-open API that takes an `AcceptedBinding` is guaranteed
/// its merchant host (the payer-key scope, F1-f/F2.3) and channel-sealing key (F2.5) are the
/// verified ones — never fabricated by an untrusted interaction layer. This is the structural
/// closure of the finding (a caller supplying an unverified `enc_key` could
/// otherwise reseal the session secret to an attacker key, compromising `k_session`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBinding {
    merchant_key: [u8; 32],
    host: String,
    enc_key: [u8; 32],
}

impl AcceptedBinding {
    /// The authenticated merchant identity key.
    pub fn merchant_key(&self) -> &[u8; 32] {
        &self.merchant_key
    }
    /// The authenticated, F2.4-normalized origin host (the payer-key scope input).
    pub fn host(&self) -> &str {
        &self.host
    }
    /// The authenticated channel-sealing key (F2.5).
    pub fn enc_key(&self) -> &[u8; 32] {
        &self.enc_key
    }

    /// **Test-only** constructor — fabricates an "accepted" binding WITHOUT artifact
    /// verification, for tests/demos exercising the channel-open path that do not stand up
    /// a full signed artifact + TLS cert. Feature-gated (`test-helpers`) + `#[doc(hidden)]`
    /// so a production build CANNOT forge acceptance — production MUST use
    /// [`BindingArtifact::accept`].
    #[cfg(any(test, feature = "test-helpers"))]
    #[doc(hidden)]
    pub fn for_test(merchant_key: [u8; 32], host: impl Into<String>, enc_key: [u8; 32]) -> Self {
        AcceptedBinding {
            merchant_key,
            host: host.into(),
            enc_key,
        }
    }
}

// --- CHANNEL_AUTH (F5.2) ---

const C_PAYER_KEY: u8 = 0x00;
const C_CHANNEL_ID: u8 = 0x01;
const C_MERCHANT_KEY: u8 = 0x02;
const C_DENOM: u8 = 0x03;
const C_MODE: u8 = 0x04;
const C_LIMIT_L: u8 = 0x05;
const C_LIMIT_E: u8 = 0x06;
const C_TH_VALUE: u8 = 0x07;
const C_TH_TIME: u8 = 0x08;
const C_REFUND_PTR: u8 = 0x09;
const C_BASELINE_NET: u8 = 0x0A;
const C_RATE_SOURCE: u8 = 0x0B;
const C_RATE_DEV: u8 = 0x0C;
const C_SCHEMA: u8 = 0x0D;
const C_VECTOR: u8 = 0x0E;
const C_REGISTRY_V: u8 = 0x0F;
const C_HS: u8 = 0x10;
// 0x11 CONN_BINDING — RESERVED-UNUSED (F1.6); never listed → parse rejects it.
const C_PREDECESSOR: u8 = 0x12;
const C_TIMESTAMP: u8 = 0x13;
const C_BASELINE_ASSET: u8 = 0x14;
const C_CONTRACT: u8 = 0x15;
const C_FIN_MEED: u8 = 0x16;
const C_FIN_DENOM: u8 = 0x17;
const C_SIG: u8 = 0x70;

pub const MODE_PREPAY: u8 = 0x00;
pub const MODE_POSTPAY: u8 = 0x01;

/// One canonical meed-vector entry (F4-b): `role ‖ bp ‖ len ‖ dest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorEntry {
    pub role: u8,
    pub bp: u16,
    pub dest: String,
}

/// `CHANNEL_AUTH` (F5.2) — the payer-signed channel terms. Presence rules
/// (enforced on build + parse): `REFUND_PTR` iff prepay; `RATE_SOURCE`/`RATE_DEV`
/// iff `DENOM ≠ BASELINE_ASSET`; `PREDECESSOR` optional; `0x11` never.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAuth {
    pub payer_key: [u8; 32],
    pub channel_id: [u8; 8],
    pub merchant_key: [u8; 32],
    pub denom: String,
    pub mode: u8,
    pub limit_l: u128,
    pub limit_e: u128,
    pub th_value: u128,
    pub th_time: u64,
    pub refund_ptr: Option<String>,
    pub baseline_net: String,
    pub rate_source: Option<String>,
    pub rate_dev: Option<u128>,
    pub schema: u32,
    pub vector: Vec<VectorEntry>,
    pub registry_v: u32,
    pub hs: [u8; 32],
    pub predecessor: Option<([u8; 8], [u8; 32])>,
    pub timestamp: u64,
    pub baseline_asset: String,
    pub contract: u32,
    pub fin_meed: String,
    pub fin_denom: String,
    pub sig: Option<[u8; 64]>,
}

fn auth_schema() -> Schema {
    // Closed; 0x11 deliberately ABSENT so its presence is rejected (F1.6).
    Schema::new(
        Openness::Closed,
        &[
            (C_PAYER_KEY, false),
            (C_CHANNEL_ID, false),
            (C_MERCHANT_KEY, false),
            (C_DENOM, false),
            (C_MODE, false),
            (C_LIMIT_L, false),
            (C_LIMIT_E, false),
            (C_TH_VALUE, false),
            (C_TH_TIME, false),
            (C_REFUND_PTR, false),
            (C_BASELINE_NET, false),
            (C_RATE_SOURCE, false),
            (C_RATE_DEV, false),
            (C_SCHEMA, false),
            (C_VECTOR, false),
            (C_REGISTRY_V, false),
            (C_HS, false),
            (C_PREDECESSOR, false),
            (C_TIMESTAMP, false),
            (C_BASELINE_ASSET, false),
            (C_CONTRACT, false),
            (C_FIN_MEED, false),
            (C_FIN_DENOM, false),
            (C_SIG, false),
        ],
    )
}

impl ChannelAuth {
    fn vector_value(&self) -> Vec<u8> {
        let items: Vec<Vec<u8>> = self
            .vector
            .iter()
            .map(|e| {
                let mut it = vec![e.role];
                it.extend_from_slice(&e.bp.to_be_bytes());
                let d = e.dest.as_bytes();
                crate::leb128::encode_into(d.len() as u64, &mut it);
                it.extend_from_slice(d);
                it
            })
            .collect();
        tlv::build_count_prefixed(&items)
    }

    /// Validate presence rules (F5.2/F5-d/F5-b). Enforced on build and parse.
    fn check_presence(&self) -> Result<()> {
        // CHANNEL_ID is 64-bit random, non-zero (F5.2) — enforced on both emit and
        // parse; the all-zero id is malformed.
        if self.channel_id == [0u8; 8] {
            return Err(Error::FieldDomain);
        }
        match self.mode {
            MODE_PREPAY => {
                if self.refund_ptr.is_none() {
                    return Err(Error::MissingField); // REFUND_PTR required in prepay
                }
            }
            MODE_POSTPAY => {
                if self.refund_ptr.is_some() {
                    return Err(Error::FieldDomain); // no REFUND_PTR in postpay
                }
            }
            _ => return Err(Error::FieldDomain),
        }
        let needs_rate = self.denom != self.baseline_asset;
        if self.rate_source.is_some() != needs_rate || self.rate_dev.is_some() != needs_rate {
            return Err(Error::FieldDomain); // RATE_SOURCE/RATE_DEV iff DENOM ≠ BASELINE_ASSET
        }
        Ok(())
    }

    /// Validate the CAIP/pointer grammar of the identifier fields (F5.2/F5.3/F9),
    /// enforced on **both** emit and parse so a conformance artifact neither emits nor
    /// accepts a non-conformant channel term. `F1-g` text validity is a separate,
    /// earlier check (`validate_text` on every string field); this adds the *structure*:
    /// `DENOM` a CAIP asset id or the F9.1 adapter form; `BASELINE_ASSET` a CAIP asset id
    /// (never adapter — the baseline is always a contract-capable CAIP rail, F5.2);
    /// `BASELINE_NET` a CAIP-2 chain id; `REFUND_PTR` (prepay) an F9.1 destination pointer.
    /// (`RATE_SOURCE` is a registry rate-source identifier, validated by its own grammar
    /// where it is resolved, not here.)
    fn validate_grammar(&self) -> Result<()> {
        if !is_asset_id(&self.denom, true) {
            return Err(Error::FieldDomain); // DENOM: CAIP-19 asset or F9.1 adapter
        }
        if !is_asset_id(&self.baseline_asset, false) {
            return Err(Error::FieldDomain); // BASELINE_ASSET: CAIP-19 asset (never adapter)
        }
        if !is_caip2(&self.baseline_net) {
            return Err(Error::FieldDomain); // BASELINE_NET: CAIP-2 chain id
        }
        if let Some(rp) = &self.refund_ptr {
            Pointer::parse(rp)?; // REFUND_PTR: F9.1 destination pointer
        }
        Ok(())
    }

    /// The content fields (all but `SIG`), in ascending type order.
    fn content_fields(&self) -> Result<Vec<Field>> {
        self.check_presence()?;
        self.validate_grammar()?;
        let mut f = vec![
            Field::new(C_PAYER_KEY, false, self.payer_key.to_vec()),
            Field::new(C_CHANNEL_ID, false, self.channel_id.to_vec()),
            Field::new(C_MERCHANT_KEY, false, self.merchant_key.to_vec()),
            Field::new(C_DENOM, false, self.denom.as_bytes().to_vec()),
            Field::new(C_MODE, false, vec![self.mode]),
            Field::new(C_LIMIT_L, false, tlv::encode_uint_u128(self.limit_l)),
            Field::new(C_LIMIT_E, false, tlv::encode_uint_u128(self.limit_e)),
            Field::new(C_TH_VALUE, false, tlv::encode_uint_u128(self.th_value)),
            Field::new(
                C_TH_TIME,
                false,
                tlv::encode_uint_u128(self.th_time as u128),
            ),
        ];
        if let Some(rp) = &self.refund_ptr {
            f.push(Field::new(C_REFUND_PTR, false, rp.as_bytes().to_vec()));
        }
        f.push(Field::new(
            C_BASELINE_NET,
            false,
            self.baseline_net.as_bytes().to_vec(),
        ));
        if let Some(rs) = &self.rate_source {
            f.push(Field::new(C_RATE_SOURCE, false, rs.as_bytes().to_vec()));
        }
        if let Some(rd) = self.rate_dev {
            f.push(Field::new(C_RATE_DEV, false, tlv::encode_uint_u128(rd)));
        }
        f.push(Field::new(
            C_SCHEMA,
            false,
            tlv::encode_uint_u128(self.schema as u128),
        ));
        f.push(Field::new(C_VECTOR, false, self.vector_value()));
        f.push(Field::new(
            C_REGISTRY_V,
            false,
            tlv::encode_uint_u128(self.registry_v as u128),
        ));
        f.push(Field::new(C_HS, false, self.hs.to_vec()));
        if let Some((prev_id, prev_ref)) = &self.predecessor {
            let mut v = prev_id.to_vec();
            v.extend_from_slice(prev_ref);
            f.push(Field::new(C_PREDECESSOR, false, v));
        }
        f.push(Field::new(
            C_TIMESTAMP,
            false,
            tlv::encode_uint_u128(self.timestamp as u128),
        ));
        f.push(Field::new(
            C_BASELINE_ASSET,
            false,
            self.baseline_asset.as_bytes().to_vec(),
        ));
        f.push(Field::new(
            C_CONTRACT,
            false,
            tlv::encode_uint_u128(self.contract as u128),
        ));
        f.push(Field::new(
            C_FIN_MEED,
            false,
            self.fin_meed.as_bytes().to_vec(),
        ));
        f.push(Field::new(
            C_FIN_DENOM,
            false,
            self.fin_denom.as_bytes().to_vec(),
        ));
        Ok(f)
    }

    /// The canonical content bytes (no label, no sig) — the seal `aad` (F2.5).
    pub fn canonical_content(&self) -> Result<Vec<u8>> {
        Ok(Object::from_fields(self.content_fields()?)?.encode())
    }

    /// The `COVERED` bytes the payer signs (`PayTPv1-chan-auth`).
    pub fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(DomainLabel::ChanAuth, &self.canonical_content()?))
    }

    pub fn sign(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(payer_sk, &self.covered_bytes()?));
        Ok(())
    }

    /// Verify the payer signature (`0x70` under `PayTPv1-chan-auth`).
    pub fn verify(&self) -> Result<()> {
        let sig = self.sig.ok_or(Error::MissingField)?;
        ed25519_verify_strict(&self.payer_key, &self.covered_bytes()?, &sig)
    }

    /// Validate the `CHANNEL_AUTH` meed vector against schema `0x01` **and governed destination
    /// correctness** (**F5-o**, formalizing §5.4/F3.2/F4-b) — the same governed check the Tier-0
    /// quote applies. A channel MUST NOT open with a vector that understates, reorders, or
    /// **misroutes** the protocol meed: shape (roles/order/bp/total/CAIP,
    /// [`crate::tier0::quote::validate_shape_schema_01`]) AND destination correctness
    /// ([`crate::tier0::quote::validate_governed_destinations`]: `0x13` == the schema-pinned
    /// Dev-Fund constant, `0x11` registry-listed-or-independent-fund against the auth's own named
    /// `registry_v` version). The payer signs it and the merchant re-checks it at open — so the
    /// interaction layer cannot **redirect** the OS / Dev-Fund shares to an attacker (the prior
    /// shape-only check caught a *stripped* share but not a *misrouted* one). The caller MUST
    /// supply its registry `snapshot` store; `0x10`/`0x12` keep pointer freedom (F5-o).
    pub fn validate_vector_governed(&self, registry: &SnapshotStore) -> Result<()> {
        crate::tier0::quote::validate_shape_schema_01(
            self.schema,
            self.vector.iter().map(|v| (v.role, v.bp, v.dest.as_str())),
        )?;
        crate::tier0::quote::validate_governed_destinations(
            self.registry_v,
            self.vector.iter().map(|v| (v.role, v.dest.as_str())),
            registry,
        )
    }

    /// Payer-side self-defense for this `CHANNEL_AUTH`'s meed vector (**F5-o / F9.4
    /// step 3**): validate the pointer-free `0x10`/`0x12` shares against the asserting
    /// parties' OWN expected pointers. The interaction layer assembles this vector, so
    /// a hostile IL that reroutes the wallet's `0x12` share to itself is caught here
    /// **before the payer signs** `CHANNEL_AUTH`. The caller passes
    /// [`ExpectedDest::Unchecked`] for a role it does not own (the wallet leaves `0x10`
    /// unchecked — an IL rerouting its OWN share is not payer/wallet loss).
    pub fn validate_payer_side(
        &self,
        il: crate::tier0::quote::ExpectedDest,
        wallet: crate::tier0::quote::ExpectedDest,
    ) -> Result<()> {
        crate::tier0::quote::validate_payer_side_destinations(
            self.vector.iter().map(|v| (v.role, v.dest.as_str())),
            il,
            wallet,
        )
    }

    /// `AUTH_HASH = SHA-256(COVERED(CHANNEL_AUTH))` (F5.3/F5-e).
    pub fn auth_hash(&self) -> Result<[u8; 32]> {
        Ok(sha256(&self.covered_bytes()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig {
            fields.push(Field::new(C_SIG, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }

    pub fn parse(buf: &[u8]) -> Result<ChannelAuth> {
        let obj = Object::parse(buf)?;
        // The closed schema rejects the reserved 0x11 (and any unknown field).
        obj.validate(&auth_schema())?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        // Every text field is UTF-8 AND F1-g strict (NFC, no BOM, no control chars) —
        // enforced on receipt so a signed object cannot smuggle control/escape bytes
        // into DENOM/BASELINE_*/RATE_SOURCE/REFUND_PTR (log/store injection).
        let txt = |t: u8| -> Result<String> {
            let s = String::from_utf8(get(t)?.value.clone()).map_err(|_| Error::TextControlChar)?;
            tlv::validate_text(s.as_bytes())?;
            Ok(s)
        };
        let opt_txt = |t: u8| -> Result<Option<String>> {
            obj.get(t)
                .map(|f| -> Result<String> {
                    let s =
                        String::from_utf8(f.value.clone()).map_err(|_| Error::TextControlChar)?;
                    tlv::validate_text(s.as_bytes())?;
                    Ok(s)
                })
                .transpose()
        };
        let mode = {
            let v = &get(C_MODE)?.value;
            if v.len() != 1 {
                return Err(Error::WrongWidth);
            }
            v[0]
        };
        let vector = tlv::parse_count_prefixed(&get(C_VECTOR)?.value, |b| {
            if b.len() < 3 {
                return Err(Error::CountMismatch);
            }
            let role = b[0];
            let bp = u16::from_be_bytes([b[1], b[2]]);
            let (len, n) = crate::leb128::decode(&b[3..])?;
            let s = 3 + n;
            let e = s.checked_add(len as usize).ok_or(Error::LengthOverrun)?;
            if e > b.len() {
                return Err(Error::LengthOverrun);
            }
            let dest = String::from_utf8(b[s..e].to_vec()).map_err(|_| Error::TextControlChar)?;
            tlv::validate_text(dest.as_bytes())?;
            Ok((VectorEntry { role, bp, dest }, e))
        })?;
        for w in vector.windows(2) {
            if w[0].role >= w[1].role {
                return Err(Error::TypeOrder); // ascending role, unique (F4-b)
            }
        }
        let predecessor = obj
            .get(C_PREDECESSOR)
            .map(|f| -> Result<([u8; 8], [u8; 32])> {
                if f.value.len() != 40 {
                    return Err(Error::WrongWidth);
                }
                Ok((
                    f.value[..8].try_into().unwrap(),
                    f.value[8..40].try_into().unwrap(),
                ))
            })
            .transpose()?;
        let channel_id: [u8; 8] = get(C_CHANNEL_ID)?
            .value
            .clone()
            .try_into()
            .map_err(|_| Error::WrongWidth)?;
        let auth = ChannelAuth {
            payer_key: fixed32(&get(C_PAYER_KEY)?.value)?,
            channel_id,
            merchant_key: fixed32(&get(C_MERCHANT_KEY)?.value)?,
            denom: txt(C_DENOM)?,
            mode,
            limit_l: tlv::decode_uint_u128(&get(C_LIMIT_L)?.value)?,
            limit_e: tlv::decode_uint_u128(&get(C_LIMIT_E)?.value)?,
            th_value: tlv::decode_uint_u128(&get(C_TH_VALUE)?.value)?,
            th_time: tlv::decode_uint_time(&get(C_TH_TIME)?.value)?, // F1-l time domain ≤ 2⁵³−1
            refund_ptr: opt_txt(C_REFUND_PTR)?,
            baseline_net: txt(C_BASELINE_NET)?,
            rate_source: opt_txt(C_RATE_SOURCE)?,
            rate_dev: obj
                .get(C_RATE_DEV)
                .map(|f| tlv::decode_uint_u128(&f.value))
                .transpose()?,
            schema: tlv::decode_uint_u32(&get(C_SCHEMA)?.value)?,
            vector,
            registry_v: tlv::decode_uint_u32(&get(C_REGISTRY_V)?.value)?,
            hs: fixed32(&get(C_HS)?.value)?,
            predecessor,
            timestamp: tlv::decode_uint_time(&get(C_TIMESTAMP)?.value)?, // F1-l time domain ≤ 2⁵³−1
            baseline_asset: txt(C_BASELINE_ASSET)?,
            contract: tlv::decode_uint_u32(&get(C_CONTRACT)?.value)?,
            fin_meed: txt(C_FIN_MEED)?,
            fin_denom: txt(C_FIN_DENOM)?,
            sig: obj.get(C_SIG).map(|f| fixed64(&f.value)).transpose()?,
        };
        auth.check_presence()?; // mode-determined REFUND_PTR, conditional RATE_*
        auth.validate_grammar()?; // CAIP/pointer grammar of DENOM/BASELINE_*/REFUND_PTR
        Ok(auth)
    }
}

// --- CHANNEL_OPEN (F5.2) ---

const O_AUTH: u8 = 0x00;
const O_SEAL: u8 = 0x01;

/// `CHANNEL_OPEN` (F5.2): the unsigned envelope — its signature is the
/// `CHANNEL_AUTH` it carries. `SEAL` is the 80-byte `enc ‖ ct` (F2-f).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpen {
    pub auth: ChannelAuth,
    pub seal: Vec<u8>,
}

impl ChannelOpen {
    /// Build a `CHANNEL_OPEN`: seal `s` to the artifact's `enc_key` (aad = the
    /// canonical `CHANNEL_AUTH` content, F2.5). `auth` must already be signed and
    /// its `hs` must equal `H(s)`.
    pub fn build(auth: ChannelAuth, enc_key: &[u8; 32], s: &[u8; 32]) -> Result<ChannelOpen> {
        let seal = crate::crypto::seal_session_secret(enc_key, &auth.canonical_content()?, s)?;
        Ok(ChannelOpen { auth, seal })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let fields = vec![
            Field::new(O_AUTH, false, self.auth.encode()?),
            Field::new(O_SEAL, false, self.seal.clone()),
        ];
        Ok(Object::from_fields(fields)?.encode())
    }

    pub fn parse(buf: &[u8]) -> Result<ChannelOpen> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[(O_AUTH, false), (O_SEAL, false)],
        ))?;
        let auth = ChannelAuth::parse(&obj.get(O_AUTH).ok_or(Error::MissingField)?.value)?;
        let seal = obj.get(O_SEAL).ok_or(Error::MissingField)?.value.clone();
        if seal.len() != 80 {
            return Err(Error::WrongWidth); // enc(32) ‖ ct(48), F2-f
        }
        Ok(ChannelOpen { auth, seal })
    }
}

// --- CHANNEL_ACK (F5.3) ---

const K_AUTH_HASH: u8 = 0x00;
const K_SETTLE_PTR: u8 = 0x01;
const K_SIG: u8 = 0x70;

/// `CHANNEL_ACK` (F5.3): the merchant's answer that makes the channel exist. Binds
/// `AUTH_HASH` + the merchant's settlement pointer under `PayTPv1-chan-ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAck {
    pub auth_hash: [u8; 32],
    pub settle_ptr: String,
    pub sig: Option<[u8; 64]>,
}

impl ChannelAck {
    fn content_fields(&self) -> Result<Vec<Field>> {
        tlv::validate_text(self.settle_ptr.as_bytes())?;
        Pointer::parse(&self.settle_ptr)?; // SETTLE_PTR: F9.1 destination pointer
        Ok(vec![
            Field::new(K_AUTH_HASH, false, self.auth_hash.to_vec()),
            Field::new(K_SETTLE_PTR, false, self.settle_ptr.as_bytes().to_vec()),
        ])
    }
    fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(
            DomainLabel::ChanAck,
            &Object::from_fields(self.content_fields()?)?.encode(),
        ))
    }
    pub fn sign(&mut self, merchant_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(merchant_sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn verify(&self, merchant_key: &[u8; 32]) -> Result<()> {
        let sig = self.sig.ok_or(Error::MissingField)?;
        ed25519_verify_strict(merchant_key, &self.covered_bytes()?, &sig)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig {
            fields.push(Field::new(K_SIG, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<ChannelAck> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[(K_AUTH_HASH, false), (K_SETTLE_PTR, false), (K_SIG, false)],
        ))?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let settle_ptr = String::from_utf8(get(K_SETTLE_PTR)?.value.clone())
            .map_err(|_| Error::TextControlChar)?;
        tlv::validate_text(settle_ptr.as_bytes())?;
        Pointer::parse(&settle_ptr)?; // SETTLE_PTR: F9.1 destination pointer
        Ok(ChannelAck {
            auth_hash: fixed32(&get(K_AUTH_HASH)?.value)?,
            settle_ptr,
            sig: obj.get(K_SIG).map(|f| fixed64(&f.value)).transpose()?,
        })
    }
}

// --- ACK_REQUEST (F5.3) ---

/// `ACK_REQUEST` (F5.3): a payer-signed retrieval of a channel's `CHANNEL_ACK`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRequest {
    pub channel_id: [u8; 8],
    pub timestamp: u64,
    pub sig: Option<[u8; 64]>,
}

impl AckRequest {
    fn content_fields(&self) -> Vec<Field> {
        vec![
            Field::new(0x00, false, self.channel_id.to_vec()),
            Field::new(0x01, false, tlv::encode_uint_u128(self.timestamp as u128)),
        ]
    }
    fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(
            DomainLabel::AckReq,
            &Object::from_fields(self.content_fields())?.encode(),
        ))
    }
    pub fn sign(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(payer_sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn verify(&self, payer_key: &[u8; 32]) -> Result<()> {
        let sig = self.sig.ok_or(Error::MissingField)?;
        ed25519_verify_strict(payer_key, &self.covered_bytes()?, &sig)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields();
        if let Some(s) = self.sig {
            fields.push(Field::new(0x70, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<AckRequest> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[(0x00, false), (0x01, false), (0x70, false)],
        ))?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        Ok(AckRequest {
            channel_id: get(0x00)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            timestamp: tlv::decode_uint_time(&get(0x01)?.value)?, // F1-l time domain ≤ 2⁵³−1
            sig: obj.get(0x70).map(|f| fixed64(&f.value)).transpose()?,
        })
    }
}

// --- FUNDING_PROOF (F5.4) ---

/// `FUNDING_PROOF` (F5.4): a payer-signed proof of a `DENOM`-rail funding transfer
/// bound to one channel (`AUTH_HASH`), consumed once by the merchant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingProof {
    pub channel_id: [u8; 8],
    pub auth_hash: [u8; 32],
    pub rail: String,
    pub tx_ref: String,
    pub amount: u128,
    pub sig: Option<[u8; 64]>,
}

impl FundingProof {
    fn content_fields(&self) -> Result<Vec<Field>> {
        tlv::validate_text(self.rail.as_bytes())?;
        tlv::validate_text(self.tx_ref.as_bytes())?;
        // RAIL: an F9.1 rail id (CAIP-2 or `x-` adapter). The *value* stays
        // adapter-authoritative — `on_funding` ignores `fp.rail` (the connected adapter
        // is the rail, so a mutated rail string never enters the one-decision key, C65)
        // — but a *malformed* rail is an interop divergence a conformant peer would
        // reject, so it is rejected here on both emit and parse.
        if !is_rail_id(&self.rail) {
            return Err(Error::FieldDomain);
        }
        Ok(vec![
            Field::new(0x00, false, self.channel_id.to_vec()),
            Field::new(0x01, false, self.auth_hash.to_vec()),
            Field::new(0x02, false, self.rail.as_bytes().to_vec()),
            Field::new(0x03, false, self.tx_ref.as_bytes().to_vec()),
            Field::new(0x04, false, tlv::encode_uint_u128(self.amount)),
        ])
    }
    fn covered_bytes(&self) -> Result<Vec<u8>> {
        Ok(covered(
            DomainLabel::Funding,
            &Object::from_fields(self.content_fields()?)?.encode(),
        ))
    }
    pub fn sign(&mut self, payer_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(payer_sk, &self.covered_bytes()?));
        Ok(())
    }
    pub fn verify(&self, payer_key: &[u8; 32]) -> Result<()> {
        let sig = self.sig.ok_or(Error::MissingField)?;
        ed25519_verify_strict(payer_key, &self.covered_bytes()?, &sig)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields()?;
        if let Some(s) = self.sig {
            fields.push(Field::new(0x70, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<FundingProof> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[
                (0x00, false),
                (0x01, false),
                (0x02, false),
                (0x03, false),
                (0x04, false),
                (0x70, false),
            ],
        ))?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let txt = |t: u8| -> Result<String> {
            let s = String::from_utf8(get(t)?.value.clone()).map_err(|_| Error::TextControlChar)?;
            tlv::validate_text(s.as_bytes())?;
            Ok(s)
        };
        let rail = txt(0x02)?;
        if !is_rail_id(&rail) {
            return Err(Error::FieldDomain); // RAIL: F9.1 rail id (CAIP-2 or `x-` adapter)
        }
        Ok(FundingProof {
            channel_id: get(0x00)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            auth_hash: fixed32(&get(0x01)?.value)?,
            rail,
            tx_ref: txt(0x03)?,
            amount: tlv::decode_uint_u128(&get(0x04)?.value)?,
            sig: obj.get(0x70).map(|f| fixed64(&f.value)).transpose()?,
        })
    }
}

// --- CLOSE (F5.6) ---

/// `CLOSE` (F5.6): terminates a channel, naming the final bilateral checkpoint and
/// (payer only) the chaining intent. Signed by either party under `PayTPv1-close`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub channel_id: [u8; 8],
    pub ckpt_ref: [u8; 32],
    /// `CHAIN_INTENT` (F5-l) — honored ONLY on a payer-signed `CLOSE`; a merchant
    /// `CLOSE` MUST carry `false` and a receiver ignores it (see [`Close::accept`]).
    pub chain_intent: bool,
    pub sig: Option<[u8; 64]>,
}

/// What a verified `CLOSE` means (F5-l): who signed, and the **effective** chain
/// intent — `true` only when the payer signed and set it, so a merchant can never
/// forge a chain intent to defer a deposit return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseDecision {
    pub by_payer: bool,
    pub chain_intent: bool,
}

impl Close {
    fn content_fields(&self) -> Vec<Field> {
        vec![
            Field::new(0x00, false, self.channel_id.to_vec()),
            Field::new(0x01, false, self.ckpt_ref.to_vec()),
            Field::new(0x02, false, vec![self.chain_intent as u8]),
        ]
    }
    fn covered_bytes(&self) -> Vec<u8> {
        covered(
            DomainLabel::Close,
            &Object::from_fields(self.content_fields()).unwrap().encode(),
        )
    }
    pub fn sign(&mut self, signer_sk: &[u8; 32]) -> Result<()> {
        self.sig = Some(ed25519_sign(signer_sk, &self.covered_bytes()));
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.content_fields();
        if let Some(s) = self.sig {
            fields.push(Field::new(0x70, false, s.to_vec()));
        }
        Ok(Object::from_fields(fields)?.encode())
    }
    pub fn parse(buf: &[u8]) -> Result<Close> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(
            Openness::Closed,
            &[(0x00, false), (0x01, false), (0x02, false), (0x70, false)],
        ))?;
        let get = |t: u8| obj.get(t).ok_or(Error::MissingField);
        let intent = match get(0x02)?.value.as_slice() {
            [0x00] => false,
            [0x01] => true,
            _ => return Err(Error::FieldDomain), // CHAIN_INTENT is one byte, 0 or 1
        };
        Ok(Close {
            channel_id: get(0x00)?
                .value
                .clone()
                .try_into()
                .map_err(|_| Error::WrongWidth)?,
            ckpt_ref: fixed32(&get(0x01)?.value)?,
            chain_intent: intent,
            sig: obj.get(0x70).map(|f| fixed64(&f.value)).transpose()?,
        })
    }

    /// Verify a `CLOSE` for a specific channel and return the F5-l [`CloseDecision`].
    /// It MUST name `expected_channel_id` — a `CLOSE` for another channel is
    /// rejected, so a stale/wrong-channel object can never drive this channel into
    /// `SETTLING`. The chain intent is honored **only** from the payer's signature
    /// (a merchant-signed `CLOSE` or an unsigned `0x01` can never express one).
    /// Errors if the channel-id mismatches or the signature verifies under neither
    /// key. The caller separately validates that `CKPT_REF` names its operative
    /// checkpoint (F6.3) before settling/chaining from it.
    pub fn accept(
        &self,
        expected_channel_id: &[u8; 8],
        payer_key: &[u8; 32],
        merchant_key: &[u8; 32],
    ) -> Result<CloseDecision> {
        if &self.channel_id != expected_channel_id {
            return Err(Error::FieldDomain);
        }
        let sig = self.sig.ok_or(Error::MissingField)?;
        let covered = self.covered_bytes();
        let by_payer = ed25519_verify_strict(payer_key, &covered, &sig).is_ok();
        let by_merchant = ed25519_verify_strict(merchant_key, &covered, &sig).is_ok();
        if !by_payer && !by_merchant {
            return Err(Error::BadSignature);
        }
        Ok(CloseDecision {
            by_payer,
            chain_intent: by_payer && self.chain_intent,
        })
    }
}

fn fixed32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| Error::WrongWidth)
}
fn fixed64(v: &[u8]) -> Result<[u8; 64]> {
    v.try_into().map_err(|_| Error::WrongWidth)
}

#[cfg(test)]
mod tests;
