//! The role-registry snapshot, identifiers, and the fallback algorithm
//! (**F9.2/F9.3/F9.4**, formalizing §10.1/§10.5/§5.4).
//!
//! The Foundation publishes the role registry as a signed TLV snapshot. A
//! validator retains every snapshot from `WINDOW_FLOOR` to the newest it holds
//! (F9-d) and resolves an OS assertion at the vector's *named* version. An
//! unlisted or absent OS assertion routes to the **independent open-source fund**
//! destination (§10.1, F9.4 step 2) — a fund *outside* the Foundation's control and
//! **distinct from the Development Fund** (the neutrality mechanism, §10.5); the
//! fallback keeps the 100 bp total invariant. (Unasserted *payer-side* `0x10`/`0x12`
//! route instead to the Development Fund — F9.4 step 3 — a different fallback.)

use crate::crypto;
use crate::envelope::{covered, DomainLabel};
use crate::error::{Error, Result};
use crate::leb128;
use crate::pointer::Pointer;
use crate::tlv::{self, Field, Object, Openness, Schema};

/// Validate a registry / rate-source identifier (GAP-FILL F9-b):
/// `^[a-z0-9]([a-z0-9\-\.]{0,62}[a-z0-9])?$` (1–64 bytes, lowercase ASCII, no
/// leading/trailing separator).
pub fn validate_identifier(s: &str) -> Result<()> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return Err(Error::JsonGrammar);
    }
    let is_alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let is_mid = |c: u8| is_alnum(c) || c == b'-' || c == b'.';
    if !is_alnum(b[0]) || !is_alnum(b[b.len() - 1]) {
        return Err(Error::JsonGrammar);
    }
    if !b.iter().all(|&c| is_mid(c)) {
        return Err(Error::JsonGrammar);
    }
    Ok(())
}

const T_VERSION: u8 = 0x00;
const T_KIND: u8 = 0x01;
const T_ISSUED: u8 = 0x02;
const T_WINDOW_FLOOR: u8 = 0x03;
const T_OS_RECIPIENTS: u8 = 0x04;
const T_REVOKED: u8 = 0x05;
const T_RATE_SOURCES: u8 = 0x06;
const T_SIG: u8 = 0x70;

/// Registry snapshot kind (F9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Rotation,
    Revocation,
}

/// A parsed, signature-verified registry snapshot (F9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u32,
    pub kind: Kind,
    pub issued: u64,
    pub window_floor: u32,
    /// OS recipients, ascending by identifier bytes: `(id, dest)`.
    pub os_recipients: Vec<(String, String)>,
    /// Revoked version numbers, ascending (present iff `kind == Revocation`).
    pub revoked: Vec<u32>,
    /// Rate sources, ascending by identifier: `(id, uri)`.
    pub rate_sources: Vec<(String, String)>,
    /// The Ed25519 signature over `COVERED` (F1.3, `PayTPv1-registry`).
    pub sig: [u8; 64],
}

fn snapshot_schema() -> Schema {
    Schema::new(
        Openness::Open,
        &[
            (T_VERSION, false),
            (T_KIND, false),
            (T_ISSUED, false),
            (T_WINDOW_FLOOR, false),
            (T_OS_RECIPIENTS, false),
            (T_REVOKED, false),
            (T_RATE_SOURCES, false),
            (T_SIG, false),
        ],
    )
}

/// Encode a `(id, value)` count-prefixed list item: `id_len ‖ id ‖ v_len ‖ v`.
fn encode_id_value(id: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    leb128::encode_into(id.len() as u64, &mut out);
    out.extend_from_slice(id.as_bytes());
    leb128::encode_into(value.len() as u64, &mut out);
    out.extend_from_slice(value.as_bytes());
    out
}

/// Parse one `id_len ‖ id ‖ v_len ‖ v` item, returning `((id, value), consumed)`.
fn parse_id_value(buf: &[u8]) -> Result<((String, String), usize)> {
    let (id_len, n1) = leb128::decode(buf)?;
    let s1 = n1;
    let e1 = s1
        .checked_add(id_len as usize)
        .ok_or(Error::LengthOverrun)?;
    if e1 > buf.len() {
        return Err(Error::LengthOverrun);
    }
    let id = std::str::from_utf8(&buf[s1..e1])
        .map_err(|_| Error::TextNotUtf8)?
        .to_string();
    let (v_len, n2) = leb128::decode(&buf[e1..])?;
    let s2 = e1 + n2;
    let e2 = s2.checked_add(v_len as usize).ok_or(Error::LengthOverrun)?;
    if e2 > buf.len() {
        return Err(Error::LengthOverrun);
    }
    let value = std::str::from_utf8(&buf[s2..e2])
        .map_err(|_| Error::TextNotUtf8)?
        .to_string();
    Ok(((id, value), e2))
}

impl Snapshot {
    /// The canonical covered bytes (all fields except `SIG`), used for signing
    /// and verification under `PayTPv1-registry`.
    fn covered_bytes(obj: &Object) -> Vec<u8> {
        covered(DomainLabel::Registry, &obj.covered_bytes(&[]))
    }

    /// Build the canonical `Object` (without or with the signature).
    fn to_object(&self, include_sig: bool) -> Result<Object> {
        let mut fields = vec![
            Field::new(
                T_VERSION,
                false,
                tlv::encode_uint_u128(self.version as u128),
            ),
            Field::new(
                T_KIND,
                false,
                vec![match self.kind {
                    Kind::Rotation => 0x00,
                    Kind::Revocation => 0x01,
                }],
            ),
            Field::new(T_ISSUED, false, tlv::encode_uint_u128(self.issued as u128)),
            Field::new(
                T_WINDOW_FLOOR,
                false,
                tlv::encode_uint_u128(self.window_floor as u128),
            ),
            Field::new(
                T_OS_RECIPIENTS,
                false,
                tlv::build_count_prefixed(
                    &self
                        .os_recipients
                        .iter()
                        .map(|(id, d)| encode_id_value(id, d))
                        .collect::<Vec<_>>(),
                ),
            ),
            Field::new(
                T_RATE_SOURCES,
                false,
                tlv::build_count_prefixed(
                    &self
                        .rate_sources
                        .iter()
                        .map(|(id, u)| encode_id_value(id, u))
                        .collect::<Vec<_>>(),
                ),
            ),
        ];
        if self.kind == Kind::Revocation {
            fields.push(Field::new(
                T_REVOKED,
                false,
                tlv::build_count_prefixed(
                    &self
                        .revoked
                        .iter()
                        // Each REVOKED version is a self-delimiting LEB128 varint (F9.3): the
                        // only framing under which `parse_count_prefixed` can find each bare
                        // integer's boundary — a minimal-unsigned big-endian value carries no
                        // length, so it is unparseable inside a count-prefixed list. This MUST
                        // match the parser's `leb128::decode` (registry.rs `parse_verify`); the
                        // former `encode_uint_u128` only coincided with LEB128 below 128.
                        .map(|v| leb128::encode(*v as u64))
                        .collect::<Vec<_>>(),
                ),
            ));
        }
        if include_sig {
            fields.push(Field::new(T_SIG, false, self.sig.to_vec()));
        }
        Object::from_fields(fields)
    }

    /// Sign this snapshot with the Foundation registry signing key (test/tooling).
    pub fn sign(&mut self, foundation_signing_key: &[u8; 32]) -> Result<()> {
        let obj = self.to_object(false)?;
        let covered = Self::covered_bytes(&obj);
        self.sig = crypto::ed25519_sign(foundation_signing_key, &covered);
        Ok(())
    }

    /// Encode to canonical TLV bytes (signature included).
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.to_object(true)?.encode())
    }

    /// Parse and verify a snapshot under the Foundation registry public key.
    pub fn parse_verify(buf: &[u8], foundation_key: &[u8; 32]) -> Result<Snapshot> {
        let obj = Object::parse(buf)?;
        obj.validate(&snapshot_schema())?;

        let version = tlv::decode_uint_u32(&field(&obj, T_VERSION)?.value)?;
        let kind = match field(&obj, T_KIND)?.value.as_slice() {
            [0x00] => Kind::Rotation,
            [0x01] => Kind::Revocation,
            _ => return Err(Error::FieldDomain),
        };
        let issued = tlv::decode_uint_time(&field(&obj, T_ISSUED)?.value)?; // F1-l ≤ 2⁵³−1 (F9.3)
        let window_floor = tlv::decode_uint_u32(&field(&obj, T_WINDOW_FLOOR)?.value)?;

        let os_recipients =
            tlv::parse_count_prefixed(&field(&obj, T_OS_RECIPIENTS)?.value, parse_id_value)?;
        // Validate identifiers, destinations, and ascending order.
        check_ascending_ids(&os_recipients)?;
        for (id, dest) in &os_recipients {
            validate_identifier(id)?;
            let p = Pointer::parse(dest)?;
            if !p.is_caip() {
                return Err(Error::JsonGrammar); // OS dest is baseline-payable (F9.3)
            }
        }

        let revoked = match obj.get(T_REVOKED) {
            Some(f) => {
                if kind != Kind::Revocation {
                    return Err(Error::UnexpectedType); // REVOKED only on revocation
                }
                let list: Vec<u32> = tlv::parse_count_prefixed(&f.value, |b| {
                    let (v, n) = leb128::decode(b)?;
                    let v = u32::try_from(v).map_err(|_| Error::FieldDomain)?; // no silent truncation
                    Ok((v, n))
                })?;
                for w in list.windows(2) {
                    if w[0] >= w[1] {
                        return Err(Error::TypeOrder); // ascending
                    }
                }
                list
            }
            None => {
                if kind == Kind::Revocation {
                    return Err(Error::MissingField); // REVOKED required on revocation
                }
                Vec::new()
            }
        };

        let rate_sources =
            tlv::parse_count_prefixed(&field(&obj, T_RATE_SOURCES)?.value, parse_id_value)?;
        check_ascending_ids(&rate_sources)?;
        for (id, uri) in &rate_sources {
            validate_identifier(id)?;
            tlv::validate_text(uri.as_bytes())?; // F9.3/F1-g: uri is UTF-8, no NUL/control/non-NFC
        }

        let sig_field = field(&obj, T_SIG)?;
        if sig_field.value.len() != 64 {
            return Err(Error::WrongWidth);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_field.value);

        // Verify the Foundation signature over COVERED.
        let covered = Self::covered_bytes(&obj);
        crypto::ed25519_verify_strict(foundation_key, &covered, &sig)?;

        Ok(Snapshot {
            version,
            kind,
            issued,
            window_floor,
            os_recipients,
            revoked,
            rate_sources,
            sig,
        })
    }

    /// The canonical destination of a listed OS recipient at this version, if any.
    pub fn resolve_os(&self, id: &str) -> Option<&str> {
        self.os_recipients
            .iter()
            .find(|(rid, _)| rid == id)
            .map(|(_, dest)| dest.as_str())
    }
}

fn field(obj: &Object, t: u8) -> Result<&Field> {
    obj.get(t).ok_or(Error::MissingField)
}

fn check_ascending_ids(items: &[(String, String)]) -> Result<()> {
    for w in items.windows(2) {
        if w[0].0.as_bytes() >= w[1].0.as_bytes() {
            return Err(Error::TypeOrder); // ascending by identifier bytes
        }
    }
    Ok(())
}

/// A retained set of snapshots (F9-d): every version from `WINDOW_FLOOR` to the
/// newest held, so an in-window vector resolves against its *named* version.
#[derive(Debug, Clone, Default)]
pub struct SnapshotStore {
    by_version: std::collections::BTreeMap<u32, Snapshot>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A shared reference to a permanently-empty store — the no-registry default for a
    /// borrowed-registry caller (e.g. [`crate::tier0`]'s wallet). For governed destination
    /// correctness it accepts only the version-agnostic independent-OS-fund fallback and the pinned
    /// Dev-Fund seat (fail-closed for any claimed registry-listed `0x11` OS — a validator holding no
    /// registry cannot confirm a listing).
    pub fn empty_ref() -> &'static SnapshotStore {
        static EMPTY: std::sync::OnceLock<SnapshotStore> = std::sync::OnceLock::new();
        EMPTY.get_or_init(SnapshotStore::new)
    }

    pub fn insert(&mut self, s: Snapshot) {
        self.by_version.insert(s.version, s);
    }

    /// The newest (tip) snapshot.
    pub fn tip(&self) -> Option<&Snapshot> {
        self.by_version.values().next_back()
    }

    /// The snapshot at exactly `version`, if retained.
    pub fn at(&self, version: u32) -> Option<&Snapshot> {
        self.by_version.get(&version)
    }

    /// Version acceptance (F9.4.1): accepted iff `WINDOW_FLOOR ≤ version ≤ VERSION`
    /// under the newest snapshot held, and not in any known `REVOKED` list.
    pub fn version_accepted(&self, version: u32) -> bool {
        let Some(tip) = self.tip() else {
            return false;
        };
        if version < tip.window_floor || version > tip.version {
            return false;
        }
        // Not revoked by any retained snapshot.
        !self
            .by_version
            .values()
            .any(|s| s.revoked.contains(&version))
    }

    /// Resolve an OS assertion (F9.4.2) against the *named* version:
    /// listed → its canonical destination; unlisted or `None` → the **independent
    /// open-source fund** destination (§10.1), **not the Development Fund**. Routing
    /// an absent OS to a fund outside the Foundation's control is the neutrality
    /// mechanism (§10.5): no registry decision changes the Foundation's
    /// income. The fallback is a single release-pinned constant (F9-e), so it is not
    /// a caller-supplied parameter — a caller cannot misroute it to the Dev Fund.
    /// Errors if the named version is not accepted/retained.
    pub fn resolve_os_destination(
        &self,
        named_version: u32,
        asserted_os: Option<&str>,
    ) -> Result<String> {
        // Fail-closed governance guard (F9-e): the fallback arm resolves to the
        // release-bound independent-OS-fund PLACEHOLDER, so a non-demo build refuses
        // rather than emit a sentinel destination.
        crate::consts::ensure_governance_ready()?;
        if !self.version_accepted(named_version) {
            return Err(Error::FieldDomain); // stale/revoked/out-of-window
        }
        let snap = self.at(named_version).ok_or(Error::MissingField)?; // F9-d retention
        Ok(match asserted_os.and_then(|id| snap.resolve_os(id)) {
            Some(dest) => dest.to_string(),
            // Absent/unlisted OS → the independent open-source fund (§10.1), never
            // the Development Fund — the fallback that keeps the 100 bp total AND the
            // Foundation-neutrality invariant.
            None => crate::consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.to_string(),
        })
    }

    /// Receive-side OS-destination correctness (**F5-o / F9.4 step 2, set-membership**).
    /// The *builder* resolves an asserted OS id → destination with [`Self::resolve_os_destination`];
    /// a *validator* (merchant receive, wallet fund/sign, channel open) does **not** hold the
    /// `PayTP-Roles` OS id, so it checks the reverse: the `0x11` destination the vector already
    /// carries is acceptable **iff** the named version passes acceptance (F9.4 step 1, when a
    /// registry is held) **and** the destination is either
    /// - the pinned **independent open-source fund** fallback (`INDEPENDENT_OS_FUND_DEST_PLACEHOLDER`,
    ///   the absent/unlisted-OS destination, §10.1); or
    /// - a canonical destination of some OS recipient **listed at the vector's named version** in the
    ///   retained snapshot (byte equality, F9-a).
    ///
    /// **Version acceptance is checked first** (matching [`Self::resolve_os_destination`], which gates
    /// the fallback case too): a validator holding a registry rejects a stale/revoked/out-of-window
    /// version even for the fund fallback, so revocation reaches fallback vectors (F9.4 step 1). An
    /// empty/absent registry cannot judge the version, so it accepts **only** the fallback and
    /// **rejects** any claimed-listed OS destination (fail-closed: a validator cannot confirm a
    /// listing it does not hold). This is
    /// the check that forecloses the arbitrary-CAIP OS-share theft (a `dest` that is neither the fund
    /// nor a listed recipient); the *which listed OS* adjudication is governance's, not the
    /// merchant's (F9.4: "the merchant checks only that the named destination is registry-listed or
    /// the pinned fund").
    pub fn os_destination_accepted(&self, named_version: u32, dest: &str) -> Result<()> {
        // Fail-closed governance guard (F9-e): the fund-fallback arm below accepts the
        // release-bound independent-OS-fund PLACEHOLDER, so a non-demo build refuses the
        // governed value decision rather than vouch for a sentinel destination.
        crate::consts::ensure_governance_ready()?;
        // F9.4 step 1 (version acceptance) FIRST, matching [`Self::resolve_os_destination`] — which
        // gates the `None`/fallback case on `version_accepted` too. A validator that HOLDS a registry
        // (non-empty store) MUST reject a vector naming a stale/revoked/out-of-window version **even
        // when 0x11 uses the fund fallback**, so revocation reaches fallback vectors. A validator with
        // NO registry (empty store) cannot judge the version; it vouches ONLY for the version-agnostic
        // pinned fallback below (fail-closed for any listed OS — the `at()` lookup then misses).
        if self.tip().is_some() && !self.version_accepted(named_version) {
            return Err(Error::FieldDomain); // registry held, named version not accepted
        }
        if dest == crate::consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER {
            return Ok(()); // the absent/unlisted-OS fallback — pinned constant
        }
        // Listed arm: `dest` must be a recipient listed at the (retained, F9-d) named version. A
        // version not retained (incl. an empty store) OR a dest not among its recipients → reject
        // with one uniform domain error (a validator cannot confirm a listing it does not hold).
        match self.at(named_version) {
            Some(snap) if snap.os_recipients.iter().any(|(_, d)| d == dest) => Ok(()),
            _ => Err(Error::FieldDomain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot(kind: Kind) -> Snapshot {
        Snapshot {
            version: 5,
            kind,
            issued: 1_700_000_000,
            window_floor: 3,
            os_recipients: vec![
                ("apple".into(), "eip155:1:0xApple".into()),
                ("google".into(), "eip155:1:0xGoogle".into()),
            ],
            revoked: if kind == Kind::Revocation {
                vec![4]
            } else {
                vec![]
            },
            rate_sources: vec![("coinbase".into(), "https://api.example/rates".into())],
            sig: [0u8; 64],
        }
    }

    #[test]
    fn identifier_grammar() {
        for ok in ["apple", "a", "os-vendor.inc", "x9"] {
            assert!(validate_identifier(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-apple", "apple-", "Apple", "a..b_ok?", &"x".repeat(65)] {
            assert!(validate_identifier(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_rejects_control_char_in_rate_source_uri() {
        // F9.3+F1-g: a signed snapshot smuggling a NUL into a rate-source
        // uri (id is already validated) MUST be rejected at parse, like the sibling fields.
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut snap = test_snapshot(Kind::Rotation);
        snap.rate_sources = vec![("coinbase".into(), "https://api.example/\u{0}rates".into())];
        snap.sign(&sk).unwrap();
        let bytes = snap.encode().unwrap();
        assert!(
            Snapshot::parse_verify(&bytes, &pk).is_err(),
            "a NUL in a rate-source uri must be rejected"
        );
    }

    #[test]
    fn parse_rejects_issued_over_2_53_time_domain() {
        // F1-l (F9.3): the snapshot's `ISSUED` (Unix seconds) is a time field,
        // capped at 2⁵³ − 1. A signed snapshot with `ISSUED = 2⁵³` — a valid u64 the old
        // raw decode accepted — MUST be rejected at parse (receive-side strictness).
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut snap = test_snapshot(Kind::Rotation);
        snap.issued = 1u64 << 53; // 2⁵³ — out of the F1-l time domain
        snap.sign(&sk).unwrap();
        let bytes = snap.encode().unwrap();
        assert!(
            Snapshot::parse_verify(&bytes, &pk).is_err(),
            "ISSUED = 2^53 must be rejected (F1-l time domain)"
        );
        // The exact boundary 2⁵³ − 1 still round-trips.
        let mut ok = test_snapshot(Kind::Rotation);
        ok.issued = (1u64 << 53) - 1;
        ok.sign(&sk).unwrap();
        assert!(Snapshot::parse_verify(&ok.encode().unwrap(), &pk).is_ok());
    }

    #[test]
    fn snapshot_sign_parse_verify_roundtrip() {
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut snap = test_snapshot(Kind::Rotation);
        snap.sign(&sk).unwrap();
        let bytes = snap.encode().unwrap();
        let parsed = Snapshot::parse_verify(&bytes, &pk).unwrap();
        assert_eq!(parsed, snap);
        // Wrong Foundation key → reject.
        let other = crypto::ed25519_public(&[0x44u8; 32]);
        assert!(Snapshot::parse_verify(&bytes, &other).is_err());
    }

    #[test]
    fn version_window_and_revocation() {
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut rot = test_snapshot(Kind::Rotation);
        rot.sign(&sk).unwrap();
        let mut store = SnapshotStore::new();
        store.insert(Snapshot::parse_verify(&rot.encode().unwrap(), &pk).unwrap());
        assert!(store.version_accepted(5));
        assert!(store.version_accepted(3)); // == window_floor
        assert!(!store.version_accepted(2)); // below floor
        assert!(!store.version_accepted(6)); // above tip

        // A revocation snapshot withdrawing version 4.
        let mut rev = test_snapshot(Kind::Revocation);
        rev.version = 6;
        rev.window_floor = 3;
        rev.revoked = vec![4];
        rev.sign(&sk).unwrap();
        store.insert(Snapshot::parse_verify(&rev.encode().unwrap(), &pk).unwrap());
        assert!(!store.version_accepted(4)); // now revoked
        assert!(store.version_accepted(6));
    }

    #[test]
    fn revocation_snapshot_roundtrips_versions_at_and_above_128() {
        // F9.3 REPRO (soundness/interop): the REVOKED list MUST round-trip version numbers
        // ≥ 128. The count-prefixed entries are self-delimiting LEB128 — the only viable framing
        // for a list of bare integers (a minimal-unsigned big-endian value carries no length, so
        // `parse_count_prefixed` could not find each entry's boundary). The encoder wrote each
        // version with `encode_uint_u128` (minimal big-endian) instead, which COINCIDES with
        // LEB128 below 128 and DIVERGES at 128 (`[0x80]` is 128 as a minimal uint but a truncated
        // LEB128). So a validly-signed revocation snapshot naming a revoked version ≥ 128 failed
        // to verify against itself. Straddle the boundary and include a multi-byte value.
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut rev = test_snapshot(Kind::Revocation);
        rev.version = 400;
        rev.window_floor = 3;
        rev.revoked = vec![127, 128, 129, 256, 400];
        rev.sign(&sk).unwrap();
        let bytes = rev.encode().unwrap();
        let parsed = Snapshot::parse_verify(&bytes, &pk)
            .expect("a signed revocation snapshot must verify against itself for versions ≥ 128");
        assert_eq!(parsed, rev);
        assert_eq!(parsed.revoked, vec![127, 128, 129, 256, 400]);
    }

    #[test]
    fn os_resolution_and_fallback() {
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut rot = test_snapshot(Kind::Rotation);
        rot.sign(&sk).unwrap();
        let mut store = SnapshotStore::new();
        store.insert(Snapshot::parse_verify(&rot.encode().unwrap(), &pk).unwrap());
        let indep = crate::consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER;
        // Listed → canonical dest.
        assert_eq!(
            store.resolve_os_destination(5, Some("apple")).unwrap(),
            "eip155:1:0xApple"
        );
        // Unlisted → the independent open-source fund (NOT the Dev Fund), §10.1.
        assert_eq!(
            store.resolve_os_destination(5, Some("nokia")).unwrap(),
            indep
        );
        // None → the independent open-source fund.
        assert_eq!(store.resolve_os_destination(5, None).unwrap(), indep);
        // Necessary neutrality condition: the OS fallback is a distinct destination
        // from the Development Fund (its real independent-steward identity is
        // release-bound, F9-e — not asserted here).
        assert_ne!(indep, crate::consts::DEV_FUND_DEST_PLACEHOLDER);
    }

    #[test]
    fn os_destination_accepted_honors_version_acceptance_even_for_the_fund_fallback() {
        // F9.4 step 1: a validator that HOLDS a registry MUST reject a vector naming a
        // stale/revoked/out-of-window version — even when 0x11 uses the independent-fund
        // fallback (matching `resolve_os_destination`, which gates the None case too). The
        // fund short-circuit must NOT bypass version acceptance when a registry is held.
        let sk = [0x33u8; 32];
        let pk = crypto::ed25519_public(&sk);
        let mut rot = test_snapshot(Kind::Rotation); // version 5, window_floor 3
        rot.sign(&sk).unwrap();
        let mut store = SnapshotStore::new();
        store.insert(Snapshot::parse_verify(&rot.encode().unwrap(), &pk).unwrap());
        let mut rev = test_snapshot(Kind::Revocation); // version 6, revokes 4
        rev.version = 6;
        rev.window_floor = 3;
        rev.revoked = vec![4];
        rev.sign(&sk).unwrap();
        store.insert(Snapshot::parse_verify(&rev.encode().unwrap(), &pk).unwrap());
        let indep = crate::consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER;

        // Accepted version + fund → OK.
        assert!(store.os_destination_accepted(5, indep).is_ok());
        // Revoked version (4) + fund → REJECT (revocation must reach fallback vectors).
        assert!(store.os_destination_accepted(4, indep).is_err());
        // Below window floor (2) + fund → REJECT.
        assert!(store.os_destination_accepted(2, indep).is_err());
        // Above tip (7) + fund → REJECT.
        assert!(store.os_destination_accepted(7, indep).is_err());

        // A validator holding NO registry cannot judge the version; it vouches only for the
        // version-agnostic pinned fallback (fail-closed for any listed OS) — so any version passes
        // with the fund, and a listed claim is rejected.
        let empty = SnapshotStore::new();
        assert!(empty.os_destination_accepted(999, indep).is_ok());
        assert!(empty
            .os_destination_accepted(999, "eip155:1:0xApple")
            .is_err());
    }
}
