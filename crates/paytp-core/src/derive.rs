//! Split / meed-instance address seeds and the entry identifier
//! (**F4.1 / GAP-FILL F4-a/F4-b/F4-c**, formalizing §5.6/§11.1).
//!
//! Both contract forms derive from the same `ADDRESS_INPUTS` under two labels
//! that never share an address:
//!
//! ```text
//! seed_split    = SHA-256("PayTPv1-split"    ‖ 0x00 ‖ canonical_bytes(ADDRESS_INPUTS))
//! seed_instance = SHA-256("PayTPv1-instance" ‖ 0x00 ‖ canonical_bytes(ADDRESS_INPUTS))
//! ```
//!
//! The entry identifier commits **every parameter the merchant and instance
//! check** — amount and the window deadlines — which is the mempool-squat
//! closure (F4-c): any deviation derives a different, orphaned id.

use crate::crypto::sha256;
use crate::error::{Error, Result};
use crate::leb128;
use crate::tlv::{self, Field, Object};

/// One canonical meed-vector entry (GAP-FILL F4-b): `role ‖ bp ‖ len ‖ dest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeedVectorEntry {
    pub role: u8,
    pub bp: u16,
    /// Destination pointer (UTF-8, F9 grammar; here validated only as F1-g text).
    pub dest: String,
}

impl MeedVectorEntry {
    fn encode_item(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.role);
        out.extend_from_slice(&self.bp.to_be_bytes()); // 2 bytes unsigned BE
        let dest = self.dest.as_bytes();
        leb128::encode_into(dest.len() as u64, &mut out);
        out.extend_from_slice(dest);
        out
    }
}

/// The `ADDRESS_INPUTS` TLV object (F4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInputs {
    /// `0x00` — the merchant Ed25519 identity key.
    pub merchant_key: [u8; 32],
    /// `0x01` — the settlement asset identifier (UTF-8, CAIP-scoped).
    pub asset: String,
    /// `0x02` — `MEED_SCHEMA_ID`.
    pub schema: u32,
    /// `0x03` — the canonical meed vector: exactly the schema-priced roles,
    /// ascending role id (F3.2 cardinality; fallback entries under their own ids).
    pub vector: Vec<MeedVectorEntry>,
    /// `0x04` — the contract-kit version.
    pub contract: u32,
    /// `0x05` — the merchant's **net (~99%) destination**, a baseline-payable F9
    /// pointer (F4.1). Present **only for the split form** (a baseline offer
    /// has a merchant seat), absent for the meed-**instance** form (meed-only,
    /// no merchant seat). Committing it makes the split address bind the net seat, so
    /// a substituted net destination derives a different address the wallet refuses
    /// (the split front-run closure). Enforced by [`seed_split`]/[`seed_instance`].
    pub merchant_net: Option<String>,
}

const T_MERCHANT_KEY: u8 = 0x00;
const T_ASSET: u8 = 0x01;
const T_SCHEMA: u8 = 0x02;
const T_VECTOR: u8 = 0x03;
const T_CONTRACT: u8 = 0x04;
const T_MERCHANT_NET: u8 = 0x05;

impl AddressInputs {
    /// Validate and produce the canonical `ADDRESS_INPUTS` TLV bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        tlv::validate_text(self.asset.as_bytes())?;
        // Vector: ascending, unique roles; dest is F1-g text.
        let mut roles = self.vector.iter().map(|e| e.role).collect::<Vec<_>>();
        roles.sort_unstable();
        roles.dedup();
        if roles.len() != self.vector.len() {
            return Err(Error::DuplicateType); // duplicate role in vector
        }
        let mut sorted = self.vector.clone();
        sorted.sort_by_key(|e| e.role);
        for e in &sorted {
            tlv::validate_text(e.dest.as_bytes())?;
        }
        let items: Vec<Vec<u8>> = sorted.iter().map(|e| e.encode_item()).collect();
        let vector_value = tlv::build_count_prefixed(&items);

        let mut fields = vec![
            Field::new(T_MERCHANT_KEY, false, self.merchant_key.to_vec()),
            Field::new(T_ASSET, false, self.asset.as_bytes().to_vec()),
            Field::new(T_SCHEMA, false, tlv::encode_uint_u128(self.schema as u128)),
            Field::new(T_VECTOR, false, vector_value),
            Field::new(
                T_CONTRACT,
                false,
                tlv::encode_uint_u128(self.contract as u128),
            ),
        ];
        // 0x05 MERCHANT_NET — present only for the split form (F4.1). A baseline-payable
        // F9 pointer, validated as F1-g text like the asset and the vector dests.
        if let Some(mn) = &self.merchant_net {
            tlv::validate_text(mn.as_bytes())?;
            fields.push(Field::new(T_MERCHANT_NET, false, mn.as_bytes().to_vec()));
        }
        let obj = Object::from_fields(fields)?;
        Ok(obj.encode())
    }

    /// `seed_split` (F4-a) — the baseline split's PDA seed. A split MUST commit its
    /// merchant-net destination, so `merchant_net` MUST be present; deriving a
    /// split without it is the front-run gap this closes and is a hard error.
    pub fn seed_split(&self) -> Result<[u8; 32]> {
        if self.merchant_net.is_none() {
            return Err(Error::MissingField); // a split MUST commit MERCHANT_NET (F4.1)
        }
        Ok(labelled_hash("PayTPv1-split", &self.canonical_bytes()?))
    }

    /// `seed_instance` (F4-a) — the meed instance's seed. The instance is
    /// meed-only (no merchant seat), so its inputs MUST NOT carry `merchant_net`
    /// — committing one would diverge from the contract's instance preimage.
    pub fn seed_instance(&self) -> Result<[u8; 32]> {
        if self.merchant_net.is_some() {
            return Err(Error::UnexpectedType); // an instance has no MERCHANT_NET (F4.1)
        }
        Ok(labelled_hash("PayTPv1-instance", &self.canonical_bytes()?))
    }
}

fn labelled_hash(label: &str, body: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(label.len() + 1 + body.len());
    input.extend_from_slice(label.as_bytes());
    input.push(0x00); // F1-h delimiter
    input.extend_from_slice(body);
    sha256(&input)
}

/// A Tier 0 purchase entry identifier (GAP-FILL **F4-c**):
///
/// ```text
/// entry_id = SHA-256("PayTPv1-entry" ‖ 0x00 ‖ seed_instance ‖ nonce ‖ AMT ‖ T_open ‖ T_lapse ‖ contest)
/// ```
///
/// `AMT` is a 16-byte unsigned big-endian (baseline minimum units, F7-a domain);
/// `T_open`/`T_lapse`/`contest` are 8-byte unsigned big-endian.
#[allow(clippy::too_many_arguments)]
pub fn entry_id_purchase(
    seed_instance: &[u8; 32],
    nonce: &[u8; 32],
    amt: u128,
    t_open: u64,
    t_lapse: u64,
    contest: u64,
) -> [u8; 32] {
    let mut body = Vec::with_capacity(32 + 32 + 16 + 8 + 8 + 8);
    body.extend_from_slice(seed_instance);
    body.extend_from_slice(nonce);
    body.extend_from_slice(&amt.to_be_bytes()); // 16-byte BE
    body.extend_from_slice(&t_open.to_be_bytes());
    body.extend_from_slice(&t_lapse.to_be_bytes());
    body.extend_from_slice(&contest.to_be_bytes());
    labelled_hash("PayTPv1-entry", &body)
}

/// A channel claim-record identifier (F4.2) — windowless, no deadline terms:
///
/// ```text
/// id = SHA-256("PayTPv1-entry" ‖ 0x00 ‖ seed_instance ‖ channel_id ‖ ckpt_ref ‖ P)
/// ```
///
/// `P` is the round's aggregate meed (F7.2), a 16-byte unsigned big-endian.
pub fn claim_record_id(
    seed_instance: &[u8; 32],
    channel_id: &[u8; 8],
    ckpt_ref: &[u8; 32],
    p: u128,
) -> [u8; 32] {
    let mut body = Vec::with_capacity(32 + 8 + 32 + 16);
    body.extend_from_slice(seed_instance);
    body.extend_from_slice(channel_id);
    body.extend_from_slice(ckpt_ref);
    body.extend_from_slice(&p.to_be_bytes()); // 16-byte BE
    labelled_hash("PayTPv1-entry", &body)
}

/// The settlement **net-leg** round binding (GAP-FILL **F6-h**) — the immutable,
/// sender-chosen memo a postpay net-leg (`0x02`) transfer carries so it **names the
/// round it settles** on the rail:
///
/// ```text
/// NET_MEMO = SHA-256("PayTPv1-net" ‖ 0x00 ‖ channel_id ‖ ckpt_ref)
/// ```
///
/// The creditor recomputes and checks it exactly as it checks the meed leg's memo
/// against [`claim_record_id`], closing the **net-leg hijack** (a debtor naming a
/// victim's transfer to the shared settlement pointer as its own leg). Unlike the
/// meed leg's claim-record key it does **not** commit `P`/amount: the net leg's
/// amount is matched against the round's recomputed `OUTPUTS`, and `ckpt_ref` is unique
/// per round, so `(channel_id, ckpt_ref)` alone ties a transfer to one settleable position.
pub fn settlement_net_memo(channel_id: &[u8; 8], ckpt_ref: &[u8; 32]) -> [u8; 32] {
    let mut body = Vec::with_capacity(8 + 32);
    body.extend_from_slice(channel_id);
    body.extend_from_slice(ckpt_ref);
    labelled_hash("PayTPv1-net", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn address_inputs_canonical_orders_vector() {
        let ai = AddressInputs {
            merchant_key: [0x11; 32],
            asset: "eip155:1/erc20:0xA0b8".to_string(),
            schema: 1,
            vector: vec![
                MeedVectorEntry {
                    role: 0x13,
                    bp: 10,
                    dest: "d3".into(),
                },
                MeedVectorEntry {
                    role: 0x10,
                    bp: 50,
                    dest: "d0".into(),
                },
            ],
            contract: 1,
            merchant_net: None,
        };
        // Canonicalizes regardless of input order → same bytes for same facts.
        let mut reordered = ai.clone();
        reordered.vector.reverse();
        assert_eq!(
            ai.canonical_bytes().unwrap(),
            reordered.canonical_bytes().unwrap()
        );
    }

    fn sample_inputs(merchant_net: Option<&str>) -> AddressInputs {
        AddressInputs {
            merchant_key: [0x11; 32],
            asset: "a".into(),
            schema: 1,
            vector: vec![MeedVectorEntry {
                role: 0x10,
                bp: 100,
                dest: "d".into(),
            }],
            contract: 1,
            merchant_net: merchant_net.map(|s| s.to_string()),
        }
    }

    #[test]
    fn seeds_differ_by_label() {
        // A split (commits its merchant-net seat) and an instance (meed-only) never
        // share an address — by the F4-a label AND by the split-only merchant_net field.
        let split = sample_inputs(Some("net"));
        let instance = sample_inputs(None);
        assert_ne!(
            split.seed_split().unwrap(),
            instance.seed_instance().unwrap()
        );
    }

    #[test]
    fn seed_split_binds_merchant_net() {
        // front-run closure: two splits identical EXCEPT the merchant-net seat
        // derive DIFFERENT addresses, so a substituted net destination can never occupy
        // the honest split the wallet re-derives and pays.
        let a = sample_inputs(Some("solana:dev:merchant-A"))
            .seed_split()
            .unwrap();
        let b = sample_inputs(Some("solana:dev:merchant-B"))
            .seed_split()
            .unwrap();
        assert_ne!(
            a, b,
            "the split address must commit the merchant-net destination"
        );
        // A split with no merchant-net is rejected (the pre-F4.1 gap is now a hard error).
        assert!(sample_inputs(None).seed_split().is_err());
        // An instance MUST NOT carry a merchant-net seat (diverges from the contract).
        assert!(sample_inputs(Some("x")).seed_instance().is_err());
    }

    #[test]
    fn entry_id_squat_derives_distinct_ids() {
        // F4-c mempool-squat closure: dust amount and wrong deadlines both land
        // distinct, orphaned ids — never the honest one.
        let si = [0xaa; 32];
        let nonce = [0xbb; 32];
        let honest = entry_id_purchase(&si, &nonce, 1_000_000, 100, 200, 30);
        let dust = entry_id_purchase(&si, &nonce, 1, 100, 200, 30);
        let wrong_deadline = entry_id_purchase(&si, &nonce, 1_000_000, 100, 999, 30);
        assert_ne!(honest, dust);
        assert_ne!(honest, wrong_deadline);
        assert_ne!(dust, wrong_deadline);
    }

    #[test]
    fn entry_and_claim_ids_match_svm_and_python_reference() {
        // F4-c cross-implementation conformance: the host derivation must
        // byte-match the on-chain SVM contract (contracts/) and an independent
        // Python reference. The same two constants are asserted in the LiteSVM
        // test `derivation_matches_independent_reference`; if any implementation's
        // preimage drifts, one of the two suites fails.
        let seed = [0xaau8; 32];
        let nonce = [0xbbu8; 32];
        let id = entry_id_purchase(&seed, &nonce, 1_000_000, 1_000_000_100, 1_000_004_000, 600);
        assert_eq!(
            hexs(&id),
            "2a78c23325dd2a55278153a71f5e7172774a956696491e1c79701cbde63fe893"
        );
        let cid = claim_record_id(&seed, &[0, 0, 0, 0, 0, 0, 0, 7], &[0xee; 32], 10_000);
        assert_eq!(
            hexs(&cid),
            "eba416a167e8d62cccd5b8783dc4fb50ecd56215fa82458a4f78e56390810f99"
        );
    }

    #[test]
    fn claim_record_id_is_windowless_and_p_keyed() {
        let si = [0xaa; 32];
        let cid = [0, 0, 0, 0, 0, 0, 0, 1];
        let ckpt = [0xcc; 32];
        let a = claim_record_id(&si, &cid, &ckpt, 100);
        let b = claim_record_id(&si, &cid, &ckpt, 101);
        assert_ne!(
            a, b,
            "distinct P → distinct id (dust squat lands an orphan)"
        );
        // Reference smoke: value is stable across calls.
        assert_eq!(a, claim_record_id(&si, &cid, &ckpt, 100));
        let _ = hexs(&a);
    }

    #[test]
    fn settlement_net_memo_binds_channel_and_ckpt() {
        let c1 = [0, 0, 0, 0, 0, 0, 0, 1];
        let c2 = [0, 0, 0, 0, 0, 0, 0, 2];
        let k1 = [0xcc; 32];
        let k2 = [0xdd; 32];
        // Distinct channel OR distinct checkpoint → distinct memo (the hijack bar:
        // a victim's transfer, bound to its own channel/round, cannot satisfy another's leg).
        assert_ne!(settlement_net_memo(&c1, &k1), settlement_net_memo(&c2, &k1));
        assert_ne!(settlement_net_memo(&c1, &k1), settlement_net_memo(&c1, &k2));
        // Stable across calls; deterministic.
        assert_eq!(settlement_net_memo(&c1, &k1), settlement_net_memo(&c1, &k1));
        // Domain-separated from the meed claim-record key: even at the SAME
        // (channel, ckpt) the two legs' rail memos never collide (labels differ).
        assert_ne!(
            settlement_net_memo(&c1, &k1).to_vec(),
            claim_record_id(&[0u8; 32], &c1, &k1, 0).to_vec()
        );
    }
}
