//! F10 conformance-corpus harness.
//!
//! Loads the JSON vector files from `conformance/` and drives `paytp-core`
//! against them. The vectors are the source of truth (F10.4): a failure here is
//! a code bug (for hand-derived vectors) or a spec D-entry — never a reason to
//! edit the vector.

use paytp_core::channel::trigger::{self, Trigger};
use paytp_core::{crypto, derive, envelope, fee, jcs, tlv, transcript};
use serde_json::Value;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/paytp-core ; the corpus is at the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .canonicalize()
        .expect("conformance dir exists")
}

fn load(name: &str) -> Value {
    let path = corpus_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn vectors(v: &Value) -> &Vec<Value> {
    v["vectors"].as_array().expect("vectors array")
}

fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn hex32(s: &str) -> [u8; 32] {
    hexb(s).try_into().expect("32 bytes")
}

fn hex8(s: &str) -> [u8; 8] {
    hexb(s).try_into().expect("8 bytes")
}

fn bigu(v: &Value) -> num_bigint::BigUint {
    v.as_str().unwrap().parse().expect("biguint")
}

// ---------------------------------------------------------------------------
// F1 encoding
// ---------------------------------------------------------------------------

#[test]
fn f1_encoding_corpus() {
    let file = load("f1-encoding.json");
    for v in vectors(&file) {
        let id = v["id"].as_str().unwrap();
        let class = v["class"].as_str().unwrap();
        let inputs = &v["inputs"];
        let expect = &v["expect"];
        let accept = expect["verdict"] == "accept";
        match class {
            "leb128" => {
                let bytes = hexb(inputs["bytes"].as_str().unwrap());
                match paytp_core::leb128::decode_exact(&bytes) {
                    Ok(val) => {
                        assert!(accept, "{id}: expected reject, got {val}");
                        assert_eq!(val.to_string(), expect["value"].as_str().unwrap(), "{id}");
                    }
                    Err(_) => assert!(!accept, "{id}: expected accept, got reject"),
                }
            }
            "uint" => {
                let bytes = hexb(inputs["bytes"].as_str().unwrap());
                match tlv::decode_uint_biguint(&bytes) {
                    Ok(val) => {
                        assert!(accept, "{id}: expected reject");
                        assert_eq!(val.to_string(), expect["value"].as_str().unwrap(), "{id}");
                    }
                    Err(_) => assert!(!accept, "{id}: expected accept"),
                }
            }
            "sint" => {
                let bytes = hexb(inputs["bytes"].as_str().unwrap());
                match tlv::decode_sint_i128(&bytes) {
                    Ok(val) => {
                        assert!(accept, "{id}: expected reject");
                        assert_eq!(val.to_string(), expect["value"].as_str().unwrap(), "{id}");
                    }
                    Err(_) => assert!(!accept, "{id}: expected accept"),
                }
            }
            "json_uint" => {
                let ok = jcs::validate_uint_string(inputs["string"].as_str().unwrap()).is_ok();
                assert_eq!(ok, accept, "{id}");
            }
            "json_sint" => {
                let ok = jcs::validate_sint_string(inputs["string"].as_str().unwrap()).is_ok();
                assert_eq!(ok, accept, "{id}");
            }
            "jcs_dup" => {
                let ok = jcs::parse_strict(inputs["json"].as_str().unwrap()).is_ok();
                assert_eq!(ok, accept, "{id}");
            }
            "framing" => {
                let bytes = hexb(inputs["bytes"].as_str().unwrap());
                let ok = tlv::parse_frames(&bytes, |o| tlv::Object::parse(o).map(|_| ())).is_ok();
                assert_eq!(ok, accept, "{id}");
            }
            other => panic!("{id}: unknown class {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// F1 crypto anchors
// ---------------------------------------------------------------------------

#[test]
fn f1_crypto_anchors() {
    let file = load("f1-crypto.json");
    for v in vectors(&file) {
        let id = v["id"].as_str().unwrap();
        let inputs = &v["inputs"];
        let want = v["expect"]["value"].as_str().unwrap();
        let got = match id {
            "f1-crypto-hs-001" => {
                hex::encode(crypto::h_commit(&hex32(inputs["s"].as_str().unwrap())))
            }
            "f1-crypto-slice-prefix-001" => {
                hex::encode(envelope::covered(envelope::DomainLabel::Slice, b""))
            }
            "f1-crypto-head0-001" => {
                let cid: [u8; 8] = hexb(inputs["channel_id"].as_str().unwrap())
                    .try_into()
                    .unwrap();
                hex::encode(transcript::head_0(&cid))
            }
            // Composition anchors (F10.2, generation-required) — independently
            // confirmed in tests/composition_independent.rs; consumed here too.
            "f1-crypto-bindsalt-001" => hex::encode(crypto::bind_salt(
                &hex32(inputs["payer_key"].as_str().unwrap()),
                &hex32(inputs["merchant_key"].as_str().unwrap()),
            )),
            "f1-crypto-ksession-001" => {
                let cid: [u8; 8] = hexb(inputs["channel_id"].as_str().unwrap())
                    .try_into()
                    .unwrap();
                hex::encode(crypto::k_session(
                    &hex32(inputs["s"].as_str().unwrap()),
                    &hex32(inputs["bind_salt"].as_str().unwrap()),
                    &cid,
                ))
            }
            "f1-crypto-subkey-001" => {
                let seq: u64 = inputs["seq"].as_str().unwrap().parse().unwrap();
                hex::encode(crypto::slice_subkey(
                    &hex32(inputs["k_session"].as_str().unwrap()),
                    seq,
                ))
            }
            "f1-crypto-slicemac-001" => {
                let seq: u64 = inputs["seq"].as_str().unwrap().parse().unwrap();
                let amt: u64 = inputs["amt_micro"].as_str().unwrap().parse().unwrap();
                let covered = paytp_core::slice::covered_bytes(seq, amt);
                let subkey = hex32(inputs["subkey"].as_str().unwrap());
                hex::encode(crypto::slice_tag(&subkey, &covered))
            }
            other => panic!("unknown crypto anchor {other}"),
        };
        assert_eq!(got, want, "{id}");
    }
}

// ---------------------------------------------------------------------------
// F4 derivation
// ---------------------------------------------------------------------------

#[test]
fn f4_derive_corpus() {
    let file = load("f4-derive.json");
    for v in vectors(&file) {
        let id = v["id"].as_str().unwrap();
        let i = &v["inputs"];
        assert_eq!(id, "f4-entry-id-001");
        let got = derive::entry_id_purchase(
            &hex32(i["seed_instance"].as_str().unwrap()),
            &hex32(i["nonce"].as_str().unwrap()),
            i["amt"].as_str().unwrap().parse().unwrap(),
            i["t_open"].as_str().unwrap().parse().unwrap(),
            i["t_lapse"].as_str().unwrap().parse().unwrap(),
            i["contest"].as_str().unwrap().parse().unwrap(),
        );
        assert_eq!(
            hex::encode(got),
            v["expect"]["value"].as_str().unwrap(),
            "{id}"
        );
    }
}

// ---------------------------------------------------------------------------
// F6 settlement reconciliation + triggers
// ---------------------------------------------------------------------------

fn u256_list(v: &Value) -> Vec<fee::U256> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().parse().unwrap())
        .collect()
}

fn u256(v: &Value) -> fee::U256 {
    v.as_str().unwrap().parse().unwrap()
}

fn rejected(expect: &Value) -> bool {
    expect["verdict"] == "reject"
}

#[test]
fn f6_settlement_corpus() {
    let file = load("f6-settlement.json");
    for v in vectors(&file) {
        let id = v["id"].as_str().unwrap();
        let class = v["class"].as_str().unwrap();
        let i = &v["inputs"];
        let e = &v["expect"];
        match class {
            "reconcile-meed" => {
                let got = fee::reconcile::outstanding_meed_per_role(
                    &u256_list(&i["accrued"]),
                    &u256_list(&i["settled_r"]),
                );
                match got {
                    Ok(out) => {
                        assert!(!rejected(e), "{id}: expected reject, got Ok");
                        let want: Vec<String> = e["value"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|x| x.as_str().unwrap().to_string())
                            .collect();
                        let got: Vec<String> = out.iter().map(|x| x.to_string()).collect();
                        assert_eq!(got, want, "{id}");
                    }
                    Err(_) => assert!(rejected(e), "{id}: expected Ok, got reject"),
                }
            }
            "reconcile-carve" => {
                let got = fee::reconcile::meed_carve(&u256_list(&i["accruals"]));
                assert_eq!(got.to_string(), e["value"].as_str().unwrap(), "{id}");
            }
            "reconcile-merchant-net" => {
                let got = fee::reconcile::outstanding_merchant_net(
                    &u256(&i["cum_total"]),
                    &u256_list(&i["accruals"]),
                    &u256(&i["net_legs_sum"]),
                    &u256(&i["funding_sum"]),
                );
                assert_eq!(got.to_string(), e["value"].as_str().unwrap(), "{id}");
            }
            "reconcile-prepay-deposit" => {
                let got = fee::reconcile::prepay_unconsumed_deposit(
                    &u256(&i["funding_sum"]),
                    &u256(&i["cum_total"]),
                );
                match got {
                    Ok(d) => {
                        assert!(!rejected(e), "{id}: expected reject, got Ok");
                        assert_eq!(d.to_string(), e["value"].as_str().unwrap(), "{id}");
                    }
                    Err(_) => assert!(rejected(e), "{id}: expected Ok, got reject"),
                }
            }
            "settleable" => {
                let got = trigger::settleable(
                    i["merchant_net"].as_str().unwrap().parse().unwrap(),
                    i["e_extinguished"].as_str().unwrap().parse().unwrap(),
                );
                assert_eq!(got, e["value"].as_bool().unwrap(), "{id}");
            }
            "trigger" => {
                let got = trigger::evaluate(
                    i["unsettled_value"].as_str().unwrap().parse().unwrap(),
                    i["settleable"].as_bool().unwrap(),
                    i["now"].as_str().unwrap().parse().unwrap(),
                    i["last_settle"].as_str().unwrap().parse().unwrap(),
                    i["th_value"].as_str().unwrap().parse().unwrap(),
                    i["th_time"].as_str().unwrap().parse().unwrap(),
                );
                let got = match got {
                    Trigger::None => "none",
                    Trigger::Value => "value",
                    Trigger::Time => "time",
                };
                assert_eq!(got, e["value"].as_str().unwrap(), "{id}");
            }
            "prepay-halt" => {
                let t = match i["trigger"].as_str().unwrap() {
                    "none" => Trigger::None,
                    "value" => Trigger::Value,
                    "time" => Trigger::Time,
                    other => panic!("{id}: unknown trigger {other}"),
                };
                assert_eq!(
                    trigger::prepay_halt(t),
                    e["value"].as_bool().unwrap(),
                    "{id}"
                );
            }
            "stillborn-checkpoint" => {
                // F6-e: build the stillborn synthetic checkpoint deterministically and
                // byte-pin its canonical bytes + reference (no authenticator TLVs).
                use paytp_core::channel::checkpoint::StillbornState;
                let accruals = i["accruals"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| (a["role"].as_u64().unwrap() as u8, bigu(&a["num"])))
                    .collect();
                let s = StillbornState {
                    channel_id: hex8(i["channel_id"].as_str().unwrap()),
                    prepay: i["prepay"].as_bool().unwrap(),
                    cum_total: bigu(&i["cum_total"]),
                    accruals,
                    settled_sum: bigu(&i["settled_sum"]),
                    net_legs_sum: bigu(&i["net_legs_sum"]),
                    funding_sum: bigu(&i["funding_sum"]),
                    timestamp: i["timestamp"].as_str().unwrap().parse().unwrap(),
                    prev_ref: hex32(i["prev_ref"].as_str().unwrap()),
                };
                let cp = s.synthetic_checkpoint().expect("synthetic checkpoint");
                let bal = if cp.balance_negative {
                    format!("-{}", cp.balance)
                } else {
                    cp.balance.to_string()
                };
                assert_eq!(bal, e["balance"].as_str().unwrap(), "{id} balance");
                assert_eq!(
                    hex::encode(cp.encode().unwrap()),
                    e["bytes"].as_str().unwrap(),
                    "{id} bytes"
                );
                assert_eq!(
                    hex::encode(cp.synthetic_reference().unwrap()),
                    e["reference"].as_str().unwrap(),
                    "{id} reference"
                );
            }
            "watermark-advance" => {
                // The Option W per-channel meed watermark advance (F6-o), pinned via the SAME
                // shared f7 arithmetic the MeedInstance + the on-chain kit both run: the
                // OWN-CUMULATIVE target `floor((Σaccrued − Σimported_settled)/1e4)`, the F6.2 delta
                // (0 on an idempotent re-advance), the F7-d/F7.3 per-DESTINATION split (roles
                // sharing a destination floor once on `bp_d = Σ_r bp_r`), and the bounded §10.2
                // chain-boundary residue — with `target = Σ split + residue` (the ≤1µ/hop dust
                // the F6.6 amendment documents; NOT a conservation break).
                let accrued = u256_list(&i["accrued"]);
                let imported = u256_list(&i["imported_settled"]);
                let funded_before = u256(&i["funded_p_before"]);
                let bps: Vec<u32> = i["bps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|b| b.as_u64().unwrap() as u32)
                    .collect();
                let bp_total: u32 = bps.iter().sum();
                let outstanding =
                    fee::reconcile::outstanding_meed_per_role(&accrued, &imported).unwrap();
                let target = fee::reconcile::meed_carve(&outstanding);
                assert_eq!(
                    target.to_string(),
                    e["target_p"].as_str().unwrap(),
                    "{id} target_p"
                );
                let delta = if target > funded_before {
                    target - funded_before
                } else {
                    fee::U256::ZERO
                };
                assert_eq!(
                    delta.to_string(),
                    e["delta"].as_str().unwrap(),
                    "{id} delta"
                );
                // Aggregate by DESTINATION before flooring (F7-d/F7.3): `dests[r]` is the
                // destination index role r pays; absent ⇒ all-distinct (identity). Each
                // destination floors ONCE on `bp_d = Σ_r bp_r` — roles sharing a dest never floor
                // independently (per-role flooring would strand a sub-unit; the F6-o↔F7-d fix).
                // The `payouts` array is per-destination, indexed by destination id.
                let dests: Vec<usize> = match i.get("dests") {
                    Some(v) => v
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|d| d.as_u64().unwrap() as usize)
                        .collect(),
                    None => (0..bps.len()).collect(),
                };
                let ndest = dests.iter().copied().max().map(|m| m + 1).unwrap_or(0);
                let mut bp_by_dest = vec![0u32; ndest];
                for (r, &d) in dests.iter().enumerate() {
                    bp_by_dest[d] += bps[r];
                }
                let want_payouts = e["payouts"].as_array().unwrap();
                let mut distributed = fee::U256::ZERO;
                for (d, &bp) in bp_by_dest.iter().enumerate() {
                    // What destination d already holds at `funded_before`, and its cumulative
                    // entitlement at `target`; the advance tops up by the difference (F7.3).
                    let paid_d = fee::claimable_d(&funded_before, bp, bp_total, &fee::U256::ZERO);
                    let payout = fee::claimable_d(&target, bp, bp_total, &paid_d);
                    assert_eq!(
                        payout.to_string(),
                        want_payouts[d].as_str().unwrap(),
                        "{id} payout[{d}]"
                    );
                    distributed += fee::claimable_d(&target, bp, bp_total, &fee::U256::ZERO);
                }
                let residue = target - distributed;
                assert_eq!(
                    residue.to_string(),
                    e["residue"].as_str().unwrap(),
                    "{id} residue"
                );
            }
            other => panic!("{id}: unknown class {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// F7 arithmetic
// ---------------------------------------------------------------------------

#[test]
fn f7_arithmetic_corpus() {
    let file = load("f7-arithmetic.json");
    for v in vectors(&file) {
        let id = v["id"].as_str().unwrap();
        let i = &v["inputs"];
        if id.starts_with("f7-divide") {
            let n_r: Vec<fee::U256> = i["n_r"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().parse().unwrap())
                .collect();
            let p: u128 = i["rate"]["p"].as_str().unwrap().parse().unwrap();
            let q: u128 = i["rate"]["q"].as_str().unwrap().parse().unwrap();
            let d = fee::divide_round(&n_r, &fee::Rate::new(p, q).unwrap()).unwrap();
            let e = &v["expect"];
            assert_eq!(d.p.to_string(), e["p"].as_str().unwrap(), "{id} P");
            assert_eq!(d.e.to_string(), e["e"].as_str().unwrap(), "{id} E");
            assert_eq!(d.leg, e["leg"].as_bool().unwrap(), "{id} leg");
            let want_er: Vec<String> = e["e_r"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let got_er: Vec<String> = d.e_r.iter().map(|x| x.to_string()).collect();
            assert_eq!(got_er, want_er, "{id} E_r");
        } else if id.starts_with("f7-instance") {
            let got = fee::claimable_d(
                &i["v_received"].as_str().unwrap().parse().unwrap(),
                i["bp_d"].as_str().unwrap().parse().unwrap(),
                i["bp_total"].as_str().unwrap().parse().unwrap(),
                &i["paid_d"].as_str().unwrap().parse().unwrap(),
            );
            assert_eq!(
                got.to_string(),
                v["expect"]["value"].as_str().unwrap(),
                "{id}"
            );
        } else {
            panic!("{id}: unknown F7 vector shape");
        }
    }
}
