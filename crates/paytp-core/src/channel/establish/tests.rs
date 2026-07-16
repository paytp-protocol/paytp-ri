//! Object-level tests for the establishment wire objects (F2.2/F5.2–F5.4) — sign/
//! encode/parse roundtrips, the presence rules, the reserved-`0x11` rejection, the
//! seal round-trip + `H(s)` commitment, and binding determinism (Change A).

use super::*;
use crate::crypto;

fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = [seed; 32];
    (sk, crypto::ed25519_public(&sk))
}

fn sample_auth(mode: u8, denom: &str, baseline: &str, hs: [u8; 32]) -> ChannelAuth {
    let cross = denom != baseline;
    ChannelAuth {
        payer_key: [0x11; 32],
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        merchant_key: [0x22; 32],
        denom: denom.into(),
        mode,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: if mode == MODE_PREPAY {
            Some("solana:dev:refundacct".into())
        } else {
            None
        },
        baseline_net: "solana:dev".into(),
        rate_source: if cross {
            Some("registry:oracle-1".into())
        } else {
            None
        },
        rate_dev: if cross { Some(50) } else { None },
        schema: 1,
        vector: vec![
            VectorEntry {
                role: 0x10,
                bp: 50,
                dest: "solana:dev:il".into(),
            },
            VectorEntry {
                role: 0x12,
                bp: 50,
                dest: "solana:dev:wallet".into(),
            },
        ],
        registry_v: 5,
        hs,
        predecessor: None,
        timestamp: 1_700_000_000,
        baseline_asset: baseline.into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    }
}

#[test]
fn channel_auth_roundtrip_prepay_postpay_crosscurrency() {
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    for auth0 in [
        sample_auth(MODE_PREPAY, "solana:dev/usdc", "solana:dev/usdc", hs),
        sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs),
        sample_auth(MODE_POSTPAY, "eip155:1/eur", "solana:dev/usdc", hs), // cross-currency
    ] {
        let mut auth = auth0.clone();
        auth.payer_key = ppk;
        auth.sign(&psk).unwrap();
        auth.verify().unwrap();
        let bytes = auth.encode().unwrap();
        let parsed = ChannelAuth::parse(&bytes).unwrap();
        assert_eq!(parsed, auth);
        // AUTH_HASH is stable across encode/parse.
        assert_eq!(parsed.auth_hash().unwrap(), auth.auth_hash().unwrap());
    }
}

#[test]
fn channel_auth_presence_rules() {
    let hs = crypto::h_commit(&[9u8; 32]);
    // Postpay carrying a REFUND_PTR is malformed.
    let mut bad = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    bad.refund_ptr = Some("x".into());
    assert!(bad.encode().is_err());
    // Prepay missing REFUND_PTR is malformed.
    let mut bad = sample_auth(MODE_PREPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    bad.refund_ptr = None;
    assert!(bad.encode().is_err());
    // DENOM == BASELINE but a RATE_SOURCE present → malformed.
    let mut bad = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    bad.rate_source = Some("r".into());
    bad.rate_dev = Some(1);
    assert!(bad.encode().is_err());
    // DENOM != BASELINE but RATE_SOURCE absent → malformed.
    let mut bad = sample_auth(MODE_POSTPAY, "eip155:1/eur", "solana:dev/usdc", hs);
    bad.rate_source = None;
    bad.rate_dev = None;
    assert!(bad.encode().is_err());
}

#[test]
fn reserved_0x11_rejected() {
    // A CHANNEL_AUTH carrying the reserved 0x11 (former CONN_BINDING) is malformed
    // (F1.6): rebuild the object with a 0x11 field and confirm parse rejects it.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    auth.payer_key = ppk;
    auth.sign(&psk).unwrap();
    let bytes = auth.encode().unwrap();
    let obj = crate::tlv::Object::parse(&bytes).unwrap();
    let mut fields = obj.fields().to_vec();
    fields.push(crate::tlv::Field::new(0x11, false, vec![0u8; 32])); // the reserved field
    let extended = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(
        ChannelAuth::parse(&extended).is_err(),
        "0x11 presence is malformed"
    );
}

#[test]
fn seal_roundtrip_and_hs_commitment() {
    // The payer seals s to the merchant's enc_key (aad = canonical CHANNEL_AUTH);
    // the merchant unseals and H(s) matches the commitment.
    let (psk, ppk) = keys(1);
    let (enc_sk, enc_pk) = crypto::x25519_keypair_from_seed(&[7u8; 32]);
    let s = [0x5a; 32];
    let hs = crypto::h_commit(&s);
    let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    auth.payer_key = ppk;
    auth.sign(&psk).unwrap();

    let open = ChannelOpen::build(auth.clone(), &enc_pk, &s).unwrap();
    let bytes = open.encode().unwrap();
    let parsed = ChannelOpen::parse(&bytes).unwrap();
    assert_eq!(parsed.auth, auth);
    // Merchant unseals with its enc secret + the aad the parsed auth reproduces.
    let recovered = crypto::open_session_secret(
        &enc_sk,
        &parsed.seal,
        &parsed.auth.canonical_content().unwrap(),
    )
    .unwrap();
    assert_eq!(recovered, s);
    assert_eq!(
        crypto::h_commit(&recovered),
        parsed.auth.hs,
        "H(s) commitment holds"
    );
}

#[test]
fn artifact_accept_and_reject() {
    let (msk, mpk) = keys(2);
    let (_esk, enc_pk) = crypto::x25519_keypair_from_seed(&[7u8; 32]);
    let cert = [0xcc; 32];
    let mut art = BindingArtifact {
        host: "api.example.com".into(),
        cert_hash: cert,
        enc_key: enc_pk,
        not_before: 1_000,
        not_after: 2_000,
        sig: None,
    };
    art.sign(&msk).unwrap();
    let parsed = BindingArtifact::parse(&art.encode().unwrap()).unwrap();
    assert_eq!(parsed, art);
    // Accepts for the right cert + host + a current time, and yields the AUTHENTICATED
    // (merchant_key, host, enc_key) triple — the ONLY provenance a wallet may scope/seal to
    // (structural fix: an unverified enc_key/host can never reach the open path).
    let binding = parsed
        .accept(&mpk, &cert, "api.example.com", 1_500)
        .unwrap();
    assert_eq!(binding.merchant_key(), &mpk);
    assert_eq!(binding.host(), "api.example.com");
    assert_eq!(binding.enc_key(), &enc_pk);
    // Wrong cert / wrong host / expired / wrong key all reject.
    assert!(parsed
        .accept(&mpk, &[0xdd; 32], "api.example.com", 1_500)
        .is_err());
    assert!(parsed
        .accept(&mpk, &cert, "evil.example.com", 1_500)
        .is_err());
    assert!(parsed
        .accept(&mpk, &cert, "api.example.com", 3_000)
        .is_err());
    assert!(parsed
        .accept(&[0x33; 32], &cert, "api.example.com", 1_500)
        .is_err());
}

#[test]
fn ack_request_funding_proof_roundtrip() {
    let (psk, ppk) = keys(1);
    let (msk, mpk) = keys(2);
    let mut ack = ChannelAck {
        auth_hash: [0xaa; 32],
        settle_ptr: "solana:dev:settle".into(),
        sig: None,
    };
    ack.sign(&msk).unwrap();
    ack.verify(&mpk).unwrap();
    assert_eq!(ChannelAck::parse(&ack.encode().unwrap()).unwrap(), ack);

    let mut req = AckRequest {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        timestamp: 1_700_000_000,
        sig: None,
    };
    req.sign(&psk).unwrap();
    req.verify(&ppk).unwrap();
    assert_eq!(AckRequest::parse(&req.encode().unwrap()).unwrap(), req);

    let mut fp = FundingProof {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        auth_hash: [0xaa; 32],
        rail: "solana:dev".into(),
        tx_ref: "sig123".into(),
        amount: 500_000,
        sig: None,
    };
    fp.sign(&psk).unwrap();
    fp.verify(&ppk).unwrap();
    assert_eq!(FundingProof::parse(&fp.encode().unwrap()).unwrap(), fp);
}

#[test]
fn zero_channel_id_rejected() {
    // CHANNEL_ID is non-zero (F5.2): reject on both emit and parse.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    auth.payer_key = ppk;
    auth.channel_id = [0u8; 8];
    assert!(
        auth.sign(&psk).is_err(),
        "emitting a zero CHANNEL_ID is malformed"
    );
    // And a wire object carrying a zero CHANNEL_ID does not parse.
    let mut good = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    good.payer_key = ppk;
    good.sign(&psk).unwrap();
    let obj = crate::tlv::Object::parse(&good.encode().unwrap()).unwrap();
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x01 {
                crate::tlv::Field::new(0x01, false, vec![0u8; 8])
            } else {
                f.clone()
            }
        })
        .collect();
    let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(ChannelAuth::parse(&tampered).is_err());
}

#[test]
fn oversized_u64_field_rejected() {
    // A minimally-encoded integer that exceeds u64 (here TIMESTAMP = 2^64) is a
    // field-domain error, never silently truncated to a signed/sealed value.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    auth.payer_key = ppk;
    auth.sign(&psk).unwrap();
    let obj = crate::tlv::Object::parse(&auth.encode().unwrap()).unwrap();
    // 0x13 is TIMESTAMP; replace its value with a 9-byte 2^64 (minimal, > u64::MAX).
    let big = crate::tlv::encode_uint_u128(1u128 << 64);
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x13 {
                crate::tlv::Field::new(0x13, false, big.clone())
            } else {
                f.clone()
            }
        })
        .collect();
    let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(ChannelAuth::parse(&tampered).is_err());
}

#[test]
fn artifact_not_before_after_over_2_53_rejected() {
    // F1-l: the binding artifact's NOT_BEFORE/NOT_AFTER are time fields
    // capped at 2⁵³ − 1. A value of 2⁵³ (valid u64, out of the time domain) is rejected
    // at parse, for each of the two fields independently.
    let (msk, _mpk) = keys(2);
    let (_esk, enc_pk) = crypto::x25519_keypair_from_seed(&[7u8; 32]);
    for field_num in [0x03u8, 0x04u8] {
        let mut art = BindingArtifact {
            host: "api.example.com".into(),
            cert_hash: [0xcc; 32],
            enc_key: enc_pk,
            not_before: 1_000,
            not_after: 2_000,
            sig: None,
        };
        art.sign(&msk).unwrap();
        let obj = crate::tlv::Object::parse(&art.encode().unwrap()).unwrap();
        let over = crate::tlv::encode_uint_u128(1u128 << 53);
        let fields: Vec<_> = obj
            .fields()
            .iter()
            .map(|f| {
                if f.type_num == field_num {
                    crate::tlv::Field::new(field_num, false, over.clone())
                } else {
                    f.clone()
                }
            })
            .collect();
        let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
        assert!(
            BindingArtifact::parse(&tampered).is_err(),
            "artifact time field 0x{field_num:02x} = 2^53 must be rejected (F1-l)"
        );
    }
}

#[test]
fn time_field_over_2_53_rejected_but_boundary_accepted() {
    // F1-l: time fields (TH_TIME 0x08, TIMESTAMP 0x13) are capped at the
    // IEEE-safe bound 2⁵³ − 1, NOT the raw u64 range. A value in (2⁵³, 2⁶⁴ − 1] — a
    // valid u64 the old raw `decode_uint_u64` accepted — must now be rejected at parse
    // (receive-side strictness), so a strict F1-l peer and the RI never diverge and F8
    // window sums stay overflow-safe. The exact boundary 2⁵³ − 1 stays accepted.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let over = crate::tlv::encode_uint_u128(1u128 << 53); // 2⁵³, minimal, valid u64, OUT of domain
    let boundary = crate::tlv::encode_uint_u128((1u128 << 53) - 1); // 2⁵³ − 1, max in-domain
    for field_num in [0x08u8, 0x13u8] {
        // Over-domain (2⁵³) is rejected at parse.
        let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
        auth.payer_key = ppk;
        auth.sign(&psk).unwrap();
        let obj = crate::tlv::Object::parse(&auth.encode().unwrap()).unwrap();
        let fields: Vec<_> = obj
            .fields()
            .iter()
            .map(|f| {
                if f.type_num == field_num {
                    crate::tlv::Field::new(field_num, false, over.clone())
                } else {
                    f.clone()
                }
            })
            .collect();
        let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
        assert!(
            ChannelAuth::parse(&tampered).is_err(),
            "time field 0x{field_num:02x} = 2^53 must be rejected (F1-l)"
        );
        // The exact boundary 2⁵³ − 1 still parses (grammar/domain both pass).
        let obj2 = crate::tlv::Object::parse(&auth.encode().unwrap()).unwrap();
        let fields2: Vec<_> = obj2
            .fields()
            .iter()
            .map(|f| {
                if f.type_num == field_num {
                    crate::tlv::Field::new(field_num, false, boundary.clone())
                } else {
                    f.clone()
                }
            })
            .collect();
        let ok = crate::tlv::Object::from_fields(fields2).unwrap().encode();
        assert!(
            ChannelAuth::parse(&ok).is_ok(),
            "time field 0x{field_num:02x} = 2^53 − 1 must be accepted (F1-l boundary)"
        );
    }
}

#[test]
fn control_char_in_text_field_rejected() {
    // F1-g: a signed CHANNEL_AUTH cannot smuggle a control byte into a text field
    // (here DENOM). Parse must reject it, not pass it through to the data layer.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut auth = sample_auth(MODE_POSTPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    auth.payer_key = ppk;
    auth.sign(&psk).unwrap();
    let obj = crate::tlv::Object::parse(&auth.encode().unwrap()).unwrap();
    // 0x03 is DENOM; inject a NUL control byte.
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x03 {
                crate::tlv::Field::new(0x03, false, b"sol\x00ana".to_vec())
            } else {
                f.clone()
            }
        })
        .collect();
    let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(ChannelAuth::parse(&tampered).is_err());
}

// Rebuild a signed sample_auth's wire bytes with one field's value swapped — for
// exercising the PARSE (receive) boundary with a non-conformant field.
fn auth_with_field_swapped(
    psk: &[u8; 32],
    ppk: [u8; 32],
    denom: &str,
    baseline: &str,
    type_num: u8,
    value: Vec<u8>,
) -> Vec<u8> {
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut auth = sample_auth(MODE_POSTPAY, denom, baseline, hs);
    auth.payer_key = ppk;
    auth.sign(psk).unwrap();
    let obj = crate::tlv::Object::parse(&auth.encode().unwrap()).unwrap();
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == type_num {
                crate::tlv::Field::new(type_num, false, value.clone())
            } else {
                f.clone()
            }
        })
        .collect();
    crate::tlv::Object::from_fields(fields).unwrap().encode()
}

#[test]
fn channel_auth_rejects_noncaip_asset_and_network_fields() {
    // F5.2/F5.3/F9: DENOM/BASELINE_ASSET are CAIP asset ids and BASELINE_NET
    // a CAIP-2 chain id — enforced structurally (not only F1-g text) on emit AND parse.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);

    // Emit side: a bare-token DENOM/BASELINE_ASSET cannot be signed/encoded.
    let mut bad = sample_auth(MODE_POSTPAY, "usd", "usd", hs);
    bad.payer_key = ppk;
    assert!(
        bad.sign(&psk).is_err(),
        "a bare-token asset id is malformed on emit"
    );

    // Parse side: BASELINE_NET (0x0A) swapped to a non-CAIP-2 value is rejected.
    let wire = auth_with_field_swapped(
        &psk,
        ppk,
        "solana:dev/usdc",
        "solana:dev/usdc",
        0x0A,
        b"not-caip2".to_vec(),
    );
    assert!(
        ChannelAuth::parse(&wire).is_err(),
        "non-CAIP-2 BASELINE_NET rejected at parse"
    );

    // Parse side: DENOM (0x03) swapped to a bare token on a cross-currency auth (rate
    // present, so the presence rule still holds and the grammar check is what fires).
    let wire = auth_with_field_swapped(
        &psk,
        ppk,
        "eip155:1/eur",
        "solana:dev/usdc",
        0x03,
        b"usd".to_vec(),
    );
    assert!(
        ChannelAuth::parse(&wire).is_err(),
        "bare-token DENOM rejected at parse"
    );
}

#[test]
fn channel_auth_rejects_malformed_refund_ptr() {
    // F9.1: a prepay REFUND_PTR must be a destination pointer.
    let (psk, ppk) = keys(1);
    let hs = crypto::h_commit(&[9u8; 32]);
    let mut bad = sample_auth(MODE_PREPAY, "solana:dev/usdc", "solana:dev/usdc", hs);
    bad.payer_key = ppk;
    bad.refund_ptr = Some("not a pointer".into());
    assert!(
        bad.sign(&psk).is_err(),
        "a malformed REFUND_PTR is rejected on emit"
    );
}

#[test]
fn channel_ack_rejects_malformed_settle_ptr() {
    // F9.1: SETTLE_PTR must be a destination pointer, on emit and parse.
    let (msk, _mpk) = keys(2);
    let mut bad = ChannelAck {
        auth_hash: [0xaa; 32],
        settle_ptr: "not a pointer".into(),
        sig: None,
    };
    assert!(
        bad.sign(&msk).is_err(),
        "a malformed SETTLE_PTR is rejected on emit"
    );

    // Parse side: a good ack's SETTLE_PTR (0x01) swapped to a bare token.
    let mut good = ChannelAck {
        auth_hash: [0xaa; 32],
        settle_ptr: "solana:dev:settle".into(),
        sig: None,
    };
    good.sign(&msk).unwrap();
    let obj = crate::tlv::Object::parse(&good.encode().unwrap()).unwrap();
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x01 {
                crate::tlv::Field::new(0x01, false, b"usd".to_vec())
            } else {
                f.clone()
            }
        })
        .collect();
    let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(
        ChannelAck::parse(&tampered).is_err(),
        "malformed SETTLE_PTR rejected at parse"
    );
}

#[test]
fn funding_proof_rejects_malformed_rail() {
    // F5.4/F9.1: RAIL must be a rail id (CAIP-2 or `x-` adapter), on emit
    // and parse — even though on_funding ignores the value (the adapter is authoritative).
    let (psk, _ppk) = keys(1);
    let mut bad = FundingProof {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        auth_hash: [0xaa; 32],
        rail: "r".into(),
        tx_ref: "sig123".into(),
        amount: 500_000,
        sig: None,
    };
    assert!(
        bad.sign(&psk).is_err(),
        "a malformed RAIL is rejected on emit"
    );

    // Parse side: a good proof's RAIL (0x02) swapped to a bare token.
    let mut good = FundingProof {
        channel_id: [0, 0, 0, 0, 0, 0, 0, 7],
        auth_hash: [0xaa; 32],
        rail: "solana:dev".into(),
        tx_ref: "sig123".into(),
        amount: 500_000,
        sig: None,
    };
    good.sign(&psk).unwrap();
    let obj = crate::tlv::Object::parse(&good.encode().unwrap()).unwrap();
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x02 {
                crate::tlv::Field::new(0x02, false, b"r".to_vec())
            } else {
                f.clone()
            }
        })
        .collect();
    let tampered = crate::tlv::Object::from_fields(fields).unwrap().encode();
    assert!(
        FundingProof::parse(&tampered).is_err(),
        "malformed RAIL rejected at parse"
    );
}

#[test]
fn artifact_host_must_be_normalized() {
    // F2.4: a non-lowercase-ASCII HOST is rejected, never repaired.
    let (msk, _mpk) = keys(2);
    let (_esk, enc_pk) = crypto::x25519_keypair_from_seed(&[7u8; 32]);
    let mut art = BindingArtifact {
        host: "API.Example.com".into(), // uppercase → not normalized
        cert_hash: [0xcc; 32],
        enc_key: enc_pk,
        not_before: 1_000,
        not_after: 2_000,
        sig: None,
    };
    assert!(
        art.sign(&msk).is_err(),
        "a non-normalized HOST is malformed"
    );
}

#[test]
fn artifact_validity_applies_skew() {
    // F8.2: current iff NOT_BEFORE − SKEW ≤ now ≤ NOT_AFTER + SKEW (±300 s).
    let (msk, mpk) = keys(2);
    let (_esk, enc_pk) = crypto::x25519_keypair_from_seed(&[7u8; 32]);
    let mut art = BindingArtifact {
        host: "api.example.com".into(),
        cert_hash: [0xcc; 32],
        enc_key: enc_pk,
        not_before: 1_000,
        not_after: 2_000,
        sig: None,
    };
    art.sign(&msk).unwrap();
    // 299 s before NOT_BEFORE and 299 s after NOT_AFTER are still current.
    art.accept(&mpk, &[0xcc; 32], "api.example.com", 1_000 - 299)
        .unwrap();
    art.accept(&mpk, &[0xcc; 32], "api.example.com", 2_000 + 299)
        .unwrap();
    // Beyond the skew, not current.
    assert!(art
        .accept(&mpk, &[0xcc; 32], "api.example.com", 1_000 - 301)
        .is_err());
    assert!(art
        .accept(&mpk, &[0xcc; 32], "api.example.com", 2_000 + 301)
        .is_err());
}

#[test]
fn binding_determinism_and_isolation() {
    // Change A: both ends derive the same K_session from the public BindSalt;
    // distinct per (payer, merchant) and per channel_id.
    let p1 = [0x11; 32];
    let m1 = [0x22; 32];
    let s = [0x5a; 32];
    let cid = [0, 0, 0, 0, 0, 0, 0, 7];
    let salt = crypto::bind_salt(&p1, &m1);
    let ks = crypto::k_session(&s, &salt, &cid);
    // Deterministic from public inputs.
    assert_eq!(
        ks,
        crypto::k_session(&s, &crypto::bind_salt(&p1, &m1), &cid)
    );
    // Distinct per relationship.
    assert_ne!(
        ks,
        crypto::k_session(&s, &crypto::bind_salt(&[0x99; 32], &m1), &cid)
    );
    // Distinct per channel.
    assert_ne!(ks, crypto::k_session(&s, &salt, &[0, 0, 0, 0, 0, 0, 0, 8]));
}

#[test]
fn close_roundtrip_and_chain_intent_is_payer_only() {
    // F5.6 / F5-l: a payer-signed CLOSE can express chain intent; a merchant-signed
    // one cannot, and a receiver ignores the byte on a non-payer CLOSE.
    let (psk, ppk) = keys(1);
    let (msk, mpk) = keys(2);
    let ckpt = [0xcd; 32];

    let cid = [0u8, 0, 0, 0, 0, 0, 0, 7];
    let mut c = Close {
        channel_id: cid,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    c.sign(&psk).unwrap();
    assert_eq!(Close::parse(&c.encode().unwrap()).unwrap(), c);
    let d = c.accept(&cid, &ppk, &mpk).unwrap();
    assert!(d.by_payer && d.chain_intent);

    // A CLOSE for a DIFFERENT channel is rejected (cannot settle this one).
    assert!(c.accept(&[0, 0, 0, 0, 0, 0, 0, 8], &ppk, &mpk).is_err());

    // Merchant CLOSE carrying chain_intent=true → the intent is IGNORED (F5-l).
    let mut m = Close {
        channel_id: cid,
        ckpt_ref: ckpt,
        chain_intent: true,
        sig: None,
    };
    m.sign(&msk).unwrap();
    let dm = m.accept(&cid, &ppk, &mpk).unwrap();
    assert!(
        !dm.by_payer && !dm.chain_intent,
        "merchant chain intent ignored"
    );

    // A CLOSE signed by neither party is rejected.
    let mut bad = Close {
        channel_id: cid,
        ckpt_ref: ckpt,
        chain_intent: false,
        sig: None,
    };
    bad.sign(&[0x33; 32]).unwrap();
    assert!(bad.accept(&cid, &ppk, &mpk).is_err());

    // A non-0/1 CHAIN_INTENT byte is malformed.
    let obj = crate::tlv::Object::parse(&c.encode().unwrap()).unwrap();
    let fields: Vec<_> = obj
        .fields()
        .iter()
        .map(|f| {
            if f.type_num == 0x02 {
                crate::tlv::Field::new(0x02, false, vec![0x02])
            } else {
                f.clone()
            }
        })
        .collect();
    assert!(Close::parse(&crate::tlv::Object::from_fields(fields).unwrap().encode()).is_err());
}
