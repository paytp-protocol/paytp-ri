//! F5.6 settlement-message codec tests — sign/encode/parse roundtrips, the
//! `PROPOSAL_HASH` (F5-h), and the ordering/presence invariants.

use super::*;
use crate::crypto;

fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = [seed; 32];
    (sk, crypto::ed25519_public(&sk))
}

const CID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];
const CKPT: [u8; 32] = [0xcd; 32];

fn u(n: u32) -> BigUint {
    BigUint::from(n)
}

fn instance_leg() -> InstanceLeg {
    InstanceLeg {
        amount: u(10_000),
        credited: vec![],
        extinguished: vec![(0x10, u(5_000)), (0x12, u(5_000))],
    }
}

#[test]
fn deterministic_propose_single_signed_roundtrip() {
    // DENOM = BASELINE: no CONVERSION, single-signed by the debtor (payer, postpay).
    let (psk, ppk) = keys(1);
    let mut p = SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![Output {
            amount: u(990_000),
            asset: "solana:dev/usdc".into(),
            dest: "solana:dev:merchant".into(),
        }],
        instance_leg: Some(instance_leg()),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    p.sign_payer(&psk).unwrap();
    p.verify_payer(&ppk).unwrap();
    let h = p.proposal_hash().unwrap();
    let parsed = SettlementPropose::parse(&p.encode().unwrap()).unwrap();
    assert_eq!(parsed, p);
    assert_eq!(
        parsed.proposal_hash().unwrap(),
        h,
        "PROPOSAL_HASH stable across parse"
    );
    assert!(
        parsed.sig_merchant.is_none(),
        "deterministic round is single-signed"
    );
}

#[test]
fn cross_currency_propose_both_signed_roundtrip() {
    // DENOM != BASELINE: carries CONVERSION and is both-signed.
    let (psk, ppk) = keys(1);
    let (msk, mpk) = keys(2);
    let mut p = SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![Output {
            amount: u(500),
            asset: "eip155:1/eur".into(),
            dest: "eip155:1:merchant".into(),
        }],
        instance_leg: Some(instance_leg()),
        conversion: Some(Conversion {
            rate: "0.3".into(),
            rate_time: 1_700_000_000,
            rate_exp: 1_700_000_600,
            rate_grace: 300,
        }),
        sig_payer: None,
        sig_merchant: None,
    };
    p.sign_payer(&psk).unwrap();
    p.sign_merchant(&msk).unwrap();
    p.verify_payer(&ppk).unwrap();
    p.verify_merchant(&mpk).unwrap();
    assert_eq!(SettlementPropose::parse(&p.encode().unwrap()).unwrap(), p);
    // PROPOSAL_HASH is stable across parse for the completed both-signed object.
    let h = p.proposal_hash().unwrap();
    assert_eq!(
        SettlementPropose::parse(&p.encode().unwrap())
            .unwrap()
            .proposal_hash()
            .unwrap(),
        h
    );
    // PROPOSAL_HASH is over the complete bytes (F5-h) — a different signature set
    // yields a different hash. (Ensuring a both-signed round is countersigned before
    // the hash is treated as binding is the driver's job, F6.5, not the codec's.)
    let mut single = p.clone();
    single.sig_merchant = None;
    assert_ne!(single.proposal_hash().unwrap(), h);
}

#[test]
fn outputs_discipline_enforced() {
    let base = |outputs: Vec<Output>| SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs,
        instance_leg: None,
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    // Zero-amount output is malformed (must be omitted).
    assert!(base(vec![Output {
        amount: u(0),
        asset: "a".into(),
        dest: "d".into()
    }])
    .encode()
    .is_err());
    // Not sorted ascending by (dest, asset) → malformed.
    let unsorted = vec![
        Output {
            amount: u(1),
            asset: "a".into(),
            dest: "z".into(),
        },
        Output {
            amount: u(1),
            asset: "a".into(),
            dest: "a".into(),
        },
    ];
    assert!(base(unsorted).encode().is_err());
    // Duplicate (dest, asset) → malformed.
    let dup = vec![
        Output {
            amount: u(1),
            asset: "a".into(),
            dest: "d".into(),
        },
        Output {
            amount: u(2),
            asset: "a".into(),
            dest: "d".into(),
        },
    ];
    assert!(base(dup).encode().is_err());
}

#[test]
fn instance_leg_extinguished_must_be_ascending() {
    // Parse rejects a non-ascending EXTINGUISHED list. Build a valid leg, encode,
    // then rebuild the nested object with the roles swapped and confirm parse fails.
    let leg = InstanceLeg {
        amount: u(10_000),
        credited: vec![CreditedLeg {
            kind: 0x01,
            rail: "solana:dev".into(),
            reference: "meedref".into(),
            finality: "final".into(),
        }],
        extinguished: vec![(0x12, u(3)), (0x10, u(7))], // descending — malformed
    };
    let p = SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![],
        instance_leg: Some(leg),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    // encode now validates the nested leg, so the non-canonical object is refused
    // at emit — a signer can never commit to bytes every peer rejects.
    assert!(p.encode().is_err());
}

#[test]
fn instance_leg_allows_zero_share_role() {
    // F7.3: a zero-share role legitimately extinguishes 0 while the round makes
    // progress overall (ΣE_r ≥ 1). The recompute emits the full zero-inclusive role vector,
    // so such a leg MUST encode, round-trip, and validate — a strict `each E_r > 0` rule
    // would make an otherwise-valid round unsettleable (and F5.4's mandatory 4-role vector
    // makes a per-round zero-share role reachable).
    let (psk, _ppk) = keys(1);
    let mut p = SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![Output {
            amount: u(990_000),
            asset: "solana:dev/usdc".into(),
            dest: "solana:dev:merchant".into(),
        }],
        instance_leg: Some(InstanceLeg {
            amount: u(10_000),
            credited: vec![],
            extinguished: vec![(0x10, u(7)), (0x11, u(0)), (0x12, u(3))], // 0x11 zero-share
        }),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    p.sign_payer(&psk).unwrap();
    let parsed = SettlementPropose::parse(&p.encode().unwrap()).unwrap();
    assert_eq!(parsed, p);
    assert_eq!(
        parsed.instance_leg.unwrap().extinguished,
        vec![(0x10, u(7)), (0x11, u(0)), (0x12, u(3))],
    );
}

#[test]
fn instance_leg_rejects_zero_progress_and_bad_signers() {
    let base = |leg: InstanceLeg| SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![],
        instance_leg: Some(leg),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    // amount = 0 (no zero-value aggregate leg).
    assert!(base(InstanceLeg {
        amount: u(0),
        credited: vec![],
        extinguished: vec![(0x10, u(1))]
    })
    .encode()
    .is_err());
    // empty EXTINGUISHED (a present leg means E >= 1).
    assert!(base(InstanceLeg {
        amount: u(10),
        credited: vec![],
        extinguished: vec![]
    })
    .encode()
    .is_err());
    // an all-zero EXTINGUISHED (ΣE_r = 0 → no extinguishment progress) is rejected — an
    // individual zero-share role IS allowed (see instance_leg_allows_zero_share_role), but
    // a leg where every role is zero is not a real round.
    assert!(base(InstanceLeg {
        amount: u(10),
        credited: vec![],
        extinguished: vec![(0x10, u(0))]
    })
    .encode()
    .is_err());

    let with_rate = |rate: &str| SettlementPropose {
        channel_id: CID,
        ckpt_ref: CKPT,
        outputs: vec![],
        instance_leg: Some(instance_leg()),
        conversion: Some(Conversion {
            rate: rate.into(),
            rate_time: 1,
            rate_exp: 2,
            rate_grace: 3,
        }),
        sig_payer: None,
        sig_merchant: None,
    };
    // Non-positive / malformed / non-canonical CONVERSION rates are rejected.
    for bad in [
        "0",
        "-1.5",
        "not-a-rate",
        "1.2.3",
        "",
        "01.5",
        "1.50",
        "1.",
        "00",
    ] {
        assert!(
            with_rate(bad).encode().is_err(),
            "rate {bad:?} must be rejected"
        );
    }
    // Canonical positive decimals/integers are accepted.
    for good in ["1", "2.5", "0.5", "100", "0.03"] {
        assert!(
            with_rate(good).encode().is_ok(),
            "rate {good:?} must be accepted"
        );
    }

    // A proof/confirmed with both or neither signature is malformed (single-signer).
    let both = SettlementProof {
        channel_id: CID,
        proposal_hash: [0xab; 32],
        tx_refs: vec![TxRef {
            leg: 0x01,
            reference: "r".into(),
            finality: "f".into(),
        }],
        sig_payer: Some([1u8; 64]),
        sig_merchant: Some([2u8; 64]),
    };
    assert!(both.encode().is_err());
    let neither = SettlementConfirmed {
        channel_id: CID,
        proposal_hash: [0xab; 32],
        sig_payer: None,
        sig_merchant: None,
    };
    assert!(neither.encode().is_err());
}

#[test]
fn proof_roundtrip_and_tx_ref_order() {
    let (psk, ppk) = keys(1);
    let mut pr = SettlementProof {
        channel_id: CID,
        proposal_hash: [0xab; 32],
        tx_refs: vec![
            TxRef {
                leg: 0x01,
                reference: "meedref".into(),
                finality: "final".into(),
            },
            TxRef {
                leg: 0x02,
                reference: "netref".into(),
                finality: "final".into(),
            },
        ],
        sig_payer: None,
        sig_merchant: None,
    };
    pr.sign_payer(&psk).unwrap(); // debtor (payer, postpay)
    pr.verify_payer(&ppk).unwrap();
    assert_eq!(SettlementProof::parse(&pr.encode().unwrap()).unwrap(), pr);

    // Out-of-order tx_refs are malformed.
    let bad = SettlementProof {
        channel_id: CID,
        proposal_hash: [0xab; 32],
        tx_refs: vec![
            TxRef {
                leg: 0x02,
                reference: "b".into(),
                finality: "f".into(),
            },
            TxRef {
                leg: 0x01,
                reference: "a".into(),
                finality: "f".into(),
            },
        ],
        sig_payer: None,
        sig_merchant: None,
    };
    assert!(bad.encode().is_err());
}

#[test]
fn confirmed_roundtrip() {
    let (msk, mpk) = keys(2);
    let mut c = SettlementConfirmed {
        channel_id: CID,
        proposal_hash: [0xab; 32],
        sig_payer: None,
        sig_merchant: None,
    };
    c.sign_merchant(&msk); // creditor (merchant, postpay)
    c.verify_merchant(&mpk).unwrap();
    assert_eq!(SettlementConfirmed::parse(&c.encode().unwrap()).unwrap(), c);
    // A wrong signer fails.
    assert!(c.verify_payer(&mpk).is_err());
}
