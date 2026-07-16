//! M6.1b — emit a **shipped x402 V1** `PaymentRequired` (F3-j) for a PayTP
//! baseline offer on **Solana** (exact-svm), so the Node interop harness can
//! validate it against the actual `x402@1.2.0` npm package's zod schemas.
//!
//! Prints the `PaymentRequired` JSON to stdout. `payTo` is a Solana base58
//! address (the split-program PDA in a live deployment — here a fixed valid
//! pubkey), `asset` an SPL mint, `network` the x402 **named** value
//! (`solana-devnet`) while the signed `paytp.baseline` stays CAIP-2, and
//! no PayTP `extra.memo` — shipped x402 exact-svm clients/facilitators cap the
//! payment at the compute-budget instructions plus one `TransferChecked`.
//!
//! Run: `cargo run -p paytp-core --example emit_solana_402`

use paytp_core::consts;
use paytp_core::tier0::quote::{MeedEntry, Offer, Quote};
use paytp_core::x402::{paytp_extension, PaymentRequired, PaymentRequirements};
use paytp_core::{crypto, x402};

// Real Solana values (CAIP-2 devnet, a real devnet USDC mint, a valid base58
// pubkey standing in for the split PDA).
const SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const SPLIT_PAYTO: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const RESOURCE: &str = "https://api.example/solana-premium";

fn main() {
    let sk = [0x55u8; 32];
    let merchant_pk = crypto::ed25519_public(&sk);
    let nonce = [0x22u8; 32];

    // Schema-0x01 meed vector (meed roles), destinations as Solana base58 (the
    // OS/dev-fund share routed to the fund placeholder).
    // Destinations are CAIP-10 pointers (F9.1): `solana:<genesis>:<base58 account>`.
    let il_dest =
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW";
    let wallet_dest =
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:9nZq7Y5r9c8t4V2b5X1yF6uH8mK1pN2qR4sT6vW8xZ2";
    let vector = vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: il_dest.into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            // Absent/unlisted OS → the independent open-source fund (§10.1/F9.4 step 2),
            // NOT the Development Fund.
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: wallet_dest.into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ];

    // The complete shipped-x402-V1 PaymentRequirements (the mirror + accepts[0]).
    let mut extra = serde_json::Map::new();
    // exact-svm requires a facilitator feePayer; a placeholder valid base58 here.
    extra.insert(
        "feePayer".into(),
        serde_json::Value::String("EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd".into()),
    );
    let accept_reqs = PaymentRequirements {
        scheme: "exact".into(),
        network: "solana-devnet".into(), // x402 NAMED network (F3-j); baseline stays CAIP-2
        max_amount_required: "1000000".into(),
        asset: USDC_DEVNET.into(),
        pay_to: SPLIT_PAYTO.into(),
        resource: RESOURCE.into(),
        description: "Premium Solana data".into(),
        mime_type: "application/json".into(),
        max_timeout_seconds: 60,
        extra: Some(extra),
    };
    let accept = accept_reqs.to_strict().expect("mirror");

    let mut quote = Quote {
        v: "1".into(),
        resource: RESOURCE.into(),
        nonce,
        exp: 2_000_000_000,
        idem: b"idem-solana-1".to_vec(),
        schema: consts::SCHEMA_V0_1,
        contract: consts::CONTRACT_VERSION_V0_1,
        registry: 5,
        baseline: SOLANA_DEVNET.into(),
        grace: 300,
        retry: 600,
        vector,
        offers: vec![Offer {
            accept,
            finality: Some("finalized".into()),
            // F4.1: the merchant's net (~99%) destination, committed in the split.
            merchant_net: Some(
                "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:9nZq7Y5r9c8t4V2b5X1yF6uH8mK1pN2qR4sT6vW8xZ2"
                    .into(),
            ),
            two_leg: None,
        }],
        signature: None,
    };
    quote.sign(&sk);

    // Sanity: the merchant re-verifies + the baseline shape holds.
    let json = String::from_utf8(quote.to_json()).unwrap();
    let verified = Quote::parse_verify(&json, &merchant_pk).expect("self-verify");
    // Governed validation requires the caller's registry (F5-o/F9.4). This demo's OS share uses
    // the version-agnostic independent-OS-fund fallback, so an empty store suffices; a real
    // deployment supplies its retained snapshot set.
    verified
        .validate_tier0(&paytp_core::registry::SnapshotStore::default())
        .expect("tier0 (governed vector + networks + merchantNet)");

    // Wrap into the x402 V2 envelope.
    let paytp_obj: serde_json::Value = serde_json::from_slice(&quote.to_json()).unwrap();
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "PayTP quote extension v1",
        "type": "object",
        "required": ["v", "nonce", "vector", "offers", "signature"],
    });
    let pr = PaymentRequired {
        x402_version: x402::X402_VERSION, // shipped V1: the literal 1
        error: None,    // shipped `error` is a strict enum; omit on the initial 402
        resource: None, // per-requirement in V1 (F3-j rule 4)
        accepts: vec![accept_reqs],
        extensions: Some(paytp_extension(paytp_obj, schema)),
    };
    // Emit pretty JSON for the Node harness.
    let value: serde_json::Value = serde_json::from_slice(&pr.to_json()).unwrap();
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}
