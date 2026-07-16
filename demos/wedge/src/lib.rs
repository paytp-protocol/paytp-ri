//! Shared configuration and payload types for the M8 **wedge demo** — one clean
//! end-to-end flow: an AI agent pays a metered API per request, and the PayTP
//! distribution meed settles to the distribution roles.
//!
//! Both binaries (`wedge-merchant`, `wedge-agent`) share this so the wire shapes
//! and the demo's fixed economics live in exactly one place. Everything settles
//! against the in-process **virtual rail** (deterministic, no chain) — the same
//! F7-d split division the RI gates elsewhere; the on-chain reality is proven
//! separately by `interop/x402/settle-localnet.mjs` (M6.1c, a real validator).

use serde::{Deserialize, Serialize};

/// The demo listens here (overridable via `WEDGE_ADDR`).
pub const DEFAULT_ADDR: &str = "127.0.0.1:8402";

/// The single metered resource the demo serves.
pub const RESOURCE_PATH: &str = "/api/premium-quote";

/// Price per request, in the asset's minor units (1.0 token @ 6 decimals). At
/// this amount the schema-0x01 meed (100 bp = 1%) divides to round numbers:
/// merchant 990000, IL 5000, wallet 3000, Development Fund 2000.
pub const PRICE: u128 = 1_000_000;

/// The baseline rail as a CAIP-2 identifier (Solana devnet). The signed
/// `paytp.baseline` stays CAIP-2; the mirrored x402 `network` renders as the
/// named `solana-devnet` (F3-j). On the virtual rail this is nominal.
pub const BASELINE_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// The settlement asset (a real Solana devnet USDC mint, nominal on the virtual
/// rail — the rail keys its ledger by the string).
pub const ASSET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

/// Quoted finality level the payment must reach before delivery (virtual rail
/// levels are `pending`/`final`).
pub const FINALITY: &str = "final";

/// Where the merchant's 99% residue lands on the rail.
pub const MERCHANT_PAYOUT: &str =
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:MERCHANTpayout1111111111111111111111111111";

/// A distribution role in the meed vector: its schema-0x01 id, basis points, the
/// CAIP-10 destination it settles to, and a human label for the recipient view.
pub struct Role {
    pub id: u8,
    pub bp: u16,
    pub dest: &'static str,
    pub label: &'static str,
}

/// The schema-0x01 meed vector (§10.1), destinations resolved for the demo. The OS role is
/// unasserted here, so it routes to the **independent open-source fund** (§10.1/F9.4 step 2 — a
/// fund outside the Foundation's control, distinct from the Development Fund), and the 0x13
/// Development-Fund seat to the Development Fund — two distinct governed recipients, exactly as
/// `validate_vector_governed` (F5-o) requires on receipt.
pub fn roles() -> Vec<Role> {
    use paytp_core::consts;
    vec![
        Role {
            id: consts::ROLE_INTERACTION_LAYER,
            bp: 50,
            dest:
                "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:INTERACTIONlayerdest1111111111111111111111",
            label: "Interaction Layer (agent framework / browser)",
        },
        Role {
            id: consts::ROLE_OS,
            bp: 10,
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER,
            label: "OS / Runtime → independent open-source fund",
        },
        Role {
            id: consts::ROLE_WALLET,
            bp: 30,
            dest:
                "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:WALLETproviderdest11111111111111111111111",
            label: "Wallet Provider",
        },
        Role {
            id: consts::ROLE_DEV_FUND,
            bp: 10,
            dest: consts::DEV_FUND_DEST_PLACEHOLDER,
            label: "Development Fund",
        },
    ]
}

/// Build the `paytp-core` meed-vector entries (schema 0x01) from [`roles`].
pub fn meed_vector() -> Vec<paytp_core::tier0::quote::MeedEntry> {
    roles()
        .into_iter()
        .map(|r| paytp_core::tier0::quote::MeedEntry {
            role: r.id,
            bp: r.bp,
            dest: r.dest.to_string(),
        })
        .collect()
}

// --- Wire shapes shared by the two binaries ---

/// The content of the `X-PAYMENT` header (base64url-encoded JSON) a PayTP-aware
/// agent presents to redeem: the signed quote it received, plus the transfer it
/// authorized and the private settlement id. The merchant re-verifies the quote's
/// own signature and settles the payment itself (settlement precedes delivery, F4.4).
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentProof {
    /// The signed `paytp` quote object (from `extensions.paytp.info`) as the
    /// **raw JSON text** the agent received — passed through verbatim so the
    /// merchant re-verifies the signature over exactly the bytes it signed.
    pub quote: String,
    /// The split address to pay (the signed offer's `payTo`).
    pub to: String,
    pub asset: String,
    /// Amount as a decimal string (matches x402's `maxAmountRequired`).
    pub amount: String,
    /// Base64url-encoded 32-byte signed-transaction identity stand-in.
    pub settle_id_b64: String,
}

/// The `GET /recipients` view: what the distribution meed has settled.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientsView {
    pub asset: String,
    pub requests_paid: u64,
    pub gross_settled: String,
    pub rows: Vec<RecipientRow>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientRow {
    pub label: String,
    pub dest: String,
    pub bp: u16,
    pub settled: String,
}

/// The `X-PAYMENT` header name (an x402-style payment header).
pub const PAYMENT_HEADER: &str = "X-PAYMENT";
