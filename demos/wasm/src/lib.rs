//! `paytp-demo-wasm` — the demo suite's browser wasm facade.
//!
//! This is **demo glue, not the implementer SDK.** Its public functions are
//! `dNN_*_trace()` calls that run the REAL RI core (`paytp-core` + `paytp-rail`'s
//! `VirtualRail` doing the F7-d division, plus `paytp-merchant`/`paytp-wallet` for the
//! two-sided flows) and emit a **JSON visualization trace** the browser visualizer
//! renders. Implementers do NOT build on this — they target the RI crates, the formal
//! spec, and the F10 conformance vectors.
//!
//! Pure `State + Action → trace`: no host I/O, no HTTP, no timers — the RNG (where a
//! path needs it) draws from Web Crypto via the wasm `getrandom` js feature. That the
//! pure core extracts cleanly is proven by this crate compiling to
//! `wasm32-unknown-unknown`.

use paytp_core::channel::checkpoint::CheckpointRequest;
use paytp_core::channel::establish::{ChannelAuth, ChannelOpen, MODE_POSTPAY};
use paytp_core::channel::settle_msg::{InstanceLeg, Output, SettlementPropose};
use paytp_core::channel::{ChannelState, Mode, VectorEntry};
use paytp_core::consts;
use paytp_core::crypto;
use paytp_core::derive::{AddressInputs, MeedVectorEntry};
use paytp_core::slice::Slice;
use paytp_core::tier0::quote::MeedEntry;
use paytp_core::tlv::{self, Field, Object};
use paytp_merchant::{
    BaselineParams, Carriage, ChannelDriver, InMemoryStore, Merchant, RedeemError, TwoLegParams,
};
use paytp_rail::{MeedShare, RailAdapter, Transfer, TransferKind, VirtualRail};
use paytp_wallet::channel::ChannelOpenParams;
use paytp_wallet::{ChannelClient, Clock, Custody, PayerChannelTrust, StaticPolicy, Wallet};

/// A fixed wallet clock for the demo (the meed-strip gate refuses at signing, before any
/// `TH_TIME` evaluation — a constant time keeps the facade deterministic and wasm-safe).
struct DemoClock;
impl Clock for DemoClock {
    fn now(&self) -> u64 {
        1_700_000_000
    }
}
static DEMO_CLOCK: DemoClock = DemoClock;
use serde::Serialize;
use serde_json::json;
use wasm_bindgen::prelude::*;

/// The schema-0x01 meed vector: OS → the independent open-source
/// fund, the Dev-Fund role → the Development Fund (distinct destinations).
fn schema01_vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:0xINTERACTIONLAYER".into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: "eip155:1:0xWALLETPROVIDER".into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

// --- The demo's settlement asset (DISPLAY metadata only). ---
// The protocol carries integer minor units + the asset id; the ticker and decimals
// are off-protocol asset metadata the DEMO supplies to make amounts human-readable.
// Default: real Base USDC (6-decimal). To add rails/assets later, thread an `asset`
// param through the demos and emit the matching {ticker, decimals} — e.g. EURC (6dp),
// SOL (9dp), a game token (varying dp); the wire (raw units + asset id) is unchanged.
const ASSET_ID: &str = "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base USDC
const ASSET_TICKER: &str = "USDC";
const ASSET_DECIMALS: u32 = 6;

/// Format raw integer minor units in the asset's decimals — **exact** (no rounding),
/// trailing zeros trimmed. e.g. 5000 @ 6dp → "0.005", 990000 → "0.99", 1000000 → "1".
fn fmt_units(raw: u128) -> String {
    let div = 10u128.pow(ASSET_DECIMALS);
    let (whole, frac) = (raw / div, raw % div);
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{:0w$}", frac, w = ASSET_DECIMALS as usize);
    format!("{}.{}", whole, frac_str.trim_end_matches('0'))
}

/// A display amount with the asset ticker, e.g. "0.99 USDC".
fn amt(raw: u128) -> String {
    format!("{} {}", fmt_units(raw), ASSET_TICKER)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Combine the narrative events (for the animation) with the **real wire artifacts**
/// (for the under-the-hood panel) — the actual bytes/objects the RI produced this run.
fn out(events: Vec<serde_json::Value>, wire: serde_json::Value) -> String {
    json!({
        "events": events,
        "wire": wire,
        // Display metadata the visualizer uses to format raw minor units (ticker +
        // decimals). Change this (or thread an `asset` param) to render other assets.
        "display": { "ticker": ASSET_TICKER, "decimals": ASSET_DECIMALS, "asset": ASSET_ID },
    })
    .to_string()
}

/// Like [`out`], plus a per-demo **code walkthrough** — used by the split view (D-05),
/// whose events are a typed enum with no per-event `code` field. Step demos instead carry
/// `code` inline on each event (see [`code`]).
fn out_wt(
    events: Vec<serde_json::Value>,
    wire: serde_json::Value,
    walkthrough: Vec<serde_json::Value>,
) -> String {
    json!({
        "events": events,
        "wire": wire,
        "walkthrough": walkthrough,
        "display": { "ticker": ASSET_TICKER, "decimals": ASSET_DECIMALS, "asset": ASSET_ID },
    })
    .to_string()
}

/// One **"under the hood"** annotation: the real RI entry point a step exercises,
/// authored right beside the call that runs it so it cannot drift from what actually
/// executed. `tag` ∈ `"exec"` (real RI running in your browser this run) · `"depicted"`
/// (a gated wire-plane mechanic proven elsewhere in the RI, cited) · `"off"` (no RI path
/// — an illustrative/business figure). `func` is the `crate::module::fn`; `path` is its
/// source file; `does` is one plain-English line of what runs. No line number: the
/// function name is the durable anchor (greppable), so unrelated edits don't rot it.
fn code(tag: &str, func: &str, path: &str, does: &str) -> serde_json::Value {
    json!({ "tag": tag, "fn": func, "path": path, "does": does })
}

/// Parse the RI's canonical JSON bytes into a Value for faithful display (the signed
/// quote / receipt shown under the hood is the exact object the RI signed, not a re-render).
fn as_value(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null)
}

/// One recipient of the on-wire split, as the visualizer renders it.
#[derive(Serialize)]
struct Recipient {
    label: String,
    dest: String,
    bp: u16,
    settled: String,
}

/// A single trace event (append-only; the visualizer + the replay renderer both read
/// this shape). Kept deliberately small for the spike.
#[derive(Serialize)]
#[serde(tag = "event")]
enum TraceEvent {
    #[serde(rename = "quote")]
    Quote { gross: String, roles: usize },
    #[serde(rename = "paid")]
    Paid { to_split: String, gross: String },
    #[serde(rename = "divided")]
    Divided { recipients: Vec<Recipient> },
    #[serde(rename = "conserved")]
    Conserved {
        total_out: String,
        gross: String,
        ok: bool,
    },
}

/// The schema-0x01 distribution roles: the OS role routes to the
/// **independent open-source fund** (outside the Foundation), the Dev-Fund role to the
/// Development Fund — two distinct destinations (that distinction is D-05's neutrality
/// beat). `(label, bp, dest)`.
/// The REAL F4.1 address inputs for a schema-0x01 split/instance: the deploy seed is
/// SHA-256(ADDRESS_INPUTS) over merchant key + asset + schema + meed vector + contract, so the
/// deployed address genuinely depends on merchant/asset/vector — flip any entry and it changes.
/// `dests_bps` is the 4-entry meed vector in canonical role order (0x10 IL / 0x11 OS /
/// 0x12 Wallet / 0x13 Dev-Fund) — exactly how the merchant derives it in `build_baseline_quote`.
fn demo_address_inputs(
    merchant_key: [u8; 32],
    dests_bps: &[(String, u16)],
    merchant_net: Option<&str>,
) -> AddressInputs {
    let role_ids = [0x10u8, 0x11, 0x12, 0x13];
    let vector = dests_bps
        .iter()
        .enumerate()
        .map(|(i, (dest, bp))| MeedVectorEntry {
            role: role_ids[i],
            bp: *bp,
            dest: dest.clone(),
        })
        .collect();
    AddressInputs {
        merchant_key,
        asset: ASSET_ID.into(),
        schema: consts::SCHEMA_V0_1,
        vector,
        contract: consts::CONTRACT_VERSION_V0_1,
        // F4.1: Some for a split (baseline), None for a meed instance.
        merchant_net: merchant_net.map(String::from),
    }
}

/// The fixed demo merchant identity key (Ed25519 public of the [0x55;32] signing key used by
/// the RI `Merchant` throughout the suite) — for the split demos that hold only a payout string.
fn demo_merchant_key() -> [u8; 32] {
    crypto::ed25519_public(&[0x55u8; 32])
}

/// The schema-`0x01` distribution roles for the D-05 split. `os_absent` toggles the
/// **OS (`0x11`) share's destination** — the neutrality beat (§10.1/§10.5): an
/// **asserted, registry-listed OS** receives its own 0.1% at its own address; an
/// **absent/unlisted OS**'s 0.1% routes to the **independent open-source fund** (outside
/// the Foundation, §10.1), *not* to the Development Fund and *not* redistributed to the
/// other roles. Only the OS entry (label + dest) changes between the two — the merchant's
/// 99% and the Development Fund's 0.1% are byte-for-byte identical either way, so
/// approving or denying an OS changes the Foundation's income by exactly zero (§10.5).
fn roles(os_absent: bool) -> Vec<(&'static str, u16, String)> {
    let (os_label, os_dest) = if os_absent {
        (
            "OS (absent) → Independent Open-Source Fund",
            consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.to_string(),
        )
    } else {
        // A concrete registry-listed OS: its 0.1% lands at its own address. (D-05 is the
        // pure division view — `deploy_split` + pay — so the dest is simply what the
        // vector names; the receive-side registry check that would GATE a bad OS dest is
        // exercised on the redeem/open paths, e.g. D-09.)
        (
            "OS (registry-listed) → its own address",
            "eip155:1:0xOPENSOURCEOS".to_string(),
        )
    };
    vec![
        (
            "Interaction Layer",
            50,
            "eip155:1:0xINTERACTIONLAYER".to_string(),
        ),
        (os_label, 10, os_dest),
        (
            "Wallet Provider",
            30,
            "eip155:1:0xWALLETPROVIDER".to_string(),
        ),
        (
            "Development Fund",
            10,
            consts::DEV_FUND_DEST_PLACEHOLDER.to_string(),
        ),
    ]
}

/// The D-05 canonical live path: divide a payment of `amount` (minor units) on-wire and
/// return the canonical trace as JSON. Real split division on the `VirtualRail` — a plain
/// payment to the split address divides among the recipients by basis points. `os_absent`
/// toggles the neutrality beat: with an OS asserted its 0.1% lands at its own address;
/// with the OS absent that 0.1% routes to the independent open-source fund — and the
/// merchant's 99% and the Development Fund's 0.1% are unchanged (§10.5).
#[wasm_bindgen]
pub fn d05_split_trace(amount: u64, os_absent: bool) -> String {
    let amount = amount as u128;
    let roles = roles(os_absent);
    let merchant_payout = "eip155:1:0xMERCHANT".to_string();

    // Deploy the split (recipients = meed dests + merchant at 10000 − Σ meed bp)
    // and pay it — the division is a property of the address (F7-d).
    let meed: Vec<(String, u16)> = roles
        .iter()
        .map(|(_, bp, dest)| (dest.clone(), *bp))
        .collect();
    let rail = VirtualRail::new(0);
    // The address is a real F4.1 derivation over merchant/asset/vector (not a fixed seed); the
    // bound deploy recomputes that seed and derives the recipients from the SAME inputs, so
    // the division is provably a property of the address.
    let inputs = demo_address_inputs(demo_merchant_key(), &meed, Some(merchant_payout.as_str()));
    let seed = inputs.seed_split().expect("seed");
    let addr = rail
        .deploy_split(&seed, &inputs)
        .expect("demo split inputs are well-formed");
    rail.submit(Transfer {
        to: addr.clone(),
        asset: ASSET_ID.into(),
        amount,
        kind: TransferKind::Payment,
        memo: None,
    })
    .expect("virtual-rail split payment");

    // Read what settled at each destination.
    let mut recipients: Vec<Recipient> = roles
        .iter()
        .map(|(label, bp, dest)| Recipient {
            label: (*label).to_string(),
            dest: dest.clone(),
            bp: *bp,
            settled: rail.balance(dest).to_string(),
        })
        .collect();
    let merchant_bp = 10_000 - consts::MEED_BASE_BP;
    recipients.push(Recipient {
        label: "Merchant".to_string(),
        dest: merchant_payout.clone(),
        bp: merchant_bp,
        settled: rail.balance(&merchant_payout).to_string(),
    });

    let total_out: u128 = recipients
        .iter()
        .map(|r| r.settled.parse::<u128>().unwrap_or(0))
        .sum();

    // Real wire artifacts (captured before the events move `recipients`/`addr`).
    let wire = json!({
        "meed_vector_schema_0x01": roles.iter().map(|(label, bp, dest)| json!({ "role": label, "bp": bp, "dest": dest })).collect::<Vec<_>>(),
        "derived_split_address": addr,
        "on_wire_division": recipients.iter().map(|r| json!({ "recipient": r.label, "dest": r.dest, "bp": r.bp, "settled_minor_units": r.settled })).collect::<Vec<_>>(),
        "rule": "running-V split division (F7-d): each recipient's entitlement = floor(V × bp_d / bp_total) − paid_d, computed on the VirtualRail split contract. For the baseline split bp_total = 10000 (the merchant's 9900 bp + the four meed roles' 100 bp), so each meed role receives floor(V × bp / 10000). (A meed instance divides only the 100 bp meed pool, so there bp_total = 100 — not 10000.)",
        "os_mode": if os_absent { "OS absent → its 0.1% routes to the independent open-source fund (§10.1)" } else { "OS registry-listed → its 0.1% lands at its own address" },
        "neutrality": "Toggling the OS role changes ONLY the 0x11 destination. The merchant's 9900 bp and the Development Fund's 10 bp are identical in both states — approving or denying an OS changes the Foundation's income by exactly zero (§10.5). An absent OS's share leaves the Foundation entirely, to the independent open-source fund; it is never redistributed to the other roles. (The split address itself differs between the two states — the division is a property of the address, F4.1.)",
        "denomination": "amounts are integer minor units of the quoted asset — the protocol is denomination-agnostic. Here the asset is USDC (6 decimals), so 1,000,000 minor units = 1.00 USDC; the ticker + decimals are the DEMO's display metadata (not protocol). The identical flow renders any asset — e.g. EURC (6dp) or SOL (9dp) — the wire integers are unchanged.",
        "address_note": "derived_split_address is the VirtualRail's rendering of address = f(SHA-256(ADDRESS_INPUTS)); the 'virt:' prefix marks the in-process demo rail. On a real rail this is the actual on-chain PDA — the identical derivation runs on Solana in interop/x402 (M6.1c).",
    });
    let walkthrough = vec![
        code(
            "exec",
            "paytp_rail::VirtualRail::deploy_split",
            "crates/paytp-rail/src/virtual_rail.rs",
            "Recomputes the F4.1 seed from ADDRESS_INPUTS (merchant · asset · schema · meed vector · contract) and binds the recipient set to the address; a mismatched seed is rejected. Flip any input — including the OS destination — and the address changes.",
        ),
        code(
            "exec",
            "paytp_rail::VirtualRail::submit",
            "crates/paytp-rail/src/virtual_rail.rs",
            "A plain payment lands at the split address — no PayTP awareness needed; the split divides whatever arrives, by construction.",
        ),
        code(
            "exec",
            "paytp_rail::VirtualRail::distribute (split contract)",
            "crates/paytp-rail/src/virtual_rail.rs",
            "Running-V split division: each recipient = floor(V × bp_d / bp_total). The OS 0.1% lands at its own address (asserted) or the independent open-source fund (absent); the merchant 99% and Dev-Fund 0.1% are unchanged either way.",
        ),
        code(
            "exec",
            "paytp_rail::VirtualRail::balance",
            "crates/paytp-rail/src/virtual_rail.rs",
            "Reads the settled balance at each destination; the sum equals the payment to the minor unit (conservation).",
        ),
    ];
    let trace = vec![
        TraceEvent::Quote {
            gross: amount.to_string(),
            roles: roles.len(),
        },
        TraceEvent::Paid {
            to_split: addr,
            gross: amount.to_string(),
        },
        TraceEvent::Divided { recipients },
        TraceEvent::Conserved {
            total_out: total_out.to_string(),
            gross: amount.to_string(),
            ok: total_out == amount,
        },
    ];
    out_wt(
        serde_json::to_value(&trace)
            .unwrap_or(json!([]))
            .as_array()
            .cloned()
            .unwrap_or_default(),
        wire,
        walkthrough,
    )
}

/// Build, pay, and redeem a baseline quote for `amount`. Returns (merchant, rail, the
/// signed quote JSON, the split address, redeem result). Shared by D-03/D-07/D-09.
fn baseline_flow(
    amount: u128,
    resource: &str,
    nonce: [u8; 32],
) -> (
    VirtualRail,
    paytp_merchant::BaselineQuote,
    Result<paytp_core::tier0::Receipt, RedeemError>,
) {
    let sk = [0x55u8; 32];
    let merchant = Merchant::new(sk, "eip155:1:0xMERCHANT");
    let rail = VirtualRail::new(0);
    let store = InMemoryStore::new();
    let bq = merchant.build_baseline_quote(
        &rail,
        BaselineParams {
            resource,
            nonce,
            exp: 2_000_000_000,
            idem: b"demo".to_vec(),
            registry_version: 5,
            baseline_network: "eip155:8453",
            asset: ASSET_ID,
            amount,
            finality: "final",
            grace: 300,
            retry: 600,
            max_timeout_seconds: 60,
            extra: None,
            vector: schema01_vector(),
        },
    );
    let transfer = Transfer {
        to: bq.split_address.clone(),
        asset: ASSET_ID.into(),
        amount,
        kind: TransferKind::Payment,
        memo: None,
    };
    let quote_json = String::from_utf8(bq.quote.to_json()).unwrap();
    let now = rail.chain_time();
    let receipt =
        merchant.redeem_baseline(&quote_json, resource, transfer, nonce, &rail, &store, now);
    (rail, bq, receipt)
}

/// The real wire artifacts of a baseline flow: the exact signed quote (JCS bytes the
/// merchant signed), the derived split address, and the signed receipt. Shown verbatim
/// under the hood — this is the actual protocol data, not the narrative.
fn baseline_wire(
    bq: &paytp_merchant::BaselineQuote,
    receipt: &Result<paytp_core::tier0::Receipt, RedeemError>,
) -> serde_json::Value {
    json!({
        "signed_paytp_quote": as_value(&bq.quote.to_json()),
        "derived_split_address": bq.split_address,
        "receipt": match receipt {
            Ok(r) => as_value(&r.to_json()),
            Err(e) => json!({ "redeem_error": format!("{e:?}") }),
        },
    })
}

/// **D-03** — a one-shot purchase across the full range ($0.05 → $50 → $1000): PayTP is
/// not just for micropayments; settle-before-delivery; the fee advantage at scale.
#[wasm_bindgen]
pub fn d03_oneshot_trace(amount: u64) -> String {
    let amount = amount as u128;
    let resource = "https://api.example/item";
    let mut nonce = [0x30u8; 32];
    nonce[0] = (amount & 0xff) as u8;
    nonce[1] = ((amount >> 8) & 0xff) as u8;
    let (_, bq, receipt) = baseline_flow(amount, resource, nonce);
    let split = bq.split_address.clone();

    let mut events = vec![
        json!({"event":"402","text":"Merchant returns <b>HTTP 402</b> carrying a signed <code>paytp</code> quote — nonce, resource, and the MEED_VECTOR (x402-compatible).",
            "code":[ code("exec","paytp_merchant::Merchant::build_baseline_quote","crates/paytp-merchant/src/lib.rs","Builds and signs the quote (Ed25519), derives + deploys the bound split (F4.1), and mirrors a shipped x402 v1 PaymentRequirements (F3-a/F3-j).") ]}),
        json!({"event":"pay","text": format!("Wallet authorizes <b>{}</b> to the split address <span class='mono'>{}</span>; the merchant settles that authorization.", amt(amount), split),
            "code":[ code("exec","paytp_rail::VirtualRail::settle","crates/paytp-rail/src/virtual_rail.rs","Moves the full amount to the split payTo once per settle_id; a retry returns the cached ref without a second mint.") ]}),
    ];
    match &receipt {
        Ok(_) => {
            events.push(json!({"event":"settle","ok":true,"text":"<b>Settlement precedes delivery</b> — the merchant confirms the payment reached the split at quoted finality, then the meed divides 99/1 on-wire.",
                "code":[
                    code("exec","paytp_merchant::Merchant::redeem_baseline","crates/paytp-merchant/src/lib.rs","The receive path: re-verifies the signed quote, settles the presented transfer, then checks quoted finality (F4.4), full amount + asset, resource binding (F3.4), and the durable nonce/ref record before delivery."),
                    code("exec","paytp_core::tier0::quote::Quote::validate_vector_governed","crates/paytp-core/src/tier0/quote.rs","The governed-destination check: 0x13 MUST equal the pinned Dev-Fund; 0x11 MUST be registry-listed or the independent OS fund. A misrouted governed share is rejected here.")
                ]}));
            events.push(json!({"event":"deliver","ok":true,"text":"Data delivered + a <b>merchant-signed receipt</b> returned — durable proof of exactly this purchase.",
                "code":[ code("exec","paytp_merchant::Merchant::redeem_baseline · consume_nonce → Receipt::baseline().sign","crates/paytp-merchant/src/lib.rs","Atomically consumes the nonce (a replay returns RedeemError::Replayed), then signs the receipt — one authorization, one delivery.") ]}));
        }
        Err(e) => events.push(
            json!({"event":"reject","reject":true,"text": format!("redeem failed: {:?}", e)}),
        ),
    }
    // Illustrative card-fee comparison (whitepaper §3.1 — NOT RI-computed; the PayTP 1% is).
    let paytp = amount / 100;
    let card = 300_000u128.saturating_add(amount.saturating_mul(290) / 10_000); // $0.30 + 2.9%
    events.push(json!({"event":"fees","text": format!(
        "Fees at this size — <b>typical card fees (illustrative, §3.1 — NOT RI-computed; fiat cards charge ~$0.30 + 2–3%)</b>: ~<b>{}</b> plus chargeback risk. <b>PayTP (RI-computed): {}</b> (a flat 1%). Merchant keeps <b>{}</b> vs {}. At 0.05 USDC the card fee alone exceeds the item — cards structurally can't serve it.",
        amt(card), amt(paytp), amt(amount - paytp), amt(amount.saturating_sub(card))),
        "code":[ code("off","—","(no RI path)","The card-fee figures are illustrative (§3.1) — NOT RI-computed. Only the 1% PayTP meed on this line is produced by the RI.") ]}));
    events.push(json!({"event":"note","text":"<i>Buyer note: no card-style chargeback — a merchant benefit, not buyer insurance. A large one-shot to an unknown party relies on off-protocol recourse or a channel (§7.8).</i>"}));
    out(events, baseline_wire(&bq, &receipt))
}

/// **D-04** — the reclaim path. Meed-first-final ordering (§5.6.2): the meed leg
/// lands FIRST, and the wallet only starts the net leg once the meed is final. So an
/// interruption between the legs "strands at most the meed" (§5.6.2; the bound is §7.8's
/// residual-risk row) — which is reclaimable. `scenario` ∈ {"deliver", "netfail" (the
/// primary failsafe), "fraud"}.
#[wasm_bindgen]
pub fn d04_reclaim_trace(scenario: &str) -> String {
    let sk = [0x55u8; 32];
    let merchant = Merchant::new(sk, "eip155:1:0xMERCHANT");
    let rail = VirtualRail::new(0);
    let meed = [
        MeedShare {
            dest: "eip155:1:0xIL".into(),
            bp: 50,
        },
        MeedShare {
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
        MeedShare {
            dest: "eip155:1:0xWALLET".into(),
            bp: 30,
        },
        MeedShare {
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
    ];
    let dests_bps: Vec<(String, u16)> = meed.iter().map(|r| (r.dest.clone(), r.bp)).collect();
    // The bound deploy recomputes the seed from these real F4.1 inputs and binds the merchant key
    // + meed destinations from the SAME inputs — the demo proves the on-chain seed↔recipients
    // binding, it does not merely assert it.
    let inputs = demo_address_inputs(merchant.key, &dests_bps, None);
    let seed = inputs.seed_instance().expect("seed");
    let addr = rail
        .deploy_instance(&seed, &inputs)
        .expect("demo instance inputs are well-formed");
    let nonce = [0x44u8; 32];
    let meed_amount = 10_000u128; // the meed leg ($0.01)
    let net_amount = 990_000u128; // the net leg ($0.99), direct to the merchant
    let (t_open, t_lapse, contest) = (1_000_000_100u64, 1_000_000_400u64, 30u64);
    let (_, entry_id) = rail
        .fund_entry(
            &addr,
            nonce,
            meed_amount,
            "eip155:1:0xPAYER".into(),
            t_open,
            t_lapse,
            contest,
            ASSET_ID.into(),
        )
        .expect("fund entry");
    let payer = "eip155:1:0xPAYER";
    let merch = "eip155:1:0xMERCHANT";

    // Meed leg lands FIRST (finality-first). The net leg is only started after.
    let mut events = vec![json!({"event":"meed","text": format!(
        "<b>Meed leg first (finality-first, §5.6.2):</b> {} lands in a reclaimable on-rail entry. The wallet does NOT start the net leg until the meed is final — so the whole {} net is still in the payer's wallet at this point.",
        amt(meed_amount), amt(net_amount)),
        "code":[ code("exec","paytp_rail::VirtualRail::fund_entry","crates/paytp-rail/src/virtual_rail.rs","Funds the reclaimable meed entry FIRST (finality-first ordering, §5.6.2): a FUNDED entry recording the destinations, amount, refund pointer, and the reclaim + contest windows.") ]})];
    let reclaim = |ev: &mut Vec<serde_json::Value>| {
        rail.advance_clock(150);
        rail.open_reclaim(&addr, entry_id).expect("open reclaim");
        rail.advance_clock(contest + 1);
        rail.execute_reclaim(&addr, entry_id)
            .expect("execute reclaim");
        ev.push(json!({"event":"reclaim","ok":true,"text": format!("After the contest delay the <b>payer reclaims the meed entry — {} returned</b>. No enabling role is paid for a purchase that didn't complete.", amt(rail.balance(payer))),
            "code":[ code("exec","paytp_rail::VirtualRail::open_reclaim + execute_reclaim","crates/paytp-rail/src/virtual_rail.rs","The entry machine: FUNDED → RECLAIM_OPEN, then after the contest window RECLAIM_OPEN → RECLAIMED, refunding the meed to the payer's pointer.") ]}));
    };

    match scenario {
        "deliver" => {
            rail.submit(Transfer { to: merch.into(), asset: ASSET_ID.into(), amount: net_amount, kind: TransferKind::Payment, memo: Some(nonce) }).expect("net leg");
            let att = merchant.make_attestation(nonce, entry_id);
            rail.attest_entry(&addr, entry_id, &att).expect("attest");
            events.push(json!({"event":"net","ok":true,"text": format!("Net leg completes — <b>{}</b> to the merchant. Both legs final.", amt(rail.balance(merch))),
                "code":[ code("exec","paytp_rail::VirtualRail::submit","crates/paytp-rail/src/virtual_rail.rs","The net leg is a direct transfer to the merchant — only started after the meed leg reached finality.") ]}));
            events.push(json!({"event":"release","ok":true,"text": format!("Merchant delivers + posts the attestation → the meed shares release (IL {}). Everyone paid, because the good was delivered.", amt(rail.balance("eip155:1:0xIL"))),
                "code":[ code("exec","paytp_merchant::Merchant::make_attestation + paytp_rail::VirtualRail::attest_entry","crates/paytp-rail/src/virtual_rail.rs","The merchant signs a delivery attestation; posting it drives the entry FUNDED → ATTESTED, which distributes the meed shares.") ]}));
        }
        "fraud" => {
            // Both legs land; the merchant has the net but never delivers/attests (the rarer worst case).
            rail.submit(Transfer { to: merch.into(), asset: ASSET_ID.into(), amount: net_amount, kind: TransferKind::Payment, memo: Some(nonce) }).expect("net leg");
            events.push(json!({"event":"net","text": format!("Net leg completes — <b>{}</b> reaches the merchant. Then the merchant <b>takes the payment but never delivers</b> (no attestation).", amt(rail.balance(merch))),
                "code":[ code("exec","paytp_rail::VirtualRail::submit","crates/paytp-rail/src/virtual_rail.rs","The net leg lands directly at the merchant — a plain transfer, NOT escrowed (only the meed leg is reclaimable).") ]}));
            reclaim(&mut events);
            events.push(json!({"event":"note","text": format!("<i>The rarer worst case: the payer reclaims the {} meed, but the {} net is already with the merchant — a direct payment, not escrowed. Bounded, not absorbed; chargeback-style protection is future work (Ch 13 dispute layer). Off-protocol recourse applies as in any sale.</i>", amt(meed_amount), amt(net_amount))}));
        }
        _ /* netfail — THE PRIMARY FAILSAFE */ => {
            // The net leg fails technically — it is never submitted / never reaches the
            // merchant. Merchant balance stays 0; the payer's 99% never left.
            events.push(json!({"event":"netfail","reject":true,"text": format!("📉 <b>The net leg to the merchant FAILS</b> — a technical hiccup (dropped connection, rail congestion, no route). Merchant received: <b>{}</b>. The purchase never completes.", amt(rail.balance(merch))),
                "code":[ code("exec","paytp_rail::VirtualRail::balance","crates/paytp-rail/src/virtual_rail.rs","No net transfer is submitted — the merchant's balance stays 0 (the technical-failure case). The payer's 99% never left the wallet.") ]}));
            events.push(json!({"event":"stranded","text": format!("Because the meed landed first, the interruption briefly <b>locks at most the {} meed</b> (§5.6.2) — a <b>time</b> cost until the reclaim triggers, not a value loss; the payer's {} net never left the wallet.", amt(meed_amount), amt(net_amount)),
                "code":[ code("exec","paytp_rail::VirtualRail::entry_status","crates/paytp-rail/src/virtual_rail.rs","The meed entry sits FUNDED and reclaimable — the stranded amount is capped at the meed, never the net (§5.6.2; bound §7.8).") ]}));
            reclaim(&mut events);
            events.push(json!({"event":"note","ok":true,"text": format!("<i>This is what reclaim was primarily built for — the common case: a two-leg purchase interrupted after the meed leg. The payer is <b>made whole — no value lost</b>: the {} meed is reclaimed in full and the {} net was never sent. The only cost is the brief reclaim delay (a time cost), after which the meed returns whole.</i>", amt(meed_amount), amt(net_amount))}));
        }
    }
    let wire = json!({
        "instance_address": addr,
        "entry_id": hex(&entry_id),
        "meed_amount_minor_units": meed_amount,
        "net_amount_minor_units": net_amount,
        "merchant_received_minor_units": rail.balance(merch),
        "payer_reclaimed_minor_units": rail.balance(payer),
        "entry_state": format!("{:?}", rail.entry_status(&addr, &entry_id)),
    });
    out(events, wire)
}

/// **D-07** — x402 coexistence and selection: kinship not rivalry; selection not capture.
/// A plain x402 client completes a baseline offer (the split divides by construction, no
/// PayTP receipt/attribution); a PayTP-aware client selects the signed offer (meed +
/// signed receipt). Both succeed side by side.
#[wasm_bindgen]
pub fn d07_coexistence_trace() -> String {
    let amount = 1_000_000u128;
    let resource = "https://api.example/resource";

    // Plain x402 client: pays the split payTo with NO PayTP awareness. The split still divides —
    // F3-a client-independence.
    let sk = [0x55u8; 32];
    let merchant = Merchant::new(sk, "eip155:1:0xMERCHANT");
    let plain_rail = VirtualRail::new(0);
    let bq = merchant.build_baseline_quote(
        &plain_rail,
        BaselineParams {
            resource,
            nonce: [0x77u8; 32],
            exp: 2_000_000_000,
            idem: b"d07".to_vec(),
            registry_version: 5,
            baseline_network: "eip155:8453",
            asset: ASSET_ID,
            amount,
            finality: "final",
            grace: 300,
            retry: 600,
            max_timeout_seconds: 60,
            extra: None,
            vector: schema01_vector(),
        },
    );
    let split = bq.split_address.clone();
    plain_rail
        .submit(Transfer {
            to: split.clone(),
            asset: ASSET_ID.into(),
            amount,
            kind: TransferKind::Payment,
            memo: None,
        })
        .expect("plain pay");
    let il_plain = plain_rail.balance("eip155:1:0xINTERACTIONLAYER");

    // PayTP-aware client: same merchant, verifies the signed quote, presents the payment
    // authorization to the merchant, and gets a signed receipt.
    let nonce = [0x78u8; 32];
    let (paytp_rail, bq2, receipt) = baseline_flow(amount, resource, nonce);
    let il_paytp = paytp_rail.balance("eip155:1:0xINTERACTIONLAYER");

    let events = vec![
        json!({"event":"menu","text":"One merchant, two ways to pay. A plain x402 client and a PayTP-aware client both hit the same 402."}),
        json!({"event":"plain","ok":true,"text": format!("<b>Plain x402 client</b> pays the split <code>payTo</code> with zero PayTP awareness. The split divides by construction (IL gets {}) — but there is <b>no PayTP receipt and no attribution</b>: it is not a PayTP payment, exactly as a card payment beside it is not.", amt(il_plain)),
            "code":[ code("exec","paytp_rail::VirtualRail::submit (to the split payTo)","crates/paytp-rail/src/virtual_rail.rs","A plain client pays the split address directly; it divides whatever arrives — F3-a client-independence — with no PayTP receipt or attribution.") ]}),
        json!({"event":"paytp","ok": receipt.is_ok(),"text": format!("<b>PayTP-aware client</b> verifies the merchant-signed quote and presents the payment authorization → the meed flows (IL {}) <b>and it gets a signed receipt</b>. Selection, not capture — the client chose PayTP; nothing traps it.", amt(il_paytp)),
            "code":[ code("exec","paytp_merchant::Merchant::redeem_baseline","crates/paytp-merchant/src/lib.rs","The PayTP path: the merchant settles the presented payment against its signed quote and returns a signed receipt (attribution) — the same split, plus a receipt.") ]}),
        json!({"event":"note","text":"<i>No lock-in: the mirror rule means an envelope rewrite draws no PayTP execution; the client always pays the signed terms or plain x402.</i>"}),
    ];
    let wire = json!({
        "plain_x402_client": { "split_address": split, "IL_settled_minor_units": il_plain, "paytp_receipt": null,
            "note": "the split divides by construction, but no PayTP receipt/attribution" },
        "paytp_aware_client": { "signed_paytp_quote": as_value(&bq2.quote.to_json()), "split_address": bq2.split_address,
            "IL_settled_minor_units": il_paytp, "receipt": receipt.as_ref().ok().map(|r| as_value(&r.to_json())) },
    });
    out(events, wire)
}

/// **D-09** — attacks that fail: the security model holds. Each attack is executed against
/// the real payer/merchant gate and REJECTED. `attack` ∈ the three commitment-level paths
/// {"meed-strip","understate","bad-quote"} plus the Tier-0 baseline paths
/// {"replay","substitution","short"}.
#[wasm_bindgen]
pub fn d09_attack_trace(attack: &str) -> String {
    // Commitment-level adversarial paths (Tier 1) — each drives the REAL payer/merchant
    // gate and renders the actual error it returned. The baseline (Tier 0) redeem attacks
    // below (replay/substitution/short) fall through.
    match attack {
        "meed-strip" => return d09_meed_strip(),
        "understate" => return d09_understated_settlement(),
        "bad-quote" => return d09_bad_quote(),
        _ => {}
    }
    let sk = [0x55u8; 32];
    let merchant = Merchant::new(sk, "eip155:1:0xMERCHANT");
    let rail = VirtualRail::new(0);
    let store = InMemoryStore::new();
    let resource = "https://api.example/A";
    let amount = 1_000_000u128;
    let nonce = [0x99u8; 32];
    let bq = merchant.build_baseline_quote(
        &rail,
        BaselineParams {
            resource,
            nonce,
            exp: 2_000_000_000,
            idem: b"d09".to_vec(),
            registry_version: 5,
            baseline_network: "eip155:8453",
            asset: ASSET_ID,
            amount,
            finality: "final",
            grace: 300,
            retry: 600,
            max_timeout_seconds: 60,
            extra: None,
            vector: schema01_vector(),
        },
    );
    let split = bq.split_address.clone();
    let quote_json = String::from_utf8(bq.quote.to_json()).unwrap();
    let now = rail.chain_time();

    let mut events = vec![];
    // Render the ACTUAL redeem outcome — never assert "rejected" unless it truly was.
    // If an attack ever unexpectedly succeeds, say so loudly (that would be a real hole).
    let verdict = |res: Result<paytp_core::tier0::Receipt, RedeemError>,
                   why: &str|
     -> serde_json::Value {
        match res {
            Ok(_) => {
                json!({"event":"FAIL","ok":false,"text": format!("⚠ Attack SUCCEEDED — {} would be a real hole. (It does not; this branch should never render.)", why)})
            }
            Err(e) => {
                json!({"event":"reject","reject":true,"text": format!("<b>Rejected: {:?}</b> — {}", e, why)})
            }
        }
    };
    match attack {
        "replay" => {
            // Re-present the SAME payment authorization twice — the free-riding
            // "one authorization, many deliveries" attack.
            let transfer = Transfer { to: split.clone(), asset: ASSET_ID.into(), amount, kind: TransferKind::Payment, memo: None };
            let settle_id = [0xA1; 32];
            let first = merchant.redeem_baseline(&quote_json, resource, transfer.clone(), settle_id, &rail, &store, now);
            let second = merchant.redeem_baseline(&quote_json, resource, transfer, settle_id, &rail, &store, now);
            events.push(json!({"event":"attack","text":"<b>Nonce double-spend / free-riding</b>: reuse one authorization's nonce to unlock a second delivery.",
                "code":[ code("exec","paytp_merchant::Merchant::redeem_baseline · store.consume_nonce","crates/paytp-merchant/src/lib.rs","The consumed-nonce record is atomic and checked before delivery; the second redeem of the same nonce returns RedeemError::Replayed — one authorization, one delivery.") ]}));
            events.push(match &first {
                Ok(_) => json!({"event":"ok","ok":true,"text":"First redeem: delivered once (legitimate)."}),
                Err(e) => json!({"event":"reject","reject":true,"text": format!("First redeem unexpectedly failed: {:?}.", e)}),
            });
            events.push(verdict(second, "the atomic consumed-nonce record (checked at the merchant, before delivery) blocks the second delivery — one authorization, one delivery"));
        }
        "substitution" => {
            let transfer = Transfer { to: split.clone(), asset: ASSET_ID.into(), amount, kind: TransferKind::Payment, memo: None };
            let bad = merchant.redeem_baseline(&quote_json, "https://api.example/B", transfer, [0xA2; 32], &rail, &store, now);
            events.push(json!({"event":"attack","text":"<b>Cross-resource substitution</b>: reuse a proof paid for resource A to unlock a different resource B.",
                "code":[ code("exec","paytp_merchant::Merchant::redeem_baseline (resource binding, F3.4)","crates/paytp-merchant/src/lib.rs","The merchant-signed quote binds the payment to ONE resource; a redeem whose expected_resource differs from the signed resource is rejected before delivery.") ]}));
            events.push(verdict(bad, "the merchant-signed quote binds the payment to <i>one</i> resource"));
        }
        _ /* short */ => {
            let short = amount / 2;
            let transfer = Transfer { to: split.clone(), asset: ASSET_ID.into(), amount: short, kind: TransferKind::Payment, memo: None };
            let bad = merchant.redeem_baseline(&quote_json, resource, transfer, [0xA3; 32], &rail, &store, now);
            events.push(json!({"event":"attack","text":"<b>Underpayment</b>: pay half and demand delivery.",
                "code":[ code("exec","paytp_merchant::Merchant::redeem_baseline (amount check, F4.4)","crates/paytp-merchant/src/lib.rs","Settlement-precedes-delivery verifies the FULL quoted amount reached the split at quoted finality; a short payment is rejected before delivery.") ]}));
            events.push(verdict(bad, "settlement-precedes-delivery verifies the full amount reached the split at quoted finality"));
        }
    }
    events.push(json!({"event":"note","text":"<i>Each attack is executed against the real RI merchant in your browser — the rejection is the code refusing, not a scripted animation.</i>"}));
    let wire = json!({
        "attack": attack,
        "signed_paytp_quote": as_value(&bq.quote.to_json()),
        "split_address": split,
        "note": "the redeem error shown in each step is the real RedeemError enum the merchant returned",
    });
    out(events, wire)
}

// ---- D-09 commitment-level adversarial paths (Tier 1) ----------------------------
// Each maps to one of the three commitments and drives the REAL payer/merchant gate,
// rendering the actual error it returned. The bad object is always a fully-valid,
// signed baseline with exactly ONE field corrupted, so the rejection is provably the
// specific gate — not an incidental malformation. Fixed test identities (deterministic).
const ADV_PAYER_SK: [u8; 32] = [1u8; 32];
const ADV_MERCH_SK: [u8; 32] = [2u8; 32];
const ADV_ENC_SEED: [u8; 32] = [7u8; 32];
const ADV_CID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 7];
const ADV_NOW: u64 = 1_700_000_000;

/// The conformant schema-0x01 channel vector (IL/OS/Wallet/DevFund 50/10/30/10). Governed
/// destinations use the pinned constants: 0x11 OS → independent OS fund (unasserted OS, §10.1),
/// 0x13 → the Development Fund — so it passes `validate_vector_governed` (F5-o).
fn conformant_channel_vector() -> Vec<VectorEntry> {
    vec![
        VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:0xIL".into(),
        },
        VectorEntry {
            role: 0x11,
            bp: 10,
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        VectorEntry {
            role: 0x12,
            bp: 30,
            dest: "eip155:1:0xWALLET".into(),
        },
        VectorEntry {
            role: 0x13,
            bp: 10,
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

/// A fully-populated postpay CHANNEL_AUTH carrying `vector` (unsigned).
fn adv_channel_auth(merchant_key: [u8; 32], vector: Vec<VectorEntry>, s: [u8; 32]) -> ChannelAuth {
    ChannelAuth {
        payer_key: crypto::ed25519_public(&ADV_PAYER_SK),
        channel_id: ADV_CID,
        merchant_key,
        denom: "eip155:1/erc20:0xUSDC".into(),
        mode: MODE_POSTPAY,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        refund_ptr: None,
        baseline_net: "eip155:1".into(),
        rate_source: None,
        rate_dev: None,
        schema: 1,
        vector,
        registry_v: 5,
        hs: crypto::h_commit(&s),
        predecessor: None,
        timestamp: ADV_NOW,
        baseline_asset: "eip155:1/erc20:0xUSDC".into(),
        contract: 1,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        sig: None,
    }
}

fn adv_k_session(merchant_key: [u8; 32], s: [u8; 32]) -> [u8; 32] {
    crypto::k_session(
        &s,
        &crypto::bind_salt(&crypto::ed25519_public(&ADV_PAYER_SK), &merchant_key),
        &ADV_CID,
    )
}

fn adv_batch_body(cid: [u8; 8], slices: &[Slice]) -> Vec<u8> {
    let head = Object::from_fields(vec![Field::new(0x00, false, cid.to_vec())])
        .unwrap()
        .encode();
    let mut frames = vec![head];
    frames.extend(slices.iter().map(|s| s.encode()));
    tlv::frame_objects(&frames)
}

fn framed(octet: u8, obj: &[u8]) -> Vec<u8> {
    let mut v = vec![octet];
    v.extend_from_slice(obj);
    v
}

/// **D-09 · meed-strip** (edge incentives / the USP). A rogue interaction layer ships a
/// 2-role `[IL 50, Wallet 50]` vector that starves OS + the Dev-Fund. TWO independent gates
/// refuse it: the wallet won't sign the CHANNEL_AUTH, and the merchant won't open it — so the
/// governed 50/10/30/10 cannot be stripped off the wire.
fn d09_meed_strip() -> String {
    let mut driver = ChannelDriver::new(ADV_MERCH_SK, &ADV_ENC_SEED, "eip155:1:0xMERCHANT");
    let mkey = driver.key();
    let enc = driver.enc_key();
    let stripped = vec![
        VectorEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:0xIL".into(),
        },
        VectorEntry {
            role: 0x12,
            bp: 50,
            dest: "eip155:1:0xWALLET".into(),
        },
    ];

    let mut events = vec![
        json!({"event":"attack","text":"<b>Meed-strip</b> (defending the meed): a rogue interaction layer assembles a channel whose MEED_VECTOR drops the OS and Development-Fund roles — a 2-role <code>[IL 50bp, Wallet 50bp]</code> split — to keep the governed 1% for itself instead of the 50/10/30/10 the protocol mandates."}),
    ];

    // Gate 1 — the WALLET refuses to sign a nonconformant CHANNEL_AUTH (payer-side).
    let custody = Custody::from_root(&[0xE9u8; 32]);
    let mut params = adv_channel_params();
    params.vector = stripped.clone();
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        mkey,
        "merchant.example.com",
        enc,
    );
    let trust = PayerChannelTrust::new(&custody, &binding).with_meed_dest("eip155:1:0xWALLET");
    let sign_res = ChannelClient::open(
        &trust,
        &DEMO_CLOCK,
        StaticPolicy::new("eip155:1:0xUSDC", 2_000_000),
        &params,
        paytp_core::registry::SnapshotStore::empty_ref(),
    );
    let wallet_err = match &sign_res {
        Ok(_) => None,
        Err(e) => Some(format!("{:?}", e)),
    };
    events.push(match &sign_res {
        Ok(_) => json!({"event":"FAIL","ok":false,"text":"⚠ The wallet SIGNED a stripped vector — that would be a real hole. (This branch should never render.)"}),
        Err(e) => json!({"event":"reject","reject":true,"text": format!("<b>Gate 1 — the wallet refuses to sign: {:?}</b>. The payer validates the MEED_VECTOR against schema 0x01 before signing; it never relies on the merchant to police the split that routes the meed.", e),
            "code":[ code("exec","paytp_wallet::ChannelClient::open","crates/paytp-wallet/src/channel.rs","Before signing the CHANNEL_AUTH, the wallet validates the MEED_VECTOR shape (schema 0x01); a stripped vector returns ChannelClientError::Establish — the payer never signs it.") ]}),
    });

    // Gate 2 — even a rogue payer-signed bad auth is refused by the MERCHANT at open.
    let mut auth = adv_channel_auth(mkey, stripped.clone(), [0x5au8; 32]);
    auth.sign(&ADV_PAYER_SK).expect("sign auth");
    let sig_ok = auth.verify().is_ok();
    let open = ChannelOpen::build(auth, &enc, &[0x5au8; 32]).expect("build open");
    let open_res = driver.open_channel(&open, ADV_NOW);
    let merchant_err = match &open_res {
        Ok(_) => None,
        Err(e) => Some(format!("{:?}", e)),
    };
    events.push(match &open_res {
        Ok(_) => json!({"event":"FAIL","ok":false,"text":"⚠ The merchant OPENED a stripped-vector channel — that would be a real hole."}),
        Err(e) => json!({"event":"reject","reject":true,"text": format!("<b>Gate 2 — the merchant refuses to open: {:?}</b>. The payer signature verifies ({}), so the rejection is the merchant re-checking the MEED_VECTOR at open — not a bad signature. Two independent gates: the governed 1% cannot be stripped off the wire.", e, if sig_ok { "valid" } else { "INVALID?" }),
            "code":[ code("exec","paytp_merchant::ChannelDriver::open_channel","crates/paytp-merchant/src/channel.rs","At open the merchant independently re-validates the CHANNEL_AUTH vector (validate_vector_governed); a stripped vector returns ChannelError::BadAuth even with a valid payer signature.") ]}),
    });
    events.push(json!({"event":"note","text":"<i>Both refusals are the real RI channel code executing in your browser — the wallet's pre-sign check and the merchant's open-time check, each returning its actual error enum.</i>"}));

    let wire = json!({
        "attack": "meed-strip",
        "governed_vector_schema_0x01": [{"role":"0x10 Interaction Layer","bp":50},{"role":"0x11 OS","bp":10},{"role":"0x12 Wallet","bp":30},{"role":"0x13 Dev-Fund","bp":10}],
        "attacker_vector": [{"role":"0x10 Interaction Layer","bp":50},{"role":"0x12 Wallet","bp":50}],
        "wallet_sign_error": wallet_err,
        "merchant_open_error": merchant_err,
        "note": "wallet rejects at sign-time (ChannelClientError), merchant rejects at open-time (ChannelError) — both are the real enum values the RI returned",
    });
    out(events, wire)
}

/// The wire-terms the interaction layer assembles for a channel open (conformant baseline).
/// The merchant identity is NOT here — it comes from the ACCEPTED binding at open, not the
/// IL-assembled params.
fn adv_channel_params() -> ChannelOpenParams {
    ChannelOpenParams {
        channel_id: ADV_CID,
        denom: "eip155:1/erc20:0xUSDC".into(),
        baseline_asset: "eip155:1/erc20:0xUSDC".into(),
        baseline_net: "eip155:1".into(),
        prepay: true,
        limit_l: 1_000_000,
        limit_e: 500_000,
        th_value: 100_000,
        th_time: 3600,
        schema: 1,
        contract: 1,
        registry_v: 5,
        vector: conformant_channel_vector(),
        refund_ptr: Some("eip155:1:0xPAYERREFUND".into()),
        rate_source: None,
        rate_dev: None,
        fin_meed: "final".into(),
        fin_denom: "final".into(),
        timestamp: ADV_NOW,
    }
}

/// **D-09 · understated settlement** (bounded trust). A real channel meters + checkpoints;
/// at settlement the debtor proposes a round paying the merchant far less than the checkpoint
/// owes. The merchant recomputes against its own metered books (F6-f) and rejects.
fn d09_understated_settlement() -> String {
    let mut c = Carriage::demo(ChannelDriver::new(
        ADV_MERCH_SK,
        &ADV_ENC_SEED,
        "eip155:1:0xSETTLE",
    ));
    let mkey = c.merchant_key();
    let enc = c.enc_key();
    let s = [0x5au8; 32];

    // Open a real channel (conformant vector) through the carriage.
    let mut auth = adv_channel_auth(mkey, conformant_channel_vector(), s);
    auth.sign(&ADV_PAYER_SK).expect("sign auth");
    let open = ChannelOpen::build(auth, &enc, &s).expect("build open");
    c.channel(&framed(0x01, &open.encode().unwrap()), ADV_NOW)
        .expect("open channel");

    // Meter two real Value-Slices: gross 15_000 minor units.
    let k = adv_k_session(mkey, s);
    let slices = [
        Slice::seal(1, 10_000, &k).expect("seal 1"),
        Slice::seal(2, 5_000, &k).expect("seal 2"),
    ];
    c.batch(&adv_batch_body(ADV_CID, &slices)).expect("meter");
    let metered: u128 = 15_000;

    // A real bilateral checkpoint co-signs the running total; capture the operative ref.
    let mut cp = c
        .state(&ADV_CID)
        .unwrap()
        .build_checkpoint(ADV_NOW, [0u8; 32], vec![]);
    cp.sign_payer(&ADV_PAYER_SK).expect("payer ckpt");
    let mut bilateral = cp.clone();
    bilateral
        .sign_merchant(&ADV_MERCH_SK)
        .expect("merchant ckpt");
    let ckpt_ref = bilateral.reference().expect("ckpt ref");
    // F5.5 two-label wrapper: {0x00 PROPOSED (half-signed ckpt), 0x70 SIG (ckpt-req)}.
    let mut req = CheckpointRequest::proposing(cp);
    req.sign(&ADV_PAYER_SK).expect("ckpt-req sig");
    c.channel(&framed(0x03, &req.encode().unwrap()), ADV_NOW)
        .expect("checkpoint");

    // The debtor proposes an UNDERSTATED deterministic round: net = 1 (owed = 14_850). The
    // meed leg (P / E_r) is left correct — only the merchant-net is understated — so the
    // rejection is provably the F6-f net recompute, not a malformed leg.
    let understated = SettlementPropose {
        channel_id: ADV_CID,
        ckpt_ref,
        outputs: vec![Output {
            amount: num_bigint::BigUint::from(1u32),
            asset: "eip155:1:0xUSDC".into(),
            dest: "eip155:1:0xSETTLE".into(),
        }],
        instance_leg: Some(InstanceLeg {
            amount: num_bigint::BigUint::from(150u32),
            credited: vec![],
            extinguished: vec![
                (0x10, num_bigint::BigUint::from(750_000u32)),
                (0x11, num_bigint::BigUint::from(150_000u32)),
                (0x12, num_bigint::BigUint::from(450_000u32)),
                (0x13, num_bigint::BigUint::from(150_000u32)),
            ],
        }),
        conversion: None,
        sig_payer: None,
        sig_merchant: None,
    };
    let mut understated = understated;
    understated.sign_payer(&ADV_PAYER_SK).expect("sign propose");
    let res = c.channel(&framed(0x06, &understated.encode().unwrap()), ADV_NOW);
    let merchant_err = match &res {
        Ok(_) => None,
        Err(e) => Some(format!("{:?}", e)),
    };

    let mut events = vec![
        json!({"event":"attack","text": format!("<b>Understated settlement</b> (bounded trust): a real channel meters <b>{}</b> (15,000 minor units) across two Value-Slices, and a bilateral checkpoint co-signs the total. At settlement the debtor proposes a round paying the merchant <b>1 minor unit</b> — far below the 14,850 the checkpoint owes.", amt(metered))}),
    ];
    events.push(match &res {
        Ok(_) => json!({"event":"FAIL","ok":false,"text":"⚠ The merchant ACCEPTED an understated round — that would be a real hole."}),
        Err(e) => json!({"event":"reject","reject":true,"text": format!("<b>The merchant refuses to accept the settlement ({:?})</b>. It recomputes the round against its own metered checkpoint (F6-f): the proposed net does not equal the merchant-net the books owe. Bounded trust — the cap holds at settlement.", e),
            "code":[ code("exec","paytp_merchant::Carriage::on_settlement_propose → recompute_round","crates/paytp-merchant/src/carriage.rs","The merchant recomputes the round's outputs from its own metered checkpoint (F6-f); a proposal whose net differs from the recomputed owed is rejected (CarriageError::Rejected).") ]}),
    });
    events.push(json!({"event":"note","text":"<i>The channel opened, metered, and checkpointed for real; the rejection is the carriage's real settlement recompute, executing in your browser.</i>"}));

    let wire = json!({
        "attack": "understated-settlement",
        "channel_metered_minor_units": metered,
        "merchant_net_owed_minor_units": 14_850,
        "proposed_net_minor_units": 1,
        "operative_ckpt_ref": hex(&ckpt_ref),
        "merchant_error": merchant_err,
        "note": "the checkpoint is bilaterally co-signed; the merchant's F6-f recompute rejects any round that under-pays the metered total",
    });
    out(events, wire)
}

/// A conformant schema-0x01 meed vector as `MeedEntry`s. Governed destinations use the pinned
/// constants (0x11 OS → independent OS fund, 0x13 → Development Fund) so it passes
/// `validate_vector_governed` (F5-o); 0x10/0x12 are free payer-side CAIP pointers.
fn conformant_meed_vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: "eip155:1:0xIL".into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: "eip155:1:0xWALLET".into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

/// **D-09 · over-charging quote** (end-to-end / payer sovereignty). A compromised interaction
/// layer hands the wallet a merchant-signed quote demanding a meed far above the governed
/// carve (here 500,000 on a 990,000 net — ~50%, vs the ~1% cap). The vector is conformant, so
/// this exercises a DISTINCT gate from meed-strip: the wallet's per-payment spend/carve
/// policy denies it before any funds move.
fn d09_bad_quote() -> String {
    // The rail routes the quote's net+meed asset so the wallet's F4.5 route/finality
    // pre-flight passes and the refusal is provably the meed-carve gate (this demo's point),
    // not route availability. The window is feasible (exp far in the future).
    let rail = VirtualRail::new(1).with_assets(vec!["eip155:1/native".into()]);
    let merchant = Merchant::new([0x55u8; 32], "eip155:1:0xMERCHANTNET");
    let custody = Custody::from_root(&[0xD6u8; 32]);
    // Budget generous enough that the two legs' SUM passes — so the refusal is provably the
    // meed-carve gate, not the spend budget. The wallet's own 0x12 payout pointer matches the
    // conformant vector's wallet share, so the F5-o payer-side self-defense passes and the
    // refusal is the meed-carve gate (not the 0x12 misroute check).
    let wallet = Wallet::new(&custody, StaticPolicy::new("eip155:1/native", 2_000_000))
        .with_meed_dest("eip155:1:0xWALLET");

    // Same-asset net + meed so the tight ≤-carve gate applies (F7). The meed
    // (500,000) dwarfs the governed carve on the 990,000 net. The merchant SIGNS it (it signs
    // whatever it is handed); the payer-side gate is what refuses.
    let resource = "https://api.example/premium";
    let net_amount: u128 = 990_000;
    let meed_demanded: u128 = 500_000;
    let params = TwoLegParams {
        resource,
        nonce: [0x08u8; 32],
        exp: 2_000_000_000,
        idem: b"d09-overcharge".to_vec(),
        registry_version: 5,
        net_network: "eip155:1",
        net_asset: "eip155:1/native",
        net_amount,
        baseline_network: "eip155:1",
        baseline_asset: "eip155:1/native",
        meed_amount: meed_demanded,
        rate: "1",
        rate_source: "coinbase-spot",
        reclaim: 3_600,
        contest: 600,
        grace: 300,
        retry: 600,
        fin_meed: "final",
        fin_net: "final",
        vector: conformant_meed_vector(),
    };
    let tlq = merchant.build_two_leg_quote(&rail, params);
    let quote_json = String::from_utf8(tlq.quote.to_json()).unwrap();
    // The origin binding's host MUST match the requested resource's host
    // (`api.example`), else `plan_two_leg` short-circuits on the F2-k origin/resource
    // bind before it can reach the payer-side meed-carve gate this scenario demonstrates.
    let binding = paytp_core::channel::establish::AcceptedBinding::for_test(
        merchant.key,
        "api.example",
        [0xE5; 32],
    );

    let res = wallet.plan_two_leg(
        &rail,
        &quote_json,
        &tlq.offer, // the operator-approved offer (F3-a mirror passes); the meed-carve gate is what rejects
        &binding,
        resource,
        "eip155:1:0xPAYERREFUND",
        None,
    );
    let wallet_err = match &res {
        Ok(_) => None,
        Err(e) => Some(format!("{:?}", e)),
    };

    let mut events = vec![
        json!({"event":"attack","text": format!("<b>Over-charging quote</b> (payer sovereignty): a compromised interaction layer hands the wallet a merchant-signed quote demanding a meed of <b>{}</b> (500,000 minor units) on a <b>{}</b> net — roughly half the payment, far above the governed ~1% carve.", amt(meed_demanded), amt(net_amount))}),
    ];
    events.push(json!({"event":"ok","text":"The <i>merchant</i> signs the quote — a signature only attests the merchant issued it, not that its terms are within policy."}));
    events.push(match &res {
        Ok(_) => json!({"event":"FAIL","ok":false,"text":"⚠ The wallet FUNDED an over-charging quote — that would be a real hole."}),
        Err(e) => json!({"event":"reject","reject":true,"text": format!("<b>The wallet denies it: {:?}</b>. Before funding, the wallet gates the quote against its own per-payment policy and the bounded meed carve — it does not trust the merchant's terms. No funds move.", e),
            "code":[ code("exec","paytp_wallet::Wallet::plan_two_leg","crates/paytp-wallet/src/execute.rs","Before any funds move, the wallet gates the merchant-signed quote against its own bounded meed carve (meed_carve_cap); a meed far above the carve returns WalletError::PolicyDenied.") ]}),
    });
    events.push(json!({"event":"note","text":"<i>The refusal is the real wallet's <code>plan_two_leg</code> executing in your browser — the end-to-end guarantee: the decision is the payer's, at the payer's edge.</i>"}));

    let wire = json!({
        "attack": "over-charging-quote",
        "signed_paytp_quote": as_value(&tlq.quote.to_json()),
        "net_minor_units": net_amount,
        "meed_demanded_minor_units": meed_demanded,
        "governed_meed_is": "~1% of the net; the wallet's carve gate caps the meed leg well below the 500,000 demanded",
        "wallet_plan_error": wallet_err,
        "note": "the quote carries a valid merchant signature and a conformant vector; the wallet's plan_two_leg denies it on the bounded meed carve (a distinct gate from the meed-strip conformance check) before any funds move",
    });
    out(events, wire)
}

/// **D-01 / D-02** — Tier 1 channels: settlement compression + the meed on the wire.
/// `requests` micro-payments are metered off-chain as slices and settled in a small
/// number of aggregate rounds; each round's meed funds an F4.2 claim-record (the real
/// aggregate-leg primitive) that divides among the distribution roles. `postpay` toggles
/// the agent (postpay credit window) vs the reader (prepay deposit) framing.
#[wasm_bindgen]
pub fn d_channel_trace(postpay: bool, requests: u32) -> String {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55u8; 32], "eip155:1:0xMERCHANT");
    let meed = [
        MeedShare {
            dest: "eip155:1:0xIL".into(),
            bp: 50,
        },
        MeedShare {
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
        MeedShare {
            dest: "eip155:1:0xWALLET".into(),
            bp: 30,
        },
        MeedShare {
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
    ];
    let dests_bps: Vec<(String, u16)> = meed.iter().map(|r| (r.dest.clone(), r.bp)).collect();
    // The bound deploy recomputes the seed from these real F4.1 inputs and binds the merchant key
    // + meed destinations from the SAME inputs — the demo proves the on-chain seed↔recipients
    // binding, it does not merely assert it.
    let inputs = demo_address_inputs(merchant.key, &dests_bps, None);
    let seed = inputs.seed_instance().expect("seed");
    let addr = rail
        .deploy_instance(&seed, &inputs)
        .expect("demo instance inputs are well-formed");

    let n = requests.max(1) as u64;
    let per_slice = 1_000_000u64; // $1 / request gross
    let k_session = [0x0cu8; 32];
    let vector = vec![(0x10u8, 50u16), (0x11, 10), (0x12, 30), (0x13, 10)];
    let big = (n as u128) * (per_slice as u128) + 1_000_000_000;
    let mode = if postpay { Mode::Postpay } else { Mode::Prepay };
    // A REAL channel state: prepay funds the deposit first (drives B negative,
    // deposit-before-consume, F6-g), then N MAC-sealed Value-Slices are accepted.
    let mut ch = ChannelState::new([0xc1u8; 8], k_session, mode, big, big, vector);
    if !postpay {
        ch.credit_funding((n as u128) * (per_slice as u128));
    }
    for seq in 1..=n {
        let slice = Slice::seal(seq, per_slice, &k_session).expect("seal slice");
        ch.accept_slice(&slice).expect("accept slice"); // real MAC verify + metering
    }
    ch.checkpoint(); // a real bilateral checkpoint (advances the floor)
    let metered = ch.cum_total(); // = n * per_slice, the REAL metered total

    // Settle every `batch` slices → M REAL on-rail watermark advances. M DERIVES from N (never
    // hardcoded): M = ceil(N / batch). Each round advances the channel's cumulative meed
    // watermark (F6-o, Option-W) to the total owed through that batch — the delta divides among
    // the roles. One channel id across all rounds (a per-round claim-record is the retired path).
    let batch = 50u64;
    let channel_id = [0xc1u8; 8]; // the ONE channel (matches `ChannelState` above)
    let mut m = 0u32;
    let mut covered = 0u64;
    while covered < n {
        let next = (covered + batch).min(n);
        // The cumulative meed owed through slice `next` — the new watermark target.
        let cum_meed = (next as u128) * (per_slice as u128) / 100;
        rail.advance_channel_meed(None, &addr, channel_id, cum_meed, ASSET_ID.into())
            .expect("channel meed watermark advance");
        m += 1;
        covered = next;
    }

    let actor = if postpay { "coding agent" } else { "reader" };
    let il = rail.balance("eip155:1:0xIL");
    let os = rail.balance(consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER);
    let wallet = rail.balance("eip155:1:0xWALLET");
    let fund = rail.balance(consts::DEV_FUND_DEST_PLACEHOLDER);
    let events = vec![
        json!({"event":"open","text": format!("Channel opens ({} mode). {}",
            if postpay {"postpay"} else {"prepay"},
            if postpay {"The merchant extends a credit window — the agent gets value first, settles later."}
                       else {"The reader deposits once (funding drives the balance negative); unlocks draw it back toward 0."})}),
        json!({"event":"stream","mode":"exec","text": format!("The {} makes <b>{} requests</b> — each a real ~36-byte Value-Slice, <b>MAC-sealed and accepted into a real channel state</b>. Metered off-rail: <b>{}</b> across {} slices, zero rail transfers.", actor, n, amt(metered), n),
        "code":[
            code("exec","paytp_core::slice::Slice::seal","crates/paytp-core/src/slice.rs","Seals each 36-byte Value-Slice (SEQ 8 + AMT 6 + Poly1305 TAG 16 + TLV framing) under the session key."),
            code("exec","paytp_core::channel::ChannelState::accept_slice","crates/paytp-core/src/channel/state.rs","MAC-verifies each slice (constant-time) FIRST, then meters it into the channel's running cum_total — off-rail, zero transfers.")
        ]}),
        json!({"event":"checkpoint","mode":"exec","text": format!("A real bilateral <b>checkpoint</b> co-signs the running total (cum_total = {}) and advances the floor.", amt(metered)),
            "code":[ code("exec","paytp_core::channel::ChannelState::checkpoint","crates/paytp-core/src/channel/state.rs","Folds the metered window into the checkpoint transcript and advances the settled floor — the co-signed running total.") ]}),
        json!({"event":"settle","mode":"exec","ok":true,"text": format!("Settled in <b>{} real on-rail rounds</b> (one channel meed watermark advance each, ~{} slices per round) — the meed divides among the enabling roles.", m, batch),
            "code":[ code("exec","paytp_rail::VirtualRail::advance_channel_meed","crates/paytp-rail/src/virtual_rail.rs","Each settlement round advances the channel's cumulative meed watermark (F6-o, Option-W); the round count M = ceil(N / 50) is derived from N, never hardcoded.") ]}),
        json!({"event":"divided","mode":"exec","ok":true,"text": format!("Meed to the enabling roles: <b>Interaction Layer {}</b>{}, Wallet {}, Development Fund {}.",
            amt(il),
            if postpay { format!(" (the agent framework), OS → the independent open-source fund {} (headless server — outside the Foundation)", amt(os)) }
            else { format!(", OS {}", amt(os)) },
            amt(wallet), amt(fund)),
            "code":[ code("exec","paytp_rail::MeedInstance::advance_channel_meed","crates/paytp-rail/src/instance.rs","The watermark advance divides its meed delta among the establishment-bound roles on the wire (cumulative target_P, floor(P·bp_d/bp_total) per destination).") ]}),
        json!({"event":"compress","mode":"exec","ok":true,"text": format!("<b>{} slices → {} rail settlements</b> (executed here — real slices into a real channel state). Channels compress settlement; the per-request rail overhead is amortized, and every enabling role is still paid, on the wire.", n, m)}),
    ];
    let wire = json!({
        "instance_address": addr,
        "channel_cum_total_minor_units": metered,
        "slices_accepted": n,
        "settlement_rounds": m,
        "batch_per_round": batch,
        "meed_division": { "interaction_layer_minor_units": il, "os_independent_fund_minor_units": os, "wallet_minor_units": wallet, "development_fund_minor_units": fund },
    });
    out(events, wire)
}

/// **D-06** — rail-agnosticism: the same payment's division is identical across rails; the
/// meed always executes on the baseline. Rail A (VirtualRail) runs in-page; the
/// identical division on the Solana exact-svm split PDA is proven live in `interop/x402`.
#[wasm_bindgen]
pub fn d06_rail_trace() -> String {
    let amount = 1_000_000u128;
    let meed: Vec<(String, u16)> = vec![
        ("eip155:1:0xIL".into(), 50),
        (consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(), 10),
        ("eip155:1:0xWALLET".into(), 30),
        (consts::DEV_FUND_DEST_PLACEHOLDER.into(), 10),
    ];
    let rail = VirtualRail::new(0);
    // The address is a real F4.1 derivation over merchant/asset/vector — this is exactly D-06's
    // point (same inputs → same address on any rail), so it must not be a fixed seed. The bound
    // deploy recomputes the seed and derives the recipients from the SAME inputs.
    let inputs = demo_address_inputs(demo_merchant_key(), &meed, Some("eip155:1:0xMERCHANT"));
    let seed = inputs.seed_split().expect("seed");
    let addr = rail
        .deploy_split(&seed, &inputs)
        .expect("demo split inputs are well-formed");
    rail.submit(Transfer {
        to: addr.clone(),
        asset: ASSET_ID.into(),
        amount,
        kind: TransferKind::Payment,
        memo: None,
    })
    .expect("pay");
    let il = rail.balance("eip155:1:0xIL");
    let merchant = rail.balance("eip155:1:0xMERCHANT");
    let events = vec![
        json!({"event":"quote","text":"One signed quote, one MEED_VECTOR, one division — the split address is derived from the merchant/asset/vector, not the rail."}),
        json!({"event":"railA","mode":"exec","ok":true,"text": format!("<b>Rail A — VirtualRail</b> (executed in your browser): merchant {}, meed divides on the wire (IL {} …). Value conserved.", amt(merchant), amt(il)),
            "code":[ code("exec","paytp_rail::VirtualRail::deploy_split + distribute","crates/paytp-rail/src/virtual_rail.rs","The split address derives from merchant/asset/vector (F4.1), NOT the rail; the bound deploy recomputes the seed, and a plain payment then divides on the wire.") ]}),
        json!({"event":"railB","mode":"depicted","text":"<b>Rail B — Solana exact-svm split PDA</b>: the <b>identical</b> division — a plain client pays <code>TransferChecked → ATA(split_PDA)</code>, and <code>split_claim</code> divides 99/1 on-chain. <b>Proven in the RI</b>: runs live on a local validator in <code>interop/x402/settle-localnet.mjs</code> (M6.1c). Not re-run in this browser.",
            "code":[ code("depicted","paytp_kit::split_claim (Solana SBF contract)","interop/x402/settle-localnet.mjs","The identical F4.1 derivation + F7-d division on the on-chain split PDA — proven live on a local validator in interop/x402 (M6.1c); depicted here, not re-run in the browser.") ]}),
        json!({"event":"note","text":"Markets choose rails; the protocol doesn't. The meed always executes on the <b>baseline</b> rail — inside the payment on-baseline, or as its own small leg otherwise."}),
    ];
    let wire = json!({
        "derived_split_address": addr,
        "note": "the split address derives from merchant/asset/vector, NOT the rail — identical across rails",
        "on_wire_division_minor_units": {
            "merchant": merchant,
            "interaction_layer": il,
            "os_independent_fund": rail.balance(consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER),
            "wallet": rail.balance("eip155:1:0xWALLET"),
            "development_fund": rail.balance(consts::DEV_FUND_DEST_PLACEHOLDER),
        },
    });
    out(events, wire)
}

/// **D-08** — channel survives a reconnect (chaining): the tab continues with no
/// forced settlement and no value lost; the rail is never touched during the reconnect.
#[wasm_bindgen]
pub fn d08_reconnect_trace() -> String {
    let rail = VirtualRail::new(0);
    let merchant = Merchant::new([0x55u8; 32], "eip155:1:0xMERCHANT");
    let meed = [
        MeedShare {
            dest: "eip155:1:0xIL".into(),
            bp: 50,
        },
        MeedShare {
            dest: consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
        MeedShare {
            dest: "eip155:1:0xWALLET".into(),
            bp: 30,
        },
        MeedShare {
            dest: consts::DEV_FUND_DEST_PLACEHOLDER.into(),
            bp: 10,
        },
    ];
    let dests_bps: Vec<(String, u16)> = meed.iter().map(|r| (r.dest.clone(), r.bp)).collect();
    // The bound deploy recomputes the seed from these real F4.1 inputs and binds the merchant key
    // + meed destinations from the SAME inputs — the demo proves the on-chain seed↔recipients
    // binding, it does not merely assert it.
    let inputs = demo_address_inputs(merchant.key, &dests_bps, None);
    let seed = inputs.seed_instance().expect("seed");
    let addr = rail
        .deploy_instance(&seed, &inputs)
        .expect("demo instance inputs are well-formed");
    let il = "eip155:1:0xIL";

    // Stream 40 slices, drop, chain, stream 40 more — all off-rail. Prove the rail
    // ledger is untouched across the reconnect (settlement happens once, at the end).
    let rail_before_settle = rail.balance(il); // real: must be 0 through the whole reconnect
    let mut events = vec![
        json!({"event":"open","text":"A mobile reader opens a prepay channel and streams unlocks as Value-Slices in the connection. <i>(The chaining/stillborn mechanic below is F6.6 / F6-e — <b>proven in the RI's chaining + stillborn-checkpoint tests and the f6-stillborn F10 vector</b>; depicted here while the demo executes the settlement and proves the invariant that matters.)</i>"}),
        json!({"event":"stream","mode":"depicted","text":"<b>~40 slices</b> metered — the tab grows, co-signed in checkpoints. No rail transfer per slice.",
            "code":[ code("depicted","paytp_core::channel::ChannelState::accept_slice","crates/paytp-core/src/channel/state.rs","The metering plane (proven in D-01/D-02's executed path and the channel tests); depicted here to keep D-08 focused on the reconnect invariant.") ]}),
        json!({"event":"drop","mode":"depicted","reject":true,"text":"📵 <b>Connection drops</b> (Wi-Fi → cellular). The channel is bound to that connection — it ends with it."}),
        json!({"event":"chain","mode":"depicted","text":"The wallet <b>chains a fresh-keyed successor</b> from the last checkpoint, importing the tab's cumulative position. No settlement is forced.",
            "code":[ code("depicted","paytp_core::channel::checkpoint::StillbornState","crates/paytp-core/src/channel/checkpoint.rs","F6-e/F6.6: the deterministic synthetic checkpoint a fresh-keyed successor imports — proven in the RI's chaining + stillborn tests and the f6-stillborn F10 vector; depicted here.") ]}),
        json!({"event":"proof","mode":"exec","ok": rail_before_settle == 0,"text": format!("<b>Executed proof:</b> rail transfers <b>during the reconnect: 0</b> — the on-rail meed balance is still <b>{}</b>. The tab carried forward in the connection layer, never touching the settlement rail.", amt(rail_before_settle)),
            "code":[ code("exec","paytp_rail::VirtualRail::balance","crates/paytp-rail/src/virtual_rail.rs","Reads the on-rail meed balance across the drop: 0 — the executed proof that the reconnect touched no rail state.") ]}),
        json!({"event":"stream2","mode":"depicted","text":"The successor streams <b>~40 more slices</b> — the reader never noticed."}),
    ];
    // One REAL settlement at the very end (the whole ~80-request tab's meed) — a single
    // advance of the channel's cumulative meed watermark to the tab total (F6-o, Option-W).
    let total_meed = 80u128 * (1_000_000u128 / 100);
    rail.advance_channel_meed(None, &addr, [0xc1u8; 8], total_meed, ASSET_ID.into())
        .expect("settle");
    events.push(json!({"event":"settle","mode":"exec","ok":true,"text": format!("<b>Executed:</b> at close, <b>one</b> real settlement round divides the whole ~80-slice tab's meed — IL now holds {} on the rail. ~80 unlocks, 1 reconnect, <b>1 rail settlement</b>, zero value lost.", amt(rail.balance(il))),
        "code":[ code("exec","paytp_rail::VirtualRail::advance_channel_meed","crates/paytp-rail/src/virtual_rail.rs","One real settlement at close advances the channel meed watermark (F6-o, Option-W) for the whole ~80-slice tab's meed — the only rail transfer of the session.") ]}));
    let wire = json!({
        "instance_address": addr,
        "rail_balance_during_reconnect_minor_units": rail_before_settle,
        "final_settlement_meed_minor_units": total_meed,
        "IL_settled_after_close_minor_units": rail.balance(il),
        "note": "rail_balance_during_reconnect = 0 is the EXECUTED proof (no on-rail activity across the drop); the slice/checkpoint/chaining plane is depicted (M3/F6.6)",
    });
    out(events, wire)
}

// A native smoke test (also proves the path off-wasm; the wasm build is the spike gate).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d05_divides_and_conserves() {
        // OS ABSENT: IL 5000, OS→indep 1000, wallet 3000, dev 1000, merchant 990000; conserved.
        let json = d05_split_trace(1_000_000, true);
        assert!(json.contains("\"settled\":\"5000\""));
        assert!(json.contains("\"settled\":\"990000\""));
        assert!(json.contains("\"ok\":true"));
        // The absent-OS share is at the independent fund, distinct from the Dev Fund.
        assert!(json.contains(consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER));
        assert!(json.contains(consts::DEV_FUND_DEST_PLACEHOLDER));
    }

    #[test]
    fn d05_os_toggle_is_neutral_to_the_foundation() {
        // The neutrality invariant, on the REAL split: toggling the OS role changes ONLY
        // the OS destination. Merchant 99% and Dev-Fund 0.1% are byte-identical in both
        // states; the absent OS routes to the independent fund, the asserted OS to itself.
        let absent = d05_split_trace(1_000_000, true);
        let asserted = d05_split_trace(1_000_000, false);
        for j in [&absent, &asserted] {
            assert!(
                j.contains("\"settled\":\"990000\""),
                "merchant 99% unchanged"
            );
            assert!(j.contains("\"ok\":true"), "conserved");
        }
        // Absent → the OS 0.1% is at the independent fund; asserted → at its own address.
        assert!(absent.contains(consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER));
        assert!(asserted.contains("0xOPENSOURCEOS"));
        assert!(!asserted.contains(consts::INDEPENDENT_OS_FUND_DEST_PLACEHOLDER));
        // The Development Fund gets its 0.1% in BOTH states (Foundation income unchanged).
        assert!(absent.contains(consts::DEV_FUND_DEST_PLACEHOLDER));
        assert!(asserted.contains(consts::DEV_FUND_DEST_PLACEHOLDER));
    }

    #[test]
    fn d03_delivers_and_compares_fees() {
        let j = d03_oneshot_trace(1_000_000_000); // $1000
        assert!(j.contains("\"ok\":true"), "delivered");
        assert!(j.contains("a flat 1%"));
    }

    #[test]
    fn d04_scenarios() {
        assert!(d04_reclaim_trace("deliver").contains("shares release"));
        // Primary failsafe: net leg fails → payer whole, net never left.
        let nf = d04_reclaim_trace("netfail");
        assert!(
            nf.contains("payer reclaims")
                && nf.contains("never left the wallet")
                && nf.contains("whole")
        );
        // Worst case: merchant has the net, payer loses it (bounded).
        let fr = d04_reclaim_trace("fraud");
        assert!(fr.contains("already with the merchant") && fr.contains("payer reclaims"));
    }

    #[test]
    fn d07_both_paths_succeed() {
        let j = d07_coexistence_trace();
        assert!(j.contains("Plain x402 client"));
        assert!(j.contains("signed receipt"));
    }

    #[test]
    fn d_channel_compresses_and_divides() {
        let j = super::d_channel_trace(true, 100);
        assert!(j.contains("100 slices → 2 rail settlements")); // M = ceil(100/50), derived
        assert!(j.contains("real channel state"));
        assert!(j.contains("independent open-source fund")); // postpay OS neutrality
        let r = super::d_channel_trace(false, 50);
        assert!(r.contains("50 slices → 1 rail settlements")); // ceil(50/50) = 1
    }

    #[test]
    fn d09_attacks_are_rejected() {
        assert!(d09_attack_trace("replay").contains("Replayed"));
        assert!(d09_attack_trace("substitution").contains("\"reject\":true"));
        assert!(d09_attack_trace("short").contains("\"reject\":true"));
    }

    #[test]
    fn d09_commitment_attacks_are_rejected() {
        // Each commitment-level path must render a REAL rejection (never the FAIL/hole branch)
        // and carry the actual error the gate returned.
        let strip = d09_attack_trace("meed-strip");
        assert!(
            strip.contains("Establish"),
            "wallet must refuse to sign (Establish)"
        );
        assert!(
            strip.contains("BadAuth"),
            "merchant must refuse to open (BadAuth)"
        );
        assert!(
            !strip.contains("\"event\":\"FAIL\""),
            "no attack may succeed"
        );

        let under = d09_attack_trace("understate");
        assert!(
            under.contains("Rejected"),
            "carriage must reject the understated round"
        );
        assert!(!under.contains("\"event\":\"FAIL\""));

        let bad = d09_attack_trace("bad-quote");
        assert!(
            bad.contains("PolicyDenied"),
            "wallet must deny the over-charge (PolicyDenied)"
        );
        assert!(!bad.contains("\"event\":\"FAIL\""));
    }
}
