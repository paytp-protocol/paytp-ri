//! The M8 wedge demo, **Phase 2 — the channel upgrade** (§10.7 crossover),
//! demonstrated on the virtual rail.
//!
//! The baseline flow (see `wedge-agent`) settles each request on its own: k
//! requests = k on-rail splits, the meed divided k times. At repeat traffic a
//! Tier 1 channel engages — a postpay "tab" that meters requests off-chain and
//! settles them in **one aggregate round** that advances the channel's cumulative
//! **meed watermark** (F6-o, Option-W — the per-channel replacement for the
//! per-round claim-record the M3 channel plane once used).
//!
//! This scripted flow proves the two things that matter, side by side on the
//! rail: (1) the distribution meed is **identical** either way — the channel
//! does not avoid the meed, it amortizes the *per-request rail overhead*; and
//! (2) k requests settle in 1 rail operation instead of k. Per the §6 timebox
//! valve, the full live-HTTP slice carriage (M3, built + gated) is not re-driven
//! here; this demonstrates the upgrade's settlement + economics.
//!
//! Usage: `wedge-channel [N]`  (default 3)

use paytp_merchant::measure::channel_crossover_rail_ops;
use paytp_rail::{MeedShare, RailAdapter, Transfer, TransferKind, VirtualRail};
use paytp_wedge_demo as demo;

/// The per-request meed (gross × 100 bp) and its division among the roles.
const MEED_PER_REQ: u128 = demo::PRICE * (paytp_core::consts::MEED_BASE_BP as u128) / 10_000;

fn meed_shares() -> Vec<MeedShare> {
    demo::roles()
        .into_iter()
        .map(|r| MeedShare {
            dest: r.dest.to_string(),
            bp: r.bp,
        })
        .collect()
}

/// Distinct meed-role destinations (OS + Dev Fund share one), preserving order.
fn meed_dests() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for r in demo::roles() {
        if !out.iter().any(|(d, _)| d == r.dest) {
            out.push((r.dest.to_string(), r.label.to_string()));
        }
    }
    out
}

/// BASELINE: k separate on-rail split payments. Returns (per-dest meed, rail settlement ops).
fn baseline(k: u64) -> (Vec<u128>, u64) {
    let rail = VirtualRail::new(0);
    let meed: Vec<(String, u16)> = demo::roles()
        .into_iter()
        .map(|r| (r.dest.to_string(), r.bp))
        .collect();
    let recips = VirtualRail::split_recipients(&meed, demo::MERCHANT_PAYOUT)
        .expect("demo schema-0x01 meed vector sums within BP_DENOM");
    let seed = [0x51u8; 32];
    let addr = rail.deploy_split_unchecked(&seed, recips);
    for _ in 0..k {
        rail.submit(Transfer {
            to: addr.clone(),
            asset: demo::ASSET.into(),
            amount: demo::PRICE,
            kind: TransferKind::Payment,
            memo: None,
        })
        .unwrap();
    }
    let bal = meed_dests().iter().map(|(d, _)| rail.balance(d)).collect();
    (bal, k) // k on-rail settlements (one split payment per request)
}

/// CHANNEL: k requests metered off-chain, settled in ONE aggregate round that
/// advances the channel meed watermark (F6-o, the Option-W per-channel
/// replacement for the per-round claim-record). Returns (per-dest meed,
/// rail settlement ops).
fn channel(k: u64) -> (Vec<u128>, u64) {
    let rail = VirtualRail::new(0);
    let seed = [0x52u8; 32];
    let addr = rail.deploy_instance_unchecked(&seed, [0x55u8; 32], meed_shares());
    // The aggregate meed owed for k metered requests, settled once by advancing the
    // channel's cumulative meed watermark to that total (postpay → `from = None`).
    let aggregate = MEED_PER_REQ * (k as u128);
    rail.advance_channel_meed(None, &addr, [0u8; 8], aggregate, demo::ASSET.into())
        .expect("aggregate channel meed watermark advance");
    let bal = meed_dests().iter().map(|(d, _)| rail.balance(d)).collect();
    (bal, 1) // one on-rail settlement (the aggregate watermark advance)
}

fn main() {
    let k: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    let (base_roy, base_ops) = baseline(k);
    let (chan_roy, chan_ops) = channel(k);
    let dests = meed_dests();

    println!("── channel upgrade (§10.7 crossover), k = {k} requests ──\n");
    println!(
        "  {:<48}{:>14}{:>14}",
        "distribution role", "baseline", "channel"
    );
    let mut identical = true;
    for (i, (_dest, label)) in dests.iter().enumerate() {
        println!("  {:<48}{:>14}{:>14}", label, base_roy[i], chan_roy[i]);
        identical &= base_roy[i] == chan_roy[i];
    }
    let base_total: u128 = base_roy.iter().sum();
    let chan_total: u128 = chan_roy.iter().sum();
    println!(
        "  {:<48}{:>14}{:>14}",
        "— total meed —", base_total, chan_total
    );
    println!(
        "\n  on-rail settlements:   baseline = {base_ops} (one per request)   \
         channel = {chan_ops} (one aggregate round)"
    );

    // The M4-certified structural crossover (two-leg one-shot vs channel).
    let k_star = channel_crossover_rail_ops(3, 1, 2);
    println!(
        "  §10.7 two-leg crossover: a channel wins from k ≥ {k_star} (M4 structural rail-ops)."
    );

    let ok = identical && base_total == chan_total && base_total > 0 && chan_ops < base_ops;
    if ok {
        println!(
            "\nPASS — the distribution meed is IDENTICAL ({base_total}); the channel \
             settles {k} requests in {chan_ops} rail op vs {base_ops}. Same meed, \
             per-request overhead amortized."
        );
    } else {
        eprintln!("\nFAIL — meed mismatch or no amortization (identical={identical}, base_ops={base_ops}, chan_ops={chan_ops})");
        std::process::exit(1);
    }
}
