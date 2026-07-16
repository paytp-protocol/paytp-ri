//! The M4 `report` command — emits the §7 measurement report.
//!
//! Run: `cargo run -p paytp-merchant --example report`
//!
//! Every row is marked **measured-on-virtual** (structural: bytes / rail-op
//! counts / arithmetic floors) or **pending-real-rail** (gas / latency, whose
//! methodology is named but whose value waits for M5's real-rail measurement —
//! the §7 discipline that testnet gas is never reported as a mainnet number).

#![allow(clippy::print_literal)] // a report-printing binary, not library code

use paytp_merchant::measure::{channel_crossover_rail_ops, report, Source};

fn main() {
    println!("PayTP RI — M4 measurement report (virtual rail)\n");
    println!(
        "{:<38} {:>10}  {:<12}  {}",
        "row", "value", "unit", "source / note"
    );
    let sep = "-".repeat(96);
    println!("{sep}");
    for r in report() {
        let (val, src) = match r.source {
            Source::Structural => (
                r.value.map(|v| v.to_string()).unwrap_or_default(),
                "measured-on-virtual",
            ),
            Source::PendingRealRail => ("—".to_string(), "pending-real-rail (M5)"),
        };
        println!(
            "{:<38} {:>10}  {:<12}  {:<22} {}",
            r.name, val, r.unit, src, r.note
        );
    }
    println!();
    println!("§10.7 upgrade-to-channel crossover (structural, rail-ops): a channel beats one-shot");
    println!(
        "two-leg purchases from k = {} payments (2-op settlement vs 3-op one-shots).",
        channel_crossover_rail_ops(3, 1, 2)
    );
    println!(
        "The gas crossover is M5 (real-rail-only); this is the rail-agnostic op-count crossover."
    );
}
