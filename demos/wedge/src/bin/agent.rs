//! The M8 wedge-demo **agent client** — an AI agent paying a metered API per
//! request, PayTP-aware. It drives the real flow over HTTP:
//!
//!   1. GET the resource → receive HTTP 402 with the shipped-x402-V1 body;
//!   2. read the signed `paytp` quote (`extensions.paytp.info`) and the offer's
//!      `payTo` / `asset` / `maxAmountRequired`;
//!   3. present the authorized transfer plus a private settlement id;
//!   4. re-request with the `X-PAYMENT` proof → receive 200 + data + receipt.
//!
//! After `--calls N` requests it reads `/recipients` and **asserts** the
//! distribution meed settled end-to-end (exit non-zero on failure) — so this
//! one command is the CI gate: a paid request AND a settled meed.
//!
//! Usage: `wedge-agent [N]`  (env `WEDGE_URL`, default http://127.0.0.1:8402)

use base64::Engine;
use paytp_core::x402::PaymentRequired;
use paytp_wedge_demo as demo;

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// GET a URL, returning `(status, body)` — treating a 402 as a normal outcome
/// (ureq surfaces non-2xx as an error carrying the response).
fn get(url: &str, payment: Option<&str>) -> (u16, String) {
    let mut req = ureq::get(url);
    if let Some(p) = payment {
        req = req.set(demo::PAYMENT_HEADER, p);
    }
    match req.call() {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => {
            eprintln!("transport error: {e}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let arg1 = std::env::args().nth(1);

    // Container healthcheck mode: probe the local merchant's /healthz.
    if arg1.as_deref() == Some("--healthcheck") {
        let url =
            std::env::var("WEDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:8402".to_string());
        let (st, _) = get(&format!("{url}/healthz"), None);
        std::process::exit(if st == 200 { 0 } else { 1 });
    }

    let base = std::env::var("WEDGE_URL").unwrap_or_else(|_| "http://127.0.0.1:8402".to_string());
    let calls: u64 = arg1.and_then(|s| s.parse().ok()).unwrap_or(1);
    let resource = format!("{base}{}", demo::RESOURCE_PATH);

    let mut paid = 0u64;
    for k in 1..=calls {
        println!("\n── request {k}/{calls} ──");
        if pay_once(&base, &resource) {
            paid += 1;
        }
        if k == 2 {
            println!(
                "  ↑ at k≥2 the per-request settlement overhead is where a Tier 1 \
                 channel (postpay 'tab') amortizes — the §10.7 crossover."
            );
        }
    }

    // The CI assertion: a paid request AND a settled meed end-to-end.
    let (st, body) = get(&format!("{base}/recipients"), None);
    if st != 200 {
        eprintln!("FAIL: /recipients returned {st}");
        std::process::exit(1);
    }
    let view: demo::RecipientsView = serde_json::from_str(&body).expect("recipients json");
    let meed: u128 = view
        .rows
        .iter()
        .filter(|r| !r.label.starts_with("Merchant"))
        .map(|r| r.settled.parse::<u128>().unwrap_or(0))
        .sum();
    let expect_meed =
        demo::PRICE * (paytp_core::consts::MEED_BASE_BP as u128) / 10_000 * (paid as u128);

    println!("\n══ settled meed view ══");
    for r in &view.rows {
        println!("  {:<48} {:>10}  ({} bp)", r.label, r.settled, r.bp);
    }
    println!(
        "  requests_paid={}  meed_settled={}  (expected {})",
        view.requests_paid, meed, expect_meed
    );

    let ok = view.requests_paid == paid && paid == calls && meed == expect_meed && meed > 0;
    if ok {
        println!(
            "\nPASS — {paid} paid request(s) AND {meed} meed settled to the distribution roles."
        );
    } else {
        eprintln!("\nFAIL — paid={paid}/{calls}, meed_settled={meed}, expected={expect_meed}");
        std::process::exit(1);
    }
}

/// One full request→402→pay→deliver cycle. Returns true on delivery.
fn pay_once(_base: &str, resource: &str) -> bool {
    // 1. Unpaid request → 402.
    let (st, body) = get(resource, None);
    if st != 402 {
        eprintln!("  expected 402, got {st}: {body}");
        return false;
    }
    let pr = match PaymentRequired::parse(&body) {
        Ok(pr) => pr,
        Err(e) => {
            eprintln!("  402 body is not a valid PaymentRequired: {e:?}");
            return false;
        }
    };
    let req = &pr.accepts[0];
    println!(
        "  402: pay {} {} → {}  (network={}, merchant-settled)",
        req.max_amount_required, req.asset, req.pay_to, req.network
    );

    // The signed quote to present back (the raw paytp.info text — verbatim).
    let quote_json = match pr.paytp_info_json() {
        Some(q) => q,
        None => {
            eprintln!("  no paytp extension in the 402 (not a PayTP offer)");
            return false;
        }
    };

    // 2. Present the authorized split payment for the merchant to settle.
    let settle_id = paytp_core::crypto::random_bytes::<32>();
    let proof = demo::PaymentProof {
        quote: quote_json,
        to: req.pay_to.clone(),
        asset: req.asset.clone(),
        amount: req.max_amount_required.clone(),
        settle_id_b64: b64u(&settle_id),
    };
    println!("  payment authorization prepared");

    // 3. Re-request with the payment proof → 200 + data.
    let header = b64u(serde_json::to_string(&proof).unwrap().as_bytes());
    let (st, body) = get(resource, Some(&header));
    if st != 200 {
        eprintln!("  delivery failed ({st}): {body}");
        return false;
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    println!(
        "  200: delivered data = {}  (receipt signed)",
        v.get("data").map(|d| d.to_string()).unwrap_or_default()
    );
    true
}
