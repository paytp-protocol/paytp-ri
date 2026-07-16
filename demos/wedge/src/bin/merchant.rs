//! The M8 wedge-demo **metered API merchant** — a thin live axum server over
//! `paytp-merchant` (the live-HTTP surface the RI otherwise served only
//! in-process). It emits the RI's real shipped-x402-V1 `402`, redeems on payment
//! with **settlement-precedes-delivery** (F4.4), and exposes the settled
//! distribution meed at `/recipients`.
//!
//! Endpoints:
//!   GET  /api/premium-quote  — 402 (PaymentRequired) with no `X-PAYMENT`;
//!                              200 (data + signed receipt) with a valid one.
//!   GET  /recipients         — the meed settled to each distribution role.
//!   GET  /                   — a minimal HTML recipient dashboard.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::Engine;

use paytp_merchant::{BaselineParams, InMemoryStore, Merchant, RedeemError};
use paytp_rail::{RailAdapter, Transfer, TransferKind, VirtualRail};
use paytp_wedge_demo as demo;

struct App {
    merchant: Merchant,
    rail: VirtualRail,
    store: InMemoryStore,
    nonce_ctr: AtomicU64,
    requests_paid: AtomicU64,
    gross_settled: AtomicU64,
}

impl App {
    /// A fresh 32-byte nonce for a new quote (counter in the low 8 bytes).
    fn next_nonce(&self) -> [u8; 32] {
        let n = self.nonce_ctr.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; 32];
        nonce[24..].copy_from_slice(&n.to_be_bytes());
        nonce
    }
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("WEDGE_ADDR").unwrap_or_else(|_| demo::DEFAULT_ADDR.to_string());

    // A deterministic demo merchant. `finality_delay = 0` → a submitted payment
    // is `final` immediately, so the flow needs no clock plumbing.
    let merchant = Merchant::new([0x55u8; 32], demo::MERCHANT_PAYOUT);
    let app = Arc::new(App {
        merchant,
        rail: VirtualRail::new(0),
        store: InMemoryStore::new(),
        nonce_ctr: AtomicU64::new(1),
        requests_paid: AtomicU64::new(0),
        gross_settled: AtomicU64::new(0),
    });

    let router = Router::new()
        .route("/", get(dashboard))
        .route(demo::RESOURCE_PATH, get(metered))
        .route("/recipients", get(recipients))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    eprintln!("wedge-merchant listening on http://{addr}");
    eprintln!("  resource: GET http://{addr}{}", demo::RESOURCE_PATH);
    eprintln!("  recipients dashboard: GET http://{addr}/");
    axum::serve(listener, router).await.unwrap();
}

/// The metered resource: 402 without payment, 200 (data + receipt) with it.
async fn metered(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    match headers.get(demo::PAYMENT_HEADER) {
        None => challenge_402(&app),
        Some(h) => match redeem(&app, h.to_str().unwrap_or("")) {
            Ok(body) => (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::VARY, "PayTP, PayTP-Roles"),
                ],
                body,
            )
                .into_response(),
            Err(e) => (
                StatusCode::PAYMENT_REQUIRED,
                format!("payment rejected: {e:?}"),
            )
                .into_response(),
        },
    }
}

/// Build and sign a baseline quote, deploy its split on the rail, and return the
/// shipped-x402-V1 `402` a plain client (or a PayTP-aware agent) reads.
fn challenge_402(app: &App) -> Response {
    let nonce = app.next_nonce();
    let bq = app.merchant.build_baseline_quote(
        &app.rail,
        BaselineParams {
            resource: demo::RESOURCE_PATH,
            nonce,
            exp: 2_000_000_000,
            idem: format!(
                "wedge-{}",
                u64::from_be_bytes(nonce[24..].try_into().unwrap())
            )
            .into_bytes(),
            registry_version: 5,
            baseline_network: demo::BASELINE_CAIP2,
            asset: demo::ASSET,
            amount: demo::PRICE,
            finality: demo::FINALITY,
            grace: 300,
            retry: 600,
            max_timeout_seconds: 60,
            extra: None,
            vector: demo::meed_vector(),
        },
    );
    let body = String::from_utf8(bq.to_payment_required().to_json()).expect("x402 json is utf8");
    Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::VARY, "PayTP, PayTP-Roles")
        .body(body.into())
        .unwrap()
}

/// Redeem an `X-PAYMENT` proof: verify the quote's signature, settle the payer's
/// presented transfer, confirm the rail payment reached the split at quoted finality,
/// consume the nonce atomically, then deliver the data + signed receipt (F4.4).
fn redeem(app: &App, header_val: &str) -> Result<String, RedeemError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_val)
        .map_err(|_| RedeemError::QuoteInvalid)?;
    let proof: demo::PaymentProof =
        serde_json::from_slice(&raw).map_err(|_| RedeemError::QuoteInvalid)?;
    let amount: u128 = proof
        .amount
        .parse()
        .map_err(|_| RedeemError::PaymentUnverified)?;
    let settle_id =
        decode_settle_id(&proof.settle_id_b64).map_err(|_| RedeemError::PaymentUnverified)?;
    let transfer = Transfer {
        to: proof.to,
        asset: proof.asset,
        amount,
        kind: TransferKind::Payment,
        memo: None,
    };
    let now = app.rail.chain_time();
    let receipt = app.merchant.redeem_baseline(
        &proof.quote,
        demo::RESOURCE_PATH,
        transfer,
        settle_id,
        &app.rail,
        &app.store,
        now,
    )?;

    app.requests_paid.fetch_add(1, Ordering::SeqCst);
    app.gross_settled
        .fetch_add(demo::PRICE as u64, Ordering::SeqCst);

    let out = serde_json::json!({
        "resource": demo::RESOURCE_PATH,
        "data": {
            "symbol": "PAYTP/USD",
            "price": "1.0000",
            "note": "premium metered data — delivered after settlement (F4.4)",
        },
        "receipt": serde_json::from_slice::<serde_json::Value>(&receipt.to_json())
            .unwrap_or(serde_json::Value::Null),
    });
    Ok(out.to_string())
}

fn decode_settle_id(b64: &str) -> Result<[u8; 32], ()> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

/// The recipient view: the meed settled to each distribution role.
async fn recipients(State(app): State<Arc<App>>) -> Json<demo::RecipientsView> {
    Json(build_recipients(&app))
}

fn build_recipients(app: &App) -> demo::RecipientsView {
    // Aggregate bp by destination (OS + Dev Fund share the fund dest), matching
    // the on-rail split's recipient set, then read each dest's settled balance.
    let mut rows: Vec<demo::RecipientRow> = Vec::new();
    for role in demo::roles() {
        match rows.iter_mut().find(|r| r.dest == role.dest) {
            Some(existing) => {
                existing.bp += role.bp;
                existing.label = format!("{} + {}", existing.label, role.label);
            }
            None => rows.push(demo::RecipientRow {
                label: role.label.to_string(),
                dest: role.dest.to_string(),
                bp: role.bp,
                settled: String::new(),
            }),
        }
    }
    for r in rows.iter_mut() {
        r.settled = app.rail.balance(&r.dest).to_string();
    }
    // The merchant's residue seat.
    rows.push(demo::RecipientRow {
        label: "Merchant (residue)".to_string(),
        dest: demo::MERCHANT_PAYOUT.to_string(),
        bp: 10_000 - paytp_core::consts::MEED_BASE_BP,
        settled: app.rail.balance(demo::MERCHANT_PAYOUT).to_string(),
    });

    demo::RecipientsView {
        asset: demo::ASSET.to_string(),
        requests_paid: app.requests_paid.load(Ordering::SeqCst),
        gross_settled: app.gross_settled.load(Ordering::SeqCst).to_string(),
        rows,
    }
}

/// A minimal, dependency-free HTML dashboard rendering the current meed split.
async fn dashboard(State(app): State<Arc<App>>) -> Html<String> {
    let v = build_recipients(&app);
    let mut trows = String::new();
    for r in &v.rows {
        trows.push_str(&format!(
            "<tr><td>{}</td><td class=mono>{}</td><td>{} bp</td><td class=num>{}</td></tr>",
            html_escape(&r.label),
            html_escape(&r.dest),
            r.bp,
            r.settled
        ));
    }
    let html = format!(
        r#"<!doctype html><meta charset=utf-8><title>PayTP wedge demo — settled meeds</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#111}}
 h1{{font-size:1.3rem}} .sub{{color:#555}}
 table{{border-collapse:collapse;width:100%;margin-top:1rem}}
 th,td{{text-align:left;padding:.5rem .6rem;border-bottom:1px solid #e3e3e3}}
 .num,td.num{{text-align:right;font-variant-numeric:tabular-nums}}
 .mono{{font-family:ui-monospace,monospace;font-size:.8rem;color:#666;word-break:break-all}}
 .badge{{background:#eef;border-radius:6px;padding:.15rem .4rem}}
</style>
<h1>PayTP — the distribution meed, settled</h1>
<p class=sub>An agent paid a metered API. Each request's price divided on-wire: the
merchant keeps 99%, and <b>1% routes to the distribution roles</b> that made the
transaction possible — the durable USP no per-request protocol claims.</p>
<p><span class=badge>requests paid: {paid}</span>
   <span class=badge>gross settled: {gross}</span>
   <span class=badge>asset: {asset}</span></p>
<table><thead><tr><th>Recipient</th><th>Destination</th><th>Share</th><th class=num>Settled</th></tr></thead>
<tbody>{trows}</tbody></table>
<p class=sub>Settling on the in-process virtual rail (deterministic F7-d division).
The same split lands on a live Solana validator in <code>interop/x402/settle-localnet.mjs</code>.</p>"#,
        paid = v.requests_paid,
        gross = v.gross_settled,
        asset = html_escape(&v.asset),
        trows = trows,
    );
    Html(html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
