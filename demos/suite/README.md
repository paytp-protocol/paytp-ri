# PayTP demo suite — the demo is the proof

Nine in-browser demos, each executing the **real baseline-profile reference
implementation** compiled to WebAssembly (no mocks). The money-flow visualizer only
renders what the RI actually did. (What the baseline-profile RI does and does not prove:
see the repo-root [`SCOPE.md`](../../SCOPE.md).)

## Run it

```bash
node demos/suite/serve.mjs          # → http://127.0.0.1:8091  (correct application/wasm MIME)
```

Open the URL, pick a demo in the left nav, press **Run ▸**. Toggle light/dark (top-right);
works on mobile. To rebuild the WASM after changing `demos/wasm/`:

```bash
./demos/suite/build.sh              # wasm-pack build + re-vendor into demos/suite/lib/
```

## The demos

| # | Demo | Proves | Execution |
|---|---|---|---|
| D-05 | The meed, visualized | The USP — a governed, capped 1% meed splitting on the wire; toggle the OS role and its share leaves the Foundation (to the independent open-source fund) with the merchant + Dev-Fund shares unchanged. | **Real** split division; live OS-neutrality toggle. |
| D-03 | One-shot — the full range | Not just micropayments ($0.05→$1000); settle-before-deliver; x402-compatible; fee advantage. | **Real** quote→pay→redeem→receipt. Card fees illustrative (§3.1). |
| D-04 | The reclaim path | Meed integrity + bounded trust — meed escrowed, released on attested delivery; non-delivery → payer reclaims the **meed leg only** (not the net; not a chargeback). | **Real** entry machine + net leg. |
| D-07 | x402 coexistence | Selection not capture; a plain x402 client divides the split (no receipt) vs a PayTP client (meed + receipt). | **Real** split + redeem. |
| D-09 | Attacks that fail | Nonce double-spend → `Replayed`; cross-resource substitution; underpayment — each rejected by the real merchant. | **Real** — renders the actual `Result`. |
| D-01 | The reader's month (prepay) | Channels compress settlement; bounded prepay. | Meed **claim-record aggregation real**; slices/checkpoints are the depicted M3 plane. |
| D-02 | The agent's API bill (postpay) | The wedge; postpay credit; headless-OS → independent fund. | Same as D-01. |
| D-06 | Rail-agnosticism | Same division across rails; meed always on the baseline. | Rail A (VirtualRail) **real**; Rail B (Solana) proven separately in `interop/x402` (M6.1c), not re-run here. |
| D-08 | Channel survives a reconnect | Chaining across a dropped connection, no value lost, rail untouched during the reconnect. | Rail-untouched + the settlement are **executed**; slice-streaming/chaining is the depicted M3/F6.6 mechanic. |

## Honesty (the governing rule)

Every "paid / rejected / conserved / divided" on screen is a real RI result. Where a demo
**depicts** the channel wire-plane (slices/checkpoints) rather than re-streaming it in-page,
the copy says so explicitly, and the demo still **executes** the fact that matters (the
on-rail settlement, the division, the rejection). The suite was independently reviewed for
honesty.

## Status
Foundation = the demo wasm facade (`demos/wasm/`, `paytp-demo-wasm`) built with wasm-pack (`--target web`),
`--remap-path-prefix`'d so the shipped binary carries no local build path (`build.sh` self-checks this). The
full facade is ~1.3 MB raw / ~0.4 MB brotli — it links the payer wallet + the F2.4 host normalizer + the
crypto stack the D-09 adversarial paths exercise, well beyond the original split-only core. **One remaining leg is
unverified: real iOS Safari / Android Chrome** — needs a device or BrowserStack (desktop Chromium + mobile
emulation are green).
