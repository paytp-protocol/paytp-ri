# PayTP wedge demo — an agent pays a metered API, the meed settles

**One clean end-to-end flow (M8).** An AI agent pays a metered HTTP API *per
request*. Each payment divides on-wire: the merchant keeps 99%, and **1% routes
to the distribution roles** — the interaction layer, the wallet provider, the
OS/runtime, and the Development Fund — that made the transaction possible. That
protocol-defined distribution meed is PayTP's durable USP: no per-request
payment protocol pays the distribution layer.

This is the wedge (metered API / agent billing) told as a runnable showcase. It
settles on the in-process **virtual rail** (deterministic, no chain); the *same*
split lands on a live Solana validator in [`interop/x402/settle-localnet.mjs`](../../interop/x402/settle-localnet.mjs)
(M6.1c), which you can run separately for the real-chain proof.

## What's in the box

| Component | Role |
|---|---|
| `wedge-merchant` | A live **axum** server over `paytp-merchant`. Emits a real shipped-x402-V1 `402`; redeems on payment with **settlement-precedes-delivery** (F4.4); serves the meed view. |
| `wedge-agent` | A PayTP-aware agent. Gets the `402`, reads the signed quote + `payTo`, prepares the payment authorization, re-requests with the proof, gets the data. |
| the rail | The in-process `VirtualRail`; the merchant settles the payer-presented authorization against it. |
| `/recipients` + `/` | The recipient view: the meed settled to each distribution role, as JSON and as a minimal HTML dashboard. |
| `wedge-channel` | The **channel upgrade** (§10.7 crossover), demonstrated on the rail: k requests metered off-chain settle in one aggregate round whose meed leg funds a single claim-record (F4.2) — proving the same meed reaches the same roles in **1** rail op instead of k. |

The flow a request takes:

```
agent ──GET /api/premium-quote──▶ merchant         (no payment)
      ◀──── 402 PaymentRequired ──                 (x402 V1 body; signed paytp quote in extensions)
agent ──GET + X-PAYMENT proof────▶ merchant         (verify sig → settle payment → confirm finality → consume nonce → deliver)
      ◀──── 200 { data, receipt }─
```

## Run it

**Clean-room (Docker) — the CI criterion.** `docker compose up` builds the image,
starts the merchant, waits for health, runs the agent once; the agent's exit code
is the assertion (a paid request AND a settled meed end-to-end):

```bash
cd demos/wedge
docker compose up --build --exit-code-from agent --abort-on-container-exit
```

**Native (no Docker) — fast:**

```bash
cd demos/wedge
./run.sh 3          # 3 paid requests, then assert the settled meed
```

**Watch it live:** start the merchant (`WEDGE_ADDR=127.0.0.1:8402 cargo run --release --bin wedge-merchant`),
open <http://127.0.0.1:8402/> for the dashboard, and in another shell run
`WEDGE_URL=http://127.0.0.1:8402 cargo run --release --bin wedge-agent 5`.

## Timed walkthrough (~5 minutes; the 15-minute bar is a ceiling)

1. **(~2 min build)** `./run.sh 3`. First run compiles the RI crates + the demo.
2. **(watch)** each request prints: the `402` (price, asset, split `payTo`,
   `network=solana-devnet`) → the merchant-settled payment authorization → the
   `200` delivery with a signed receipt.
3. **(the point)** the run ends with the **settled meed view**: at 3 × 1.0
   token, the 1% meed divides to `Interaction Layer 15000`, `Wallet Provider
   9000`, `Development Fund 6000` (OS + Dev Fund roles), merchant residue
   `2970000` — value conserved. `PASS` = a paid request AND a settled meed.
4. **(the upgrade)** `run.sh` then runs `wedge-channel`: the same k requests, now
   metered over a channel and settled in **one** aggregate round — the
   distribution meed is identical, settled in 1 rail op instead of k. That's
   the §10.7 crossover: the channel amortizes the per-request overhead, not the
   meed.
5. **(optional, real chain)** run `interop/x402/run-localnet.sh` to watch the
   identical split divide 99/1 on a live `solana-test-validator`.

## What's real vs simulated (said plainly)

- **Real:** the HTTP surface, the x402-V1 `402` body (validated against the
  shipped `x402@1.2.0` tooling in `interop/x402/`), the merchant signature +
  verification, settlement-precedes-delivery, the atomic consumed-nonce record,
  the F7-d meed division, and the signed receipt.
- **Simulated:** the settlement rail is in-process (`VirtualRail`) — instant
  finality, no gas, no contention. The real-chain equivalent is M6.1c.
- **The channel upgrade:** `wedge-channel` demonstrates the §10.7 crossover on the
  rail — k requests settling in one aggregate round (the meed leg funding a
  single F4.2 claim-record), same meed, 1 rail op instead of k. Per the §6
  timebox valve, the full **live-HTTP** slice carriage (the M3 channel plane is
  built + gated) is not re-driven inside this demo; the upgrade's settlement and
  economics are shown, the baseline flow is the one live HTTP path.
