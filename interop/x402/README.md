# M6 — x402 interop against real tooling

Proves the PayTP baseline Tier 0 path interoperates with the **shipped** x402
reference tooling (`x402@1.2.0` npm — the package a real client/facilitator
runs), not just against the spec text.

## Run

```
npm install
cargo run -p paytp-core --example emit_solana_402 | npm test
```

`emit_solana_402` emits the RI's canonical **shipped-x402-V1** `PaymentRequired`
(F3-j) for a Solana exact-svm baseline offer (the split `payTo`, the signed
`paytp` extension, no PayTP `extra.memo`). `validate.mjs` checks it against the
real x402 zod schemas (`PaymentRequirementsSchema` + `x402ResponseSchema`) and
the real `selectPaymentRequirements` client logic.

## What it proves (all green)

1. The RI's canonical 402 **validates against the shipped `x402@1.2.0` schema**
   as-is — both `accepts[0]` and the whole body (`x402Version: 1`).
2. A **plain, PayTP-unaware** client (the real `selectPaymentRequirements`)
   selects the PayTP baseline requirement and would pay its `payTo` — the split
   address, so the meed divides on-chain (the M6.1a split-divider) with no
   PayTP awareness.
3. The baseline offer does **not** rely on exact-svm `extra.memo`; replay closure
   lives in the merchant's durable consumed-settlement record, while the shipped
   x402 payment stays within the facilitator's 3-instruction shape.
4. The **resource binding** (F3-j rule 4): `accepts[0].resource` == the signed
   `paytp.resource`.

## Background — the shape decision (F3-j)

The M6.1b harness first surfaced that the shipped `x402@1.2.0` is **V1-protocol-
shaped** (`maxAmountRequired` not `amount`; a **named-enum** `network` like
`solana-devnet`/`base`, not CAIP-2; `resource`/`description`/`mimeType` inside
each requirement), diverging from the x402 **V2 spec doc**. Since the "plain x402
client pays the split" USP only works against tooling that exists today, PayTP
**emits the shipped V1 shape now**, keeping the V2 doc as the forward
target. The RI's `paytp-core::x402` emission is V1 directly, so — unlike the first
harness — no V1 projection is needed; the RI's canonical 402 is validated as-is.

Rules the RI builds to (F3-j): the signed `paytp` object stays **hybrid**
(`paytp.baseline` CAIP-2, MEED_VECTOR dests CAIP-10, but the mirrored accepts entry
carries x402's named vocabulary); a PayTP-aware wallet does the **baseline rail
check** (map named network → CAIP-2 via the normative 1:1 table in
`paytp-core::x402_net`, fail-closed, `== paytp.baseline`) and the resource check —
baseline offers only. **Note (verified against `x402@1.2.0`):** the shipped
top-level schema validates a 402 carrying `extensions` but **strips it on parse**,
so a PayTP-aware client reads the `paytp` object from the **raw** 402 bytes; the
durable, schema-retained slot is `accepts[i].extra` if a future F3 revision moves
the embedding there.

## Live on-chain settlement (M6.1c) — `settle-localnet.mjs`

The full baseline USP, proven **end-to-end on a running local Agave validator**
(real BPF loader/runtime, real SPL tooling), driven by the **real x402 client's
requirement selection**:

```
cargo build-sbf --manifest-path ../../contracts/Cargo.toml   # once, if the .so is stale
npm install
./run-localnet.sh          # starts the validator, deploys paytp_kit, runs the loop
```

`settle-localnet.mjs` (against `solana-test-validator`):

1. derives the split address (as a merchant would — `seed_split` over the
   `ADDRESS_INPUTS` preimage) and `deploy_split`s the on-chain split;
2. builds a shipped-x402-V1 402 whose `payTo` **is** that split PDA; the real
   `selectPaymentRequirements` (x402@1.2.0) selects it, and `ATA(payTo, mint)` is
   verified to equal the split vault;
3. the buyer pays the selected `payTo` with a real exact-svm-shaped
   `TransferChecked → ATA(split_PDA, mint)` under the shipped 3-instruction cap;
4. a **permissionless** `split_claim` (a random cranker) divides the vault **99/1**
   among the merchant seat and the four meed roles — asserted on-chain, value
   conserved.

Runs green: `ALL CHECKS PASS — the baseline USP settles on a live Agave
validator`. This closes M6: the wire/selection interop (this dir), the on-chain
division (the M6.1a `split_divider.rs` LiteSVM suite), and now the live
end-to-end loop are all proven. (The exact-svm facilitator-sponsored fee payer is
a facilitator concern elided in the local demo — the buyer pays its own fee; the
settlement path and division are real.)
