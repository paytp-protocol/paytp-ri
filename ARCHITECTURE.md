# ARCHITECTURE — the `paytp-ri` crate map

A guide for an external implementer reading `paytp-ri`, the **baseline-profile reference
implementation** of PayTP. Start with [`SCOPE.md`](SCOPE.md) for what the RI does and does
not prove; this file is the map of *where* each piece lives.

## Anchor legend

Spec references throughout the code and docs use two forms, both resolving publicly:

- **`Fx.y`** — the **formal interop spec** at [paytp.org/spec](https://paytp.org/spec)
  (e.g. `F7.2`, `F4.4`). The RI implements the commit pinned in
  [`PINNED_SPEC`](PINNED_SPEC).
- **`§x.y`** — the **whitepaper** at [paytp.org/whitepaper](https://paytp.org/whitepaper)
  (e.g. `§10.3`, `§5.6`).

Test coverage is indexed separately: [`conformance/COVERAGE.md`](conformance/COVERAGE.md)
is the **spec-rule → test** map — every baseline normative MUST → a test or an explicit
classification.

## Crate dependency graph

```
        paytp-f7  ─────────────┐            (no_std F7 arithmetic; ALSO → contracts/)
   (fixed-width meed math)     │
                               ▼
        paytp-host  ───────► paytp-core ───────► paytp-rail ───────┬────► paytp-merchant
   (F2.4 host normalizer;   (canonical lib,   (RailAdapter +       │      (merchant side)
    ALSO → paytp-wallet)     F1–F10, §11.1)    VirtualRail)        │
                               ▲                                   ├────► paytp-wallet ──► paytp-client
                               └───────────────────────────────────┘      (payer side)      (interaction
                                                                                              layer, §10.3)
        contracts/   ── standalone Anchor/SBF workspace (split + entry machine); shares paytp-f7 verbatim.
        demos/       ── runnable demos over the crates above (wedge = live HTTP, wasm/suite = browser).
```

Edges are `depends-on` (arrows point to the dependency's consumer). The two leaves —
`paytp-f7` and `paytp-host` — are deliberately shared: `paytp-f7` is compiled into both
`paytp-core` **and** the on-chain contract so the meed division cannot drift, and
`paytp-host` is the ONE F2.4 normalizer used by both the artifact-host validation
(`paytp-core`) and the payer-key scope (`paytp-wallet`).

## Crates, one line each

| Crate | What it is | Spec home |
|---|---|---|
| [`paytp-f7`](crates/paytp-f7) | `no_std`, heap-free, fixed-width F7 settlement arithmetic — the one source of the meed division, shared **verbatim** with the SBF contract. | F7 / §5.6 |
| [`paytp-host`](crates/paytp-host) | the ONE shared F2.4 host normalizer (pinned `idna`/UTS#46 non-transitional + STD3 + bidi/joiner, and a vendored dated PSL for the registrable domain). | F2.4 |
| [`paytp-core`](crates/paytp-core) | the canonical library "bound into every role" — wire codecs, canonical forms, crypto suite, entry-id derivation, the registry, Tier-0 objects, and the channel state machine. | F1–F10 / §11.1 |
| [`paytp-rail`](crates/paytp-rail) | the `RailAdapter` trait + the in-process `VirtualRail` (programmable finality/fees/outage; native split + entry machine). | F4/F6/F8 / §5.6 |
| [`paytp-merchant`](crates/paytp-merchant) | the merchant side — quote construction, the durable one-decision store, and redemption with settlement-precedes-delivery. | F3/F4/F5/F6 |
| [`paytp-wallet`](crates/paytp-wallet) | the payer side — key custody, the spend-policy boundary, and Tier-0 / two-leg / channel execution. | §7.2/§10.3/§11.1 |
| [`paytp-client`](crates/paytp-client) | the interaction layer (`0x10`) — discovery, `PayTP-Roles` assembly, and the §10.4 external-wallet selection seam. | §10.3/§10.4 |
| [`contracts/`](contracts) | the split + entry-machine SVM contract kit — a standalone Anchor/SBF workspace with its own LiteSVM tests. | F4.1/F4.2 / §5.6 |
| [`demos/`](demos) | runnable proofs over the crates above (see [`demos/README.md`](demos/README.md)). | — |

Note the **`paytp-f7` ↔ `paytp-core::fee`** relationship: `paytp-f7` holds the `no_std`
fixed-width arithmetic (division, extinguishment, the F6-f reconciliation), and
`paytp-core::fee` wraps it for the host with the surrounding types. The SBF contract links
the *same* `paytp-f7`, so on-chain and host division are bit-identical by construction.

## Read order — the money path

To follow one payment from math to settlement, read in this order:

1. **`paytp-f7` / `paytp-core::fee`** — how a meed vector divides an amount into role
   shares (the fixed-width F7 arithmetic).
2. **`paytp-core::tier0::quote`** — the Tier-0 quote: its schema, the governed
   meed-vector validation (`validate_governed_destinations`), and split derivation.
3. **`paytp-merchant::redeem_baseline`** — the merchant settles the payer-presented
   transfer, confirms it reached the split at quoted finality, atomically consumes the
   nonce keyed by the canonical settlement ref, and signs the receipt
   (settlement-precedes-delivery).
4. **`paytp-core::channel` / `channel::state`** — for streamed value, the F6 metering
   state machine (slice acceptance, checkpoints, settlement rounds).

The payer's mirror of steps 2–3 is `paytp-wallet::execute` (validate the signed quote,
then prepare the payment authorization), and the interaction layer that drives it is
`paytp-client::flow`.
