# demos — runnable proofs of the baseline-profile RI

Each demo executes the **real** `paytp-ri` (the baseline-profile reference
implementation) — no mocks on the facts that matter (paid / rejected / divided /
conserved). See the repo-root [`SCOPE.md`](../SCOPE.md) for what the RI does and does not
prove.

| Demo | What it is | Start here |
|---|---|---|
| **suite** | Nine in-browser demos — the RI compiled to WebAssembly, with a money-flow visualizer. | [`suite/README.md`](suite/README.md) → `node suite/serve.mjs` |
| **wedge** | A native, live-HTTP end-to-end: an agent drives `402 → pay → 200` against a real merchant and the meed settles to the roles. | `cargo run --manifest-path wedge/Cargo.toml --bin wedge-channel` |
| **wasm** | The WASM facade the suite is built from (demo trace glue, **not** an implementer SDK). | Built via `suite/build.sh` |

**Honesty rule:** where a demo *depicts* the channel wire-plane rather than re-streaming
it in-page, the copy says so, and the demo still executes the fact that matters (the
on-rail settlement, the division, the rejection). Start with [`suite/README.md`](suite/README.md).
