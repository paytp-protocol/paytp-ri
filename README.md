# paytp-ri — PayTP baseline-profile reference implementation

The **baseline-profile reference / conformance implementation** of the
[PayTP](https://paytp.org) open payment protocol. It implements the *baseline
settlement profile* of the formal interop specification (F1–F10) — the **spec is the
source of truth**, published at [paytp.org/spec](https://paytp.org/spec) (formal) and
[paytp.org/whitepaper](https://paytp.org/whitepaper), and pinned by commit hash in
[`PINNED_SPEC`](PINNED_SPEC). A divergence found while building moves the spec first,
never a silent code workaround.

This is a conformance and measurement artifact — **not** production money software.
Nothing here is deployed or handles real funds. **Read [`SCOPE.md`](SCOPE.md) first**: it
states plainly what this RI proves and every boundary it deliberately draws (real rail
adapters, TLS carrier obligations, multi-replica durability, off-baseline settlement,
placeholder governance constants). Wherever this repo describes conformance it means
*baseline-profile* conformance — never an unqualified "implements F1–F10."

**License:** MIT OR Apache-2.0.

## Status

**M0–M8 complete, CI green.** The baseline settlement profile is built end-to-end:
Tier‑0 baseline + two‑leg redemption, the channel/metering state machine, F7 fee
arithmetic, the F10 conformance corpus, merchant‑scoped payer unlinkability, and the
separately‑tested SVM contract kit. The remaining milestone is **ASYNC‑1** (the
async‑settlement follow‑ups). See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the crate map and money‑path read order,
and [`conformance/COVERAGE.md`](conformance/COVERAGE.md) for the spec‑rule → test index.

## Layout

```
crates/paytp-core/      # the canonical library (§11.1): wire codecs, canonical forms,
                        # crypto suite, entry-id derivation, registry, tier0, channel
crates/paytp-f7/        # F7 settlement arithmetic — no_std, shared verbatim with the SBF contract
crates/paytp-host/      # the ONE shared F2.4 host normalizer (IDNA/UTS#46 + PSL)
crates/paytp-rail/      # RailAdapter trait + the in-process VirtualRail (finality/fees/outage)
crates/paytp-merchant/  # merchant side: quote construction, durable one-decision store, redemption
crates/paytp-wallet/    # payer side: custody, the spend-policy boundary, two-leg/channel execution
crates/paytp-client/    # the interaction layer (§10.3): discovery, roles, external-wallet selection
contracts/              # the split/entry-machine SVM contract kit (standalone Anchor/SBF workspace)
conformance/            # the F10 test-vector corpus (data; a second decoder reads it)
demos/                  # runnable demos (see demos/README.md) — wedge (live HTTP), wasm (browser), suite
scripts/                # independent anchor cross-check (python hashlib)
```

## Build & test

```sh
cargo test --all-features --workspace     # unit + F10 conformance corpus + proptest
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
python3 scripts/confirm_anchors.py        # independent SHA-256 anchor cross-check
```

The demo workspaces (`demos/wasm`, `demos/wedge`) and the SVM contract kit (`contracts/`)
are separate workspaces gated by their own CI jobs. CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all of the above on every
push — "tests green" means green in CI.

## Conformance corpus

`conformance/` holds the F10 vectors as JSON data files, consumed by both the Rust
harness (`crates/paytp-core/tests/conformance.rs`) and an independent path. **Never edit
a vector to make code pass** (F10.4) — a failure reopens its spec section.
