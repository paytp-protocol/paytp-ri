# F10 conformance corpus

The canonical test-vector corpus (F10). **Vector files are data**, consumed by
every implementation's harness — the Rust harness is
`crates/paytp-core/tests/conformance.rs`; a second decoder (M1's TS crypto path)
consumes the same files. A vector failure reopens its section for review;
**never edit a vector to make code pass** (F10.4).

## Vector schema (F10.1)

```json
{ "id": "<section>-<class>-<nnn>", "title": "…", "inputs": {…}, "expect": {…} }
```

Binary values are lowercase hex; integers are F1-c decimal strings. `expect` is
`{"value": …}`/`{"bytes": …}` for constructive vectors or `{"verdict":
"accept"|"reject"}` for decision vectors.

## What is here now (M0)

- **`f1-encoding.json`** — LEB128, minimal (un)signed integers, and the F1-c
  anchored JSON grammars + duplicate-member rejection.
- **`f1-crypto.json`** — the SHA-256-only anchors: `H(s)`, the slice `COVERED`
  prefix, transcript `head_0`. Canonical by hand derivation.
- **`f4-derive.json`** — the `entry_id` anchor, **regenerated** (F4-c
  now commits `AMT` + the window deadlines; the old `33f42cfb…` is void).
- **`f7-arithmetic.json`** — the F7 division/extinguishment vectors A/B, the
  `P ≥ 1`/`E = 0` sub-extinguishment trap, unity rate, zero, and the F7-d
  instance rule.

## Independence (F10.2)

The SHA-256 seed anchors are cross-checked by a *second, unrelated*
implementation — `scripts/confirm_anchors.py` (Python `hashlib`), run as its own
CI job. Ed25519 / Poly1305 / HPKE / exporter vectors are **generation-required**
(F10.2): the RI produces them from pinned test keys, and their independent
confirmation lands with M1's native-TS crypto path (a wasm wrapper of this same
Rust core is *not* independent). They are not treated as final before then.

## Not yet here (later milestones)

F2 host/artifact vectors, F3 quote/receipt, the F5 message layouts and F6
state-machine corpus, F8 clocks, F9 registry — added as M1–M4 build those units
(F10.3 is the corpus's table of contents; M7 verifies completeness).
