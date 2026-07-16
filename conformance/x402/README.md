# Vendored x402 V2 reference (interop oracle for M6)

Frozen snapshot of the **x402 protocol V2** specification the RI's Tier 0
baseline path interoperates with (F3.1: "Tier 0 **is** an x402 V2 flow"). These
files are the source-of-truth the RI's `paytp-core::x402` envelope types and the
M6 interop harness are checked against — not editable RI artifacts.

**Pinned source** (re-verified live 2026-07-09):

| File | Upstream path (`github.com/coinbase/x402`) |
|---|---|
| `x402-specification-v2.md` | `specs/x402-specification-v2.md` |
| `scheme_exact.md` | `specs/schemes/exact/scheme_exact.md` |
| `scheme_exact_svm.md` | `specs/schemes/exact/scheme_exact_svm.md` |

Protocol version: **2** (spec V2 dated 2025-12-09). Reference npm package:
`x402` (latest `1.2.0`), which implements protocol v2. Facilitator API:
`POST /verify`, `POST /settle`, `GET /supported`. Solana is a first-class
network (`solana:<genesis>`), the RI's baseline rail.

## Interop deltas surfaced building M6.0

1. **x402 envelope was unmodelled in the RI.** The RI `Quote` modelled only the
   inner `paytp` object; there was no `PaymentRequired`/`PaymentPayload`/
   `extensions`. Built in `paytp-core::x402` (M6.0). The spec (F3.1) already
   declares V2, so this is an RI catch-up, not a spec change.
2. **The mirror was skeletal.** `offer.accept` carried only
   `scheme/network/asset/amount/payTo`; a real x402 V2 `PaymentRequirements`
   also needs `maxTimeoutSeconds` (and, for exact-svm, `extra.feePayer`).
   Completed in M6.0 (`BaselineParams.max_timeout_seconds`/`extra`).
3. **`extensions.paytp` embedding — needs ratification.** x402 V2 §5.1.2 makes
   each extension value `{info, schema}` and says a client "echoes info, cannot
   delete/overwrite, may append." The RI embeds the signed `paytp` object
   **directly** as `extensions.paytp.info`. Two open questions for F3.1: (a) is
   `info` the `paytp` object itself or a wrapper; (b) does V2's append-only echo
   rule preserve PayTP's `signature` under F3.4's "member-preserved" — an
   appended `info` member would not change the JCS of the signed sub-object, but
   this must be stated normatively.
4. **exact-svm split shape.** A plain x402 SVM client pays a `TransferChecked`
   to `ATA(owner = payTo, mint = asset)` (strict instruction layout, facilitator
   fee-payer). So the PayTP baseline **split `payTo` must be an SPL owner whose
   ATA receipt is divisible by the split program.** Whether the M5 on-chain kit
   renders a baseline *split* contract in that shape (M5 built the meed
   *instance* custody; the baseline divider may be virtual-rail-only) is a gap to
   confirm before the M6.1 local-validator loop.
5. **`extra.memo` vs PayTP nonce-binding.** The exact-svm mirror retains upstream's
   optional `extra.memo` description, but PayTP baseline no longer relies on it:
   shipped x402 clients/facilitators do not carry the additional Memo instruction.
   Baseline nonce/ref binding is the merchant-settled transaction identity plus the
   durable consumed-settlement record (`used_refs`).
