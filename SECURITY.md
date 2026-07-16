# Security policy

`paytp-ri` is the **baseline-profile reference implementation** of the
[PayTP](https://paytp.org) payment protocol. It is a reference and conformance
implementation — **not production money software**. Nothing here is deployed, and
nothing here moves real funds. Read [`SCOPE.md`](SCOPE.md) first: it states plainly what
this repository proves and the boundaries it draws on purpose. This document describes
the security posture of that baseline profile and how to report a vulnerability.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue for a
security problem.

- Preferred: open a private advisory through this repository's **Security → Report a
  vulnerability** (GitHub Security Advisories).
- Alternatively: contact the maintainers via the security contact listed at
  [paytp.org](https://paytp.org).

Please include a description, the affected component (crate/file), and a reproduction if
you have one. Because this is a reference implementation rather than a deployed service,
there is no bug-bounty program; we still welcome and credit good-faith reports.

## What was reviewed

The **money and fidelity paths** — meed division and destination governance, settlement
and reconciliation, exactly-once redemption, payer-key derivation/unlinkability, the
address seed↔recipients binding, and the SVM settlement contract — were developed
repro-first (an adversarial test is written and shown to fail before the fix) and
subjected to **independent adversarial review**, including clean-room re-derivation of
the critical subsystems (meed-vector validation, the registry, settlement/reconciliation,
and channel state). Findings from that review are closed in the shipped code; the
value-conservation and destination-correctness properties below are the result.

The conformance corpus that grounds these claims is in
[`conformance/`](conformance/), and every shipped baseline rule maps to an executable
test in [`conformance/COVERAGE.md`](conformance/COVERAGE.md).

## Threat model — what the baseline money paths defend against

Within the baseline profile, the implementation is built to resist:

- **Governed-destination theft.** A meed vector that is shape-valid (roles, basis points,
  total, payable CAIP) but routes a *governed* share (the open-source or Development-Fund
  destination) to an attacker is **rejected**: the value-decision path validates each
  governed destination against the accepted registry snapshot. The context-free validator
  is not reachable as a value-decision path (the compiler forces callers onto the governed
  one), on both the merchant receive and wallet fund/sign sides.
- **Payer-side misrouting.** A hostile counterparty or interaction layer that tries to
  misroute a payer-side share (the interaction layer's or the wallet's own meed seat) is
  caught before the wallet signs or pays: an asserted destination is checked against the
  asserting party's own pointer, an unasserted one against the Development-Fund fallback.
- **Unbound settlement addresses.** A settlement address must commit the recipient set it
  pays. Both the in-process rail and the SVM contract **recompute** the address seed from
  the canonical address inputs and derive the recipients from those same inputs, so a
  caller cannot deploy an unbound or swapped recipient at an address.
- **Replay and double-settlement.** Redemption is single-owner and exactly-once — one
  merchant decision per consumed nonce and per live `(channel, checkpoint)` — proven under
  concurrent races and backed by write-ahead durable stores that fail closed on corruption.
- **Payer linkability.** Payer keys are derived per `(merchant, registrable-domain)` over
  one shared, pinned IDNA/UTS#46 + Public-Suffix-List host normalizer, so a payer is not
  correlatable across unrelated merchants.
- **x402 attack classes.** Cross-resource substitution, underpayment, leaked-token
  resubmission, and the duplicate-settlement race are covered as must-fail tests.
- **Off-baseline confusion.** A converted / off-baseline channel (`DENOM ≠ BASELINE_ASSET`)
  is refused **at open** — fail-closed — rather than settled on an unproven rate.
- **Placeholder-governance confusion.** The release-bound placeholder governance constants
  are guarded by a fail-closed check: any non-demo / non-proof build **refuses** to run a
  governed value decision while the placeholders are in place, rather than silently settling
  a governed share to an unspendable sentinel.

## Out of scope (declared boundaries — not security guarantees)

These are intentional limits of the baseline-profile RI, stated in full in
[`SCOPE.md`](SCOPE.md). They are **not** properties this profile claims to secure; a
production deployment must supply and audit them:

- **Real rail / chain adapters** — the APIs take a virtual rail; there is no live
  settlement adapter, and no on-chain custody is exercised in production form.
- **Live TLS / carrier obligations** — the binding is transport-independent, so the
  TLS-carrier MUSTs (0-RTT early-data handling, artifact cache-control headers,
  PSK-session detection) have no surface here and ride with a carrier an integrator adds.
- **Multi-replica linearizable durability** — the durable stores are restart-safe for a
  **single active owner**; running two active owners against one identity is out of scope.
- **Active-channel restart recovery** — live in-memory state of an *open* channel does not
  survive a restart (terminated/again-openable state is durable and fail-closed).
- **Off-baseline settlement** — deferred wholesale (it needs a confirmed rate oracle).
- **Forward-conformance boundaries** — a few narrow conformance limits that are inert in
  every flow this RI runs (JSON number canonicalization is a pass-through, two-leg
  redemption selects the first two-leg offer, and the x402 baseline mirror compares the
  modeled fields) are declared in full in [`SCOPE.md`](SCOPE.md). None is a live defect.

## Supported versions

This is a pre-1.0 reference implementation published alongside the formal spec. Security
fixes land on `main`; there is no long-term-support branch. Pin a commit if you depend on
specific behavior, and track the pinned spec commit in [`PINNED_SPEC`](PINNED_SPEC).
