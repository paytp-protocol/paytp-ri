# SCOPE — what `paytp-ri` is, and is not

`paytp-ri` is the **baseline-profile reference implementation** of the
[PayTP](https://paytp.org) open payment protocol. Read this before reading any claim
the code or the demos make: it states plainly what this repository proves, and — just
as plainly — the boundaries it draws on purpose. Every deferral below is a **declared
boundary**, not a gap left for a reader to discover.

This is **not** production money software. Nothing here is deployed, and nothing here
moves real funds.

---

## What it is

A **baseline-profile, transport-independent, virtual-rail** reference and conformance
implementation of PayTP:

- **Baseline-profile.** It implements the *baseline settlement profile* of the formal
  spec — Tier‑0 quotes, the two‑leg redemption, the channel/metering state machine, and
  the F7 fee arithmetic. It does **not** implement every optional or off‑baseline path
  the spec permits (see boundaries below). Wherever this README, the coverage map, the
  crate docs, or the demos describe conformance, they mean *baseline‑profile
  conformance* — never an unqualified "implements F1–F10."
- **Transport-independent.** The binding is over message **bodies**, not a specific
  carrier. There is no HTTP server, TLS stack, or network transport in the protocol
  crates; a carrier is something an integrator supplies.
- **Virtual-rail.** Settlement runs against an in‑process `VirtualRail` with programmable
  finality, fees, and outage. The role‑facing APIs take a `&VirtualRail` (or the
  `RailAdapter` trait) — there is **no** real chain / rail adapter wired in.

The formal spec (F1–F10) and the whitepaper are the source of truth, published at
[paytp.org/spec](https://paytp.org/spec) and
[paytp.org/whitepaper](https://paytp.org/whitepaper); this repository implements that
spec at the commit pinned in [`PINNED_SPEC`](PINNED_SPEC). It does not *decide* the
spec — a divergence found while building moves the spec first.

---

## What it proves

Exercised end‑to‑end, with an executable test **or** an explicit classification behind
each normative baseline MUST (see [`conformance/COVERAGE.md`](conformance/COVERAGE.md)):

- **Tier‑0 baseline settlement + two‑leg redemption** — the quote → pay → divide →
  receipt spine, and the reclaim‑then‑attest two‑leg flow, against the virtual rail.
- **F7 fee arithmetic** — exact fixed‑width meed division, accrual, extinguishment, and
  the F6‑f reconciliation math, shared *verbatim* between the host and the on‑chain
  contract (one `no_std` crate, `paytp-f7`, so the two can never drift).
- **The F10 conformance‑vector corpus** — byte‑level accept/reject vectors, with the
  SHA‑256 anchors independently re‑derived by Python `hashlib` and the HKDF/Poly1305
  composition anchors independently re‑derived by a second Rust path that does not call
  `paytp-core`.
- **Single‑owner, exactly‑once redemption** — one merchant decision per `(nonce)` and
  per live `(channel, checkpoint)`, proven under concurrent races. Tier‑0
  consumed‑nonce decisions and channel guard decisions are backed by write‑ahead durable
  stores; live channel round state is single‑owner and falls under the active‑channel
  restart boundary below.
- **Merchant‑scoped payer unlinkability** — per‑`(merchant, registrable‑domain)`
  payer‑key derivation over one shared, pinned IDNA/UTS#46 + PSL host normalizer.
- **Separately‑tested SVM contracts** — the split/entry‑machine contract kit
  (`contracts/`) is a standalone Anchor/SBF workspace with its own LiteSVM tests; the
  host and the contract re‑derive the same addresses and the same division.

---

## What it deliberately does NOT do (yet) — declared boundaries

These are intentional scope limits of the baseline‑profile RI. Each is honest **because
it is named here**; none is a hidden gap.

- **Real rail / chain adapters.** The APIs take a `VirtualRail`. There is no live
  settlement adapter for any chain or payment rail. A production build must supply and
  audit one — and because this profile **trusts the adapter's reported facts** (finality
  levels, canonical transfer references, and the on‑chain distribution fact), a production
  adapter must either **prove** those facts (light‑client / on‑chain verification) or the
  RI must treat them as **untrusted evidence**: finalized‑gating every fold and credit,
  durable poll‑then‑settle replay, and canonical‑event verification. An adapter that lies
  about, or reorgs, a fact could otherwise cause a credit, close, or delivery on a fact no
  honest rail would confirm.
- **Live TLS / carrier obligations.** Because the binding is transport‑independent, the
  TLS‑carrier MUSTs (e.g. "slices MUST NOT be sent in TLS 0‑RTT early data," artifact
  cache‑control headers, PSK‑session detection) have **no surface** in this build. They
  ride with the live HTTP/TLS stack an integrator adds, and are classified as such in
  the coverage map (§A), not silently skipped.
- **Multi‑replica linearizable durability.** The one‑decision store is durable and
  restart‑safe for a **single active owner**. It is not a linearizable multi‑replica
  store; running two active owners against one identity is out of scope. Fail‑closed:
  an owner that loses this state refuses what it can no longer adjudicate.
- **Active‑channel restart recovery.** Live in‑memory channel state does not survive a
  restart of an *open* channel. Terminated/again‑openable state is durable (F5‑m
  tombstones, fail‑closed); resuming a mid‑stream channel across a restart is not built.
- **Off‑baseline settlement.** `DENOM ≠ BASELINE_ASSET` (a converted / off‑baseline
  channel) is refused **at open** — fail‑closed (F5‑p). The RI defers off‑baseline
  settlement wholesale (it would need the CONFIRMED rate oracle); the spec permits it,
  this profile does not implement it.

### Forward‑conformance boundaries (inert in every flow the RI produces)

These are narrower conformance limits. None affects a flow this RI actually runs — each
is inert today — and each is named here so it is a declared limit, not a latent gap a
future profile discovers:

- **JSON number canonicalization is a pass‑through.** The JCS serializer orders object
  members per RFC 8785, but it emits numbers in their stored string form rather than
  applying RFC 8785's full ECMAScript number canonicalization. This is inert because
  PayTP‑native signed objects encode every numeric value as a string (F1‑c), so the RI
  emits no bare JSON number of its own to canonicalize. A profile that must canonicalize
  bare numbers (for a non‑string‑numeric peer object) would add the full step.
- **Two‑leg redemption selects the first two‑leg offer.** The redemption path takes the
  first offer carrying the `twoLeg` sub‑object. The RI emits a single two‑leg offer per
  quote, so the selection is unambiguous in every quote it produces; redeeming a quote
  that carries several distinct two‑leg offers is not exercised, and a profile that emits
  more than one would define an explicit selection rule.
- **The x402 baseline mirror compares the modeled fields.** The F3‑a mirror‑equality
  check compares the typed, schema‑modeled fields of an x402 `PaymentRequirements` entry
  against the signed PayTP mirror. An unmodeled extra member a proxy appends to the outer
  entry is not part of that comparison — it cannot change a modeled field without breaking
  equality, and the client pays the signed mirror regardless — but comparison over the
  full, un‑modeled object is a forward‑conformance item.

### Now implemented (previously a boundary)

- **Full IDNA/PSL host scoping + merchant‑scoped channel custody** — **implemented.** A
  single pinned F2.4 normalizer (`paytp-host`: `idna` `=1.1.0` UTS#46 non‑transitional +
  STD3 + bidi/joiner, and a vendored, dated Public Suffix List) resolves the registrable
  domain, and the wallet derives a per‑`(merchant, registrable‑domain)` payer key over
  it. The **same** normalizer validates the artifact host. Merchant‑scoped payer
  unlinkability is therefore an *implemented* property here, not a labeled deferral: the
  site MAY claim it.

### Placeholder governance constants (release‑bound, fail‑closed)

The Development Fund destination, the independent open‑source‑fund destination, and the
Foundation registry key in [`crates/paytp-core/src/consts.rs`](crates/paytp-core/src/consts.rs)
are **release‑bound sentinels, not real addresses** (F9‑e: these cannot be derived from
F1–F10 alone — they are pinned at a release). Beyond carrying obvious
`PLACEHOLDER-…` sentinel text, they are guarded so they **cannot be confused with real
governance wiring**: [`consts::ensure_governance_ready`](crates/paytp-core/src/consts.rs)
is a **fail‑closed guard** wired into the governed value path (registry resolution and
governed‑vector validation). A build that has **not** opted into the placeholders via the
`demo-governance` feature — i.e. any non‑demo / non‑proof build — **refuses** to run a
value decision while the placeholders are in place, rather than silently settling a
governed share to an unspendable sentinel. A real deployment replaces the placeholders
(and does not enable that feature) before the value path will run.

---

## Where to look next

| If you want… | Read |
|---|---|
| The public protocol spec + whitepaper | [paytp.org/spec](https://paytp.org/spec) · [paytp.org/whitepaper](https://paytp.org/whitepaper) |
| The crate map + money‑path read order | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| The spec‑rule → test index | [`conformance/COVERAGE.md`](conformance/COVERAGE.md) |
| The runnable demos | [`demos/README.md`](demos/README.md) |
| Status + milestones | [`README.md`](README.md) |
