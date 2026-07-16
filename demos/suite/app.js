// PayTP demo suite — loads the real RI core (WASM) and renders the money-flow.
// Framework-agnostic: vanilla JS + SVG/CSS + Web Animations. Each demo's trace is
// produced by the RI executing in-page; the visualizer only renders it.
import init, * as sdk from "./lib/paytp_demo_wasm.js";

// The suite mounts into a root — `document` standalone, or a shadow root when embedded
// as the <paytp-demos> web component. All queries go through $, so scoping the root is
// all it takes to render inline in any page (no iframe).
let ROOT = document;
let THEME_EL = document.documentElement; // where data-theme is applied
const $ = (s, r) => (r || ROOT).querySelector(s);
const el = (t, cls, txt) => { const e = document.createElement(t); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
const fmt = (n) => Number(n).toLocaleString("en-US");

// Asset-aware display: the SDK emits { ticker, decimals } per run (the protocol only
// carries raw integer minor units). fmtAmt renders raw units → e.g. "0.99 USDC" — exact,
// trailing zeros trimmed, whole part comma-grouped. Updated per-run from the trace.
let display = { ticker: "USDC", decimals: 6 };
function fmtAmt(raw) {
  const d = display.decimals ?? 6;
  const s = String(Math.trunc(Number(raw)));
  const neg = s.startsWith("-");
  const digits = (neg ? s.slice(1) : s).padStart(d + 1, "0");
  const whole = Number(digits.slice(0, digits.length - d)).toLocaleString("en-US");
  const frac = d ? digits.slice(digits.length - d).replace(/0+$/, "") : "";
  const tick = display.ticker ? " " + display.ticker : "";
  return `${neg ? "-" : ""}${frac ? whole + "." + frac : whole}${tick}`;
}

// Classify a recipient label → a colour class + short role tag.
function roleClass(label) {
  const l = label.toLowerCase();
  if (l.startsWith("merchant")) return "merchant";
  if (l.startsWith("interaction")) return "il";
  if (l.startsWith("wallet")) return "wallet";
  if (l.startsWith("os")) return "os";
  if (l.includes("fund")) return "fund";
  return "meed";
}

// ---- Demo registry. Each: id, title, proves, tier, optional inputs, run()->trace, kind. ----
const AMOUNTS = [["50000", "0.05 USDC"], ["50000000", "50 USDC"], ["1000000000", "1,000 USDC"]];
const DEMOS = [
  {
    id: "D-05", title: "The meed, visualized", tier: "Tier-agnostic",
    proves: "PayTP's defining feature — a governed, capped, auditable 1% meed that splits on the wire to the roles that made the payment possible. Flip the OS role between present and absent and re-run: when the OS is absent its 0.1% leaves the Foundation entirely, to an independent open-source fund — while the merchant's 99% and the Foundation's own Development-Fund share do not move. Approving or denying an OS changes the Foundation's income by exactly zero.",
    inputs: [
      { id: "amount", label: "Payment", options: [["50000", "0.05 USDC"], ["1000000", "1 USDC"], ["1000000000", "1,000 USDC"]], default: "1000000" },
      { id: "os", label: "OS role", options: [["asserted", "present (registry-listed)"], ["absent", "absent → independent fund"]], default: "asserted" },
    ],
    hood: "The schema-0x01 MEED_VECTOR (IL 50bp / OS 10bp / Wallet 30bp / Dev Fund 10bp) drives the running-V split division at the derived split address: each recipient = floor(V × bp_d / bp_total), where bp_total = 10000 for a baseline split. Flip the OS toggle: an asserted OS's 0.1% lands at its own address; an absent OS's 0.1% routes to the independent open-source fund (§10.1), distinct from the Development Fund — and the merchant + Dev-Fund shares are identical either way (§10.5 neutrality).",
    kind: "split",
    run: (i) => JSON.parse(sdk.d05_split_trace(BigInt(i.amount || "1000000"), i.os === "absent")),
  },
  {
    id: "D-03", title: "One-shot purchase — the full range", tier: "Tier 0",
    proves: "PayTP is not just for micropayments — it settles per-payment from 0.05 to 1,000 USDC; settle-before-delivery; x402-compatible; and a real fee advantage at scale.",
    inputs: [{ id: "amount", label: "Buy", options: AMOUNTS, default: "1000000000" }],
    hood: "Baseline Tier 0: a signed x402 quote → the wallet presents a split payment authorization → the merchant settles it, confirms rail finality, and delivers + signs a receipt. The card-fee figures are illustrative (§3.1), not RI-computed; the 1% is.",
    kind: "steps",
    run: (i) => JSON.parse(sdk.d03_oneshot_trace(BigInt(i.amount || "1000000000"))),
  },
  {
    id: "D-04", title: "The reclaim path", tier: "Tier 0",
    proves: "The failsafe for an interrupted two-leg purchase. Meed-first-final ordering means the meed leg lands first — so if the net leg fails (a technical hiccup, the common case) the merchant is never paid, the payer reclaims the meed AND keeps the net, ending whole. Delivery releases the meed; merchant fraud is the rarer, bounded worst case.",
    inputs: [{ id: "scenario", label: "What happens", options: [["netfail", "net leg fails (technical) — the common case"], ["deliver", "delivers — happy path"], ["fraud", "merchant takes payment, no delivery"]], default: "netfail" }],
    hood: "F4.3 entry machine on the VirtualRail. Meed leg funds the reclaimable entry FIRST (§5.6 finality-first); the net leg is a direct merchant transfer. netfail: net never sent → reclaim meed, payer whole (§7.8 'interruption strands at most the meed'). fraud: net lands, no attestation → reclaim meed, net lost (bounded, not absorbed).",
    kind: "steps",
    run: (i) => JSON.parse(sdk.d04_reclaim_trace(i.scenario || "netfail")),
  },
  {
    id: "D-07", title: "x402 coexistence & selection", tier: "Tier 0",
    proves: "Kinship, not rivalry; selection, not capture; no lock-in. A plain x402 client and a PayTP-aware client both succeed at the same merchant — one moves no meed, the other splits and receipts.",
    hood: "Client-independence + the F3-a mirror rule: a baseline split divides whatever reaches its address (so a plain client completes it), while only a PayTP-aware client that presents the signed terms through the merchant-settled path gets attribution + a receipt.",
    kind: "steps",
    run: () => JSON.parse(sdk.d07_coexistence_trace()),
  },
  {
    id: "D-09", title: "Attacks that fail", tier: "Both tiers",
    proves: "The three commitments are enforced, not just asserted. Each attack drives the real RI payer/merchant gate and is refused — a nonconformant or out-of-policy path cannot proceed; only a conformant, in-policy one can. The top three map to the commitments; the rest are the Tier-0 red-team rebuttals.",
    inputs: [{ id: "attack", label: "Attack", options: [
      ["meed-strip", "meed-strip → edge incentives"],
      ["understate", "understated settlement → bounded trust"],
      ["bad-quote", "over-charging quote → end-to-end"],
      ["replay", "nonce double-spend"],
      ["substitution", "cross-resource substitution"],
      ["short", "underpayment"],
    ], default: "meed-strip" }],
    hood: "Each attack runs against the real code. Meed-strip: the wallet won't sign and the merchant won't open a channel whose MEED_VECTOR strips OS/Dev-Fund (ChannelClient::open + ChannelDriver::open_channel). Understated settlement: the merchant recomputes the round against its metered checkpoint and refuses to accept it (F6-f carriage). Over-charging quote: the wallet's carve/policy gate denies a meed far above the governed carve before funding (plan_two_leg). Tier-0: the atomic consumed-nonce record (free-riding), the quote binding one resource (substitution), and settlement-precedes-delivery verifying the full amount (underpayment). Drawn from the RI rejection tests.",
    kind: "steps",
    run: (i) => JSON.parse(sdk.d09_attack_trace(i.attack || "meed-strip")),
  },
  {
    id: "D-01", title: "The reader's month (prepay channel)", tier: "Tier 1",
    proves: "Channels compress settlement — a month of micro-unlocks costs a handful of rail transfers; bounded prepay exposure; every enabling role still paid, on the wire.",
    inputs: [{ id: "n", label: "Unlocks", options: [["50", "50"], ["100", "100"], ["500", "500"]], default: "100" }],
    hood: "Real channel state: N MAC-sealed 36-byte Value-Slices are accepted into a paytp-core ChannelState (metering executed), then the meed settles in M = ceil(N/50) real on-rail claim-records — M is derived from N, never hardcoded. Prepay: a bounded deposit is funded first (F6-g; deposit-before-consume, drives B negative).",
    kind: "steps",
    run: (i) => JSON.parse(sdk.d_channel_trace(false, parseInt(i.n || "100", 10))),
  },
  {
    id: "D-02", title: "The agent's API bill (postpay channel)", tier: "Tier 1",
    proves: "The agentic wedge: postpay credit windows; the agent framework earns the Interaction-Layer share; a headless server's OS share routes to the independent open-source fund (not PayTP's own Development Fund).",
    inputs: [{ id: "n", label: "API calls", options: [["50", "50"], ["100", "100"], ["1000", "1000"]], default: "100" }],
    hood: "Postpay: the merchant extends an L_credit window (agent gets value first). Settlement rounds fund the meed claim-record. The headless-OS → independent-fund routing is §10.1 — the Foundation gains nothing from a missing OS.",
    kind: "steps",
    run: (i) => JSON.parse(sdk.d_channel_trace(true, parseInt(i.n || "100", 10))),
  },
  {
    id: "D-06", title: "Rail-agnosticism", tier: "Tier 0",
    proves: "Markets choose rails; the protocol doesn't. The same payment's division is identical across rails, and the meed always executes on the baseline.",
    hood: "The split address derives from the merchant/asset/vector — not the rail. Rail A (VirtualRail) runs in-page; the identical division on the Solana exact-svm split PDA is proven live on a validator in interop/x402/settle-localnet.mjs (M6.1c).",
    kind: "steps",
    run: () => JSON.parse(sdk.d06_rail_trace()),
  },
  {
    id: "D-08", title: "Channel survives a reconnect", tier: "Tier 1",
    proves: "Robustness: the tab continues via chaining across a dropped connection — no forced settlement, no value lost, and the rail is never touched during the reconnect.",
    hood: "F6.6 chaining + the F6-e stillborn synthetic checkpoint. The demo proves the rail ledger stays at 0 across the reconnect — settlement happens once, at close.",
    kind: "steps",
    run: () => JSON.parse(sdk.d08_reconnect_trace()),
  },
];

let engineReady = false;
let current = null;

function renderNav() {
  const nav = $("#nav");
  nav.innerHTML = "";
  for (const d of DEMOS) {
    const b = el("button");
    b.innerHTML = `<span class="id">${d.id}</span>${d.title}`;
    b.disabled = !d.run;
    b.onclick = () => select(d);
    b._demo = d;
    nav.appendChild(b);
  }
}

function select(d) {
  current = d;
  for (const b of $("#nav").children) b.setAttribute("aria-current", String(b._demo === d));
  $("#demo").hidden = false;
  $("#demo-title").textContent = d.title;
  $("#demo-proves").textContent = d.proves;
  $("#demo-tier").textContent = d.tier;
  const inputs = $("#demo-inputs"); inputs.innerHTML = "";
  for (const inp of d.inputs || []) {
    const lab = el("label"); lab.append(inp.label + " ");
    const sel = el("select"); sel.id = "inp-" + inp.id;
    for (const [v, t] of inp.options) { const o = el("option", null, t); o.value = v; if (v === inp.default) o.selected = true; sel.appendChild(o); }
    lab.appendChild(sel); inputs.appendChild(lab);
  }
  $("#viz").innerHTML = '<p class="status">Press <b>Run ▸</b> to execute the real RI path.</p>';
  $("#hood-note").textContent = d.hood || "";
  $("#hood-trace").textContent = "";
}

function readInputs(d) {
  const o = {};
  for (const inp of d.inputs || []) o[inp.id] = $("#inp-" + inp.id)?.value;
  return o;
}

function run() {
  if (!engineReady || !current) return;
  let result;
  try { result = current.run(readInputs(current)); }
  catch (e) { $("#viz").innerHTML = `<p class="status err">RI error: ${e}</p>`; return; }
  // Each demo returns { events, wire }: events drive the animation; wire is the REAL
  // RI artifacts (signed quote, split address, receipt+signature, entry_id, …).
  const events = Array.isArray(result) ? result : result.events;
  const wire = Array.isArray(result) ? null : result.wire;
  const walkthrough = Array.isArray(result) ? null : result.walkthrough;
  if (!Array.isArray(result) && result.display) display = result.display;
  $("#hood-trace").textContent = JSON.stringify(wire ?? events, null, 2);
  if (current.kind === "split") renderSplit(events, walkthrough);
  else renderSteps(events);
}

// The "under the hood — which code ran" panel: maps a step (or a whole split demo) to the
// real RI entry point(s) that executed, emitted by the WASM facade beside the call so it
// can't drift. Each row carries a tag shown inline — ● executed (real RI this run), ○
// depicted (a wire-plane mechanic proven elsewhere in the RI, cited), ◌ off-protocol (no
// RI path, e.g. an illustrative figure) — so an engineer is never misled about which steps
// are executed vs depicted vs non-protocol.
function modeTag(tag) {
  if (tag === "exec") return ["exec", "● executed"];
  if (tag === "depicted") return ["dep", "○ depicted"];
  return ["off", "◌ off-protocol"];
}
function codeLine(c) {
  const row = el("div", "codeline");
  const [cls, label] = modeTag(c.tag);
  row.append(el("span", "modetag " + cls, label));
  row.append(el("code", "cfn", c.fn));
  if (c.path && c.path !== "—") row.append(el("span", "cpath", c.path));
  row.append(el("div", "cdoes", c.does));
  return row;
}
function codePanel(entries, label) {
  const det = el("details", "hood-code");
  const sum = el("summary", null, label || "⌵ under the hood — which code ran");
  det.appendChild(sum);
  for (const c of entries) det.appendChild(codeLine(c));
  return det;
}

// The reusable money-flow split renderer (D-05/D-03/D-06 shapes). Two-tier: the
// payment's 99/1 split, then the 1% meed MAGNIFIED into its distribution roles.
function renderSplit(trace, walkthrough) {
  const paid = trace.find((e) => e.event === "paid");
  const divided = trace.find((e) => e.event === "divided");
  const conserved = trace.find((e) => e.event === "conserved");
  const gross = Number(paid?.gross ?? conserved?.gross ?? 0);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const recipients = divided.recipients.map((r) => ({ ...r, n: Number(r.settled), cls: roleClass(r.label) }));
  const merchant = recipients.find((r) => r.cls === "merchant");
  const meeds = recipients.filter((r) => r.cls !== "merchant");
  const meedTotal = meeds.reduce((a, r) => a + r.n, 0);

  const viz = $("#viz"); viz.innerHTML = "";
  const flow = el("div", "flow");
  const source = el("div", "source");
  source.append(el("div", "amt", fmtAmt(gross)));
  source.append(el("div", "lbl", "paid to the split address"));
  flow.appendChild(source);

  const col = el("div", "recips");

  // Tier 1 — the payment: merchant (99%) vs the meed pool (1%), true scale.
  const mkRow = (label, dest, n, widthPct, cls, bpText) => {
    const row = el("div", "recip " + cls);
    row.append(el("div", "name", label));
    const amt = el("div", "amt", fmtAmt(n));
    row.append(amt);
    if (dest) row.append(el("div", "dest", dest));
    row.append(el("div", "bp", bpText));
    const bar = el("div", "bar"); const fill = el("span"); bar.appendChild(fill);
    row.append(bar);
    col.appendChild(row);
    requestAnimationFrame(() => { fill.style.width = Math.max(widthPct, 0.4) + "%"; });
    if (!reduce) countUp(amt, n, 900);
  };
  if (merchant) mkRow(merchant.label, merchant.dest, merchant.n, gross > 0 ? merchant.n / gross * 100 : 0, "merchant", "99% — the merchant keeps almost everything");
  mkRow("↳ The meed (1%)", "", meedTotal, gross > 0 ? meedTotal / gross * 100 : 0, "meed", "a flat 1% — governed & auditable");

  // Tier 2 — the 1% meed magnified: roles at meed-pool scale.
  const magHead = el("div", "maghead", "The 1% meed, on the wire — magnified:");
  col.appendChild(magHead);
  for (const r of meeds) {
    mkRow(r.label, r.dest, r.n, meedTotal > 0 ? r.n / meedTotal * 100 : 0, r.cls, r.bp + " bp");
  }

  flow.appendChild(col);
  viz.appendChild(flow);

  if (conserved) {
    const badge = el("div", "badge " + (conserved.ok ? "ok" : "bad"));
    badge.textContent = conserved.ok
      ? `✓ value conserved to the minor unit — ${fmtAmt(gross)} in, ${fmtAmt(gross)} out`
      : "✗ value NOT conserved";
    viz.appendChild(badge);
  }
  if (walkthrough && walkthrough.length) viz.appendChild(codePanel(walkthrough));
}

function countUp(node, to, ms) {
  const start = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - start) / ms);
    node.textContent = fmtAmt(Math.round(to * (0.15 + 0.85 * p)));
    if (p < 1) requestAnimationFrame(step); else node.textContent = fmtAmt(to);
  };
  requestAnimationFrame(step);
}

// Generic step renderer (non-split demos: reclaim, coexistence, attacks).
function renderSteps(trace) {
  const viz = $("#viz"); viz.innerHTML = "";
  // Visible executed/depicted legend (a visitor must never mistake an animation
  // for an execution). Only shown when a demo mixes the two.
  if (trace.some((ev) => ev.mode)) {
    const legend = el("div", "legend");
    legend.innerHTML =
      '<span class="modetag exec">● executed</span> real RI running in your browser · ' +
      '<span class="modetag dep">○ depicted</span> the gated wire-plane mechanic, proven in the RI (cited in each step)';
    viz.appendChild(legend);
  }
  const list = el("div", "steps");
  viz.appendChild(list);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  trace.forEach((ev, i) => {
    const cls = ev.reject ? "reject" : ev.ok ? "ok" : "";
    const s = el("div", "step " + cls);
    s.append(el("span", "k", ev.event));
    if (ev.mode === "exec") s.append(el("span", "modetag exec", "● executed"));
    else if (ev.mode === "depicted") s.append(el("span", "modetag dep", "○ depicted"));
    const d = el("div", "d"); d.innerHTML = ev.text || JSON.stringify(ev);
    s.append(d);
    if (ev.code) s.append(codePanel(ev.code));
    list.appendChild(s);
    if (reduce) { s.style.opacity = 1; s.style.transform = "none"; }
    else s.animate([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }],
      { duration: 320, delay: i * 160, fill: "forwards", easing: "ease-out" });
  });
}

// Theme toggle (persisted). Only present on the standalone page, which carries its
// own #theme button; when embedded the host site owns the toggle, so guard for it.
function initTheme() {
  const saved = localStorage.getItem("paytp-theme");
  if (saved) THEME_EL.setAttribute("data-theme", saved);
  const btn = $("#theme");
  if (!btn) return;
  btn.onclick = () => {
    const cur = THEME_EL.getAttribute("data-theme")
      || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    THEME_EL.setAttribute("data-theme", next);
    localStorage.setItem("paytp-theme", next);
  };
}

// Standalone-in-iframe fallback (legacy embed): `?embed=1` hides the demo's own
// page chrome so a host frame's chrome wraps it. The preferred embedding is the
// <paytp-demos> web component (mount(shadowRoot)), which has no chrome to hide.
function applyEmbedMode() {
  const p = new URLSearchParams(location.search);
  const embedded = p.get("embed") === "1" || window.self !== window.top;
  if (embedded) document.documentElement.classList.add("embed");
  const t = p.get("theme");
  if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
}

// Mount the suite into a root: `document` for the standalone page, or a shadow root
// for the <paytp-demos> web component. Every query goes through $ (root-scoped), so
// the same code renders inline on any page with no iframe.
export async function mount(root, opts = {}) {
  ROOT = root;
  THEME_EL = opts.themeEl || root.host || document.documentElement;
  if (opts.theme === "dark" || opts.theme === "light") THEME_EL.setAttribute("data-theme", opts.theme);
  initTheme();
  renderNav();
  try {
    await init();
    engineReady = true;
    $("#engine-status").hidden = true;
    $("#run").onclick = run;
    select(DEMOS[0]);
  } catch (e) {
    const s = $("#engine-status");
    if (s) { s.textContent = "Failed to load the PayTP core (WASM): " + e; s.className = "status err"; }
  }
}

// Standalone auto-mount: if this page carries the demo markup (the standalone
// index.html), mount into it. The web component imports mount() and calls it itself.
if (typeof document !== "undefined" && document.querySelector("#nav")) {
  applyEmbedMode();
  mount(document, { themeEl: document.documentElement });
}
