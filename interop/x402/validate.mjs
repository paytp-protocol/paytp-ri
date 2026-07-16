// M6.1b — validate the RI's **shipped-x402-V1** 402 (F3-j) against the
// real `x402@1.2.0` npm package (the code a plain client/facilitator runs), and
// prove a plain exact-svm client completes the PayTP baseline offer by paying the
// split `payTo`.
//
// The RI 402 is read from stdin (piped from the Rust emitter) or `ri402.json`.
//
// The RI now emits the shipped V1 shape directly, so — unlike the M6.0
// harness which had to *project* a V2-doc 402 to V1 — the RI's canonical 402 is
// validated by the real schema as-is.

import { readFileSync } from "node:fs";
import { PaymentRequirementsSchema, x402ResponseSchema } from "x402/types";
import { selectPaymentRequirements } from "x402/client";

function readInput() {
  try {
    const stdin = readFileSync(0, "utf8");
    if (stdin.trim()) return JSON.parse(stdin);
  } catch {}
  return JSON.parse(readFileSync(new URL("./ri402.json", import.meta.url), "utf8"));
}

// The signed paytp object rides in extensions.paytp.info; a PayTP-aware client
// reads it from the RAW 402 (the x402 schema validates but strips top-level
// extensions — see the RI note in paytp-core::x402::PaymentRequired).
function paytpInfo(pr) {
  return pr?.extensions?.paytp?.info ?? null;
}

let failures = 0;
const ok = (cond, msg) => { console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); if (!cond) failures++; };

const pr = readInput();
const acc = pr.accepts[0];

console.log("=== 1. The RI's canonical 402 validates against shipped x402@1.2.0 ===");
const reqParse = PaymentRequirementsSchema.safeParse(acc);
if (!reqParse.success) console.log("  issues:", JSON.stringify(reqParse.error.issues.map(i => i.path.join(".") + ": " + i.message)));
ok(reqParse.success, "accepts[0] is a valid shipped-x402 PaymentRequirements");
const bodyParse = x402ResponseSchema.safeParse(pr);
if (!bodyParse.success) console.log("  issues:", JSON.stringify(bodyParse.error.issues.slice(0, 6).map(i => i.path.join(".") + ": " + i.message)));
ok(bodyParse.success, "the whole 402 body is a valid shipped-x402 PaymentRequired");
ok(pr.x402Version === 1, "x402Version is the shipped literal 1");

console.log("\n=== 2. A plain client's selectPaymentRequirements picks the split payTo ===");
let selected = null;
try {
  selected = selectPaymentRequirements(pr.accepts, "solana-devnet", "exact");
} catch (e) {
  console.log("  selectPaymentRequirements threw:", e.message);
}
ok(selected != null, "selectPaymentRequirements returned a requirement");
if (selected) {
  ok(selected.payTo === acc.payTo, `plain client would pay the split payTo (${selected.payTo})`);
  ok(selected.maxAmountRequired === acc.maxAmountRequired, `for the quoted amount (${selected.maxAmountRequired})`);
  ok(selected.asset === acc.asset, "in the quoted asset");
  ok(selected.network === "solana-devnet", "on the named network solana-devnet");
}

console.log("\n=== 3. PayTP extension + resource binding (F3-j rule 4) ===");
const info = paytpInfo(pr);
ok(info != null, "the signed paytp object is present in extensions.paytp.info");
if (info) {
  ok(acc.extra?.memo == null,
    "baseline accepts[0] does not rely on exact-svm extra.memo");
  ok(acc.resource === info.resource,
    `accepts[0].resource == the signed paytp.resource (${acc.resource})`);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASS" : failures + " CHECK(S) FAILED"} — PayTP baseline interoperates with shipped x402 (V1 shape, emitted directly).`);
process.exit(failures === 0 ? 0 : 1);
