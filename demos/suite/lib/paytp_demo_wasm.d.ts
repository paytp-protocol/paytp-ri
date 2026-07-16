/* tslint:disable */
/* eslint-disable */

/**
 * **D-03** — a one-shot purchase across the full range ($0.05 → $50 → $1000): PayTP is
 * not just for micropayments; settle-before-delivery; the fee advantage at scale.
 */
export function d03_oneshot_trace(amount: bigint): string;

/**
 * **D-04** — the reclaim path. Meed-first-final ordering (§5.6.2): the meed leg
 * lands FIRST, and the wallet only starts the net leg once the meed is final. So an
 * interruption between the legs "strands at most the meed" (§5.6.2; the bound is §7.8's
 * residual-risk row) — which is reclaimable. `scenario` ∈ {"deliver", "netfail" (the
 * primary failsafe), "fraud"}.
 */
export function d04_reclaim_trace(scenario: string): string;

/**
 * The D-05 canonical live path: divide a payment of `amount` (minor units) on-wire and
 * return the canonical trace as JSON. Real split division on the `VirtualRail` — a plain
 * payment to the split address divides among the recipients by basis points. `os_absent`
 * toggles the neutrality beat: with an OS asserted its 0.1% lands at its own address;
 * with the OS absent that 0.1% routes to the independent open-source fund — and the
 * merchant's 99% and the Development Fund's 0.1% are unchanged (§10.5).
 */
export function d05_split_trace(amount: bigint, os_absent: boolean): string;

/**
 * **D-06** — rail-agnosticism: the same payment's division is identical across rails; the
 * meed always executes on the baseline. Rail A (VirtualRail) runs in-page; the
 * identical division on the Solana exact-svm split PDA is proven live in `interop/x402`.
 */
export function d06_rail_trace(): string;

/**
 * **D-07** — x402 coexistence and selection: kinship not rivalry; selection not capture.
 * A plain x402 client completes a baseline offer (the split divides by construction, no
 * PayTP receipt/attribution); a PayTP-aware client selects the signed offer (meed +
 * signed receipt). Both succeed side by side.
 */
export function d07_coexistence_trace(): string;

/**
 * **D-08** — channel survives a reconnect (chaining): the tab continues with no
 * forced settlement and no value lost; the rail is never touched during the reconnect.
 */
export function d08_reconnect_trace(): string;

/**
 * **D-09** — attacks that fail: the security model holds. Each attack is executed against
 * the real payer/merchant gate and REJECTED. `attack` ∈ the three commitment-level paths
 * {"meed-strip","understate","bad-quote"} plus the Tier-0 baseline paths
 * {"replay","substitution","short"}.
 */
export function d09_attack_trace(attack: string): string;

/**
 * **D-01 / D-02** — Tier 1 channels: settlement compression + the meed on the wire.
 * `requests` micro-payments are metered off-chain as slices and settled in a small
 * number of aggregate rounds; each round's meed funds an F4.2 claim-record (the real
 * aggregate-leg primitive) that divides among the distribution roles. `postpay` toggles
 * the agent (postpay credit window) vs the reader (prepay deposit) framing.
 */
export function d_channel_trace(postpay: boolean, requests: number): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly d03_oneshot_trace: (a: bigint) => [number, number];
    readonly d04_reclaim_trace: (a: number, b: number) => [number, number];
    readonly d05_split_trace: (a: bigint, b: number) => [number, number];
    readonly d06_rail_trace: () => [number, number];
    readonly d07_coexistence_trace: () => [number, number];
    readonly d08_reconnect_trace: () => [number, number];
    readonly d09_attack_trace: (a: number, b: number) => [number, number];
    readonly d_channel_trace: (a: number, b: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
