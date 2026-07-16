# paytp_kit — the PayTP meed-instance contract (SVM)

The on-chain rendering of the PayTP **F4 entry machine** for the Solana/SBF rail
(first baseline rail; the whitepaper stays rail-agnostic). Anchor program,
built + proven offline via LiteSVM (bundled `spl_token`) and deployed to a real
local Agave validator. **This is the reference implementation, not audited for
mainnet** — see `../SECURITY.md` and "Spike simplifications" below.

Program id: `2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau` — deployment-specific. A
deployment supplies its own via `anchor keys sync`; the public reference snapshot ships
an example id here (its keypair is not distributed).

## Build & test

```
export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.avm/bin:$HOME/.cargo/bin:$PATH"
anchor build                                   # SBF .so
cargo test -p paytp_kit --test entry_machine   # LiteSVM proofs (offline, no SOL)
```

## Instructions

| Instruction | What it does | Guards |
|---|---|---|
| `deploy_instance(seed_instance, canonical_bytes)` | Create a meed instance. Recomputes `seed_instance = SHA256("PayTPv1-instance"‖0x00‖canonical_bytes)` **on-chain** and binds, from the `ADDRESS_INPUTS` preimage, the `MERCHANT_KEY` (tail `[2..34]`), the 4 meed **destination token accounts** (`[34..162]`), and the settlement **mint** (`[162..194]`). | `seed_instance` must equal the recomputed hash → a rogue key/dest/mint derives a different instance PDA (theft closure). |
| `fund_entry(entry_id, nonce, amount, t_open, t_lapse, contest, refund_account)` | Create a purchase entry (F4-c) **and atomically** create its escrow token account + deposit `amount` from the funder. | `entry_id` recomputes from the params; `amount ≤ u64::MAX`; `t_open ≤ t_lapse`; `t_lapse ≥ now`; deposit `mint == instance.mint`. Duplicate/mismatch/past-lapse reject atomically. |
| `attest(MerchantAction)` | Merchant-as-signer release → `ATTESTED` (M0.5 simplification). | Bound merchant signer; entry↔instance bound; post-`T_lapse` rejected (LAPSED). |
| `attest_detached(AttestDetached)` | **F3.5** detached Ed25519 attestation, verified by the ed25519 precompile + Instructions-sysvar introspection → `ATTESTED`. No merchant signer; relayable/batchable. | Offsets self-referential (`u16::MAX`); pubkey == `instance.merchant_key`; message == the canonical F3.5 `"PayTPv1-attest"‖0x00‖TLV(0x00 NONCE, 0x01 ENTRY_ID)` (byte-identical to core F3.5). |
| `cancel(MerchantAction)` | Merchant refund path → `CANCELLED`. | Same as `attest`. |
| `open_reclaim` / `execute_reclaim` / `lapse` (`EntryOnly`) | Permissionless F4.3 reclaim: open in `[T_open,T_lapse]`, execute strictly after `opened_at+contest`, or `lapse` a `FUNDED` entry past `T_lapse`. | State + window guards; `saturating_add` on `T_exec`. |
| `advance_channel_meed(channel_id, target_p)` | The **current channel** meed-settlement kind (F6-o, Option-W). Advances the per-channel cumulative watermark `funded_p` to `target_p`, dividing the delta among the schema-0x01 roles **per destination** (F7-d, shared `paytp-f7`). Replaces the per-round `fund_claim_record`. | Idempotent by absolute position (`target_p ≤ funded_p` distributes nothing); the monotone `funded_p` is the on-chain exactly-once record closing the cross-checkpoint double-draw (F6-o); instance-bound; watermark-only (no close/re-init). |
| `fund_claim_record(key, channel_id, ckpt_ref, p)` | The **retired** per-round channel kind (F4.2, superseded by `advance_channel_meed`). Records the on-chain F7-d split of `P` among the schema-0x01 roles (shared `paytp-f7`). | `key` recomputes from `(channel_id, ckpt_ref, P)`; atomic duplicate reject; no reclaim path exists. |
| `distribute(Distribute)` | Pay a **delivered** entry's escrow to the bound destinations (F7-d shares, residue carries). | **Guardrail:** `Attested`/`Lapsed` only; escrow == the entry's PDA; dests == `instance.dests`; idempotent (`distributed`). |
| `refund(Refund)` | Return a `Cancelled`/`Reclaimed` entry's escrow to the payer's recorded `refund_account`. | Escrow == the entry's PDA; `refund_dest == entry.refund_account`; same settled flag. |

## Accounts & PDAs

- **`Instance`** — `seeds=[b"instance", seed_instance]`. Stores `seed_instance`,
  `merchant_key`, `dests: [Pubkey; 4]`, `mint`. Is the SPL authority of every one
  of its entries' escrows.
- **`Entry`** — `seeds=[b"entry", entry_id]`. Stores `seed_instance`, `nonce`,
  `amount`, the deadlines, `state`, `distributed` (settled flag), `refund_account`.
- **escrow** — `seeds=[b"escrow", entry_id]`, an SPL token account (authority =
  the instance PDA), created + funded by `fund_entry`; drained by
  `distribute`/`refund` (both sign as the instance PDA).
- **`ClaimRecord`** — `seeds=[b"claim", key]`. Stores `amount` (P), `shares[4]`,
  `residue`. No state, no reclaim — terminal at birth.

## Security model (invariants)

1. **Everything is derived, never trusted from the caller** — instance, entry,
   claim-record, and escrow addresses are all PDAs the program recomputes; the
   instance commits its `merchant_key`/`dests`/`mint` via `seed_instance`.
2. **Value moves only for a delivered entry** — `distribute` requires
   `Attested`/`Lapsed`; a `Funded`/`ReclaimOpen`/`Reclaimed` entry
   never pays out.
3. **Value goes only where it's bound** — the escrow is bound to the entry, the
   destinations to the instance; a swapped account or a fake mint is rejected.
4. **One settlement per escrow** — the `distributed` flag makes distribute/refund
   mutually exclusive and each once.
5. **The meed arithmetic can't drift** — the on-chain division is the *same*
   `paytp-f7` crate the host uses (proven equal across a value spread in
   `claim_record_onchain_division_matches_host_and_conserves`).

## Spike simplifications (documented, not surprises)

- `ADDRESS_INPUTS` destinations are carried as resolved token-account pubkeys in
  the preimage tail (the real contract carries F9 pointers inside the meed vector).
- Deposit-side deposit CPI is exercised in `fund_entry`; the funder pre-creates its
  own source token account.
- Entry-PDA prefund is a bounded availability DoS (re-quote resolves); the escrow
  create is prefund-tolerant. Fee-on-transfer settlement tokens are out of scope.
- Public-network deployment and a **human security audit** are the pre-launch
  gates (`../SECURITY.md`).
