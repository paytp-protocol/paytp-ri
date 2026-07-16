# PayTP RI — normative-MUST coverage map (baseline profile)

**Purpose:** every normative **baseline** MUST in the spec the RI implements → at least
one executable test **or** an explicit classification. This is the spec-rule → test
index for the **baseline-profile reference implementation** (see the repo-root
[`SCOPE.md`](../SCOPE.md) for what the profile does and does not cover, and
[`ARCHITECTURE.md`](../ARCHITECTURE.md) for the crate map).

**Scope.** The RI implements the baseline settlement profile of `spec/formal/` (F1–F10),
pinned in `PINNED_SPEC`. Rows are keyed to **F10.3** (the corpus's required-coverage
table of contents) cross-referenced against the raw section MUSTs, **plus** the two
chapter MUSTs outside F1–F10: §10.4 (external-wallet selection — code) and §10.5 (charter
governance — a certification checklist). Test refs are `crate::file::fn` (host workspace)
or `contracts::…` (the separate LiteSVM workspace, not in the host test count). Current
(M8): the host workspace runs **541 tests green** plus the separate contract LiteSVM
suite, CI exit 0.

**Status legend** — `COVERED` (≥1 existing test) · `PARTIAL` (core tested, a slice rides
a launch-gate) · `CLASS:non-code` (governance checklist, §10.5) · `CLASS:launch-gate`
(declared boundary in `SCOPE.md`, not a dev-gate) ·
`CLASS:deferred` (later unit; conservative subset already tested) · `CLASS:gap` /
`CLASS:exclusion` (a by-design classification, stated inline — never a silent gap).

---

## What the corpus covers (M8)

The baseline coverage the RI carries, each keyed to executable tests:

1. ✅ **Concurrent nonce race / exactly-once** (F4.4) — `adversary::duplicate_settlement_race_consumes_the_nonce_exactly_once` proves exactly-once delivery under a 32-way thread race (T4).
2. ✅ **x402 attack classes as must-FAIL tests** — `adversary::{cross_resource_substitution_is_refused, duplicate_settlement_race_*, leaked_token_resubmission_is_refused, delivery_requires_settlement_first, underpayment_is_refused_no_upto_allowance}` (T4).
3. ✅ **Registry adversary tests** — `adversary::{rogue_os_assertion_cannot_move_value_to_the_asserter, invalid_meed_vector_is_refused, stale_or_revoked_registry_version_is_refused}` (T4).
4. ✅ **Entry-machine attacks** — `adversary::{nonce_desync_funds_an_orphan_the_merchant_never_quoted, zero_contest_window_still_requires_a_full_tick_before_reclaim}` (T4).
5. ✅ **Bare-request-is-not-authorization** (F4) — covered by construction: the merchant has no delivery path without a verified payment; the two-leg/redeem flows all require a bound payment ref (`twoleg_e2e::*`, `adversary::delivery_requires_settlement_first`).
6. ✅ **§10.4 external-wallet selection + wallet-substitution** — `paytp-client` + `paytp-wallet` built; `substitution::two_distinct_wallets_drive_the_same_flow_through_the_same_interface` drives two distinct wallet *types* through the `PayerWallet` trait (T2/T3).
7. ✅ **Composition vectors** (COVERED, slice-MAC, H(s), BindSalt, K_session, head_0) — `composition_independent::composition_anchors_confirmed_by_an_independent_path` + pinned in `f1-crypto.json`, consumed by both `conformance::f1_crypto_anchors` and the independent path (T5).
8. ✅ **Control-path suffix joining** (F2 path MUST NOT end in `/`) — `discovery::{control_path_must_not_end_in_slash, resource_suffix_joining_is_deterministic}` (T2).
9. ⏳ **Launch-gated tail (not dev-gate; classified):** TLS 0-RTT early-data reject (F1, §A — transport-independent RI has no TLS surface); artifact-specific `no-store` (F2-i, rides the live HTTP stack); `CKPT_TIMEOUT`/`SETTLE_TIMEOUT` start/expiry (F8 — thin at the driver).

**Coverage verified (M8).** The adversary suite is green (15 adversary tests);
the composition anchors are independently re-derived; wallet substitution drives two
distinct wallet *types* through the `PayerWallet` trait. Every non-`COVERED` row below is
a stated classification — a launch-gate boundary (`SCOPE.md`),
a certification-level §10.5 obligation, or a by-design builder classification — never a
silent gap.

**Classified (not a row above):** two-leg quotes have no interaction-layer resource
binding — the client's resource check is baseline-only, because there is no client
two-leg entry point yet (two-leg is driven directly by the wallet). `CLASS:gap` — add the
resource binding when a client two-leg flow is built; the wallet still verifies the
two-leg signature and extracts terms from it, so a compromised interaction layer cannot
forge two-leg terms, only (at most) present a signed quote for a resource the operator
did not ask for.

---

## F1 — Foundations

| # | Requirement (F10.3 / MUST) | Test(s) | Status |
|---|---|---|---|
| F1-1 | LEB128 accept `00`/`7f`/`80 01`/`ff ff ff ff 0f`; reject overlong, `>2³²−1` | `leb128::{f10_accept_vectors,f10_reject_vectors,roundtrip_is_byte_identical}`; conformance `f1_encoding_corpus` | COVERED |
| F1-2 | minimal unsigned/signed accept/reject | `tlv::{minimal_uint,minimal_sint,signed_int_wide_domain}` | COVERED |
| F1-3 | canonical order; dup type; `0x01`+`0x81`; wrong critical flag | `tlv::{reject_out_of_order_and_duplicate,wrong_critical_flag_rejected,parse_encode_roundtrip_canonical}` | COVERED |
| F1-4 | F1-j framing whole-body | `tlv::framing_roundtrip_and_rejects` | COVERED |
| F1-5 | text reject NUL/control/BOM/non-NFC | `tlv::text_rules` | COVERED |
| F1-6 | JSON grammar reject; duplicate members document-wide | `jcs::{uint_grammar,sint_grammar,duplicate_members_rejected_anywhere,jcs_sorts_keys_by_utf16}` | COVERED |
| F1-7 | unknown non-critical covered; reserved `0x70–0x7F` reject | `tlv::{coverage_excludes_authenticators_includes_unknown_noncritical,unknown_critical_and_authenticator_rejected}` | COVERED |
| F1-8 | slice closed object (F1-k); SEQ ≤ 2⁶³; MAC over COVERED | `slice::{closed_object_rejects_extra_tlv,seq_ceiling_boundary,tampered_amount_fails_mac}` | COVERED |
| F1-9 | slice in TLS 0-RTT early data rejected (send+recv) | — (transport-independent RI: no TLS surface) | CLASS:launch-gate (§A) |
| F1-10 | strict Ed25519; small-order key reject | `crypto::{ed25519_strict_roundtrip,ed25519_rejects_small_order_key}`; conformance `f1_crypto_anchors` | COVERED |
| F1-11 | erase `s` + keys at close (F1.6) | `channel::state::closed_key_erasure_is_unforgeable` | COVERED |
| F1-12 | crypto anchors: COVERED prefix, BindSalt, K_session schedule | `envelope::slice_covered_prefix_matches_f10_anchor`; `crypto::slice_key_schedule_is_deterministic`; `composition_independent::*` (reconstructs the slice COVERED bytes independently — a core TLV bug cannot hide); `conformance::f1_crypto_anchors` | COVERED (T5 independent confirm done) |
| F1-13 | F1-f payer-key derivation (RECOMMENDED) + unlinkability (F2.3 MUST) | `custody::{derivation_is_deterministic_and_root_separated, payer_key_is_unlinkable_across_merchant_or_domain, scoped_derivation_differs_from_the_retired_global_v1}`; `channel::payer_is_unlinkable_across_merchants_on_the_wire_lab` (reads on-wire `CHANNEL_AUTH.payer_key`); the `paytp-host` F2.4 conformance matrix. **Per-`(merchant, registrable-domain)` scoped derivation:** two merchants → different keys; same merchant/domain → stable. The registrable domain resolves through the shared F2.4 normalizer (`paytp-host` — pinned `idna`/UTS#46 + a vendored, dated PSL), the SAME one the artifact `HOST` validates through; the merchant host is taken from the VERIFIED `AcceptedBinding`. The unlinkability *property* is the F2.3 MUST (the KDF is RECOMMENDED). | COVERED |

## F2 — Identity & binding

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F2-1 | no-cert / external-PSK session MUST NOT carry establishment | `establish::artifact_accept_and_reject` (accepted-artifact gate); PSK-session detection = TLS layer | PARTIAL (artifact gate COVERED; PSK detection launch-gate) |
| F2-2 | artifact responses `Cache-Control: no-store` (F2-i) | quote/authenticated: `http::{no_store_quote_is_never_cached,quote_402_is_no_store_and_varies_on_both_headers}`; artifact header = live HTTP stack | PARTIAL |
| F2-3 | artifact acceptance a–d each singly; ENC_KEY from accepted artifact | `establish::{artifact_accept_and_reject,artifact_host_must_be_normalized,artifact_validity_applies_skew}` | COVERED |
| F2-4 | all-zero X25519 DH aborts seal/unseal | `crypto::hpke_seal_open_roundtrip_and_zero_dh_abort` | COVERED |
| F2-5 | control path MUST NOT end in `/`; deterministic suffix joining | `discovery::{control_path_must_not_end_in_slash,resource_suffix_joining_is_deterministic}` (paytp-client) | COVERED (T2) |
| F2-6 | host normalization IDNA/UTS#46/PSL/IP-literal | `establish::artifact_host_must_be_normalized`; `pointer::*` (byte-level); full IDNA/PSL is launch-gated | PARTIAL (byte-level COVERED; full IDNA launch-gate) |
| F2-7 | `H(s)` anchor `s=00×32 → c9c08bbb…` | `crypto::h_commit_anchor`; conformance `f1_crypto_anchors` | COVERED |

## F3 — Tier 0 objects

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F3-1 | quote validation: REQUIRED absent, cardinality, rate `"0"`, non-CAIP-2 | `quote::{vector_schema_validation,offer_network_must_be_caip2,sign_and_verify_roundtrip}`; baseline e2e | COVERED |
| F3-2 | mirror rule F3-a: mismatch reject; unmirrored no PayTP exec; plain allowed | `x402_interop_e2e::{envelope_rewrite_of_any_mirrored_member_is_refused,substituted_valid_quote_does_not_match_envelope_accepts,plain_x402_client_pays_the_split_and_meed_divides}` | COVERED |
| F3-3 | F3-i echo member-for-member NO append; re-verify received bytes fail-closed | `quote::appended_member_fails_closed`; `x402::paytp_extension_embeds_info_and_schema` | COVERED |
| F3-4 | baseline offer carries no PayTP `extra.memo`; redemption binds nonce to the merchant-settled canonical ref via `used_refs` | `quote::baseline_extra_memo_is_not_required`; `baseline_e2e::{baseline_quote_omits_extra_memo_and_retries_without_second_mint,design_a_rejects_cross_payer_hijack_via_used_refs}` | COVERED |
| F3-5 | honor boundary at `exp+grace` | `baseline_e2e::{expired_quote_rejected,baseline_happy_path_divides_and_receipts}` | COVERED |
| F3-6 | receipt `paid[]` order; attest/cancel labels never cross-verify | `receipt::{baseline_receipt_roundtrip,reject_bad_paid_shapes}`; `attest::attest_and_cancel_do_not_cross_verify` | COVERED |
| F3-7 | `PayTP-Roles` TLV accept/reject | `roles::{roundtrip_and_ordering,reject_bad_os_identifier_and_bad_pointer,absent_is_empty_not_error}` | COVERED |
| F3-8 | split re-derivation exact; `P<2¹²⁸`; wide product exact | `quote::split_pay_to_re_derivation`; `derive::address_inputs_canonical_orders_vector`; `fee`/`f7::*` | COVERED |
| F3-9 | `/attest` served unauthenticated by nonce+entry id | `attest_endpoint::serve_and_retrieve_attestation_unauthenticated` | COVERED |

## F4 — Entry machine

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F4-1 | `entry_id` anchor (regenerated F4-c, AMT+deadlines) | `derive::entry_and_claim_ids_match_svm_and_python_reference`; conformance `f4_derive_corpus` | COVERED |
| F4-2 | mempool-squat: distinct ids; honest never dup-rejected | `derive::entry_id_squat_derives_distinct_ids`; `instance::dust_funding_lands_a_different_id` | COVERED |
| F4-3 | atomic funding reject (no nonce / dup / past T_lapse) | `instance::atomic_funding_rejections`; contracts entry_machine | COVERED |
| F4-4 | full F4.3 machine, boundary sides of T_open/T_lapse/T_exec | `instance::{reclaim_open_execute_windows,cancel_refunds_and_blocks_attest,lapse_distributes_to_recipients}`; contracts | COVERED |
| F4-5 | claim-record kind: fund→claimable; reclaim→reject | `instance::claim_record_derived_windowless_unreclaimable`; `derive::claim_record_id_is_windowless_and_p_keyed` | COVERED |
| F4-6 | ATA(owner=payTo,mint=asset) exact-svm destination | contracts split-divider (LiteSVM) | COVERED (contracts) |
| F4-7 | batch-attest MUST silently skip terminal entries | RI posts per-delivery; eager path `twoleg_e2e::delivered_two_leg_reclaim_fails_because_attested` | CLASS:deferred |
| F4-8 | merchant MUST post attestation on every delivered two-leg | `twoleg_e2e::delivered_two_leg_reclaim_fails_because_attested` | COVERED |
| F4-9 | meed-first-means-final ordering (wallet MUST NOT start net before meed final) | **wallet-enforced:** `substitution::two_leg_net_leg_refuses_until_meed_is_final` (net leg refused until meed reaches quoted finality); merchant side `twoleg::redeem_two_leg` | COVERED |
| F4-10 | merchant MUST NOT treat bare request as payer authorization; F4.4 durable entry-order (outcomes-not-attempts, cancellation bars) | no-delivery-without-payment: `adversary::delivery_requires_settlement_first`; the merchant's durable one-decision is `MerchantStore::consume_nonce` (atomic check-and-set, `baseline_e2e::nonce_idempotency_and_replay` + `adversary::duplicate_settlement_race_*`); the entry-order/cancellation state machine lives in the rail/contract (`instance::cancel_refunds_and_blocks_attest`, `reclaim_then_attest_on_the_entry`), **not** a `mark_entry` store method (the Part-1b sketch's `mark_entry` was never built — entry-order is on the rail). | PARTIAL (documented) |
| F4-11 | durable orders outcomes-not-attempts; exactly-once across traffic | `baseline_e2e::nonce_idempotency_and_replay`; `adversary::duplicate_settlement_race_consumes_the_nonce_exactly_once` (32-way race) | COVERED (T4) |

## F5 — Channel messages

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F5-1 | one channel per request | `carriage::{batch_body,routing_rejections,malformed_slice_is_channel_independent}` | COVERED |
| F5-2 | `CHANNEL_AUTH` retired `0x11` = malformed | `establish::reserved_0x11_rejected` | COVERED |
| F5-3 | F5-m replay-suppression; identical retransmit→stored ACK, no re-init | `channel::f5m_replay_suppression`; `carriage::retransmit_open_does_not_reset_meter` | COVERED |
| F5-4 | funding channel-bind (memo==stored AUTH_HASH / per-channel ptr); global once | `carriage::{funding_replay_is_refused,rail_funding_verified_and_credited,rail_funding_wrong_memo_or_unfinalized_rejected}` | COVERED |
| F5-5 | OUTPUTS zero omitted, ascending-merge, bound dest, asset==DENOM | `settle_msg::outputs_discipline_enforced`; `carriage::settlement_propose_rejections` | COVERED |
| F5-6 | CONVERSION iff DENOM≠BASELINE_ASSET; canonical rate | `settle_msg::{cross_currency_propose_both_signed_roundtrip,deterministic_propose_single_signed_roundtrip}` | COVERED |
| F5-7 | CLOSE chain-intent requires payer sig; merchant sets 0x00 | `establish::close_roundtrip_and_chain_intent_is_payer_only` | COVERED |
| F5-8 | role-fixed slot rejects; PROOF/CONFIRMED single-signer | `settle_msg::{instance_leg_rejects_zero_progress_and_bad_signers,proof_roundtrip_and_tx_ref_order,confirmed_roundtrip}` | COVERED |
| F5-9 | claim-record iff E≥1; P≥1/E=0 trap funds none | `settlement::sub_extinguishment_trap_funds_no_record`; `channel_settlement::sub_extinguishment_round_funds_no_claim_record` | COVERED |
| F5-10 | chaining whole-chain cumulatives; carve once; value-conservation | `channel_settlement::chained_channel_conserves_value_across_generations`; `channel::stillborn_passthrough_a_to_b_to_c_conserves_value` | COVERED |
| F5-11 | transcript `head_0` anchor `…01 → 2daf9c9a…` | `transcript::head_0_anchor`; `composition_independent::*` | COVERED (T5 independent confirm done) |

## F6 — Channel state machine

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F6-1 | no value before both signed; NEGOTIATING→OPEN | `state::accepts_and_accrues`; establish handshake | COVERED |
| F6-2 | five-step acceptance order, MAC-fail before state | `state::bad_mac_before_state` | COVERED |
| F6-3 | E boundary reach=accept+pause, exceed=reject | `state::window_and_evidence_bounds` | COVERED |
| F6-4 | initial-balance F6-g (prepay/postpay B=0) | `state::{prepay_deposit_before_consume_and_floors_at_minus_l,postpay_admits_before_funding}` | COVERED |
| F6-5 | difference-of-cumulative-floors; `metered−rail-paid` | `settlement::second_round_settles_only_the_new_outstanding`; `channel_settlement::two_rounds_never_re_charge_settled_numerators`; `f7::f6f_reconcile_vectors` | COVERED |
| F6-6 | checkpoint chain lex tiebreak; supersession; duplicate→existing | `state::supersession_tiebreaker`; `carriage::{checkpoint_countersign_and_close_anchors_to_it,checkpoint_mismatch_is_rejected}` | COVERED for the tiebreak / supersession / duplicate rules. The **checkpoint-exchange vector subset is an exclusion** (`CLASS:exclusion`), **not** coverage — the codecs exist but the full checkpoint round exchange is not driven in this baseline profile. |
| F6-7 | credit FUNDING_PROOF only after ordered procedure; no double | `carriage::{funding_credits_and_reopens,funding_replay_is_refused}` | COVERED |
| F6-8 | both triggers gate on settleability | `trigger::{settleable_rule,value_trigger_fires_on_reach_when_settleable,unsettleable_value_never_triggers}` | COVERED |
| F6-9 | unbound-dest proposal reject; deterministic vs countersigned | `carriage::{settlement_propose_rejections,settlement_propose_verifies_economics_against_checkpoint}` | COVERED |
| F6-10 | one-decision per (channel,ckpt); identical-terms retry | `carriage::{settlement_round_stale_after_ledger_moves_is_rejected,correct_round}` | COVERED |
| F6-11 | chaining validation a–d; imported-position fit or reject | `channel::chained_successor_establishes_f6_6` | COVERED (full live-import CLASS:deferred) |
| F6-12 | stillborn synthetic checkpoint exact bytes | `checkpoint::stillborn_*`; conformance `f6-stillborn-checkpoint-postpay-001` | COVERED |
| F6-13 | prepay meed halt: stop at overdue, resume on settle | `trigger::prepay_halt_over_the_residual_position`; `channel_settlement::interim_round_triggers_and_prepay_halt` | COVERED |

## F7 — Fee arithmetic

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F7-1 | exact to `2¹²⁸−1`; beyond → reject | `f7::{f7_domain_rejects,extinguish_rejects_out_of_domain}` | COVERED |
| F7-2 | `P<2¹²⁸`; wide product exact | `f7::{widest_intermediate_no_panic_and_conserves,claimable_wide_and_zero_total}`; `proptest_arithmetic::round_division_conserves_value` | COVERED |
| F7-3 | inconsistent proposal rejected never repaired; `R=N−E` stays | `f7::f6f_reconcile_vectors`; conformance `f7_arithmetic_corpus` (reject case) | COVERED |
| F7-4 | anchors A/B, instance rule, N=0, unity, 2¹²⁷-scale, dust | `f7::{f7_vector_a,f7_vector_b,f7_sub_extinguishment_trap_carries_no_leg,f7_zero_and_unity,f7_instance_claimable_rule}`; `props_10_2::*` | COVERED |

## F8 — Timeouts & clocks

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F8-1 | each adapter declares a total order over finality levels | `virtual_rail::finality_reached_after_delay`; redeem quoted-finality compare (`baseline_e2e` A2) | COVERED |
| F8-2 | honor boundary: finality inside `exp+grace` MUST be honored | `baseline_e2e::{expired_quote_rejected,baseline_happy_path_divides_and_receipts}` | COVERED |
| F8-3 | two-leg quote MUST leave both legs achievable in `exp+grace` | `build_two_leg_quote` intentionally emits **without** enforcing both-leg headroom — a stated **by-design** classification, not a silent gap. The payer is protected independently of the builder: the wallet pre-flight refuses an infeasible two-leg quote **before** funding the meed leg (`WalletError::QuoteInfeasible`) and the endpoint re-validates, so a self-invalid quote is an unredeemable **merchant** misconfiguration, never a payer risk. | `CLASS:by-design` |
| F8-4 | skew edges; T_exec strict (equal=reject); timeout constants start/expiry | `establish::artifact_validity_applies_skew`; `instance::reclaim_open_execute_windows` (T_exec); `adversary::zero_contest_window_still_requires_a_full_tick_before_reclaim`; CKPT/SETTLE_TIMEOUT expiry thin | PARTIAL (skew+T_exec COVERED; timeout-constant expiry thin — flag) |
| F8-5 | quote consistency: `reclaim ≥ 0`, `contest ≥ 0`; retention `max(exp+retry, T_lapse+contest)`; `TIMEOUT_close` | contracts `fund_rejects_open_after_lapse` (t_open>t_lapse reject); retention `max()` + `TIMEOUT_close` survivor remedies not driven | PARTIAL (window-order COVERED; retention/TIMEOUT_close `CLASS:gap` — flagged) |

## F9 — Registry & snapshot

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F9-1 | pointer grammar accept/reject; case-variant byte mismatch | `pointer::{accept_caip_and_adapter,reject_malformed,equality_is_byte_equality_no_casefold,caip2_chain_ids}` | COVERED |
| F9-2 | one canonical casing; pointer rail payable in context | `pointer::equality_is_byte_equality_no_casefold`; `registry::*` | COVERED |
| F9-3 | snapshot reject unordered/absent-REVOKED/missing-REQUIRED; retain WINDOW_FLOOR→newest | `registry::{snapshot_sign_parse_verify_roundtrip,version_window_and_revocation}` | COVERED |
| F9-4 | window edges; revoked known/unknown; historical resolves against own snapshot | `registry::version_window_and_revocation` | COVERED |
| F9-5 | fallback cases → pinned dests (OS→**independent OS fund**, payer-side→Dev Fund, F9.4); governed **destination correctness enforced ON THE VALUE PATH** (0x11 registry-listed-or-independent-fund set-membership + 0x13 pinned Dev-Fund) at every receive + fund/sign caller; misrouted governed dests rejected | `registry::{os_resolution_and_fallback,version_window_and_revocation}`; `quote::{governed_destination_correctness_is_enforced,governed_os_registry_listed_destination_is_accepted}`; `consistency_c1::misrouted_governed_meed_destinations_are_rejected` | COVERED |
| F9-6 | schema-0x01 encoding + vector→ADDRESS_INPUTS→address derivation | `consts::schema_01_totals_100_bp`; `derive::address_inputs_canonical_orders_vector`; `registry::identifier_grammar` | COVERED |

## F10 — Conformance corpus

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F10-1 | e2e spine: Tier0 baseline, two-leg reclaim-then-attest, channel lifecycle | `baseline_e2e::*`; `twoleg_e2e::reclaim_then_attest_on_the_entry`; `channel_settlement::*` | COVERED (single full-lifecycle golden vector: generation-required, see F10.2 note) |
| F10-2 | composition vectors confirmed by a byte-independent decoder | `composition_independent::composition_anchors_confirmed_by_an_independent_path` (re-derives from spec, no paytp-core code; pinned in `f1-crypto.json`) | COVERED (T5) |
| F10-3 | corpus is data; a vector failure reopens its section (never edit to pass) | `tests/conformance.rs` harness | COVERED |

### F10.6 — wallet conformance criteria (§7.2/§11.1 spending policy · §10.3 selection · §10.4 pluggability)

Machine-checkable obligations (`spec/formal/10-conformance-vectors.md` F10.6:48-51). Fixtures in
`paytp-wallet/tests/f10_6_conformance.rs`; selector + policy in `paytp-wallet` `policy.rs` / `execute.rs`.

| # | Requirement | Test(s) | Status |
|---|---|---|---|
| F10.6-1 | §7.2/§11.1 spending-policy — over-limit refuse / at-limit admit (slice · Tier-0 quote · channel-open), extended with the Part-A postpay `L_credit` flow bound | `f10_6_conformance::f10_6_spending_policy_{slice_at_limit_admitted_over_limit_refused,tier0_quote_at_budget_admitted_over_budget_refused,channel_open_at_budget_admitted_over_budget_refused,postpay_flow_bound_is_l_credit}`; `policy::tests::static_policy_*`; `channel::tests::postpay_slices_past_l_credit_are_refused` | COVERED |
| F10.6-2 | §10.3 total-cost comparison — cost-minimal path selected unless operator policy authorizes a costlier one; the costlier alternative discloses the payer delta | `f10_6_conformance::f10_6_total_cost_{selects_the_cost_minimal_path,operator_authorized_costlier_path_discloses_the_delta}`; `policy::tests::select_path_*` | COVERED |
| F10.6-3 | §10.3 honor user/operator policy over own meed — an operator-excluded/deprioritized path is not selected even where it earns the software more meed | `f10_6_conformance::f10_6_honor_operator_policy_excludes_the_meed_maximal_path` | COVERED |
| F10.6-4 | §10.3 selection trust boundary — cost inputs come from a TRUSTED rate source the wallet reads, never the untrusted IL; a spoofed-cheap path cannot steer selection | `f10_6_conformance::f10_6_spoofed_il_cost_cannot_steer_selection` (selector `Wallet::select_path` + `RateSource`) | COVERED |
| F10.6-5 | §10.3 disclosure (interface-presence) — the software exposes the meed share it earns for the selected path, derivable from the signed `MEED_VECTOR` | `f10_6_conformance::f10_6_meed_share_disclosure_is_present_on_the_selection` (`PathSelection.meed_share_bp`) | COVERED |
| F10.6-6 | §10.4 pluggability · §7.2/§11.1 substitutability (interface-presence) — the IL drives any wallet behind a trait and routes authorization to the configured one | `substitution::two_distinct_wallets_drive_the_same_flow_through_the_same_interface`; `substitution::policy_substitution_also_drives_the_same_flow` (`PayerWallet` / `WalletPolicy` seam) | COVERED |

**Attestation-only F10.6 obligations (documented, NOT machine-tested — no wire/API test decides them; `10-conformance-vectors.md` F10.6:49/:51/:52):**
1. **§10.3 neutral presentation** (F10.6:52) — that a presentation layer never suppresses a cheaper path is a UI/UX property; certification-time review only.
2. **Disclosure adequacy** (F10.6:51) — the RI *exposes* the earned meed share (F10.6-5) and the cost delta (F10.6-2); whether user-facing disclosure is *adequate* is attestation.
3. **Genuine substitutability** (F10.6:51) — the RI proves the *interface* seam (F10.6-6); whether the wallet market is *genuinely* contestable (not just interface-present) is attestation.
4. **"Serves the payer" beyond an explicit policy** (F10.6:49) — the general payer-first duty past a concrete operator policy fixture is attestation; the RI machine-tests the policy-scoped slice (F10.6-2/-3).

These are the **masterless** §10.5 obligations: no wire rule, settlement rule, or protocol gate enforces them (certification-level, riding the Foundation charter, not the wire protocol).

---

## Chapter MUSTs outside F1–F10 (plan §6 names these)

| # | Requirement | Test / artifact | Status |
|---|---|---|---|
| §10.4 | interaction layer MUST allow user/operator to select an external wallet | `flow::PayerWallet` trait (the IL↔wallet boundary); `substitution::two_distinct_wallets_drive_the_same_flow_through_the_same_interface` drives TWO distinct wallet *types* (`paytp_wallet::Wallet` + an independent `DirectWallet`); `client_refuses_a_valid_quote_for_a_different_resource` | COVERED (T2/T3) |
| §10.5-a | charter MUST restrict Dev-Fund payer-side shares to spec maint / audits / conformance / grants | certification checklist below | CLASS:non-code |
| §10.5-b | registry transparent, criteria-based, open, appealable; versioned; revocation handling | certification checklist below | CLASS:non-code |

---

## Adversary suite — pillar 2

Each attack must **FAIL** against PayTP; each doubles as executable proof the
profile closes what base x402 leaves to the implementation (ch 3 §3.6). New tests
in `crates/paytp-merchant/tests/adversary.rs` unless a prior test already carries it.

| Class | Attack | Test (must-FAIL proof) | Status |
|---|---|---|---|
| replay | proof/quote replay across channels & quotes | `carriage::funding_replay_is_refused`; `baseline_e2e::free_riding_*` | COVERED |
| nonce-desync | entry-machine nonce desync | `adversary::nonce_desync_funds_an_orphan_the_merchant_never_quoted` | COVERED (T4) |
| domain-sep | attest-vs-cancel label transplant | `attest::attest_and_cancel_do_not_cross_verify` | COVERED |
| chaining | stillborn double-import / re-chain | `channel::chaining_reference_consumed_once_keyed_by_channel_and_checkpoint` | COVERED |
| settle-interrupt | interruption at every two-leg step | `twoleg_e2e::{reclaim_then_attest_on_the_entry,delivered_two_leg_reclaim_fails_because_attested}` | COVERED |
| meed-strip | strip/understate the meed leg | `carriage::settlement_understated_round_rejected` | COVERED |
| reclaim-race / zero-contest | reclaim vs attestation race; zero contest window | `adversary::zero_contest_window_still_requires_a_full_tick_before_reclaim`; `twoleg_e2e::delivered_two_leg_reclaim_fails_because_attested` | COVERED (T4) |
| outage | outage-window behavior | `virtual_rail::outage_reverts_submit` | COVERED |
| registry | rogue OS assertion / invalid routing / stale snapshot | `adversary::{rogue_os_assertion_cannot_move_value_to_the_asserter,invalid_meed_vector_is_refused,stale_or_revoked_registry_version_is_refused}` | COVERED (T4) |
| x402 cross-resource substitution | transplant a proof to an equal-priced resource | `adversary::cross_resource_substitution_is_refused` (transplants the A quote+payment onto the B endpoint → F3.4 resource-binding `QuoteInvalid`, + nonce lock); `substitution::client_refuses_a_valid_quote_for_a_different_resource` (client-side) | COVERED (T4) |
| x402 duplicate-settlement race | one nonce → many deliveries under concurrency | `adversary::duplicate_settlement_race_consumes_the_nonce_exactly_once` (32-way store race, exactly-once) + `duplicate_settlement_race_through_full_redeem_yields_one_receipt` (32-way full `redeem_baseline` → one receipt) | COVERED (T4) |
| x402 allowance overdraft | concurrent "upto" over-read, deliver-before-settle | `adversary::underpayment_is_refused_no_upto_allowance` | COVERED (T4) |
| x402 denial-of-settlement | flood past settle rate-limit, deliver free | `adversary::delivery_requires_settlement_first` | COVERED (T4) |
| x402 leaked-token resubmission | replay a captured authorization | `adversary::leaked_token_resubmission_is_refused` | COVERED (T4) |

---

## Launch-gate items — classified, NOT dev-gates

- **Public-network deployment** — the operator's authorization (money/outward).
- Durable, bounded one-decision stores — in-memory spike → production DB.
- Constant-time control-object handling — pre-launch hardening.
- Full IDNA/UTS#46/PSL host normalization.
- `rail=None` interim — launch build MUST `with_rail`.
- Off-baseline CONFIRMED rate oracle — CLASS:deferred.
- Full F6.6 chained-open live-state import — CLASS:deferred.
- **Human pre-launch protocol/crypto security audit** — the standing launch gate.

### §A — the TLS-transport MUSTs the transport-independent RI cannot host

F1's "slices MUST NOT be sent in TLS 0-RTT early data" and F2's PSK-session /
artifact-header conditions are stated against a TLS carrier. Change A made
the RI's binding transport-independent and the merchant reads message **bodies**,
so there is no TLS-early-data or PSK surface in the host build to test — these ride
with the live HTTP/TLS stack. **Open question:** confirm this is the
right classification (vs. a spec-question on whether these MUSTs still bind a
transport-independent profile).

---

## §10.5 charter certification checklist (non-code MUSTs — not silently dropped)

1. Dev-Fund payer-side shares restricted to spec maintenance / audits / conformance / grants.
2. Role registry transparent, criteria-based, open to any conforming OS, appealable.
3. Registry updates versioned; acceptance window governance-defined; revocation leaves window on learn.
4. Dev-Fund address pinned per schema; changed only under full governance; custody a charter matter.
5. Schema changes (incl. base rebalancing) require broad ecosystem consensus; 150 bp cap binds all future schemas.
6. Role-separation certification (§10.4) enforced via certification/registry/trademark, not wire.

*Governance obligations the Foundation charter carries; recorded here so the
coverage set is complete. No code asserts them.*
