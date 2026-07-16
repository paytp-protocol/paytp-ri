//! LiteSVM proofs for the **Option W per-channel meed watermark**
//! (`advance_channel_meed`, F4.2/F6-o) — the per-channel replacement for the
//! per-round `fund_claim_record` on the channel path. Renders on the real SVM
//! runtime, offline. Proves: an advance records the cumulative aggregate `funded_p`
//! and per-destination cumulative `paid[d]` (roles sharing a destination floor once on
//! the combined `bp_d`, F7-d/F7.3) with the §10.2 sub-unit `residue`; it is
//! idempotent by absolute position (a re-advance / drop-then-redraw distributes
//! nothing — the F6-o cross-checkpoint double-draw closes by construction); the
//! watermark is monotone and per-channel-keyed (the accepted ≤1 µ-unit
//! chain-boundary dust, F6.6, conserves — distributed + residue == funded_p); it is
//! prefund-tolerant and binds `(seed_instance, CHANNEL_ID)`.
//!
//! Run: `cargo build-sbf` (produces paytp_kit.so) then `cargo test`.

use anchor_lang::{AccountDeserialize, AccountSerialize, InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use paytp_kit::{derive_seed_instance, ChannelMeed};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: Pubkey = solana_pubkey::pubkey!("2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau");
const SYS: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");
const TEST_MINT: Pubkey = Pubkey::new_from_array([0x4d; 32]);
// Schema 0x01 role weights (interaction/OS/wallet/dev-fund), Σ = 100.
const BP: [u128; 4] = [50, 10, 30, 10];

mod common;

fn load() -> LiteSVM {
    common::assert_so_fresh();
    let so = std::fs::read(format!(
        "{}{}",
        env!("CARGO_MANIFEST_DIR"),
        common::SO_REL_PATH
    ))
    .expect("run `cargo build-sbf` first to produce paytp_kit.so");
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &so).unwrap();
    svm
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair) -> bool {
    let msg = Message::new(ixs, Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    let ok = svm.send_transaction(tx).is_ok();
    svm.expire_blockhash();
    ok
}

fn instance_pda(seed_instance: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"instance", seed_instance], &PROGRAM_ID).0
}
fn chanmeed_pda(seed_instance: &[u8; 32], channel_id: &[u8; 8]) -> Pubkey {
    Pubkey::find_program_address(&[b"chanmeed", seed_instance, channel_id], &PROGRAM_ID).0
}

/// Instance `ADDRESS_INPUTS` preimage: `[0x00,0x20,MK] ‖ 4 dests ‖ mint`.
fn canonical_for(merchant: &Pubkey) -> Vec<u8> {
    let dummy = [
        Pubkey::new_from_array([0xd0; 32]),
        Pubkey::new_from_array([0xd1; 32]),
        Pubkey::new_from_array([0xd2; 32]),
        Pubkey::new_from_array([0xd3; 32]),
    ];
    let mut v = vec![0x00u8, 0x20u8];
    v.extend_from_slice(&merchant.to_bytes());
    for d in &dummy {
        v.extend_from_slice(&d.to_bytes());
    }
    v.extend_from_slice(&TEST_MINT.to_bytes());
    v
}

/// Instance `ADDRESS_INPUTS` preimage with a **shared** destination: roles
/// 0x10/0x12/0x13 (bp 50/30/10) all name the Development Fund, role 0x11 (bp 10)
/// its own dest — the "chronically-shared fallback" shape (03-tier0-objects:40).
fn canonical_shared(merchant: &Pubkey, dev_fund: &Pubkey, other: &Pubkey) -> Vec<u8> {
    // dests order = ascending role id 0x10..0x13 → [dev_fund, other, dev_fund, dev_fund].
    let dests = [*dev_fund, *other, *dev_fund, *dev_fund];
    let mut v = vec![0x00u8, 0x20u8];
    v.extend_from_slice(&merchant.to_bytes());
    for d in &dests {
        v.extend_from_slice(&d.to_bytes());
    }
    v.extend_from_slice(&TEST_MINT.to_bytes());
    v
}

/// Deploy one instance; returns (svm, funder, seed_instance).
fn setup() -> (LiteSVM, Keypair, [u8; 32]) {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let canonical = canonical_for(&Keypair::new().pubkey());
    let seed = derive_seed_instance(&canonical);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: instance_pda(&seed),
            payer: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::DeployInstance {
            _seed_instance: seed,
            canonical_bytes: canonical,
        }
        .data(),
    };
    assert!(send(&mut svm, &[ix], &payer), "deploy_instance");
    (svm, payer, seed)
}

/// Deploy an instance whose meed vector SHARES a destination across three roles
/// (0x10/0x12/0x13 → Dev Fund). Returns (svm, funder, seed_instance).
fn setup_shared() -> (LiteSVM, Keypair, [u8; 32]) {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let dev_fund = Pubkey::new_from_array([0xf0; 32]);
    let other = Pubkey::new_from_array([0xf1; 32]);
    let canonical = canonical_shared(&Keypair::new().pubkey(), &dev_fund, &other);
    let seed = derive_seed_instance(&canonical);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: instance_pda(&seed),
            payer: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::DeployInstance {
            _seed_instance: seed,
            canonical_bytes: canonical,
        }
        .data(),
    };
    assert!(
        send(&mut svm, &[ix], &payer),
        "deploy_instance (shared dests)"
    );
    (svm, payer, seed)
}

fn advance_ix(
    seed_instance: &[u8; 32],
    channel_id: [u8; 8],
    target_p: u128,
    funder: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::AdvanceChannelMeed {
            instance: instance_pda(seed_instance),
            channel_meed: chanmeed_pda(seed_instance, &channel_id),
            funder: *funder,
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::AdvanceChannelMeed {
            channel_id,
            target_p,
        }
        .data(),
    }
}

fn read_chanmeed(
    svm: &LiteSVM,
    seed_instance: &[u8; 32],
    channel_id: &[u8; 8],
) -> Option<ChannelMeed> {
    let acct = svm.get_account(&chanmeed_pda(seed_instance, channel_id))?;
    if acct.data.is_empty() {
        return None;
    }
    ChannelMeed::try_deserialize(&mut acct.data.as_slice()).ok()
}

/// Per-role cumulative floor over `target_p` (F7.3), and the carried §10.2 residue.
fn expect_division(target_p: u128) -> ([u128; 4], u128) {
    let mut paid = [0u128; 4];
    let mut dist = 0u128;
    for (i, &bp) in BP.iter().enumerate() {
        paid[i] = target_p * bp / 100;
        dist += paid[i];
    }
    (paid, target_p - dist)
}

const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[test]
fn advance_records_cumulative_division() {
    let (mut svm, funder, seed) = setup();
    let target = 1_000_000u128;
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, target, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).expect("watermark created");
    assert_eq!(cr.funded_p, target);
    assert_eq!(cr.channel_id, CID);
    assert_eq!(cr.seed_instance, seed);
    assert_eq!(cr.version, 1);
    let (paid, residue) = expect_division(target);
    assert_eq!(cr.paid, paid, "per-role cumulative division");
    assert_eq!(cr.residue, residue);
    // Conservation: distributed + residue == funded_p.
    assert_eq!(cr.paid.iter().sum::<u128>() + cr.residue, cr.funded_p);
}

#[test]
fn advance_carries_sub_unit_residue() {
    // target = 199: per-role floors [99,19,59,19] = 196; residue 3 stays in the record
    // (the v1-death "all per-role floors are 0-or-low" dust, now carried per channel).
    let (mut svm, funder, seed) = setup();
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 199, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(cr.paid, [99, 19, 59, 19]);
    assert_eq!(cr.residue, 3);
    assert_eq!(cr.paid.iter().sum::<u128>() + cr.residue, 199);
}

#[test]
fn advance_idempotent_by_absolute_position() {
    // The F6-o fix, on-chain: a re-advance to the SAME (or a LOWER) target
    // distributes nothing — a drop-then-redraw or crash retry never double-pays.
    let (mut svm, funder, seed) = setup();
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 1000, &funder.pubkey())],
        &funder
    ));
    let after_first = read_chanmeed(&svm, &seed, &CID).unwrap();
    // Re-advance to the same target — idempotent no-op.
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 1000, &funder.pubkey())],
        &funder
    ));
    let after_same = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(after_same.funded_p, after_first.funded_p);
    assert_eq!(after_same.paid, after_first.paid);
    // Advance to a LOWER target (a stale/duplicate draw) — also a no-op; the monotone
    // watermark never moves backward.
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 500, &funder.pubkey())],
        &funder
    ));
    let after_lower = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(after_lower.funded_p, 1000);
    assert_eq!(after_lower.paid, after_first.paid);
}

#[test]
fn advance_monotonically_accumulates() {
    // Interim draw "to W1" then close draw "to W_final ≥ W1" move the SAME record;
    // the close distributes only the residual W1→W_final.
    let (mut svm, funder, seed) = setup();
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 1000, &funder.pubkey())],
        &funder
    ));
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 3000, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(cr.funded_p, 3000);
    let (paid, residue) = expect_division(3000); // cumulative at 3000, NOT 1000+3000
    assert_eq!(cr.paid, paid);
    assert_eq!(cr.residue, residue);
}

#[test]
fn advance_per_channel_keying_and_binding() {
    // Two channels on the SAME instance are DISTINCT records — no lineage, no
    // cross-channel interference (the v2 escrow-strand / forgeable-root closure).
    let (mut svm, funder, seed) = setup();
    let cid_a = [0xAA; 8];
    let cid_b = [0xBB; 8];
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, cid_a, 5000, &funder.pubkey())],
        &funder
    ));
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, cid_b, 7000, &funder.pubkey())],
        &funder
    ));
    let a = read_chanmeed(&svm, &seed, &cid_a).unwrap();
    let b = read_chanmeed(&svm, &seed, &cid_b).unwrap();
    assert_eq!(a.funded_p, 5000);
    assert_eq!(a.channel_id, cid_a);
    assert_eq!(b.funded_p, 7000);
    assert_eq!(b.channel_id, cid_b);
}

#[test]
fn advance_chain_boundary_dust_conserves() {
    // Two per-channel records each floor their own carve (F6.6): the combined
    // distributed can be ≤1 µ-unit/role below a single record at the sum — the
    // accepted chain-boundary dust. It CONSERVES: per channel, Σpaid + residue ==
    // funded_p, and the "lost" per-role unit is held as residue (reverts to
    // merchant/payer at close, §10.2 — never minted, never double-paid).
    let (mut svm, funder, seed) = setup();
    let cid_a = [0x0A; 8];
    let cid_b = [0x0B; 8];
    // 55 + 55 = 110. Single(110) role0 = 55; split gives 27 + 27 = 54 (1 µ-unit dust).
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, cid_a, 55, &funder.pubkey())],
        &funder
    ));
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, cid_b, 55, &funder.pubkey())],
        &funder
    ));
    let a = read_chanmeed(&svm, &seed, &cid_a).unwrap();
    let b = read_chanmeed(&svm, &seed, &cid_b).unwrap();
    // Per-channel conservation (the invariant the property test also asserts).
    assert_eq!(a.paid.iter().sum::<u128>() + a.residue, a.funded_p);
    assert_eq!(b.paid.iter().sum::<u128>() + b.residue, b.funded_p);
    let (single_paid, _) = expect_division(110);
    for (r, &a_paid) in a.paid.iter().enumerate() {
        let combined = a_paid + b.paid[r];
        let drop = single_paid[r] - combined;
        assert!(drop <= 1, "role {r} hop dust must be ≤1 µ-unit, got {drop}");
    }
    // Total value conserves across both channels: Σ(paid+residue) == 110.
    let total = a.funded_p + b.funded_p;
    assert_eq!(total, 110);
}

#[test]
fn advance_is_prefund_tolerant() {
    // The watermark PDA is public-derivable; a dust of it MUST NOT brick the first
    // advance (the deploy_split lesson, applied to the channel path).
    let (mut svm, funder, seed) = setup();
    let pda = chanmeed_pda(&seed, &CID);
    // Griefer dusts the not-yet-created PDA with 1 lamport (Anchor `init` would revert
    // on this; the manual top-up→allocate→assign path tolerates it).
    svm.airdrop(&pda, 1).unwrap();
    // First advance still succeeds and records correctly.
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 1000, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(cr.funded_p, 1000);
}

#[test]
fn advance_zero_target_creates_no_account() {
    let (mut svm, funder, seed) = setup();
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 0, &funder.pubkey())],
        &funder
    ));
    assert!(
        read_chanmeed(&svm, &seed, &CID).is_none(),
        "no rent account for a 0 no-op"
    );
}

#[test]
fn advance_wide_arithmetic_no_panic() {
    // A large aggregate P (well above u64) must not panic/overflow — target_p·bp is
    // done in the U256 domain (the wide-arithmetic discipline).
    let (mut svm, funder, seed) = setup();
    let big = (u64::MAX as u128) * 3; // ~5.5e19, > u64::MAX
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, big, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(cr.funded_p, big);
    let (paid, residue) = expect_division(big);
    assert_eq!(cr.paid, paid);
    assert_eq!(cr.residue, residue);
    assert_eq!(cr.paid.iter().sum::<u128>() + cr.residue, big);
}

#[test]
fn advance_aggregates_shared_destination_before_flooring() {
    // The F6-o↔F7-d fix (per-destination): when several roles name ONE destination,
    // the watermark floors ONCE on the combined `bp_d = Σ bp_r` (F7-d/F7.3), NOT
    // per role. Roles 0x10/0x12/0x13 (bp 50/30/10) all → the Dev Fund; role 0x11
    // (bp 10) → its own dest. `bp_dev = 90`, `bp_other = 10`.
    //
    // target = 13:
    //   per-DESTINATION (correct): dev ⌊13·90/100⌋ = ⌊11.7⌋ = 11, other ⌊13·10/100⌋ = 1
    //     → distributed 12, residue 1.
    //   per-ROLE (the stranding bug): ⌊6.5⌋+⌊3.9⌋+⌊1.3⌋ = 6+3+1 = 10 to the Dev Fund
    //     (one sub-unit stranded), role 0x11 = 1 → distributed 11, residue 2.
    //
    // The `paid[4]` slots stay role-indexed; a destination's aggregated cumulative is
    // recorded at its CANONICAL (first-naming) role index, the shared later slots hold
    // 0. So the fix records `[11, 1, 0, 0]` (dev at slot 0), NOT the per-role `[6,1,3,1]`.
    let (mut svm, funder, seed) = setup_shared();
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 13, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    // The Dev Fund's cumulative = the roles naming it (slots 0,2,3) summed — the
    // per-DESTINATION floor ⌊13·90/100⌋ = 11, never the per-role sum 10.
    let dev_paid = cr.paid[0] + cr.paid[2] + cr.paid[3];
    assert_eq!(
        dev_paid, 11,
        "shared Dev Fund floored once on bp_d=90 (⌊13·90/100⌋=11), not per-role (10)"
    );
    assert_eq!(cr.paid[1], 1, "role 0x11's own dest floored on bp=10");
    assert_eq!(
        cr.paid,
        [11, 1, 0, 0],
        "per-destination, canonical-index attribution"
    );
    assert_eq!(
        cr.residue, 1,
        "per-destination residue (per-role would strand 2)"
    );
    // Conservation holds either way: Σpaid + residue == funded_p.
    assert_eq!(cr.paid.iter().sum::<u128>() + cr.residue, 13);
    assert_eq!(cr.funded_p, 13);
}

#[test]
fn advance_transitions_a_legacy_per_role_record_without_bricking() {
    // Defense-in-depth: a `ChannelMeed` written by an earlier PER-ROLE
    // build — a shared dest's share SPREAD across its slots — must ADVANCE (not brick)
    // under the per-destination build. The spec isolates a model change behind a fresh
    // CONTRACT/`seed_instance` (fresh PDA, F6-o), so this is the backstop for an in-place
    // program upgrade: the by-destination-REGROUPED monotone check lets the legacy record
    // recompute to the per-destination layout instead of a naive per-slot `0 >= 3` reject.
    //
    // Dests [dev, other, dev, dev] (bp 50/10/30/10). Legacy record at target 13:
    // paid=[6,1,3,1] (per-role), funded 13, residue 2 (dev underpaid: 6+3+1=10 < ⌊13·90/100⌋=11).
    // Forward advance to 14 → per-destination paid=[12,1,0,0] (dev ⌊14·90/100⌋=12), residue 1.
    let (mut svm, funder, seed) = setup_shared();
    let legacy = ChannelMeed {
        seed_instance: seed,
        channel_id: CID,
        version: 1,
        funded_p: 13,
        paid: [6, 1, 3, 1],
        residue: 2,
    };
    let mut data = Vec::new();
    legacy.try_serialize(&mut data).unwrap();
    let pda = chanmeed_pda(&seed, &CID);
    let lamports = svm.minimum_balance_for_rent_exemption(data.len());
    svm.set_account(
        pda,
        solana_account::Account {
            lamports,
            data,
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    // Forward advance to 14 — must SUCCEED (a naive per-slot guard would brick it: slot 2
    // checks new 0 >= old 3).
    assert!(send(
        &mut svm,
        &[advance_ix(&seed, CID, 14, &funder.pubkey())],
        &funder
    ));
    let cr = read_chanmeed(&svm, &seed, &CID).unwrap();
    assert_eq!(cr.funded_p, 14);
    assert_eq!(
        cr.paid,
        [12, 1, 0, 0],
        "recomputed to the per-destination layout"
    );
    assert_eq!(cr.residue, 1);
    assert_eq!(cr.paid.iter().sum::<u128>() + cr.residue, 14, "conserves");
    // The transition tops the chronically-shared dev fund UP toward its correct per-dest
    // cumulative (10 legacy → 12), never a clawback.
    assert_eq!(cr.paid[0] + cr.paid[2] + cr.paid[3], 12);
}
