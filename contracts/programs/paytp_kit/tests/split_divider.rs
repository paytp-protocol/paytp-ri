//! M6.1a LiteSVM proofs — the **baseline split-divider** (F4-d) renders on the
//! real SVM runtime, offline. Proves: `deploy_split` recomputes+binds the
//! merchant-net and meed destinations from `ADDRESS_INPUTS`; a plain
//! exact-svm payment into `ATA(split_PDA, mint)` is divided 99/1 by a
//! **permissionless** `split_distribute` (merchant seat + the four meed roles,
//! shared `paytp_f7` floor division); the vault↔ATA and destination bindings are
//! the theft closure; the sub-unit residue carries.
//!
//! Run: `cargo build-sbf` (produces paytp_kit.so) then `cargo test`.

use anchor_lang::{InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use paytp_kit::derive_seed_split;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: Pubkey = solana_pubkey::pubkey!("2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau");
const SPL_TOKEN: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = solana_pubkey::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const TEST_MINT: Pubkey = Pubkey::new_from_array([0x4d; 32]);

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

fn write_mint(svm: &mut LiteSVM, mint: Pubkey) {
    let mut data = vec![0u8; 82];
    data[45] = 1;
    svm.set_account(
        mint,
        solana_account::Account {
            lamports: 5_000_000,
            data,
            owner: SPL_TOKEN,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn write_token_account(svm: &mut LiteSVM, addr: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(&mint.to_bytes());
    data[32..64].copy_from_slice(&owner.to_bytes());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1;
    svm.set_account(
        addr,
        solana_account::Account {
            lamports: 5_000_000,
            data,
            owner: SPL_TOKEN,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_balance(svm: &LiteSVM, addr: Pubkey) -> u64 {
    let d = svm.get_account(&addr).unwrap().data;
    u64::from_le_bytes(d[64..72].try_into().unwrap())
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair) -> bool {
    let msg = Message::new(ixs, Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer], msg, svm.latest_blockhash());
    let ok = svm.send_transaction(tx).is_ok();
    svm.expire_blockhash();
    ok
}

fn split_pda(seed_split: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"split", seed_split], &PROGRAM_ID).0
}
fn split_ata(split: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[split.as_ref(), SPL_TOKEN.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    )
    .0
}

/// The split preimage (F4-d spike convention): `[0x00,0x20,MK] ‖ merchant_net ‖
/// 4 meed dests ‖ mint`.
fn canonical_for_split(mk: &Pubkey, merchant_net: &Pubkey, dests: &[Pubkey; 4]) -> Vec<u8> {
    let mut v = vec![0x00u8, 0x20u8];
    v.extend_from_slice(&mk.to_bytes());
    v.extend_from_slice(&merchant_net.to_bytes());
    for d in dests {
        v.extend_from_slice(&d.to_bytes());
    }
    v.extend_from_slice(&TEST_MINT.to_bytes());
    v
}

fn deploy_split_ix(payer: &Pubkey, seed: [u8; 32], canonical: Vec<u8>) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeploySplit {
            split: split_pda(&seed),
            payer: *payer,
            system_program: solana_pubkey::pubkey!("11111111111111111111111111111111"),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::DeploySplit {
            _seed_split: seed,
            canonical_bytes: canonical,
        }
        .data(),
    }
}

fn split_claim_ix(seed: &[u8; 32], seat: u8, vault: Pubkey, dest: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::SplitClaim {
            split: split_pda(seed),
            vault,
            dest,
            token_program: SPL_TOKEN,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::SplitClaim { seat }.data(),
    }
}

/// Claim all 5 seats (merchant = seat 0, meed roles = seats 1..4) — each an
/// independent permissionless withdraw.
fn claim_all(
    svm: &mut LiteSVM,
    seed: &[u8; 32],
    vault: Pubkey,
    merchant_net: Pubkey,
    dests: &[Pubkey; 4],
    payer: &Keypair,
) {
    assert!(
        send(svm, &[split_claim_ix(seed, 0, vault, merchant_net)], payer),
        "claim merchant"
    );
    for (i, d) in dests.iter().enumerate() {
        assert!(
            send(
                svm,
                &[split_claim_ix(seed, (i + 1) as u8, vault, *d)],
                payer
            ),
            "claim meed {i}"
        );
    }
}

/// Deploy a split + write its funded vault ATA. Returns (seed, split, vault,
/// merchant_net, dests).
fn setup_split(
    svm: &mut LiteSVM,
    payer: &Keypair,
    balance: u64,
) -> ([u8; 32], Pubkey, Pubkey, Pubkey, [Pubkey; 4]) {
    write_mint(svm, TEST_MINT);
    let mk = Pubkey::new_from_array([0xab; 32]);
    let merchant_net = Pubkey::new_from_array([0x99; 32]);
    let dests = [
        Pubkey::new_from_array([0xd0; 32]),
        Pubkey::new_from_array([0xd1; 32]),
        Pubkey::new_from_array([0xd2; 32]),
        Pubkey::new_from_array([0xd3; 32]),
    ];
    let canonical = canonical_for_split(&mk, &merchant_net, &dests);
    let seed = derive_seed_split(&canonical);
    let split = split_pda(&seed);
    assert!(
        send(
            svm,
            &[deploy_split_ix(&payer.pubkey(), seed, canonical)],
            payer
        ),
        "deploy_split"
    );
    // The receiving vault = ATA(split, mint); the merchant-net + meed dests are
    // token accounts on the mint (owners arbitrary — they only receive).
    let vault = split_ata(&split, &TEST_MINT);
    write_token_account(svm, vault, TEST_MINT, split, balance);
    write_token_account(
        svm,
        merchant_net,
        TEST_MINT,
        Pubkey::new_from_array([1; 32]),
        0,
    );
    for d in &dests {
        write_token_account(svm, *d, TEST_MINT, Pubkey::new_from_array([2; 32]), 0);
    }
    (seed, split, vault, merchant_net, dests)
}

const SPLIT_ROLES: u64 = 5;

#[test]
fn split_divides_99_1_permissionlessly() {
    let mut svm = load();
    let merchant = Keypair::new();
    svm.airdrop(&merchant.pubkey(), 10_000_000_000).unwrap();
    let (seed, _split, vault, merchant_net, dests) = setup_split(&mut svm, &merchant, 1_000_000);

    // A DIFFERENT party (not the merchant) cranks each seat — permissionless.
    let cranker = Keypair::new();
    svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    claim_all(&mut svm, &seed, vault, merchant_net, &dests, &cranker);

    // 99% merchant, 1% split among 50/10/30/10 bp of the whole.
    assert_eq!(token_balance(&svm, merchant_net), 990_000);
    assert_eq!(token_balance(&svm, dests[0]), 5_000);
    assert_eq!(token_balance(&svm, dests[1]), 1_000);
    assert_eq!(token_balance(&svm, dests[2]), 3_000);
    assert_eq!(token_balance(&svm, dests[3]), 1_000);
    assert_eq!(token_balance(&svm, vault), 0); // fully divided, no dust here
}

#[test]
fn residue_carries_and_conserves_value() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let balance = 1_000_003; // not a clean multiple → sub-unit dust
    let (seed, _split, vault, merchant_net, dests) = setup_split(&mut svm, &payer, balance);
    claim_all(&mut svm, &seed, vault, merchant_net, &dests, &payer);

    let paid = token_balance(&svm, merchant_net)
        + dests.iter().map(|d| token_balance(&svm, *d)).sum::<u64>();
    let residue = token_balance(&svm, vault);
    assert_eq!(paid + residue, balance); // value conserved to the µ-unit
    assert!(residue < SPLIT_ROLES); // dust is bounded by the number of seats
}

/// The cumulative model: many sub-threshold payments must NOT
/// strand the meed. Each 101-unit payment floors the 50-bp meed to 0 on its
/// own, but the carry accrues over the cumulative total.
#[test]
fn many_small_payments_do_not_strand_meed() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    // First payment 101, claim all: merchant floor(101*0.99)=99, meeds 0.
    let (seed, _split, vault, merchant_net, dests) = setup_split(&mut svm, &payer, 101);
    claim_all(&mut svm, &seed, vault, merchant_net, &dests, &payer);
    assert_eq!(token_balance(&svm, merchant_net), 99);
    assert_eq!(token_balance(&svm, dests[0]), 0);

    // Top up the vault by another 101 (total received 202) and re-claim all.
    let topped = token_balance(&svm, vault) + 101;
    write_token_account(&mut svm, vault, TEST_MINT, split_pda(&seed), topped);
    claim_all(&mut svm, &seed, vault, merchant_net, &dests, &payer);
    // Cumulative-correct: merchant floor(202*0.99)=199, role0 floor(202*50/10000)=1.
    assert_eq!(token_balance(&svm, merchant_net), 199);
    assert_eq!(token_balance(&svm, dests[0]), 1);
    // Value conserved: paid + residue == 202.
    let paid = token_balance(&svm, merchant_net)
        + dests.iter().map(|d| token_balance(&svm, *d)).sum::<u64>();
    assert_eq!(paid + token_balance(&svm, vault), 202);
}

/// Re-claiming a seat with no new receipts owes nothing (no double-pay).
#[test]
fn reclaim_without_new_receipts_is_a_noop() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (seed, _split, vault, merchant_net, _dests) = setup_split(&mut svm, &payer, 1_000_000);
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 0, vault, merchant_net)],
        &payer
    ));
    assert_eq!(token_balance(&svm, merchant_net), 990_000);
    // Second claim, no new payment → owed 0, balance unchanged.
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 0, vault, merchant_net)],
        &payer
    ));
    assert_eq!(token_balance(&svm, merchant_net), 990_000);
}

/// Per-seat independence: a meed seat can be claimed without
/// the merchant seat and vice-versa — no single account can hold the vault hostage.
#[test]
fn seats_are_independent() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (seed, _split, vault, merchant_net, dests) = setup_split(&mut svm, &payer, 1_000_000);
    // Claim only meed seat 1 (role 0x10) — merchant not involved.
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 1, vault, dests[0])],
        &payer
    ));
    assert_eq!(token_balance(&svm, dests[0]), 5_000);
    assert_eq!(token_balance(&svm, merchant_net), 0);
    // Later the merchant claims its own seat independently.
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 0, vault, merchant_net)],
        &payer
    ));
    assert_eq!(token_balance(&svm, merchant_net), 990_000);
}

#[test]
fn wrong_vault_rejected() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (seed, split, _vault, merchant_net, _dests) = setup_split(&mut svm, &payer, 1_000_000);
    // A token account owned by the split but NOT its ATA — must be refused.
    let fake_vault = Pubkey::new_from_array([0xfe; 32]);
    write_token_account(&mut svm, fake_vault, TEST_MINT, split, 1_000_000);
    assert!(!send(
        &mut svm,
        &[split_claim_ix(&seed, 0, fake_vault, merchant_net)],
        &payer
    ));
    assert_eq!(token_balance(&svm, merchant_net), 0); // nothing moved
}

#[test]
fn wrong_destination_rejected() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (seed, _split, vault, _mn, dests) = setup_split(&mut svm, &payer, 1_000_000);
    let attacker = Pubkey::new_from_array([0xee; 32]);
    write_token_account(
        &mut svm,
        attacker,
        TEST_MINT,
        Pubkey::new_from_array([3; 32]),
        0,
    );
    // Claim the merchant seat (0) but pass an attacker destination → rejected.
    assert!(!send(
        &mut svm,
        &[split_claim_ix(&seed, 0, vault, attacker)],
        &payer
    ));
    // Claim a meed seat (2) but pass seat-1's destination → rejected (seat/dest bind).
    assert!(!send(
        &mut svm,
        &[split_claim_ix(&seed, 2, vault, dests[0])],
        &payer
    ));
    assert_eq!(token_balance(&svm, vault), 1_000_000); // vault untouched
}

#[test]
fn bad_seat_index_rejected() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let (seed, _split, vault, merchant_net, _dests) = setup_split(&mut svm, &payer, 1_000_000);
    assert!(!send(
        &mut svm,
        &[split_claim_ix(&seed, 5, vault, merchant_net)],
        &payer
    ));
}

/// A public-quote dust of the split PDA must NOT brick
/// deploy (the split address is derivable before the merchant deploys).
#[test]
fn deploy_tolerates_prefund_dust() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    write_mint(&mut svm, TEST_MINT);
    let mk = Pubkey::new_from_array([0xab; 32]);
    let merchant_net = Pubkey::new_from_array([0x99; 32]);
    let dests = [
        Pubkey::new_from_array([0xd0; 32]),
        Pubkey::new_from_array([0xd1; 32]),
        Pubkey::new_from_array([0xd2; 32]),
        Pubkey::new_from_array([0xd3; 32]),
    ];
    let canonical = canonical_for_split(&mk, &merchant_net, &dests);
    let seed = derive_seed_split(&canonical);
    let split = split_pda(&seed);
    // An attacker dusts the counterfactual split PDA (1 lamport, system-owned).
    svm.set_account(
        split,
        solana_account::Account {
            lamports: 1,
            data: vec![],
            owner: solana_pubkey::pubkey!("11111111111111111111111111111111"),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    // Deploy still succeeds (prefund-tolerant), and the split then functions.
    assert!(send(
        &mut svm,
        &[deploy_split_ix(&payer.pubkey(), seed, canonical)],
        &payer
    ));
    let vault = split_ata(&split, &TEST_MINT);
    write_token_account(&mut svm, vault, TEST_MINT, split, 1_000_000);
    write_token_account(
        &mut svm,
        merchant_net,
        TEST_MINT,
        Pubkey::new_from_array([1; 32]),
        0,
    );
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 0, vault, merchant_net)],
        &payer
    ));
    assert_eq!(token_balance(&svm, merchant_net), 990_000);
}

/// Deploy a split whose meed vector SHARES a destination across three roles
/// (`[dev, other, dev, dev]` — roles 0x10/0x12/0x13 → one Development-Fund token
/// account, role 0x11 → its own): the "chronically-shared fallback" shape
/// (`03-tier0-objects:40`). Returns (seed, split, vault, merchant_net, dests, dev, other).
#[allow(clippy::type_complexity)]
fn setup_split_shared(
    svm: &mut LiteSVM,
    payer: &Keypair,
    balance: u64,
) -> (
    [u8; 32],
    Pubkey,
    Pubkey,
    Pubkey,
    [Pubkey; 4],
    Pubkey,
    Pubkey,
) {
    write_mint(svm, TEST_MINT);
    let mk = Pubkey::new_from_array([0xab; 32]);
    let merchant_net = Pubkey::new_from_array([0x99; 32]);
    let dev = Pubkey::new_from_array([0xda; 32]);
    let other = Pubkey::new_from_array([0xd1; 32]);
    // dests order = ascending role id 0x10..0x13 → [dev, other, dev, dev].
    let dests = [dev, other, dev, dev];
    let canonical = canonical_for_split(&mk, &merchant_net, &dests);
    let seed = derive_seed_split(&canonical);
    let split = split_pda(&seed);
    assert!(
        send(
            svm,
            &[deploy_split_ix(&payer.pubkey(), seed, canonical)],
            payer
        ),
        "deploy_split (shared dests)"
    );
    let vault = split_ata(&split, &TEST_MINT);
    write_token_account(svm, vault, TEST_MINT, split, balance);
    write_token_account(
        svm,
        merchant_net,
        TEST_MINT,
        Pubkey::new_from_array([1; 32]),
        0,
    );
    write_token_account(svm, dev, TEST_MINT, Pubkey::new_from_array([2; 32]), 0);
    write_token_account(svm, other, TEST_MINT, Pubkey::new_from_array([3; 32]), 0);
    (seed, split, vault, merchant_net, dests, dev, other)
}

/// The F7-d↔F7.3 per-destination fix for the baseline split (03-tier0-objects:40):
/// when several MEED roles name ONE destination, the recipient floors ONCE on
/// the combined weight (`bp_dev = 50+30+10 = 90`), NOT per-seat. The merchant seat
/// stays a separate recipient (never merged with a meed dest — mirrors the RI
/// `VirtualRail::split_recipients`, which appends the merchant AFTER the meed-by-dest
/// fold). Per-seat flooring would strand up to `(shared_roles − 1)` sub-units on the
/// shared fund; per-destination pays it its correct floor.
#[test]
fn split_aggregates_shared_destination_before_flooring() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    // 1_234_567 chosen so the three shared-role floors (6172/3703/1234 = 11_109) fall
    // 2 short of the per-destination floor ⌊1_234_567·90/10_000⌋ = 11_111.
    let balance = 1_234_567u64;
    let (seed, _split, vault, merchant_net, dests, dev, other) =
        setup_split_shared(&mut svm, &payer, balance);
    claim_all(&mut svm, &seed, vault, merchant_net, &dests, &payer);

    // The Development Fund receives its per-DESTINATION floor (⌊B·90/10000⌋), not the
    // sum of three per-role floors (11_109). This is the RED→GREEN assertion.
    assert_eq!(
        token_balance(&svm, dev),
        11_111,
        "shared dev fund floored once on bp_d=90, not per-role (11_109)"
    );
    // role 0x11's own dest floors on bp=10.
    assert_eq!(
        token_balance(&svm, other),
        1_234,
        "unshared dest floors on bp=10"
    );
    // The merchant seat is unchanged (99% = 9900 bp).
    assert_eq!(
        token_balance(&svm, merchant_net),
        1_222_221,
        "merchant net 99%"
    );
    // Value conserved to the µ-unit; per-destination residue is 1 (per-role would be 3).
    let paid =
        token_balance(&svm, dev) + token_balance(&svm, other) + token_balance(&svm, merchant_net);
    let residue = token_balance(&svm, vault);
    assert_eq!(paid + residue, balance, "conservation");
    assert_eq!(
        residue, 1,
        "per-destination residue (per-role would strand 3)"
    );
}

/// Per-destination claim attribution: the shared destination's aggregate is drawn by
/// its CANONICAL (first-naming) seat (seat 1); the shared later seats (3, 4) owe
/// nothing (their weight is folded into seat 1). Claiming them is a clean no-op — no
/// double-pay, no revert — so the destination is never over- or under-paid regardless
/// of claim order.
#[test]
fn split_shared_noncanonical_seats_are_noops() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let balance = 1_234_567u64;
    let (seed, _split, vault, _mn, dests, dev, _other) =
        setup_split_shared(&mut svm, &payer, balance);

    // Claim a NON-canonical shared seat first (seat 3 → dev) — owes nothing.
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 3, vault, dests[2])],
        &payer
    ));
    assert_eq!(
        token_balance(&svm, dev),
        0,
        "non-canonical seat pays nothing"
    );

    // The canonical seat (seat 1 → dev) draws the destination's full aggregate.
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 1, vault, dests[0])],
        &payer
    ));
    assert_eq!(
        token_balance(&svm, dev),
        11_111,
        "canonical seat draws bp_d=90"
    );

    // Re-claiming the canonical seat with no new receipts owes nothing (no double-pay).
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 1, vault, dests[0])],
        &payer
    ));
    assert_eq!(
        token_balance(&svm, dev),
        11_111,
        "idempotent — no second payout"
    );

    // Claiming the OTHER non-canonical seat (seat 4 → dev) after the canonical draw is
    // still a no-op (its weight already paid at seat 1).
    assert!(send(
        &mut svm,
        &[split_claim_ix(&seed, 4, vault, dests[3])],
        &payer
    ));
    assert_eq!(token_balance(&svm, dev), 11_111, "still no double-pay");
}

#[test]
fn deploy_rejects_forged_seed() {
    let mut svm = load();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    write_mint(&mut svm, TEST_MINT);
    let mk = Pubkey::new_from_array([0xab; 32]);
    let mn = Pubkey::new_from_array([0x99; 32]);
    let dests = [Pubkey::new_from_array([0xd0; 32]); 4];
    let canonical = canonical_for_split(&mk, &mn, &dests);
    // A seed that is NOT derive_seed_split(canonical) → the PDA won't match / the
    // handler's recompute rejects.
    let forged = [0x00u8; 32];
    assert!(!send(
        &mut svm,
        &[deploy_split_ix(&payer.pubkey(), forged, canonical)],
        &payer
    ));
}
