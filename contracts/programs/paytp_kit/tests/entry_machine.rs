//! M0.5 LiteSVM proofs — the F4 entry machine renders on the real SVM runtime,
//! offline (no devnet, no SOL). Proves: F4.1 authentic instance derivation,
//! F4.1/F4-c address derivation from the signed-quote parameters, the F4.3 state
//! machine incl. atomic funding rejection, the LAPSED terminal, and the F4.2
//! claim-record no-reclaim kind. Includes the adversarial cases the M0.5 gate
//! required (rogue-instance authorization, preimage forgery, post-lapse action,
//! contest overflow).
//!
//! Run: `anchor test` (builds the SBF `.so` first) or `cargo test` after a build.

use anchor_lang::solana_program::clock::Clock;
use anchor_lang::{InstructionData, ToAccountMetas};
use litesvm::LiteSVM;
use paytp_kit::{derive_claim_record_id, derive_entry_id, derive_seed_instance, EntryState};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: Pubkey = solana_pubkey::pubkey!("2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau");
const SYS: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");
const ED25519_ID: Pubkey = solana_pubkey::pubkey!("Ed25519SigVerify111111111111111111111111111");
const SYSVAR_IX: Pubkey = solana_pubkey::pubkey!("Sysvar1nstructions1111111111111111111111111");
const SPL_TOKEN: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// A shared test settlement mint (all escrows/destinations/funders use it).
const TEST_MINT: Pubkey = Pubkey::new_from_array([0x4d; 32]);

/// Write a minimal initialized SPL mint (82 bytes; `is_initialized` @ 45).
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

/// A funder's deterministic test token account (on `TEST_MINT`, owned by `owner`).
fn funder_token_addr(owner: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"funder-token", owner.as_ref()], &PROGRAM_ID).0
}

/// Create the shared mint and fund `owner`'s token account generously — so the
/// atomic deposit in `fund_entry` has a source to debit.
fn mint_setup(svm: &mut LiteSVM, owner: &Pubkey) {
    write_mint(svm, TEST_MINT);
    write_token_account(
        svm,
        funder_token_addr(owner),
        TEST_MINT,
        *owner,
        u64::MAX / 2,
    );
}

/// Write an initialized SPL token account directly (no InitializeAccount needed):
/// `mint(32) ‖ owner(32) ‖ amount(8 LE) ‖ …zeros… ‖ state=1 @108`.
fn write_token_account(svm: &mut LiteSVM, addr: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(&mint.to_bytes());
    data[32..64].copy_from_slice(&owner.to_bytes());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data[108] = 1; // AccountState::Initialized
    let acct = solana_account::Account {
        lamports: 5_000_000,
        data,
        owner: SPL_TOKEN,
        executable: false,
        rent_epoch: 0,
    };
    svm.set_account(addr, acct).unwrap();
}

fn token_balance(svm: &LiteSVM, addr: Pubkey) -> u64 {
    let d = svm.get_account(&addr).unwrap().data;
    u64::from_le_bytes(d[64..72].try_into().unwrap())
}

fn refund_ix(
    inst: Pubkey,
    entry_id: &[u8; 32],
    escrow: Pubkey,
    refund_dest: Pubkey,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::Refund {
            instance: inst,
            entry: entry_pda(entry_id),
            escrow,
            refund_dest,
            token_program: SPL_TOKEN,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::Refund {}.data(),
    }
}

fn distribute_ix(
    inst: Pubkey,
    entry_id: &[u8; 32],
    escrow: Pubkey,
    dests: &[Pubkey; 4],
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::Distribute {
            instance: inst,
            entry: entry_pda(entry_id),
            escrow,
            dest0: dests[0],
            dest1: dests[1],
            dest2: dests[2],
            dest3: dests[3],
            token_program: SPL_TOKEN,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::Distribute {}.data(),
    }
}

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

fn set_clock(svm: &mut LiteSVM, unix: i64) {
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp = unix;
    svm.set_sysvar(&clock);
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> bool {
    let msg = Message::new(ixs, Some(&payer.pubkey()));
    let mut all = vec![payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new(&all, msg, svm.latest_blockhash());
    let ok = svm.send_transaction(tx).is_ok();
    // Advance the blockhash so a resend (e.g. the same instruction retried after a
    // clock warp) gets a distinct signature and isn't rejected as a duplicate.
    svm.expire_blockhash();
    ok
}

fn instance_pda(seed_instance: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"instance", seed_instance], &PROGRAM_ID).0
}
fn entry_pda(entry_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"entry", entry_id], &PROGRAM_ID).0
}
fn claim_pda(key: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"claim", key], &PROGRAM_ID).0
}

/// The `ADDRESS_INPUTS` preimage: field 0x00 (MERCHANT_KEY, type 0x00 / len 0x20 /
/// 32-byte key) then the four meed destination token accounts (32 bytes each) —
/// both bound in `seed_instance`.
fn canonical_for_dests(merchant: &Pubkey, dests: &[Pubkey; 4]) -> Vec<u8> {
    let mut v = vec![0x00u8, 0x20u8];
    v.extend_from_slice(&merchant.to_bytes());
    for d in dests {
        v.extend_from_slice(&d.to_bytes());
    }
    v.extend_from_slice(&TEST_MINT.to_bytes()); // the bound settlement mint
    v
}
/// Non-custody variant with dummy destinations (those tests never distribute).
fn canonical_for(merchant: &Pubkey) -> Vec<u8> {
    let dummy = [
        Pubkey::new_from_array([0xd0; 32]),
        Pubkey::new_from_array([0xd1; 32]),
        Pubkey::new_from_array([0xd2; 32]),
        Pubkey::new_from_array([0xd3; 32]),
    ];
    canonical_for_dests(merchant, &dummy)
}

/// Build a `deploy_instance` ix for `merchant`; returns (ix, seed_instance).
fn deploy_ix(payer: &Pubkey, merchant: &Pubkey) -> (Instruction, [u8; 32]) {
    let canonical = canonical_for(merchant);
    let seed = derive_seed_instance(&canonical);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: instance_pda(&seed),
            payer: *payer,
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::DeployInstance {
            _seed_instance: seed,
            canonical_bytes: canonical,
        }
        .data(),
    };
    (ix, seed)
}

/// Deploy one instance; returns (svm, payer, merchant, seed_instance, instance_pda).
fn setup() -> (LiteSVM, Keypair, Keypair, [u8; 32], Pubkey) {
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    let merchant = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    mint_setup(&mut svm, &payer.pubkey()); // mint + funded source for the atomic deposit
    let (ix, seed) = deploy_ix(&payer.pubkey(), &merchant.pubkey());
    assert!(send(&mut svm, &[ix], &payer, &[]), "deploy_instance");
    (svm, payer, merchant, seed, instance_pda(&seed))
}

#[allow(clippy::too_many_arguments)]
fn fund_ix(
    inst: Pubkey,
    funder: &Pubkey,
    entry_id: [u8; 32],
    nonce: [u8; 32],
    amount: u128,
    t_open: u64,
    t_lapse: u64,
    contest: u64,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundEntry {
            instance: inst,
            entry: entry_pda(&entry_id),
            escrow: entry_escrow_pda(&entry_id),
            mint: TEST_MINT,
            funder_token: funder_token_addr(funder),
            funder: *funder,
            token_program: SPL_TOKEN,
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundEntry {
            entry_id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest,
            refund_account: Pubkey::new_from_array([0xab; 32]),
        }
        .data(),
    }
}

/// The entry's escrow token-account PDA (mirror of the contract's `entry_escrow`).
fn entry_escrow_pda(entry_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"escrow", entry_id], &PROGRAM_ID).0
}

fn merchant_ix(inst: Pubkey, entry_id: &[u8; 32], merchant: &Pubkey, cancel: bool) -> Instruction {
    let accounts = paytp_kit::accounts::MerchantAction {
        instance: inst,
        entry: entry_pda(entry_id),
        merchant: *merchant,
    }
    .to_account_metas(None);
    let data = if cancel {
        paytp_kit::instruction::Cancel {}.data()
    } else {
        paytp_kit::instruction::Attest {}.data()
    };
    Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    }
}

/// The canonical F3.5 attestation message (mirror of the contract's `attest_message`):
/// `"PayTPv1-attest" ‖ 0x00 ‖ TLV(0x00 NONCE(32), 0x01 ENTRY_ID(32))` = 83 bytes,
/// byte-identical to the core's `attest::covered_bytes(Attestation, nonce, entry_id)`.
fn attest_message(nonce: &[u8; 32], entry_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(14 + 1 + 34 + 34);
    m.extend_from_slice(b"PayTPv1-attest");
    m.push(0x00); // F1-h label delimiter
    m.push(0x00); // T_NONCE
    m.push(0x20); // LEB128(32)
    m.extend_from_slice(nonce);
    m.push(0x01); // T_ENTRY_ID
    m.push(0x20); // LEB128(32)
    m.extend_from_slice(entry_id);
    m
}

/// Build a self-contained ed25519-precompile instruction over `(pubkey, sig,
/// message)` (offsets self-referential, `u16::MAX` instruction index).
fn ed25519_ix_raw(pubkey: &[u8; 32], sig: &[u8; 64], message: &[u8]) -> Instruction {
    let (pk_off, sig_off, msg_off): (u16, u16, u16) = (16, 48, 112);
    let mut d = vec![1u8, 0u8]; // one signature, padding
    d.extend_from_slice(&sig_off.to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(&pk_off.to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(&msg_off.to_le_bytes());
    d.extend_from_slice(&(message.len() as u16).to_le_bytes());
    d.extend_from_slice(&u16::MAX.to_le_bytes());
    d.extend_from_slice(pubkey);
    d.extend_from_slice(sig);
    d.extend_from_slice(message);
    Instruction {
        program_id: ED25519_ID,
        accounts: vec![],
        data: d,
    }
}

/// The ed25519 instruction carrying `signer`'s real detached signature.
fn ed25519_ix(signer: &Keypair, message: &[u8]) -> Instruction {
    let sig: [u8; 64] = signer.sign_message(message).as_ref().try_into().unwrap();
    ed25519_ix_raw(&signer.pubkey().to_bytes(), &sig, message)
}

fn attest_detached_ix(inst: Pubkey, entry_id: &[u8; 32]) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::AttestDetached {
            instance: inst,
            entry: entry_pda(entry_id),
            instructions: SYSVAR_IX,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::AttestDetached {}.data(),
    }
}

fn read_entry_state(svm: &LiteSVM, entry_id: &[u8; 32]) -> Option<EntryState> {
    let acc = svm.get_account(&entry_pda(entry_id))?;
    // After the 8-byte discriminator: seed_instance(32)+nonce(32)+amount(16)+
    // t_open(8)+t_lapse(8)+contest(8)+opened_at(8) = 112, then the 1-byte state.
    let s = acc.data.get(8 + 112)?;
    Some(match s {
        0 => EntryState::Funded,
        1 => EntryState::Attested,
        2 => EntryState::Cancelled,
        3 => EntryState::ReclaimOpen,
        4 => EntryState::Reclaimed,
        _ => EntryState::Lapsed,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// F4-c cross-implementation conformance: the on-chain preimage must byte-match
/// the host RI (`paytp-core::derive`) AND an independent Python reference. If any
/// of the three drifts, this fails — the derivation is the interop contract.
#[test]
fn derivation_matches_independent_reference() {
    let seed = [0xaau8; 32];
    let nonce = [0xbbu8; 32];
    let id = derive_entry_id(&seed, &nonce, 1_000_000, 1_000_000_100, 1_000_004_000, 600);
    assert_eq!(
        hex(&id),
        "2a78c23325dd2a55278153a71f5e7172774a956696491e1c79701cbde63fe893"
    );
    let cid = derive_claim_record_id(&seed, &[0, 0, 0, 0, 0, 0, 0, 7], &[0xee; 32], 10_000);
    assert_eq!(
        hex(&cid),
        "eba416a167e8d62cccd5b8783dc4fb50ecd56215fa82458a4f78e56390810f99"
    );
}

#[test]
fn fund_derivation_atomic_rejection_and_state_machine() {
    let (mut svm, payer, merchant, seed, inst) = setup();
    let nonce = [0xbb; 32];
    let (amount, t_open, t_lapse, contest) =
        (1_000_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let entry_id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);

    // Happy funding → FUNDED.
    let ix = fund_ix(
        inst,
        &payer.pubkey(),
        entry_id,
        nonce,
        amount,
        t_open,
        t_lapse,
        contest,
    );
    assert!(send(&mut svm, &[ix], &payer, &[]), "fund_entry");
    assert_eq!(read_entry_state(&svm, &entry_id), Some(EntryState::Funded));

    // F4-c: a DUST amount derives a DIFFERENT entry_id → a different PDA; the
    // honest entry is untouched, and the dust funding cannot occupy it.
    let dust_id = derive_entry_id(&seed, &nonce, 1, t_open, t_lapse, contest);
    assert_ne!(dust_id, entry_id);
    let ixd = fund_ix(
        inst,
        &payer.pubkey(),
        dust_id,
        nonce,
        1,
        t_open,
        t_lapse,
        contest,
    );
    assert!(
        send(&mut svm, &[ixd], &payer, &[]),
        "dust funds its own orphan id"
    );
    assert_eq!(read_entry_state(&svm, &entry_id), Some(EntryState::Funded)); // honest intact

    // Atomic rejection: an entry_id that does NOT recompute from the params reverts.
    let bad = fund_ix(
        inst,
        &payer.pubkey(),
        [0x99; 32],
        nonce,
        amount,
        t_open,
        t_lapse,
        contest,
    );
    assert!(
        !send(&mut svm, &[bad], &payer, &[]),
        "id-mismatch must revert"
    );

    // Duplicate funding of the honest id → revert (init fails atomically).
    let dup = fund_ix(
        inst,
        &payer.pubkey(),
        entry_id,
        nonce,
        amount,
        t_open,
        t_lapse,
        contest,
    );
    assert!(
        !send(&mut svm, &[dup], &payer, &[]),
        "duplicate must revert"
    );

    // Attest (merchant signer) → ATTESTED, terminal.
    let att = merchant_ix(inst, &entry_id, &merchant.pubkey(), false);
    assert!(
        send(&mut svm, std::slice::from_ref(&att), &payer, &[&merchant]),
        "attest"
    );
    assert_eq!(
        read_entry_state(&svm, &entry_id),
        Some(EntryState::Attested)
    );
    // A second attest on a terminal entry reverts.
    assert!(
        !send(&mut svm, &[att], &payer, &[&merchant]),
        "terminal is terminal"
    );
}

/// CRITICAL (M0.5 gate): `attest`/`cancel` must authorize against the entry's OWN
/// instance. An attacker who deploys a rogue instance bound to their own key
/// cannot use it to attest/cancel an honest entry.
#[test]
fn rogue_instance_cannot_authorize_honest_entry() {
    let (mut svm, payer, _merchant, seed, inst) = setup();
    let nonce = [0x11; 32];
    let (amount, t_open, t_lapse, contest) =
        (5_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let entry_id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            entry_id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));

    // Attacker deploys a distinct instance bound to their own key.
    let attacker = Keypair::new();
    let (rogue_ix, rogue_seed) = deploy_ix(&payer.pubkey(), &attacker.pubkey());
    assert_ne!(rogue_seed, seed, "rogue key → distinct seed_instance");
    assert!(
        send(&mut svm, &[rogue_ix], &payer, &[]),
        "deploy rogue instance"
    );

    // Attacker attests the honest entry via the rogue instance + own signature.
    // The MerchantAction constraint `entry.seed_instance == instance.seed_instance`
    // rejects it.
    let steal = merchant_ix(
        instance_pda(&rogue_seed),
        &entry_id,
        &attacker.pubkey(),
        true,
    );
    assert!(
        !send(&mut svm, &[steal], &payer, &[&attacker]),
        "rogue instance must NOT authorize"
    );
    assert_eq!(
        read_entry_state(&svm, &entry_id),
        Some(EntryState::Funded),
        "honest entry untouched"
    );
}

/// CRITICAL (M0.5 gate): `deploy_instance` binds the merchant key its
/// `seed_instance` preimage commits — you cannot occupy the honest instance PDA
/// with a mismatched preimage or a rogue key.
#[test]
fn deploy_rejects_forged_preimage() {
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    let honest = Keypair::new();
    let seed = derive_seed_instance(&canonical_for(&honest.pubkey()));

    // Try to deploy at the honest seed_instance but with a rogue key's preimage:
    // the on-chain hash of the supplied canonical_bytes ≠ the PDA seed → revert.
    let rogue = Keypair::new();
    let forged = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: instance_pda(&seed),
            payer: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::DeployInstance {
            _seed_instance: seed,                            // honest PDA seed
            canonical_bytes: canonical_for(&rogue.pubkey()), // rogue preimage
        }
        .data(),
    };
    assert!(
        !send(&mut svm, &[forged], &payer, &[]),
        "forged preimage must revert"
    );
    assert!(
        svm.get_account(&instance_pda(&seed)).is_none(),
        "honest PDA still free"
    );
}

#[test]
fn lapse_past_funding_rejected() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let nonce = [0xcc; 32];
    // T_lapse strictly before now (1_000_000_000) → reject.
    let (amount, t_open, t_lapse, contest) = (500u128, 100u64, 200u64, 30u64);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    let ix = fund_ix(
        inst,
        &payer.pubkey(),
        id,
        nonce,
        amount,
        t_open,
        t_lapse,
        contest,
    );
    assert!(
        !send(&mut svm, &[ix], &payer, &[]),
        "past T_lapse must revert"
    );
}

/// HIGH (M0.5 gate): after `T_lapse` a FUNDED entry is terminal LAPSED —
/// `cancel`/`attest` reject, and the permissionless `lapse` seals it.
#[test]
fn post_lapse_actions_rejected_and_lapse_seals() {
    let (mut svm, payer, merchant, seed, inst) = setup();
    let nonce = [0x22; 32];
    let (amount, t_open, t_lapse, contest) =
        (2_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));

    // Warp strictly past T_lapse.
    set_clock(&mut svm, 1_000_004_001);
    // Merchant can no longer cancel or attest — the entry is logically lapsed.
    assert!(
        !send(
            &mut svm,
            &[merchant_ix(inst, &id, &merchant.pubkey(), true)],
            &payer,
            &[&merchant]
        ),
        "cancel after lapse"
    );
    assert!(
        !send(
            &mut svm,
            &[merchant_ix(inst, &id, &merchant.pubkey(), false)],
            &payer,
            &[&merchant]
        ),
        "attest after lapse"
    );

    // Anyone can seal it LAPSED.
    let lapse = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::Lapse {}.data(),
    };
    assert!(
        send(&mut svm, std::slice::from_ref(&lapse), &payer, &[]),
        "lapse"
    );
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::Lapsed));
    // Terminal: a second lapse reverts.
    assert!(!send(&mut svm, &[lapse], &payer, &[]), "lapse is terminal");
}

#[test]
fn reclaim_windows() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let nonce = [0xdd; 32];
    let (amount, t_open, t_lapse, contest) =
        (1_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));

    let open = |eid: [u8; 32]| Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&eid),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::OpenReclaim {}.data(),
    };
    // Before T_open → reject.
    assert!(
        !send(&mut svm, &[open(id)], &payer, &[]),
        "reclaim before T_open"
    );
    // In window → RECLAIM_OPEN.
    set_clock(&mut svm, 1_000_000_200);
    assert!(send(&mut svm, &[open(id)], &payer, &[]), "open reclaim");
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::ReclaimOpen));

    let exec = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::ExecuteReclaim {}.data(),
    };
    // Before T_exec (opened_at 1_000_000_200 + contest 600 = 1_000_000_800) → reject.
    set_clock(&mut svm, 1_000_000_800);
    assert!(
        !send(&mut svm, std::slice::from_ref(&exec), &payer, &[]),
        "execute before T_exec"
    );
    // Strictly after T_exec → RECLAIMED.
    set_clock(&mut svm, 1_000_000_801);
    assert!(send(&mut svm, &[exec], &payer, &[]), "execute reclaim");
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::Reclaimed));
}

/// MEDIUM (M0.5 gate): a huge `contest` must not wrap `T_exec = opened_at +
/// contest` below `now` and let `execute_reclaim` fire early.
#[test]
fn contest_overflow_does_not_execute_early() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let nonce = [0x33; 32];
    let (amount, t_open, t_lapse, contest) =
        (1_000u128, 1_000_000_100u64, 1_000_004_000u64, u64::MAX);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));
    set_clock(&mut svm, 1_000_000_200);
    let open = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::OpenReclaim {}.data(),
    };
    assert!(send(&mut svm, &[open], &payer, &[]), "open reclaim");
    // saturating_add pins T_exec at u64::MAX; no reachable `now` exceeds it.
    set_clock(&mut svm, 1_000_003_000);
    let exec = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::ExecuteReclaim {}.data(),
    };
    assert!(
        !send(&mut svm, &[exec], &payer, &[]),
        "overflow must NOT execute early"
    );
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::ReclaimOpen));
}

#[test]
fn claim_record_windowless_and_unreclaimable() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let channel_id = [0, 0, 0, 0, 0, 0, 0, 7];
    let ckpt_ref = [0xee; 32];
    let p = 10_000u128;
    let key = derive_claim_record_id(&seed, &channel_id, &ckpt_ref, p);
    let cr_ix = |k: [u8; 32], p: u128| Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundClaimRecord {
            instance: inst,
            claim_record: claim_pda(&k),
            funder: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundClaimRecord {
            key: k,
            channel_id,
            ckpt_ref,
            p,
        }
        .data(),
    };
    // Funded once (windowless, immediately the settled record).
    assert!(
        send(&mut svm, &[cr_ix(key, p)], &payer, &[]),
        "fund claim-record"
    );
    assert!(svm.get_account(&claim_pda(&key)).is_some());
    // Duplicate (same key) → revert (init fails).
    assert!(
        !send(&mut svm, &[cr_ix(key, p)], &payer, &[]),
        "duplicate claim-record"
    );
    // There is NO reclaim instruction that accepts a claim-record account — the
    // settle-then-reclaim theft is unwritable by construction (open_reclaim/
    // execute_reclaim/lapse require an Entry account, not a ClaimRecord). This is a
    // compile-time fact: no such call exists to make.
}

/// F3.5 (M5 hardening): a **detached** Ed25519 attestation by the bound merchant,
/// verified by the ed25519 precompile + this program's introspection — no merchant
/// signer, relayable by anyone. Proves: valid → ATTESTED; wrong signer → rejected
/// by the key binding; invalid signature → rejected by the precompile itself
/// (which confirms LiteSVM actually verifies, not just parses).
#[test]
fn attest_detached_via_ed25519_precompile() {
    let (mut svm, payer, merchant, seed, inst) = setup();
    let (amount, t_open, t_lapse, contest) =
        (7_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let fund = |svm: &mut LiteSVM, nonce: [u8; 32]| {
        let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
        assert!(send(
            svm,
            &[fund_ix(
                inst,
                &payer.pubkey(),
                id,
                nonce,
                amount,
                t_open,
                t_lapse,
                contest
            )],
            &payer,
            &[]
        ));
        id
    };

    // VALID: the merchant's real detached signature → ATTESTED (payer relays it).
    let nonce = [0x44; 32];
    let id = fund(&mut svm, nonce);
    let msg = attest_message(&nonce, &id);
    assert!(
        send(
            &mut svm,
            &[ed25519_ix(&merchant, &msg), attest_detached_ix(inst, &id)],
            &payer,
            &[]
        ),
        "valid detached attest"
    );
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::Attested));

    // WRONG SIGNER: an attacker signs the same message. The precompile verifies
    // the attacker's (valid) signature, but introspection sees pubkey ≠
    // merchant_key → rejected.
    let nonce2 = [0x55; 32];
    let id2 = fund(&mut svm, nonce2);
    let msg2 = attest_message(&nonce2, &id2);
    let attacker = Keypair::new();
    assert!(
        !send(
            &mut svm,
            &[ed25519_ix(&attacker, &msg2), attest_detached_ix(inst, &id2)],
            &payer,
            &[]
        ),
        "wrong signer must NOT attest"
    );
    assert_eq!(read_entry_state(&svm, &id2), Some(EntryState::Funded));

    // INVALID SIGNATURE: the merchant's pubkey but a garbage signature → the
    // ed25519 PRECOMPILE rejects the whole transaction (LiteSVM verifies it).
    let forged = ed25519_ix_raw(&merchant.pubkey().to_bytes(), &[7u8; 64], &msg2);
    assert!(
        !send(
            &mut svm,
            &[forged, attest_detached_ix(inst, &id2)],
            &payer,
            &[]
        ),
        "invalid signature must be rejected by the precompile"
    );
    assert_eq!(read_entry_state(&svm, &id2), Some(EntryState::Funded));
}

/// A **delivered** (attested) two-leg entry can NEVER be reclaimed —
/// the meed-stripping closure. Proven both ways: (A) attested before the payer
/// can open reclaim; (B) payer opens reclaim, merchant attests during the contest
/// window (cancelling it), execute then fails.
#[test]
fn delivered_entry_cannot_be_reclaimed() {
    let (mut svm, payer, merchant, seed, inst) = setup();
    let (amount, t_open, t_lapse, contest) =
        (7_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let fund = |svm: &mut LiteSVM, nonce: [u8; 32]| {
        let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
        assert!(send(
            svm,
            &[fund_ix(
                inst,
                &payer.pubkey(),
                id,
                nonce,
                amount,
                t_open,
                t_lapse,
                contest
            )],
            &payer,
            &[]
        ));
        id
    };
    let open = |id: [u8; 32]| Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::OpenReclaim {}.data(),
    };
    let exec = |id: [u8; 32]| Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::ExecuteReclaim {}.data(),
    };

    // (A) Delivered before the reclaim window: attest, then the payer cannot even
    // open reclaim (an Attested entry is terminal).
    let nonce_a = [0x81; 32];
    let a = fund(&mut svm, nonce_a);
    let ma = attest_message(&nonce_a, &a);
    assert!(send(
        &mut svm,
        &[ed25519_ix(&merchant, &ma), attest_detached_ix(inst, &a)],
        &payer,
        &[]
    ));
    assert_eq!(read_entry_state(&svm, &a), Some(EntryState::Attested));
    set_clock(&mut svm, 1_000_000_200); // in [t_open, t_lapse]
    assert!(
        !send(&mut svm, &[open(a)], &payer, &[]),
        "cannot open reclaim on a delivered entry"
    );
    assert!(
        !send(&mut svm, &[exec(a)], &payer, &[]),
        "cannot execute reclaim on a delivered entry"
    );
    assert_eq!(read_entry_state(&svm, &a), Some(EntryState::Attested));

    // (B) Payer opens reclaim; merchant delivers (attests) during the contest
    // window, cancelling it; execute after T_exec then fails.
    let nonce_b = [0x82; 32];
    let b = fund(&mut svm, nonce_b);
    set_clock(&mut svm, 1_000_000_200);
    assert!(send(&mut svm, &[open(b)], &payer, &[]), "open reclaim");
    assert_eq!(read_entry_state(&svm, &b), Some(EntryState::ReclaimOpen));
    let mb = attest_message(&nonce_b, &b);
    assert!(
        send(
            &mut svm,
            &[ed25519_ix(&merchant, &mb), attest_detached_ix(inst, &b)],
            &payer,
            &[]
        ),
        "merchant attests the reclaim-open entry"
    );
    assert_eq!(read_entry_state(&svm, &b), Some(EntryState::Attested));
    set_clock(&mut svm, 1_000_000_801); // past opened_at + contest
    assert!(
        !send(&mut svm, &[exec(b)], &payer, &[]),
        "reclaim cancelled by the delivery attestation"
    );
    assert_eq!(read_entry_state(&svm, &b), Some(EntryState::Attested));
}

/// Composability: a relayer batches TWO detached attestations (two ed25519
/// instructions + two `attest_detached`) in one transaction — both entries attest.
/// Proves the introspection scans all ed25519 instructions rather than aborting on
/// the first non-matching one.
#[test]
fn detached_attestations_batch_in_one_tx() {
    let (mut svm, payer, merchant, seed, inst) = setup();
    let (amount, t_open, t_lapse, contest) =
        (7_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let fund = |svm: &mut LiteSVM, nonce: [u8; 32]| {
        let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
        assert!(send(
            svm,
            &[fund_ix(
                inst,
                &payer.pubkey(),
                id,
                nonce,
                amount,
                t_open,
                t_lapse,
                contest
            )],
            &payer,
            &[]
        ));
        id
    };
    let nonce_a = [0x61; 32];
    let nonce_b = [0x62; 32];
    let a = fund(&mut svm, nonce_a);
    let b = fund(&mut svm, nonce_b);
    let (ma, mb) = (attest_message(&nonce_a, &a), attest_message(&nonce_b, &b));
    // One transaction: both ed25519 proofs, then both attest_detached.
    let ixs = vec![
        ed25519_ix(&merchant, &ma),
        ed25519_ix(&merchant, &mb),
        attest_detached_ix(inst, &a),
        attest_detached_ix(inst, &b),
    ];
    assert!(
        send(&mut svm, &ixs, &payer, &[]),
        "batched detached attests"
    );
    assert_eq!(read_entry_state(&svm, &a), Some(EntryState::Attested));
    assert_eq!(read_entry_state(&svm, &b), Some(EntryState::Attested));
}

/// `fund_entry` rejects `t_open > t_lapse` (an empty reclaim window that would
/// trap the entry until it lapses).
#[test]
fn fund_rejects_open_after_lapse() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let nonce = [0x71; 32];
    // t_open (1_000_005_000) > t_lapse (1_000_004_000), both ≥ now.
    let (amount, t_open, t_lapse, contest) =
        (1_000u128, 1_000_005_000u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(
        !send(
            &mut svm,
            &[fund_ix(
                inst,
                &payer.pubkey(),
                id,
                nonce,
                amount,
                t_open,
                t_lapse,
                contest
            )],
            &payer,
            &[]
        ),
        "t_open > t_lapse must revert"
    );
}

/// Real SPL custody: a delivered entry's escrowed meed is distributed to
/// the instance's BOUND destinations via CPI, gated on `Attested`. Proves:
/// the guardrail (a Funded entry can't distribute); the theft closure (a swapped
/// destination is rejected); value conservation to the µ-unit; and idempotency.
#[test]
fn spl_custody_distributes_to_bound_destinations_only() {
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    mint_setup(&mut svm, &payer.pubkey()); // shared mint + funded source for the deposit
    let merchant = Keypair::new();
    let mint = TEST_MINT;

    // Four bound meed destination token accounts on the mint.
    let dests = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];
    for d in &dests {
        write_token_account(&mut svm, *d, mint, Pubkey::new_unique(), 0);
    }

    // Deploy the instance committing these destinations (bound in seed_instance).
    let canonical = canonical_for_dests(&merchant.pubkey(), &dests);
    let seed = derive_seed_instance(&canonical);
    let inst = instance_pda(&seed);
    let deploy = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: inst,
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
    assert!(send(&mut svm, &[deploy], &payer, &[]), "deploy");

    // Fund the entry (amount = meed).
    let meed: u64 = 10_001; // 50/10/30/10 → 5000/1000/3000/1000, residue 1
    let nonce = [0x91; 32];
    let (t_open, t_lapse, contest) = (1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, meed as u128, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            meed as u128,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));

    // fund_entry ATOMICALLY created the entry's escrow (PDA, SPL authority = the
    // instance PDA) and deposited the meed into it — the deposit-side delta.
    let escrow = entry_escrow_pda(&id);
    assert_eq!(
        token_balance(&svm, escrow),
        meed,
        "atomic deposit landed in escrow"
    );

    // ESCROW BINDING: a *different* escrow (even one owned by the instance) cannot
    // be drained for this entry.
    let rogue_escrow = Pubkey::new_unique();
    write_token_account(&mut svm, rogue_escrow, mint, inst, meed);

    // GUARDRAIL: a still-Funded (reclaimable) entry cannot distribute.
    assert!(
        !send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &dests)],
            &payer,
            &[]
        ),
        "cannot distribute a Funded entry"
    );

    // Merchant attests (delivery).
    assert!(
        send(
            &mut svm,
            &[merchant_ix(inst, &id, &merchant.pubkey(), false)],
            &payer,
            &[&merchant]
        ),
        "attest"
    );

    // THEFT ATTEMPT 1: swap dest0 for an attacker's token account → rejected.
    let attacker = Pubkey::new_unique();
    write_token_account(&mut svm, attacker, mint, Pubkey::new_unique(), 0);
    let mut rogue = dests;
    rogue[0] = attacker;
    assert!(
        !send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &rogue)],
            &payer,
            &[]
        ),
        "swapped destination rejected"
    );
    assert_eq!(token_balance(&svm, attacker), 0);

    // THEFT ATTEMPT 2: pass a DIFFERENT escrow (not this entry's PDA) → rejected,
    // so a fake/lapsed entry cannot drain another entry's escrow.
    assert!(
        !send(
            &mut svm,
            &[distribute_ix(inst, &id, rogue_escrow, &dests)],
            &payer,
            &[]
        ),
        "unbound escrow rejected"
    );
    assert_eq!(token_balance(&svm, rogue_escrow), meed); // untouched

    // Honest distribute → the bound destinations receive their shares.
    assert!(
        send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &dests)],
            &payer,
            &[]
        ),
        "distribute"
    );
    assert_eq!(token_balance(&svm, dests[0]), 5_000);
    assert_eq!(token_balance(&svm, dests[1]), 1_000);
    assert_eq!(token_balance(&svm, dests[2]), 3_000);
    assert_eq!(token_balance(&svm, dests[3]), 1_000);
    assert_eq!(token_balance(&svm, escrow), 1); // sub-unit residue carries (dust, §10.2)
                                                // Value conservation to the µ-unit.
    let out: u64 =
        dests.iter().map(|d| token_balance(&svm, *d)).sum::<u64>() + token_balance(&svm, escrow);
    assert_eq!(out, meed);

    // Idempotency: a second distribute is refused (no double payout).
    assert!(
        !send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &dests)],
            &payer,
            &[]
        ),
        "double distribute rejected"
    );
    assert_eq!(token_balance(&svm, dests[0]), 5_000); // unchanged
}

/// The guardrail, explicit for EVERY reclaimable state: the
/// distribution CPI moves value ONLY for an Attested/Lapsed entry — never Funded,
/// ReclaimOpen, or Reclaimed. (The state guard fires before the escrow/dest checks,
/// so no value can leave a still-reclaimable entry under any inputs.)
#[test]
fn distribute_gated_to_delivered_states() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let dummy_dests = [
        Pubkey::new_from_array([0xd0; 32]),
        Pubkey::new_from_array([0xd1; 32]),
        Pubkey::new_from_array([0xd2; 32]),
        Pubkey::new_from_array([0xd3; 32]),
    ];
    let nonce = [0xe5; 32];
    let (amount, t_open, t_lapse, contest) =
        (5_000u128, 1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));
    let entry_only = |data: Vec<u8>| Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::EntryOnly {
            entry: entry_pda(&id),
            caller: payer.pubkey(),
        }
        .to_account_metas(None),
        data,
    };
    let dist = |svm: &mut LiteSVM| {
        send(
            svm,
            &[distribute_ix(
                inst,
                &id,
                entry_escrow_pda(&id),
                &dummy_dests,
            )],
            &payer,
            &[],
        )
    };

    // FUNDED → rejected.
    assert!(!dist(&mut svm), "Funded is not deliverable");
    // RECLAIM_OPEN → rejected.
    set_clock(&mut svm, 1_000_000_200);
    assert!(
        send(
            &mut svm,
            &[entry_only(paytp_kit::instruction::OpenReclaim {}.data())],
            &payer,
            &[]
        ),
        "open reclaim"
    );
    assert!(!dist(&mut svm), "ReclaimOpen is not deliverable");
    // RECLAIMED → rejected.
    set_clock(&mut svm, 1_000_000_801);
    assert!(
        send(
            &mut svm,
            &[entry_only(paytp_kit::instruction::ExecuteReclaim {}.data())],
            &payer,
            &[]
        ),
        "execute reclaim"
    );
    assert_eq!(read_entry_state(&svm, &id), Some(EntryState::Reclaimed));
    assert!(!dist(&mut svm), "Reclaimed is not deliverable");
}

/// Deposit hardening: a fake-mint deposit cannot occupy an entry (the settlement
/// mint is bound to the instance), and dusting the deterministic escrow PDA does
/// not brick funding (prefund-tolerant create).
#[test]
fn deposit_rejects_fake_mint_and_tolerates_escrow_prefund() {
    let (mut svm, payer, _m, seed, inst) = setup(); // instance bound to TEST_MINT
    let (t_open, t_lapse, contest) = (1_000_000_100u64, 1_000_004_000u64, 600u64);
    let amount = 10_000u128;

    // FAKE MINT: a squatter with worthless tokens on an unbound mint is rejected —
    // no free squat, and the entry is never even created (the tx reverts).
    let fake_mint = Pubkey::new_from_array([0xfa; 32]);
    write_mint(&mut svm, fake_mint);
    let fake_token = Pubkey::new_from_array([0xfb; 32]);
    write_token_account(&mut svm, fake_token, fake_mint, payer.pubkey(), 1_000_000);
    let nonce = [0xf1; 32];
    let id = derive_entry_id(&seed, &nonce, amount, t_open, t_lapse, contest);
    let fake_fund = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundEntry {
            instance: inst,
            entry: entry_pda(&id),
            escrow: entry_escrow_pda(&id),
            mint: fake_mint,
            funder_token: fake_token,
            funder: payer.pubkey(),
            token_program: SPL_TOKEN,
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundEntry {
            entry_id: id,
            nonce,
            amount,
            t_open,
            t_lapse,
            contest,
            refund_account: Pubkey::new_from_array([0xab; 32]),
        }
        .data(),
    };
    assert!(
        !send(&mut svm, &[fake_fund], &payer, &[]),
        "fake-mint deposit rejected"
    );
    assert!(
        svm.get_account(&entry_pda(&id)).is_none(),
        "entry not even created"
    );

    // PREFUND GRIEFING: dust the deterministic escrow PDA before funding → the fund
    // still succeeds and the deposit lands (top-up + allocate + assign, not create).
    let nonce2 = [0xf2; 32];
    let id2 = derive_entry_id(&seed, &nonce2, amount, t_open, t_lapse, contest);
    let escrow2 = entry_escrow_pda(&id2);
    svm.set_account(
        escrow2,
        solana_account::Account {
            lamports: 100,
            data: vec![],
            owner: SYS,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    assert!(
        send(
            &mut svm,
            &[fund_ix(
                inst,
                &payer.pubkey(),
                id2,
                nonce2,
                amount,
                t_open,
                t_lapse,
                contest
            )],
            &payer,
            &[]
        ),
        "fund tolerates a prefunded escrow PDA"
    );
    assert_eq!(
        token_balance(&svm, escrow2),
        amount as u64,
        "deposit landed despite prefund"
    );
}

/// Refund custody: a Cancelled (or Reclaimed) entry's escrow returns to the
/// payer's recorded refund account — never distributed, never double-refunded, and
/// only to the bound refund account (F4.3 refund-to-recorded-pointer).
#[test]
fn spl_custody_refunds_cancelled_entry_to_payer() {
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    mint_setup(&mut svm, &payer.pubkey());
    let merchant = Keypair::new();
    let mint = TEST_MINT;
    let dests = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];
    let canonical = canonical_for_dests(&merchant.pubkey(), &dests);
    let seed = derive_seed_instance(&canonical);
    let inst = instance_pda(&seed);
    let deploy = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: inst,
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
    assert!(send(&mut svm, &[deploy], &payer, &[]), "deploy");

    // The payer's refund token account.
    let refund_dest = Pubkey::new_unique();
    write_token_account(&mut svm, refund_dest, mint, payer.pubkey(), 0);

    // Fund an entry recording that refund account — the atomic deposit funds the escrow.
    let meed: u64 = 8_000;
    let nonce = [0xc1; 32];
    let (t_open, t_lapse, contest) = (1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, meed as u128, t_open, t_lapse, contest);
    let fund = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundEntry {
            instance: inst,
            entry: entry_pda(&id),
            escrow: entry_escrow_pda(&id),
            mint,
            funder_token: funder_token_addr(&payer.pubkey()),
            funder: payer.pubkey(),
            token_program: SPL_TOKEN,
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundEntry {
            entry_id: id,
            nonce,
            amount: meed as u128,
            t_open,
            t_lapse,
            contest,
            refund_account: refund_dest,
        }
        .data(),
    };
    assert!(send(&mut svm, &[fund], &payer, &[]), "fund");
    let escrow = entry_escrow_pda(&id);
    assert_eq!(token_balance(&svm, escrow), meed, "atomic deposit landed");

    // Refund before a terminal-refundable state → rejected (entry is Funded).
    assert!(
        !send(
            &mut svm,
            &[refund_ix(inst, &id, escrow, refund_dest)],
            &payer,
            &[]
        ),
        "cannot refund a Funded entry"
    );

    // Merchant cancels → refundable.
    assert!(
        send(
            &mut svm,
            &[merchant_ix(inst, &id, &merchant.pubkey(), true)],
            &payer,
            &[&merchant]
        ),
        "cancel"
    );

    // Refund to the WRONG account → rejected.
    let wrong = Pubkey::new_unique();
    write_token_account(&mut svm, wrong, mint, Pubkey::new_unique(), 0);
    assert!(
        !send(
            &mut svm,
            &[refund_ix(inst, &id, escrow, wrong)],
            &payer,
            &[]
        ),
        "wrong refund account rejected"
    );

    // Honest refund → the payer gets the full escrow back.
    assert!(
        send(
            &mut svm,
            &[refund_ix(inst, &id, escrow, refund_dest)],
            &payer,
            &[]
        ),
        "refund"
    );
    assert_eq!(token_balance(&svm, refund_dest), meed);
    assert_eq!(token_balance(&svm, escrow), 0);

    // Double refund → rejected; and a refunded entry can't be distributed.
    assert!(
        !send(
            &mut svm,
            &[refund_ix(inst, &id, escrow, refund_dest)],
            &payer,
            &[]
        ),
        "double refund rejected"
    );
    assert!(
        !send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &dests)],
            &payer,
            &[]
        ),
        "no distribute after refund"
    );
}

/// The on-chain F7-d division (the shared `paytp-f7` running on SBF) must equal the
/// host `paytp-f7` division AND conserve value (Σ shares + residue == P) — checked
/// across a spread of `P` values: dust, exact, various residues, large, and a
/// >2⁶⁴ value that exercises the U512 `V·bp` path on-chain.
#[test]
fn claim_record_onchain_division_matches_host_and_conserves() {
    use ruint::aliases::U256;
    let (mut svm, payer, _m, seed, inst) = setup();
    let channel_id = [0, 0, 0, 0, 0, 0, 0, 9];
    let bp = [50u32, 10, 30, 10];
    let values: [u128; 8] = [
        1,                         // all shares floor to 0, residue 1
        7,                         // 3/0/2/0, residue 2
        100,                       // exact 50/10/30/10, residue 0
        99,                        // 49/9/29/9, residue 3
        10_001,                    // 5000/1000/3000/1000, residue 1
        987_654,                   // large-ish
        1_000_000_000_000_000_000, // 10^18
        (1u128 << 100) + 3,        // > 2^64 → the U512 V·bp path on-chain
    ];
    for (i, &p) in values.iter().enumerate() {
        let ckpt_ref = [i as u8; 32];
        let key = derive_claim_record_id(&seed, &channel_id, &ckpt_ref, p);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: paytp_kit::accounts::FundClaimRecord {
                instance: inst,
                claim_record: claim_pda(&key),
                funder: payer.pubkey(),
                system_program: SYS,
            }
            .to_account_metas(None),
            data: paytp_kit::instruction::FundClaimRecord {
                key,
                channel_id,
                ckpt_ref,
                p,
            }
            .data(),
        };
        assert!(
            send(&mut svm, &[ix], &payer, &[]),
            "fund claim-record p={p}"
        );

        // Parse the ClaimRecord: after the 8-byte discriminator — amount(16),
        // shares[4](4×16), residue(16).
        let data = svm.get_account(&claim_pda(&key)).unwrap().data;
        let rd = |off: usize| u128::from_le_bytes(data[off..off + 16].try_into().unwrap());
        assert_eq!(rd(8), p, "amount p={p}");
        let shares = [rd(24), rd(40), rd(56), rd(72)];
        let residue = rd(88);

        // On-chain shares == host paytp-f7 for every role (the core-sharing guarantee).
        for (j, &b) in bp.iter().enumerate() {
            let host =
                u128::try_from(paytp_f7::claimable_d(&U256::from(p), b, 100, &U256::ZERO)).unwrap();
            assert_eq!(shares[j], host, "p={p} share {j} on-chain==host");
        }
        // Value conservation to the µ-unit.
        assert_eq!(
            shares.iter().sum::<u128>() + residue,
            p,
            "p={p} conservation"
        );
    }
}

/// The on-chain U512 F7 division is cheap: `fund_claim_record` (4-role division +
/// account init) stays well under Solana's 200k default CU budget — the design
/// consult's "measure CU before locking" (compute-not-verify was the right call).
#[test]
fn claim_record_division_compute_units_modest() {
    let (mut svm, payer, _m, seed, inst) = setup();
    let channel_id = [0, 0, 0, 0, 0, 0, 0, 3];
    let ckpt_ref = [0xcd; 32];
    let p = 987_654u128;
    let key = derive_claim_record_id(&seed, &channel_id, &ckpt_ref, p);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundClaimRecord {
            instance: inst,
            claim_record: claim_pda(&key),
            funder: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundClaimRecord {
            key,
            channel_id,
            ckpt_ref,
            p,
        }
        .data(),
    };
    let msg = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], msg, svm.latest_blockhash());
    let meta = svm.send_transaction(tx).expect("fund");
    // Far below 200k — the U512 divide loop is not a compute concern (schema 0x01).
    assert!(
        meta.compute_units_consumed < 100_000,
        "CU {} should be well under budget",
        meta.compute_units_consumed
    );
}

/// Deploy an instance whose meed vector SHARES a destination across three roles
/// (`[dev, other, dev, dev]` — the chronically-shared Development-Fund shape,
/// `03-tier0-objects:40`). Returns (seed, instance_pda, dev, other).
fn deploy_shared_instance(
    svm: &mut LiteSVM,
    payer: &Keypair,
    merchant: &Pubkey,
) -> ([u8; 32], Pubkey, Pubkey, Pubkey) {
    let dev = Pubkey::new_from_array([0xda; 32]);
    let other = Pubkey::new_from_array([0xdb; 32]);
    let dests = [dev, other, dev, dev];
    write_token_account(svm, dev, TEST_MINT, Pubkey::new_unique(), 0);
    write_token_account(svm, other, TEST_MINT, Pubkey::new_unique(), 0);
    let canonical = canonical_for_dests(merchant, &dests);
    let seed = derive_seed_instance(&canonical);
    let inst = instance_pda(&seed);
    let deploy = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::DeployInstance {
            instance: inst,
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
    assert!(send(svm, &[deploy], payer, &[]), "deploy shared instance");
    (seed, inst, dev, other)
}

/// The F7-d↔F7.3 per-destination fix for the Tier-0 delivered-entry payout
/// (`distribute`): when several roles name ONE destination, the token account
/// receives its per-DESTINATION floor (`bp_dev = 50+30+10 = 90`), NOT the sum of three
/// per-role floors. `amount = 13`: per-destination ⌊13·90/100⌋ = 11 to the dev fund;
/// per-role (the pre-fix bug) is 6+3+1 = 10, stranding 1 in escrow. Mirrors the
/// per-destination `advance_channel_meed` and the RI `MeedInstance`.
#[test]
fn distribute_aggregates_shared_destination_before_flooring() {
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    mint_setup(&mut svm, &payer.pubkey());
    let merchant = Keypair::new();
    let (seed, inst, dev, other) = deploy_shared_instance(&mut svm, &payer, &merchant.pubkey());
    let dests = [dev, other, dev, dev];

    let amount: u64 = 13;
    let nonce = [0x71; 32];
    let (t_open, t_lapse, contest) = (1_000_000_100u64, 1_000_004_000u64, 600u64);
    let id = derive_entry_id(&seed, &nonce, amount as u128, t_open, t_lapse, contest);
    assert!(send(
        &mut svm,
        &[fund_ix(
            inst,
            &payer.pubkey(),
            id,
            nonce,
            amount as u128,
            t_open,
            t_lapse,
            contest
        )],
        &payer,
        &[]
    ));
    let escrow = entry_escrow_pda(&id);
    assert!(send(
        &mut svm,
        &[merchant_ix(inst, &id, &merchant.pubkey(), false)],
        &payer,
        &[&merchant]
    ));
    assert!(
        send(
            &mut svm,
            &[distribute_ix(inst, &id, escrow, &dests)],
            &payer,
            &[]
        ),
        "distribute"
    );
    // Per-DESTINATION: the shared dev fund gets ⌊13·90/100⌋ = 11 (RED→GREEN); the
    // unshared `other` gets ⌊13·10/100⌋ = 1; the sub-unit residue (1) carries in escrow.
    assert_eq!(
        token_balance(&svm, dev),
        11,
        "shared dev fund floored once on bp_d=90, not per-role (10)"
    );
    assert_eq!(
        token_balance(&svm, other),
        1,
        "unshared dest floors on bp=10"
    );
    assert_eq!(
        token_balance(&svm, escrow),
        1,
        "per-destination residue (per-role strands 2)"
    );
    // Value conserved to the µ-unit.
    assert_eq!(
        token_balance(&svm, dev) + token_balance(&svm, other) + token_balance(&svm, escrow),
        amount
    );
}

/// The F7-d↔F7.3 per-destination fix for the legacy channel `ClaimRecord`
/// (`distribute_p_into` via `fund_claim_record`): a shared destination's cumulative
/// is recorded ONCE at its canonical (first-naming) role slot on the combined weight;
/// the shared later slots hold 0. `P = 13`: `shares = [11, 1, 0, 0]`, residue 1
/// (per-role would be `[6, 1, 3, 1]`, residue 2).
#[test]
fn claim_record_aggregates_shared_destination_before_flooring() {
    use ruint::aliases::U256;
    let mut svm = load();
    set_clock(&mut svm, 1_000_000_000);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    mint_setup(&mut svm, &payer.pubkey());
    let merchant = Keypair::new();
    let (seed, inst, _dev, _other) = deploy_shared_instance(&mut svm, &payer, &merchant.pubkey());

    let channel_id = [0, 0, 0, 0, 0, 0, 0, 13];
    let ckpt_ref = [0x5c; 32];
    let p = 13u128;
    let key = derive_claim_record_id(&seed, &channel_id, &ckpt_ref, p);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: paytp_kit::accounts::FundClaimRecord {
            instance: inst,
            claim_record: claim_pda(&key),
            funder: payer.pubkey(),
            system_program: SYS,
        }
        .to_account_metas(None),
        data: paytp_kit::instruction::FundClaimRecord {
            key,
            channel_id,
            ckpt_ref,
            p,
        }
        .data(),
    };
    assert!(send(&mut svm, &[ix], &payer, &[]), "fund claim-record");

    // amount(16), shares[4](4×16), residue(16) after the 8-byte discriminator.
    let data = svm.get_account(&claim_pda(&key)).unwrap().data;
    let rd = |off: usize| u128::from_le_bytes(data[off..off + 16].try_into().unwrap());
    let shares = [rd(24), rd(40), rd(56), rd(72)];
    let residue = rd(88);
    // Per-destination: the dev fund's cumulative (⌊13·90/100⌋ = 11) at its canonical
    // slot 0; slot 1 = other's ⌊13·10/100⌋ = 1; the shared later slots 2,3 hold 0.
    assert_eq!(
        shares[0], 11,
        "canonical slot floors once on bp_d=90 (RED→GREEN)"
    );
    assert_eq!(shares[1], 1, "unshared dest slot on bp=10");
    assert_eq!(shares[2], 0, "shared later slot folded to 0");
    assert_eq!(shares[3], 0, "shared later slot folded to 0");
    assert_eq!(
        residue, 1,
        "per-destination residue (per-role would strand 2)"
    );
    assert_eq!(shares.iter().sum::<u128>() + residue, p, "conservation");
    // Sanity: on-chain per-destination == host paytp-f7 on the aggregated weight.
    assert_eq!(
        shares[0],
        u128::try_from(paytp_f7::claimable_d(&U256::from(p), 90, 100, &U256::ZERO)).unwrap()
    );
}
