//! PayTP contract kit — the meed-instance entry machine on the SVM (**F4**).
//!
//! The M0.5 spike: prove the F4 entry machine renders on a real SVM with no
//! semantic compromise — **F4.1 authentic instance derivation**, **F4.1/F4-c
//! address derivation from the signed-quote parameters**, the **F4.3 entry state
//! machine incl. atomic funding rejection and the LAPSED terminal** (the
//! free-riding closure), and the **F4.2 claim-record no-reclaim kind** (the
//! settle-then-reclaim theft is unwritable). Proven offline via LiteSVM and, once
//! the deployer key is funded, on Solana devnet.
//!
//! **PDA reality (§3):** a signed quote exceeds the 32-byte PDA seed limit, so
//! the entry account's seed is the 32-byte `entry_id` hash and the funding
//! instruction carries the full inputs as calldata which the program
//! **recomputes and checks** — so a dust/wrong-deadline/wrong-amount funding
//! derives a *different* id and can never occupy the honest entry (F4-c). The
//! same applies to the instance itself: `deploy_instance` recomputes
//! `seed_instance` from the `ADDRESS_INPUTS` preimage and binds the merchant key
//! that preimage commits — a rogue key derives a different `seed_instance` and
//! cannot occupy the honest instance PDA (F4.1). Each entry stores its
//! `seed_instance`, so `attest`/`cancel` authorize against the entry's *own*
//! instance, never an attacker-supplied one.
//!
//! **Spike scope, stated honestly:** `attest`/`cancel` require the bound merchant
//! as a transaction signer. The full F3.5 model — anyone posts a *detached*
//! Ed25519 attestation the instance verifies against the bound merchant key via
//! the ed25519 precompile — is the M5 hardening; it does not change the state
//! machine, derivation, or account model this spike validates. No SPL-token
//! custody/movement is modelled — the spike validates derivation, the account
//! model, and the state machine; escrow accounting is M5.

// Anchor instruction handlers take one instruction-data field per parameter (e.g. `fund_entry`'s
// F4.2 entry terms: entry_id, nonce, amount, t_open, t_lapse, contest, refund_account). Collapsing
// them into a struct would change the on-chain instruction ABI, so a high arg count is intrinsic to
// the instruction shape. The lint fires inside the `#[program]` macro expansion, so the allow must
// be crate-level to reach the generated handlers.
#![allow(clippy::too_many_arguments)]

use anchor_lang::prelude::*;
use ruint::aliases::U256;
use solana_sha256_hasher::hashv;

/// Schema-`0x01` meed weights (basis points, ascending role id 0x10..0x13),
/// summing to `SCHEMA_01_BP_TOTAL`. The contract kit version (part of
/// `ADDRESS_INPUTS`) pins the schema, so the on-chain division knows its weights.
const SCHEMA_01_BP: [u32; 4] = [50, 10, 30, 10];
const SCHEMA_01_BP_TOTAL: u32 = 100;

/// The **baseline split** weights (F4-d): the full baseline payment divides among
/// the merchant net seat and the four schema-0x01 meed roles, over 10 000 bp.
/// The merchant seat is `10000 − SCHEMA_01_BP_TOTAL` (99% for schema 0x01); the
/// meed roles keep their `SCHEMA_01_BP` weights. Sum = `SPLIT_BP_TOTAL`.
const SPLIT_MERCHANT_BP: u32 = 10_000 - SCHEMA_01_BP_TOTAL;
const SPLIT_BP_TOTAL: u32 = 10_000;

/// The `ChannelMeed` account model version (Option W, F6-o) — a forward-compat
/// marker. The watermark has no close/re-init path, so a future model change deploys
/// under a fresh version rather than mutating a live record.
const CHANMEED_VERSION: u8 = 1;

/// The SPL Associated Token Account program — the split's receiving account is
/// `ATA(owner = split_PDA, mint = asset)` so a plain x402 exact-svm client
/// (which pays `TransferChecked → ATA(payTo, asset)`) lands funds in the split.
const ATA_PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// The SPL Token program.
const SPL_TOKEN_ID: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// CPI an SPL-token `Transfer` of `amount` from `from` to `to`, signed by a PDA
/// authority whose seeds are `seeds` (`invoke_signed`). The SPL `Transfer`
/// instruction is tag `3` followed by the `u64` amount.
fn spl_transfer_signed<'info>(
    token_program: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    seeds: &[&[u8]],
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    anchor_lang::solana_program::program::invoke_signed(
        &ix,
        &[
            from.clone(),
            to.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[seeds],
    )
    .map_err(Into::into)
}

/// SPL `Transfer` authorized by a real transaction signer (`authority`), not a PDA.
fn spl_transfer<'info>(
    token_program: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    anchor_lang::solana_program::program::invoke(
        &ix,
        &[
            from.clone(),
            to.clone(),
            authority.clone(),
            token_program.clone(),
        ],
    )
    .map_err(Into::into)
}

/// Create an SPL token account at the PDA `escrow` (seeds `escrow_seeds`), with SPL
/// authority `owner` and rent paid by `payer`: system `create_account` (signed by
/// the escrow PDA) then SPL `InitializeAccount3` (tag 18, owner in calldata).
#[allow(clippy::too_many_arguments)]
fn create_escrow_token_account<'info>(
    payer: &AccountInfo<'info>,
    escrow: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    owner: &Pubkey,
    token_program: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    escrow_seeds: &[&[u8]],
) -> Result<()> {
    use anchor_lang::solana_program::{
        instruction::{AccountMeta, Instruction},
        program::{invoke, invoke_signed},
        system_instruction,
    };
    let space: u64 = 165; // SPL token account length
    let rent = Rent::get()?.minimum_balance(space as usize); // Rent via prelude
                                                             // Prefund-tolerant creation: `create_account` reverts if the escrow PDA already
                                                             // holds lamports, so an attacker could brick funding by dusting the deterministic
                                                             // PDA. Instead top up to rent, then allocate + assign (both signed by the PDA).
                                                             // An attacker can only *transfer lamports* to the PDA — never allocate/assign it
                                                             // (that needs the program's PDA signature) — so this path always succeeds.
    let current = escrow.lamports();
    if current < rent {
        let top_up = system_instruction::transfer(payer.key, escrow.key, rent - current);
        invoke(
            &top_up,
            &[payer.clone(), escrow.clone(), system_program.clone()],
        )?;
    }
    let allocate = system_instruction::allocate(escrow.key, space);
    invoke_signed(
        &allocate,
        &[escrow.clone(), system_program.clone()],
        &[escrow_seeds],
    )?;
    let assign = system_instruction::assign(escrow.key, token_program.key);
    invoke_signed(
        &assign,
        &[escrow.clone(), system_program.clone()],
        &[escrow_seeds],
    )?;
    let mut data = Vec::with_capacity(33);
    data.push(18u8); // InitializeAccount3
    data.extend_from_slice(owner.as_ref());
    let init = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*escrow.key, false),
            AccountMeta::new_readonly(*mint.key, false),
        ],
        data,
    };
    invoke(
        &init,
        &[escrow.clone(), mint.clone(), token_program.clone()],
    )?;
    Ok(())
}

/// Create a **program-owned** PDA data account prefund-tolerantly (top-up →
/// allocate → assign, all PDA-signed) — the same anti-dusting pattern as
/// `create_escrow_token_account`, but assigning to THIS program for an Anchor
/// data account. Anchor `init` uses `create_account`, which reverts if the PDA
/// already holds lamports; because a counterfactual split PDA is derivable from
/// the **public** quote, an attacker could dust it 1 lamport to brick deploy and
/// strand any funds later paid to its ATA. This path always succeeds: an attacker
/// can only *transfer lamports*, never allocate/assign (that needs the PDA sig).
fn create_pda_data_account<'info>(
    payer: &AccountInfo<'info>,
    account: &AccountInfo<'info>,
    space: u64,
    system_program: &AccountInfo<'info>,
    seeds: &[&[u8]],
) -> Result<()> {
    use anchor_lang::solana_program::{
        program::{invoke, invoke_signed},
        system_instruction,
    };
    let rent = Rent::get()?.minimum_balance(space as usize);
    let current = account.lamports();
    if current < rent {
        let top_up = system_instruction::transfer(payer.key, account.key, rent - current);
        invoke(
            &top_up,
            &[payer.clone(), account.clone(), system_program.clone()],
        )?;
    }
    let allocate = system_instruction::allocate(account.key, space);
    invoke_signed(
        &allocate,
        &[account.clone(), system_program.clone()],
        &[seeds],
    )?;
    let assign = system_instruction::assign(account.key, &crate::ID);
    invoke_signed(
        &assign,
        &[account.clone(), system_program.clone()],
        &[seeds],
    )?;
    Ok(())
}

// The program id below is deployment-specific: a real deployment supplies its own (run
// `anchor keys sync` to align this, `Anchor.toml`, and the deployed keypair). The public
// reference snapshot ships an example id here; its keypair is not distributed.
declare_id!("2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau");

/// F4.3 entry states.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryState {
    Funded,
    Attested,
    Cancelled,
    ReclaimOpen,
    Reclaimed,
    Lapsed,
}

/// `seed_instance = SHA-256("PayTPv1-instance" ‖ 0x00 ‖ canonical_bytes(ADDRESS_INPUTS))`
/// (F4.1). The preimage commits `MERCHANT_KEY` (its first canonical field), so the
/// address and the bound key are inseparable.
pub fn derive_seed_instance(canonical_bytes: &[u8]) -> [u8; 32] {
    let parts: [&[u8]; 3] = [b"PayTPv1-instance", &[0x00], canonical_bytes];
    hashv(&parts).to_bytes()
}

/// `seed_split = SHA-256("PayTPv1-split" ‖ 0x00 ‖ canonical_bytes(ADDRESS_INPUTS))`
/// (F4.1 / F4-a). The **sibling** label to `seed_instance` under one `contract`
/// version, so the split and the meed instance **never share an address**
/// (F4.1) even from the same inputs.
pub fn derive_seed_split(canonical_bytes: &[u8]) -> [u8; 32] {
    let parts: [&[u8]; 3] = [b"PayTPv1-split", &[0x00], canonical_bytes];
    hashv(&parts).to_bytes()
}

/// Read an SPL token account's `amount` (`u64` LE at offset 64 of the 165-byte
/// SPL Token account layout).
fn read_token_amount(data: &[u8]) -> Result<u64> {
    require!(data.len() >= 72, KitError::BadInputs);
    Ok(u64::from_le_bytes(data[64..72].try_into().unwrap()))
}

/// The Associated Token Account address for `(owner, mint)` under the standard
/// SPL Token program (`find_program_address([owner, TOKEN, mint], ATA_PROGRAM)`).
fn associated_token_account(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), SPL_TOKEN_ID.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// `entry_id = SHA-256("PayTPv1-entry" ‖ 0x00 ‖ seed_instance ‖ nonce ‖ AMT(16 BE)
/// ‖ T_open(8 BE) ‖ T_lapse(8 BE) ‖ contest(8 BE))` (F4-c).
pub fn derive_entry_id(
    seed_instance: &[u8; 32],
    nonce: &[u8; 32],
    amount: u128,
    t_open: u64,
    t_lapse: u64,
    contest: u64,
) -> [u8; 32] {
    let parts: [&[u8]; 8] = [
        b"PayTPv1-entry",
        &[0x00],
        seed_instance,
        nonce,
        &amount.to_be_bytes(),
        &t_open.to_be_bytes(),
        &t_lapse.to_be_bytes(),
        &contest.to_be_bytes(),
    ];
    hashv(&parts).to_bytes()
}

/// `claim_record_id = SHA-256("PayTPv1-entry" ‖ 0x00 ‖ seed_instance ‖ channel_id
/// ‖ ckpt_ref ‖ P(16 BE))` (F4.2) — windowless, no deadline terms.
pub fn derive_claim_record_id(
    seed_instance: &[u8; 32],
    channel_id: &[u8; 8],
    ckpt_ref: &[u8; 32],
    p: u128,
) -> [u8; 32] {
    let parts: [&[u8]; 6] = [
        b"PayTPv1-entry",
        &[0x00],
        seed_instance,
        channel_id,
        ckpt_ref,
        &p.to_be_bytes(),
    ];
    hashv(&parts).to_bytes()
}

#[program]
pub mod paytp_kit {
    use super::*;

    /// Deploy a meed instance (F4.1). `seed_instance` is the PDA seed; the
    /// program **recomputes it from `canonical_bytes`** and binds the
    /// `MERCHANT_KEY` that preimage commits — so no one can occupy the honest
    /// instance PDA with a rogue key (a rogue key → different preimage → different
    /// `seed_instance` → different PDA). Front-running with the honest preimage
    /// only deploys the honest instance.
    pub fn deploy_instance(
        ctx: Context<DeployInstance>,
        _seed_instance: [u8; 32],
        canonical_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(
            derive_seed_instance(&canonical_bytes) == _seed_instance,
            KitError::IdMismatch
        );
        // ADDRESS_INPUTS field 0x00 (MERCHANT_KEY) is the first canonical TLV
        // field: type byte 0x00, LEB128 length 0x20, then the 32-byte key
        // (F4.1 / F1.1). The contract binds only this field; full ADDRESS_INPUTS
        // validation is the funding wallet's duty (F4.5).
        // The preimage is `[0x00, 0x20, MERCHANT_KEY(32)]` then the four schema-0x01
        // meed **destination token accounts** (32 bytes each). Because
        // `seed_instance` hashes the whole preimage, both the merchant key AND the
        // destinations are bound to the instance address — a rogue destination set
        // derives a different instance, so an attacker cannot redirect a funded
        // entry's payout. (Spike convention: the real ADDRESS_INPUTS carries the
        // destinations as F9 pointers inside the meed vector; here they are the
        // resolved token-account pubkeys the deployer commits.)
        // Preimage: `[0x00,0x20,MERCHANT_KEY(32)]` ‖ 4 dest token accounts (128) ‖
        // the settlement MINT (32) = 194 bytes. All bound by the full-bytes hash.
        require!(
            canonical_bytes.len() >= 34 + 128 + 32
                && canonical_bytes[0] == 0x00
                && canonical_bytes[1] == 0x20,
            KitError::BadInputs
        );
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&canonical_bytes[2..34]);
        let mut dests = [Pubkey::default(); 4];
        for (i, d) in dests.iter_mut().enumerate() {
            let off = 34 + i * 32;
            *d = Pubkey::new_from_array(canonical_bytes[off..off + 32].try_into().unwrap());
        }
        let mint = Pubkey::new_from_array(canonical_bytes[162..194].try_into().unwrap());
        let inst = &mut ctx.accounts.instance;
        inst.seed_instance = _seed_instance;
        inst.merchant_key = mk;
        inst.dests = dests;
        inst.mint = mint;
        Ok(())
    }

    /// Fund a purchase entry (F4.3). Atomic rejection: `init` fails if the entry
    /// account already exists (duplicate id), and the handler reverts on a past
    /// `T_lapse` or an `entry_id` that does not recompute from the parameters
    /// (F4-c). The entry records its `seed_instance` so later authorization binds
    /// to this instance. No value enters the instance outside an entry.
    #[allow(clippy::too_many_arguments)]
    pub fn fund_entry(
        ctx: Context<FundEntry>,
        entry_id: [u8; 32],
        nonce: [u8; 32],
        amount: u128,
        t_open: u64,
        t_lapse: u64,
        contest: u64,
        refund_account: Pubkey,
    ) -> Result<()> {
        require!(amount > 0, KitError::ZeroAmount);
        require!(amount <= u64::MAX as u128, KitError::ArithmeticDomain); // SPL amounts are u64
        require!(t_open <= t_lapse, KitError::BadInputs); // else the reclaim window is empty
                                                          // The deposit MUST be on the instance's bound settlement mint — a fake-mint
                                                          // deposit cannot occupy the entry (closes the free-squat / merchant-rob).
        require!(
            ctx.accounts.mint.key() == ctx.accounts.instance.mint,
            KitError::WrongMint
        );
        let now = Clock::get()?.unix_timestamp as u64;
        require!(t_lapse >= now, KitError::LapsePast);
        let seed_instance = ctx.accounts.instance.seed_instance;
        let recomputed = derive_entry_id(&seed_instance, &nonce, amount, t_open, t_lapse, contest);
        require!(recomputed == entry_id, KitError::IdMismatch);

        let e = &mut ctx.accounts.entry;
        e.seed_instance = seed_instance;
        e.nonce = nonce;
        e.amount = amount;
        e.t_open = t_open;
        e.t_lapse = t_lapse;
        e.contest = contest;
        e.opened_at = 0;
        e.state = EntryState::Funded;
        e.distributed = false;
        e.refund_account = refund_account;

        // Atomic escrow deposit: create THIS entry's escrow token
        // account (SPL authority = the instance PDA) and transfer the meed from
        // the funder into it, in the same instruction that creates the entry — so
        // whoever creates the entry is whoever deposits. A squatter must fund their
        // own escrow, and a refund then returns only their own money.
        let escrow_bump = [ctx.bumps.escrow];
        let escrow_seeds: &[&[u8]] = &[b"escrow", entry_id.as_ref(), &escrow_bump];
        let instance_key = ctx.accounts.instance.key();
        create_escrow_token_account(
            &ctx.accounts.funder.to_account_info(),
            &ctx.accounts.escrow.to_account_info(),
            &ctx.accounts.mint.to_account_info(),
            &instance_key,
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            escrow_seeds,
        )?;
        let deposit = u64::try_from(amount).map_err(|_| KitError::ArithmeticDomain)?;
        spl_transfer(
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.funder_token.to_account_info(),
            &ctx.accounts.escrow.to_account_info(),
            &ctx.accounts.funder.to_account_info(),
            deposit,
        )?;
        Ok(())
    }

    /// Attest (F4.3): the bound merchant releases; `FUNDED`/`RECLAIM_OPEN` →
    /// `ATTESTED`, terminal. A `FUNDED` entry past `T_lapse` is logically LAPSED
    /// and rejects (terminal is terminal); a `RECLAIM_OPEN` entry stays
    /// attestable until it is executed.
    pub fn attest(ctx: Context<MerchantAction>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &mut ctx.accounts.entry;
        guard_active(e, now)?;
        e.state = EntryState::Attested;
        Ok(())
    }

    /// Attest with a **detached Ed25519 attestation** (F3.5 — the M5 hardening
    /// that closes the M0.5 merchant-as-signer simplification). *Anyone* may relay
    /// the transaction; authorization is a detached signature by the bound merchant
    /// key over the **canonical F3.5 message** — `"PayTPv1-attest" ‖ 0x00 ‖ TLV(0x00
    /// NONCE, 0x01 ENTRY_ID)`, byte-identical to the core's F3.5 attestation so
    /// one signed object verifies cross-impl — checked by the **ed25519 precompile** and
    /// cross-checked here via the Instructions sysvar. The merchant need not be online
    /// to submit — it only had to sign once.
    pub fn attest_detached(ctx: Context<AttestDetached>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &ctx.accounts.entry;
        // Re-derive the entry_id the attestation must commit to, from the entry's
        // own recorded parameters (F4-c) — never a caller argument.
        let entry_id = derive_entry_id(
            &e.seed_instance,
            &e.nonce,
            e.amount,
            e.t_open,
            e.t_lapse,
            e.contest,
        );
        let expected = attest_message(&e.nonce, &entry_id);
        verify_detached_ed25519(
            &ctx.accounts.instructions.to_account_info(),
            &ctx.accounts.instance.merchant_key,
            &expected,
        )?;
        let e = &mut ctx.accounts.entry;
        guard_active(e, now)?;
        e.state = EntryState::Attested;
        Ok(())
    }

    /// Cancel (F4.3): merchant refunds; `FUNDED`/`RECLAIM_OPEN` → `CANCELLED`,
    /// no contest delay. Same lapse boundary as `attest`.
    pub fn cancel(ctx: Context<MerchantAction>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &mut ctx.accounts.entry;
        guard_active(e, now)?;
        e.state = EntryState::Cancelled;
        Ok(())
    }

    /// Lapse (F4.3): permissionless terminal transition for a `FUNDED` entry whose
    /// `T_lapse` has passed with no attestation, cancellation, or open reclaim —
    /// `FUNDED` → `LAPSED` [claimable by the recipients].
    pub fn lapse(ctx: Context<EntryOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &mut ctx.accounts.entry;
        require!(matches!(e.state, EntryState::Funded), KitError::Terminal);
        require!(now > e.t_lapse, KitError::Window);
        e.state = EntryState::Lapsed;
        Ok(())
    }

    /// Open reclaim (F4.3): permissionless, `now ∈ [T_open, T_lapse]`,
    /// `FUNDED` → `RECLAIM_OPEN`.
    pub fn open_reclaim(ctx: Context<EntryOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &mut ctx.accounts.entry;
        require!(matches!(e.state, EntryState::Funded), KitError::Terminal);
        require!(now >= e.t_open && now <= e.t_lapse, KitError::Window);
        e.state = EntryState::ReclaimOpen;
        e.opened_at = now;
        Ok(())
    }

    /// Execute reclaim (F4.3): `RECLAIM_OPEN`, rail time strictly `> T_exec`
    /// (`opened_at + contest`) → `RECLAIMED`. `saturating_add` keeps a huge
    /// `contest` from wrapping `T_exec` below `now` and firing early.
    pub fn execute_reclaim(ctx: Context<EntryOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        let e = &mut ctx.accounts.entry;
        require!(matches!(e.state, EntryState::ReclaimOpen), KitError::Window);
        require!(
            now > e.opened_at.saturating_add(e.contest),
            KitError::Window
        );
        e.state = EntryState::Reclaimed;
        Ok(())
    }

    /// Fund a channel claim-record (F4.2) — key derived from `(channel_id,
    /// ckpt_ref, P)`; **windowless, no reclaim path exists**. Atomic-reject on a
    /// duplicate key. There is no instruction that reclaims a claim-record, so the
    /// settle-then-reclaim theft is unwritable.
    pub fn fund_claim_record(
        ctx: Context<FundClaimRecord>,
        key: [u8; 32],
        channel_id: [u8; 8],
        ckpt_ref: [u8; 32],
        p: u128,
    ) -> Result<()> {
        require!(p > 0, KitError::ZeroAmount);
        let recomputed = derive_claim_record_id(
            &ctx.accounts.instance.seed_instance,
            &channel_id,
            &ckpt_ref,
            p,
        );
        require!(recomputed == key, KitError::IdMismatch);
        // Per-destination division (F7-d/F7.3): the bound `instance.dests` are hashed into
        // `seed_instance` at deploy, so roles sharing a destination floor once on the
        // combined weight (mirrors `advance_channel_meed` / the Tier-0 `MeedInstance`).
        let dests = ctx.accounts.instance.dests;
        distribute_p_into(&mut ctx.accounts.claim_record, &dests, p)?;
        Ok(())
    }

    /// Distribute a delivered entry's escrowed meed to the bound destinations
    /// (F7-d, real SPL custody). **The guardrail:** only an `Attested`
    /// (or `Lapsed`-to-recipients) entry pays out — never `Funded`, `ReclaimOpen`,
    /// or `Reclaimed`, so value never leaves a still-reclaimable entry. The
    /// destination token accounts MUST be the ones the instance committed
    /// (bound in `seed_instance`), so an attacker cannot redirect the split. Each
    /// **destination's** share is `paytp_f7::claimable_d` on the weight aggregated by
    /// destination (F7-d/F7.3: roles sharing a fund floor once on the combined `bp_d`,
    /// not per-role); the escrow is drained by the instance-PDA authority via CPI;
    /// the sub-unit residue stays in escrow (dust, §10.2).
    pub fn distribute(ctx: Context<Distribute>) -> Result<()> {
        let e = &ctx.accounts.entry;
        require!(
            matches!(e.state, EntryState::Attested | EntryState::Lapsed),
            KitError::NotDeliverable // never a reclaimable state
        );
        require!(!e.distributed, KitError::AlreadyDistributed);
        let amount = e.amount;

        // Escrow↔entry binding: the escrow MUST be THIS entry's PDA-derived escrow,
        // so a distribution can never drain another entry's (or a victim's) escrow.
        require!(
            ctx.accounts.escrow.key() == entry_escrow(&entry_id_of(e)),
            KitError::WrongEscrow
        );

        // Destination binding: the passed token accounts MUST equal the instance's
        // committed destinations — the theft closure.
        let dests = ctx.accounts.instance.dests;
        let passed = [
            ctx.accounts.dest0.key(),
            ctx.accounts.dest1.key(),
            ctx.accounts.dest2.key(),
            ctx.accounts.dest3.key(),
        ];
        for (got, want) in passed.iter().zip(dests.iter()) {
            require!(got == want, KitError::WrongDestination);
        }

        // Sign transfers as the instance PDA (the escrow's SPL authority).
        let seed_instance = ctx.accounts.instance.seed_instance;
        let bump = [ctx.bumps.instance];
        let signer: &[&[u8]] = &[b"instance", seed_instance.as_ref(), &bump];

        // Per-destination division (F7-d/F7.3): roles sharing a destination floor ONCE on
        // the combined weight `bp_d`, paid a single transfer at that destination's
        // canonical (first-naming) slot; folded slots (`bp_d == 0`) transfer nothing.
        // Per-role flooring would strand up to one sub-unit per shared destination in
        // escrow (`⌊a⌋ + ⌊b⌋ ≤ ⌊a + b⌋`), persistently underpaying a chronically-shared
        // fallback dest. Mirrors `advance_channel_meed` / the Tier-0 `MeedInstance`.
        // This is a one-shot payout (gated by `entry.distributed`) with no cumulative
        // `paid`, so no by-destination regroup is needed; the sub-unit residue stays in
        // escrow (dust, §10.2).
        let (_canon, bp_d) = aggregate_bp_by_dest(&dests, &SCHEMA_01_BP)?;
        let pv = U256::from(amount);
        let dest_ais = [
            ctx.accounts.dest0.to_account_info(),
            ctx.accounts.dest1.to_account_info(),
            ctx.accounts.dest2.to_account_info(),
            ctx.accounts.dest3.to_account_info(),
        ];
        for (i, &bp) in bp_d.iter().enumerate() {
            // Folded slot: its weight is paid at its destination's canonical slot.
            if bp == 0 {
                continue;
            }
            let share = paytp_f7::claimable_d(&pv, bp, SCHEMA_01_BP_TOTAL, &U256::ZERO);
            // `entry.amount ≤ u64::MAX` (fund_entry), so every share fits u64 — but
            // convert checked (never a silent truncation).
            let share =
                u64::try_from(u128::try_from(share).map_err(|_| KitError::ArithmeticDomain)?)
                    .map_err(|_| KitError::ArithmeticDomain)?;
            if share == 0 {
                continue;
            }
            spl_transfer_signed(
                &ctx.accounts.token_program,
                &ctx.accounts.escrow.to_account_info(),
                &dest_ais[i],
                &ctx.accounts.instance.to_account_info(),
                share,
                signer,
            )?;
        }
        ctx.accounts.entry.distributed = true;
        Ok(())
    }

    /// Refund a Cancelled/Reclaimed entry's escrow to the payer's recorded refund
    /// account (F4.3 — refunds go only to the pointer recorded at funding). Gated
    /// on a terminal-refundable state and the escrow↔entry binding; sets the
    /// settled flag so an escrow is never both refunded and distributed.
    pub fn refund(ctx: Context<Refund>) -> Result<()> {
        let e = &ctx.accounts.entry;
        require!(
            matches!(e.state, EntryState::Cancelled | EntryState::Reclaimed),
            KitError::NotRefundable
        );
        require!(!e.distributed, KitError::AlreadyDistributed);
        require!(
            ctx.accounts.escrow.key() == entry_escrow(&entry_id_of(e)),
            KitError::WrongEscrow
        );
        require!(
            ctx.accounts.refund_dest.key() == e.refund_account,
            KitError::WrongDestination
        );
        let amount = u64::try_from(e.amount).map_err(|_| KitError::ArithmeticDomain)?;
        let seed_instance = ctx.accounts.instance.seed_instance;
        let bump = [ctx.bumps.instance];
        let signer: &[&[u8]] = &[b"instance", seed_instance.as_ref(), &bump];
        spl_transfer_signed(
            &ctx.accounts.token_program,
            &ctx.accounts.escrow.to_account_info(),
            &ctx.accounts.refund_dest.to_account_info(),
            &ctx.accounts.instance.to_account_info(),
            amount,
            signer,
        )?;
        ctx.accounts.entry.distributed = true; // settled — no later distribute
        Ok(())
    }

    /// Deploy a **baseline split** (F4-d), the on-chain sibling to the meed
    /// instance. `seed_split` is the PDA seed; the program **recomputes it from
    /// `canonical_bytes`** (`derive_seed_split`) and binds the merchant-net and
    /// meed destinations that preimage commits — so a rogue destination set
    /// derives a different `seed_split` → a different PDA, and cannot occupy the
    /// honest split. Counterfactual + idempotent (Anchor `init` rejects a second
    /// deploy at the same PDA).
    ///
    /// Preimage (spike convention, as for the instance): `[0x00,0x20,MERCHANT_KEY(32)]`
    /// ‖ MERCHANT_NET(32) ‖ 4 meed dests(128) ‖ MINT(32) = 226 bytes. The
    /// merchant-net destination is committed here because the formal meed vector
    /// prices only the meed roles; binding it to the address is what keeps the
    /// 99% seat un-redirectable (a design point flagged for the spec).
    pub fn deploy_split(
        ctx: Context<DeploySplit>,
        _seed_split: [u8; 32],
        canonical_bytes: Vec<u8>,
    ) -> Result<()> {
        require!(
            derive_seed_split(&canonical_bytes) == _seed_split,
            KitError::IdMismatch
        );
        require!(
            canonical_bytes.len() >= 34 + 32 + 128 + 32
                && canonical_bytes[0] == 0x00
                && canonical_bytes[1] == 0x20,
            KitError::BadInputs
        );
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&canonical_bytes[2..34]);
        let merchant_net = Pubkey::new_from_array(canonical_bytes[34..66].try_into().unwrap());
        let mut dests = [Pubkey::default(); 4];
        for (i, d) in dests.iter_mut().enumerate() {
            let off = 66 + i * 32;
            *d = Pubkey::new_from_array(canonical_bytes[off..off + 32].try_into().unwrap());
        }
        let mint = Pubkey::new_from_array(canonical_bytes[194..226].try_into().unwrap());
        // Prefund-tolerant create (a public-quote dust of the
        // split PDA would brick Anchor `init`). Re-deploy guard: an already-created
        // split has non-empty data (only our PDA-signed allocate can give it data).
        let split_ai = ctx.accounts.split.to_account_info();
        require!(split_ai.data_is_empty(), KitError::BadInputs);
        let space: u64 = 8 + 32 + 32 + 32 + 128 + 32 + 5 * 16;
        let bump = [ctx.bumps.split];
        let seeds: &[&[u8]] = &[b"split", _seed_split.as_ref(), &bump];
        create_pda_data_account(
            &ctx.accounts.payer.to_account_info(),
            &split_ai,
            space,
            &ctx.accounts.system_program.to_account_info(),
            seeds,
        )?;
        let split = Split {
            seed_split: _seed_split,
            merchant_key: mk,
            merchant_net,
            dests,
            mint,
            paid: [0u128; 5],
        };
        let mut data = split_ai.try_borrow_mut_data()?;
        let mut writer: &mut [u8] = &mut data;
        split.try_serialize(&mut writer)?;
        Ok(())
    }

    /// **Permissionless per-seat `split_claim`** (F4-d / Part 5 / F7.3): withdraw
    /// ONE seat's cumulative accrued share from the split vault. `seat` is 0 for
    /// the merchant-net (99%) seat or 1..=4 for the schema-0x01 meed roles.
    ///
    /// The entitlement floors over the **cumulative total received** —
    /// `total_received = vault_balance + Σ paid` (the vault only ever loses funds
    /// via this instruction, so `Σ paid` reconstructs the historical inflow) — so
    /// splitting a payment into sub-threshold amounts cannot strand the meed
    /// (the carry accrues cumulatively), and a re-claim with no new receipts owes
    /// zero. **Per-DESTINATION flooring (F7-d/F7.3):** the four meed seats aggregate by
    /// destination — roles naming one fund account floor ONCE on the combined weight,
    /// drawn by the canonical (first-naming) seat; the shared later seats owe nothing.
    /// Per-seat flooring would strand up to `(shared_roles − 1)` sub-units on a
    /// chronically-shared fund (`03-tier0-objects:40`). The merchant seat is a
    /// separate recipient, never merged with a meed dest (mirrors the RI
    /// `split_recipients`). **Per-recipient and independent**: a closed/frozen/
    /// misconfigured destination blocks only its own claim, never the others (no
    /// all-or-nothing push), so no single downstream account can hold the vault
    /// hostage. Baseline atomicity holds: a claim withdraws only its own vector-bound
    /// destination share, and the merchant seat is just seat 0 with no privileged path.
    pub fn split_claim(ctx: Context<SplitClaim>, seat: u8) -> Result<()> {
        require!((seat as usize) < 5, KitError::BadInputs);
        let seed_split = ctx.accounts.split.seed_split;
        let mint = ctx.accounts.split.mint;
        let split_key = ctx.accounts.split.key();
        // Aggregate the four MEED destinations by destination (F7-d/F7.3): roles naming
        // one dest floor ONCE on the combined weight. The merchant seat is a SEPARATE
        // recipient, NEVER merged with a meed dest — this mirrors the RI
        // `VirtualRail::split_recipients`, which appends the merchant AFTER the meed-by-dest
        // fold (so even a merchant_net that coincides with a meed dest floors independently).
        let meed_dests = ctx.accounts.split.dests;
        let (meed_canon, meed_bp_d) = aggregate_bp_by_dest(&meed_dests, &SCHEMA_01_BP)?;

        // Which weight and bound destination this seat draws, and whether it is a meed
        // seat FOLDED into an earlier seat naming the same destination. Folded slots hold
        // `meed_bp_d == 0`; their weight is drawn by the canonical (first-naming) seat, so
        // `bp` there is unused (we return before it is read).
        let (bp, want_dest, folded) = if seat == 0 {
            (SPLIT_MERCHANT_BP, ctx.accounts.split.merchant_net, false)
        } else {
            let m = (seat - 1) as usize;
            (
                meed_bp_d[m],
                ctx.accounts.split.dests[m],
                meed_canon[m] != m,
            )
        };
        // The vault MUST be the split PDA's ATA on the bound mint — the only account
        // a plain exact-svm client pays (`TransferChecked → ATA(payTo)`).
        require!(
            ctx.accounts.vault.key() == associated_token_account(&split_key, &mint),
            KitError::WrongVault
        );
        require!(
            ctx.accounts.dest.key() == want_dest,
            KitError::WrongDestination
        );
        // A folded meed seat draws nothing — its destination's full aggregate is drawn by
        // the canonical seat. Per-seat flooring would strand up to `(shared_roles − 1)`
        // sub-units on a shared fund; per-destination pays it once on `bp_d`. The dest
        // binding above still fires, so a wrong-dest claim is refused, not silently skipped.
        if folded {
            return Ok(());
        }

        let balance = read_token_amount(&ctx.accounts.vault.try_borrow_data()?)?;
        // total_received = vault_balance + Σ paid (checked; the vault loses funds
        // only through claims, so this is the exact cumulative inflow — layout-invariant:
        // Σ over ALL slots, unaffected by the per-destination regroup below).
        let mut sum_paid: u128 = 0;
        for p in ctx.accounts.split.paid.iter() {
            sum_paid = sum_paid.checked_add(*p).ok_or(KitError::ArithmeticDomain)?;
        }
        let total_received = (balance as u128)
            .checked_add(sum_paid)
            .ok_or(KitError::ArithmeticDomain)?;
        // Regroup the stored `paid` for THIS destination (layout-robust): the merchant seat
        // is its own recipient (`paid[0]`); a meed destination's baseline is Σ the paid of
        // every meed seat naming it. So a legacy PER-SEAT record (a shared dest's cumulative
        // spread across its slots — e.g. after an in-place program upgrade) transitions to
        // the per-destination layout instead of DOUBLE-PAYING (the already-paid shares of
        // its sibling slots would otherwise be missed and re-sent). A fresh record's folded
        // slots are 0, so this equals the plain `paid[seat]` for the common case.
        let paid_dest: u128 = if seat == 0 {
            ctx.accounts.split.paid[0]
        } else {
            let m = (seat - 1) as usize; // canonical meed index (folded seats returned above)
            let mut acc: u128 = 0;
            for (j, &c) in meed_canon.iter().enumerate() {
                if c == m {
                    acc = acc
                        .checked_add(ctx.accounts.split.paid[j + 1])
                        .ok_or(KitError::ArithmeticDomain)?;
                }
            }
            acc
        };
        // owed = floor(total_received · bp_d / 10000) − paid_dest (F7.3 incremental, per
        // DESTINATION). `claimable_d` clamps at 0, so a legacy over-paid dest owes nothing
        // (no clawback) and self-heals on its next receipt.
        let owed = paytp_f7::claimable_d(
            &U256::from(total_received),
            bp,
            SPLIT_BP_TOTAL,
            &U256::from(paid_dest),
        );
        let owed = u64::try_from(u128::try_from(owed).map_err(|_| KitError::ArithmeticDomain)?)
            .map_err(|_| KitError::ArithmeticDomain)?;
        if owed == 0 {
            return Ok(());
        }
        let new_paid = paid_dest
            .checked_add(owed as u128)
            .ok_or(KitError::ArithmeticDomain)?;

        let bump = [ctx.bumps.split];
        let signer: &[&[u8]] = &[b"split", seed_split.as_ref(), &bump];
        spl_transfer_signed(
            &ctx.accounts.token_program,
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.dest.to_account_info(),
            &ctx.accounts.split.to_account_info(),
            owed,
            signer,
        )?;
        // Commit only after the transfer succeeds (a revert undoes everything). Record the
        // destination's cumulative at this (canonical) seat's slot, and FOLD its legacy
        // shared meed slots to 0 so `Σ paid` stays exact and the destination is never
        // double-counted on a later claim. A fresh record's shared slots are already 0
        // (a no-op); the merchant seat has none.
        if seat != 0 {
            let m = (seat - 1) as usize;
            for (j, &c) in meed_canon.iter().enumerate() {
                if c == m && j != m {
                    ctx.accounts.split.paid[j + 1] = 0;
                }
            }
        }
        ctx.accounts.split.paid[seat as usize] = new_paid;
        Ok(())
    }

    /// Advance a channel's cumulative meed watermark to `target_p` (Option W,
    /// F4.2/F6-o) — the per-channel replacement for the per-round `fund_claim_record`
    /// on the channel path. The `ChannelMeed` account is keyed by the **signed**
    /// `(seed_instance, CHANNEL_ID)` — per-channel, **never a lineage/root** (that
    /// keying is what kills the v2 escrow-strand and forgeable-root breaks) — and holds
    /// the cumulative aggregate `funded_p` plus per-destination cumulative `paid[d]`. An
    /// advance distributes the delta `ΔP = target_p − funded_p` over the **cumulative**
    /// target, **aggregating by destination first** (`bp_d = Σ_r bp_r` per dest,
    /// `paid[d] = floor(target_p · bp_d / Σbp)`, the F7-d/F7.3 per-destination flooring —
    /// roles sharing a dest floor once on the combined weight, never per-role, mirroring
    /// `MeedInstance::new`), carries the sub-unit dust as §10.2 `residue`, and commits
    /// `funded_p = target_p`.
    ///
    /// **Idempotent by absolute position:** `target_p ≤ funded_p` distributes nothing —
    /// a drop-then-redraw, a crash retry, or a stale/duplicate re-advance is a no-op,
    /// never a second payout. The monotone `funded_p` is the on-chain exactly-once
    /// record that closes the cross-checkpoint double-draw (F6-o) **by
    /// construction**: the interim draw "to W₁" and the close draw "to W_final ≥ W₁"
    /// operate on the SAME record, so the close moves only `W₁ → W_final`, whatever
    /// checkpoint each names.
    ///
    /// **Custody boundary (M5 — unchanged from `fund_claim_record`):** like the
    /// per-round claim-record it replaces, this records the cumulative division
    /// **counterfactually**; real source-debited SPL custody + per-role delivery is the
    /// deferred real-rail (M5) hardening. The rail adapter enacts the value movement
    /// (source-debit + per-role delivery, at finality) and sets the
    /// `advanced_channel_meed` rail fact ONLY on that distributing path — so a
    /// non-distributing forge is refused at the rail-fact layer exactly as F6-m
    /// closes it for `funds_claim`. Prefund-tolerant (the address is public-derivable);
    /// no close/re-init (the watermark only ever advances).
    pub fn advance_channel_meed(
        ctx: Context<AdvanceChannelMeed>,
        channel_id: [u8; 8],
        target_p: u128,
    ) -> Result<()> {
        let cr_ai = ctx.accounts.channel_meed.to_account_info();
        let seed_instance = ctx.accounts.instance.seed_instance;

        // Load the existing watermark, or (first advance) create it prefund-tolerantly.
        // A `target_p == 0` first advance records nothing and creates no rent account.
        let mut cr: ChannelMeed = if cr_ai.data_is_empty() {
            if target_p == 0 {
                return Ok(());
            }
            let space: u64 = 8 + 32 + 8 + 1 + 16 + 4 * 16 + 16;
            let bump = [ctx.bumps.channel_meed];
            let seeds: &[&[u8]] = &[
                b"chanmeed",
                seed_instance.as_ref(),
                channel_id.as_ref(),
                &bump,
            ];
            create_pda_data_account(
                &ctx.accounts.funder.to_account_info(),
                &cr_ai,
                space,
                &ctx.accounts.system_program.to_account_info(),
                seeds,
            )?;
            ChannelMeed {
                seed_instance,
                channel_id,
                version: CHANMEED_VERSION,
                funded_p: 0,
                paid: [0u128; 4],
                residue: 0,
            }
        } else {
            let data = cr_ai.try_borrow_data()?;
            ChannelMeed::try_deserialize(&mut &data[..])?
        };

        // Binding: the watermark is bound to THIS instance and channel (also enforced
        // by the PDA seeds; re-checked defensively on the deserialized reuse path so a
        // future non-PDA caller cannot advance a mismatched record).
        require!(
            cr.seed_instance == seed_instance,
            KitError::InstanceMismatch
        );
        require!(cr.channel_id == channel_id, KitError::ChannelMismatch);

        // Idempotent by absolute position: never move the monotone watermark backward.
        if target_p <= cr.funded_p {
            return Ok(());
        }

        // Distribute over the CUMULATIVE target, AGGREGATING BY DESTINATION FIRST
        // (F7-d/F7.3), mirroring `MeedInstance::new`: for each destination `d`,
        // `bp_d = Σ_r bp_r` over the roles naming it, floored ONCE as
        // `paid_d = floor(target_p · bp_d / Σbp)`. Roles sharing a destination (e.g.
        // 0x10/0x12/0x13 → the Development Fund) floor once on the combined weight, never
        // independently — per-role flooring would strand up to one sub-unit per shared
        // destination per advance, so a chronically-shared fallback dest is persistently
        // underpaid. The `instance.dests` are trustworthy: hashed into `seed_instance` at
        // deploy (`deploy_instance`) and the instance PDA is seed-validated on this ix.
        // The `paid[4]` slots stay role-indexed; a destination's aggregated cumulative is
        // recorded at its CANONICAL (first-naming) role index, its shared later slots hold
        // 0. The sub-unit remainder carries as the per-channel §10.2 `residue` (the
        // accepted ≤1 µ-unit chain-boundary dust, F6.6; reverts to merchant/payer — NOT a
        // conservation break).
        // `bp_d` aggregated at each destination's canonical (first-naming) role slot;
        // `canon[i]` is that slot for role `i` (stable across advances — dests are fixed at
        // deploy). The shared `aggregate_bp_by_dest` fold backs every per-destination
        // flooring site (`distribute`, `split_claim`, `distribute_p_into`, this).
        let dests = ctx.accounts.instance.dests;
        let (canon, bp_d) = aggregate_bp_by_dest(&dests, &SCHEMA_01_BP)?;
        let tv = U256::from(target_p);
        let mut distributed: u128 = 0;
        let mut new_paid = [0u128; 4];
        for i in 0..bp_d.len() {
            // A non-canonical slot (`bp_d[i] == 0`, its weight folded into its
            // destination's canonical index) records 0; the canonical slot floors ONCE on
            // the combined `bp_d[i]`.
            if bp_d[i] == 0 {
                continue;
            }
            new_paid[i] = u128::try_from(paytp_f7::claimable_d(
                &tv,
                bp_d[i],
                SCHEMA_01_BP_TOTAL,
                &U256::ZERO,
            ))
            .map_err(|_| KitError::ArithmeticDomain)?;
            distributed = distributed
                .checked_add(new_paid[i])
                .ok_or(KitError::ArithmeticDomain)?;
        }
        // Monotone per DESTINATION (never a clawback): a destination's cumulative may only
        // grow. Compare against the stored `paid` REGROUPED by destination — this is
        // layout-robust, so a record written by an earlier PER-ROLE build (its dest's share
        // spread across the shared slots) transitions to the per-destination layout on its
        // next advance instead of being bricked by a per-slot `0 >= old` check. The
        // transition conserves and can only pay a chronically-shared dest UP toward its
        // correct per-dest floor (the fix's whole point). The spec's isolation for a
        // model change is a fresh CONTRACT/`seed_instance` (fresh PDA, F6-o), so this is
        // the defense-in-depth backstop for an in-place program upgrade.
        let mut old_by_dest = [0u128; 4];
        for (i, &c) in canon.iter().enumerate() {
            old_by_dest[c] = old_by_dest[c]
                .checked_add(cr.paid[i])
                .ok_or(KitError::ArithmeticDomain)?;
        }
        for (i, &np) in new_paid.iter().enumerate() {
            require!(np >= old_by_dest[i], KitError::ArithmeticDomain);
        }
        cr.paid = new_paid;
        cr.residue = target_p
            .checked_sub(distributed)
            .ok_or(KitError::ArithmeticDomain)?;
        cr.funded_p = target_p;

        // Commit only after every check passes (a revert undoes everything; the
        // watermark advances atomically or not at all).
        let mut data = cr_ai.try_borrow_mut_data()?;
        let mut writer: &mut [u8] = &mut data;
        cr.try_serialize(&mut writer)?;
        Ok(())
    }
}

/// The entry's escrow token account address — a PDA bound to the entry, so a
/// distribution/refund can only ever drain THIS entry's escrow, never another
/// entry's (the escrow↔entry binding).
fn entry_escrow(entry_id: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"escrow", entry_id.as_ref()], &crate::ID).0
}

/// Re-derive an entry's id from its own recorded parameters (F4-c) — never a
/// caller argument.
fn entry_id_of(e: &Entry) -> [u8; 32] {
    derive_entry_id(
        &e.seed_instance,
        &e.nonce,
        e.amount,
        e.t_open,
        e.t_lapse,
        e.contest,
    )
}

/// Aggregate per-role basis points onto each destination's **canonical** (first-naming)
/// role slot — the ONE fold behind every per-destination flooring site (`distribute`,
/// `split_claim`, `distribute_p_into`, `advance_channel_meed`), the F7-d/F7.3 rule that
/// two roles naming one destination floor **once** on the combined weight, never
/// independently (per-role flooring is superadditive-lossy: `⌊a⌋ + ⌊b⌋ ≤ ⌊a + b⌋`, so it
/// strands up to one sub-unit per shared destination per round). Mirrors the RI
/// `MeedInstance::new` / `VirtualRail::split_recipients` dedup fold; the contract
/// keeps the fixed `[_; N]` layout (no `Vec`) so it records the aggregate at the
/// canonical slot instead of collapsing the vector.
///
/// Returns `(canon, bp_d)`: `canon[i]` is the first index naming `dests[i]` (so
/// `canon[i] == i` marks a canonical slot, `!= i` a folded one); `bp_d[c]` is
/// `Σ weights[i]` over every role naming that destination, recorded at the canonical
/// slot `c` (folded slots hold `0`). The subtotal accumulates with `checked_add` so a
/// malformed weight vector fails **closed** (`ArithmeticDomain`) rather than wrapping to
/// `0` (which would zero the divisor's numerator and strand the payout).
fn aggregate_bp_by_dest<const N: usize>(
    dests: &[Pubkey; N],
    weights: &[u32; N],
) -> Result<([usize; N], [u32; N])> {
    let mut canon = [0usize; N];
    let mut bp_d = [0u32; N];
    for i in 0..N {
        let mut c = i;
        for j in 0..i {
            if dests[j] == dests[i] {
                c = j;
                break;
            }
        }
        canon[i] = c;
        bp_d[c] = bp_d[c]
            .checked_add(weights[i])
            .ok_or(KitError::ArithmeticDomain)?;
    }
    Ok((canon, bp_d))
}

/// Record the F7-d split of `P` among the schema-0x01 roles into a claim-record
/// (on-chain division, shared `paytp-f7`) — the channel-side settled record. Aggregates
/// **by destination first** (`aggregate_bp_by_dest`): a destination's cumulative is
/// recorded ONCE at its canonical role slot on the combined weight `bp_d`, the shared
/// later slots hold `0` (F7-d/F7.3, mirroring `advance_channel_meed` / the Tier-0
/// `MeedInstance`). Called only from `fund_claim_record` on a freshly-`init`ed record, so
/// there is no cumulative `paid` to regroup — a one-shot per-destination division.
fn distribute_p_into(cr: &mut ClaimRecord, dests: &[Pubkey; 4], p: u128) -> Result<()> {
    cr.amount = p;
    let (_canon, bp_d) = aggregate_bp_by_dest(dests, &SCHEMA_01_BP)?;
    let pv = U256::from(p);
    let mut distributed: u128 = 0;
    for (i, &bp) in bp_d.iter().enumerate() {
        // A folded slot (`bp == 0`) records 0; the canonical slot floors ONCE on the
        // combined weight `bp`.
        let share = if bp == 0 {
            0
        } else {
            u128::try_from(paytp_f7::claimable_d(
                &pv,
                bp,
                SCHEMA_01_BP_TOTAL,
                &U256::ZERO,
            ))
            .map_err(|_| KitError::ArithmeticDomain)?
        };
        cr.shares[i] = share;
        distributed = distributed
            .checked_add(share)
            .ok_or(KitError::ArithmeticDomain)?;
    }
    // `distributed ≤ p` (Σ of floors ≤ P), so the checked_sub never underflows.
    cr.residue = p
        .checked_sub(distributed)
        .ok_or(KitError::ArithmeticDomain)?;
    Ok(())
}

/// The canonical F3.5 attestation message a merchant signs: `"PayTPv1-attest" ‖ 0x00 ‖
/// TLV(0x00 NONCE, 0x01 ENTRY_ID)` (byte-identical to core F3.5, cross-impl
/// verifiable). Domain-separated so a signature over it can mean nothing else.
///
/// Cross-chain replay (a devnet attestation reused on mainnet) is closed by
/// `entry_id` itself: it commits to `seed_instance`, which commits to the
/// `ADDRESS_INPUTS` — including the **CAIP-2-scoped settlement asset**, whose
/// chain identifier differs per network (F3-f). So the "same" entry on two
/// networks derives two different ids, and a signature over one never matches the
/// other.
fn attest_message(nonce: &[u8; 32], entry_id: &[u8; 32]) -> Vec<u8> {
    // The ONE canonical F3.5 message: identical byte-for-byte to the core's
    // `attest::covered_bytes(Attestation, nonce, entry_id)` — the label + F1-h delimiter
    // over the F3.5 TLV content object `0x00 NONCE(32) · 0x01 ENTRY_ID(32)` (each field
    // `type ‖ LEB128(len=0x20) ‖ value`). Committing the NONCE too (not entry_id alone)
    // makes on-chain and core attestations one interoperable object, cross-impl verifiable.
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

/// Confirm the transaction carries an ed25519-precompile instruction that verified
/// a signature by `merchant_key` over exactly `expected_msg` (F3.5). The precompile
/// (run by the runtime) proves the signature is valid; this introspection proves it
/// bound the RIGHT key and message. The offsets MUST be self-referential
/// (`u16::MAX` instruction index) so the bytes the precompile verified are the ones
/// read here — an attacker cannot point them at another instruction's data.
fn verify_detached_ed25519(
    ix_sysvar: &AccountInfo,
    merchant_key: &[u8; 32],
    expected_msg: &[u8],
) -> Result<()> {
    use solana_instructions_sysvar::load_instruction_at_checked;
    // Scan every ed25519 instruction and accept if ANY of them verified the bound
    // key over the expected message. A non-matching ed25519 instruction is SKIPPED,
    // not fatal — so a relayer may batch several detached attestations (each with
    // its own ed25519 instruction) in one transaction. The precompile has already
    // verified every ed25519 instruction in the tx, so a match here is a valid
    // signature by construction.
    let mut i = 0usize;
    while let Ok(ix) = load_instruction_at_checked(i, ix_sysvar) {
        i += 1;
        if ix.program_id != solana_sdk_ids::ed25519_program::ID {
            continue;
        }
        let d = &ix.data;
        if d.len() < 16 || d[0] != 1 {
            continue; // want exactly one signature in this instruction
        }
        // Ed25519SignatureOffsets (little-endian u16s, sequential from byte 2):
        //   [2..4] sig_off, [4..6] sig_ix, [6..8] pk_off, [8..10] pk_ix,
        //   [10..12] msg_off, [12..14] msg_len, [14..16] msg_ix.
        let sig_ix = u16::from_le_bytes([d[4], d[5]]);
        let pk_off = u16::from_le_bytes([d[6], d[7]]) as usize;
        let pk_ix = u16::from_le_bytes([d[8], d[9]]);
        let msg_off = u16::from_le_bytes([d[10], d[11]]) as usize;
        let msg_len = u16::from_le_bytes([d[12], d[13]]) as usize;
        let msg_ix = u16::from_le_bytes([d[14], d[15]]);
        // All referenced data MUST live in THIS instruction (index u16::MAX), else
        // the bytes the precompile verified ≠ the bytes read here.
        if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
            continue;
        }
        if d.len() < pk_off + 32 || d.len() < msg_off + msg_len {
            continue;
        }
        if &d[pk_off..pk_off + 32] == merchant_key && &d[msg_off..msg_off + msg_len] == expected_msg
        {
            return Ok(()); // a valid detached attestation for this entry
        }
    }
    Err(KitError::BadAttestation.into())
}

/// The `attest`/`cancel` active-entry guard (F4.3): a `FUNDED` entry is actionable
/// only up to `T_lapse` (past it, it is terminal LAPSED); a `RECLAIM_OPEN` entry
/// stays actionable until executed; every other state is terminal.
fn guard_active(e: &Entry, now: u64) -> Result<()> {
    match e.state {
        EntryState::Funded => require!(now <= e.t_lapse, KitError::Lapsed),
        EntryState::ReclaimOpen => {}
        _ => return Err(KitError::Terminal.into()),
    }
    Ok(())
}

// --- Accounts ---

#[account]
pub struct Instance {
    pub seed_instance: [u8; 32],
    pub merchant_key: [u8; 32],
    /// The schema-0x01 meed destination token accounts, bound in
    /// `seed_instance` — the distribution can pay only these (theft closure).
    pub dests: [Pubkey; 4],
    /// The settlement SPL mint, bound in `seed_instance` — `fund_entry` accepts a
    /// deposit ONLY on this mint, so a squatter can't occupy an entry with worthless
    /// fake tokens (the escrow always holds the real settlement asset).
    pub mint: Pubkey,
}

#[account]
pub struct Entry {
    /// The instance this entry belongs to — authorizes `attest`/`cancel` (F4.3).
    pub seed_instance: [u8; 32],
    pub nonce: [u8; 32],
    pub amount: u128,
    pub t_open: u64,
    pub t_lapse: u64,
    pub contest: u64,
    pub opened_at: u64,
    pub state: EntryState,
    /// Whether the escrow has been settled — distributed OR refunded (idempotency;
    /// prevents a distribute-then-refund or double payout of the same escrow).
    pub distributed: bool,
    /// The payer's refund token account — where `refund` returns the escrow on a
    /// Cancelled/Reclaimed entry. Recorded at funding (never a caller arg later).
    ///
    /// **Deposit-side constraint (M5 gate residual):** `refund_account` is NOT
    /// committed into `entry_id` — it cannot be, because the merchant re-derives
    /// `entry_id` from its own quote (F4-c) and never sees the payer's refund
    /// pointer. So a squatter could create this entry first with their own
    /// `refund_account`. That is harmless ONLY if the escrow deposit is **atomic
    /// with `fund_entry`** (a squatter then funds their own escrow and a refund
    /// merely returns their own money). The deposit CPI (funder → escrow) is elided
    /// in this spike; when it is built it MUST be coupled to `fund_entry`. Interim:
    /// a conformant wallet checks the recorded `refund_account` before depositing
    /// (the F4.5 instance-liveness duty).
    pub refund_account: Pubkey,
}

/// A claim-record has **no state field and no reclaim path** — its existence is
/// the settled record; terminal at birth (F4.2). It also records the on-chain
/// F7-d division of `amount` (`P`) among the schema-0x01 roles and the carried
/// sub-unit `residue`, computed by the shared `paytp-f7` arithmetic.
#[account]
pub struct ClaimRecord {
    pub amount: u128,
    pub shares: [u128; 4],
    pub residue: u128,
}

/// A channel's cumulative meed watermark (Option W, F4.2/F6-o) — the per-channel
/// replacement for the per-round `ClaimRecord`. Keyed by the **signed** `(seed_instance,
/// CHANNEL_ID)` (never a lineage/root). `funded_p` is the monotone on-chain exactly-once
/// record (the aggregate meed cumulatively funded to this channel's instance);
/// `paid` holds each **destination's** cumulative distributed share (aggregated by
/// destination, F7-d/F7.3 — recorded at the destination's canonical/first-naming role
/// slot, shared later slots hold 0) and `residue` the carried sub-unit dust (§10.2). No
/// state field, no reclaim, no close/re-init — the watermark only ever advances (a
/// `target_p ≤ funded_p` advance is a no-op).
#[account]
pub struct ChannelMeed {
    pub seed_instance: [u8; 32],
    pub channel_id: [u8; 8],
    pub version: u8,
    pub funded_p: u128,
    /// Per-destination cumulative distributed share, recorded at each destination's
    /// canonical (first-naming) role slot (shared later slots hold 0), F7-d/F7.3.
    pub paid: [u128; 4],
    pub residue: u128,
}

#[derive(Accounts)]
#[instruction(seed_instance: [u8; 32])]
pub struct DeployInstance<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32 + 32 + 128 + 32, // disc + seed + merchant_key + dests[4] + mint
        seeds = [b"instance", seed_instance.as_ref()],
        bump
    )]
    pub instance: Account<'info, Instance>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(entry_id: [u8; 32])]
pub struct FundEntry<'info> {
    pub instance: Account<'info, Instance>,
    #[account(
        init,
        payer = funder,
        space = 8 + 32 + 32 + 16 + 8 + 8 + 8 + 8 + 1 + 1 + 32, // + distributed + refund_account
        seeds = [b"entry", entry_id.as_ref()],
        bump
    )]
    pub entry: Account<'info, Entry>,
    /// The entry's escrow token account — created + funded by this instruction; a
    /// PDA bound to the entry (SPL authority set to the instance PDA in the
    /// handler). CHECK: created and validated as the bound escrow PDA here.
    #[account(mut, seeds = [b"escrow", entry_id.as_ref()], bump)]
    pub escrow: UncheckedAccount<'info>,
    /// The settlement mint — validated by the token program at InitializeAccount3.
    /// CHECK: token-program-validated.
    pub mint: UncheckedAccount<'info>,
    /// The funder's source token account on `mint`; debited by `amount` (the funder
    /// is the transfer authority / a tx signer). CHECK: token-program-validated.
    #[account(mut)]
    pub funder_token: UncheckedAccount<'info>,
    #[account(mut)]
    pub funder: Signer<'info>,
    /// CHECK: address-constrained to the SPL Token program.
    #[account(address = SPL_TOKEN_ID)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MerchantAction<'info> {
    pub instance: Account<'info, Instance>,
    /// Bound to the entry's own instance — an attacker cannot supply a rogue
    /// instance to authorize against (F4.3).
    #[account(mut, constraint = entry.seed_instance == instance.seed_instance @ KitError::InstanceMismatch)]
    pub entry: Account<'info, Entry>,
    /// The bound merchant authority (division provenance, F4.3). The spike
    /// requires it as a signer; the M5 hardening verifies a detached Ed25519
    /// attestation against `instance.merchant_key` instead.
    #[account(address = Pubkey::new_from_array(instance.merchant_key))]
    pub merchant: Signer<'info>,
}

#[derive(Accounts)]
pub struct EntryOnly<'info> {
    #[account(mut)]
    pub entry: Account<'info, Entry>,
    /// Anyone may open/execute reclaim or lapse (permissionless, F4.3).
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct AttestDetached<'info> {
    pub instance: Account<'info, Instance>,
    /// Bound to the entry's own instance (F4.3) — as in `MerchantAction`.
    #[account(mut, constraint = entry.seed_instance == instance.seed_instance @ KitError::InstanceMismatch)]
    pub entry: Account<'info, Entry>,
    /// The Instructions sysvar — introspected to confirm the ed25519-precompile
    /// verification of the detached merchant attestation (F3.5). No merchant
    /// signer: authorization is the detached signature, relayable by anyone.
    /// CHECK: address-constrained to the Instructions sysvar.
    #[account(address = solana_sdk_ids::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Distribute<'info> {
    /// The instance — declared with its seeds so the program can sign transfers as
    /// this PDA (the escrow's SPL authority).
    #[account(seeds = [b"instance", instance.seed_instance.as_ref()], bump)]
    pub instance: Account<'info, Instance>,
    #[account(mut, constraint = entry.seed_instance == instance.seed_instance @ KitError::InstanceMismatch)]
    pub entry: Account<'info, Entry>,
    /// The entry's escrow token account (SPL authority = the instance PDA).
    /// CHECK: an SPL token account; the token program enforces its invariants.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: verified against `instance.dests[0]` in the handler.
    #[account(mut)]
    pub dest0: UncheckedAccount<'info>,
    /// CHECK: verified against `instance.dests[1]`.
    #[account(mut)]
    pub dest1: UncheckedAccount<'info>,
    /// CHECK: verified against `instance.dests[2]`.
    #[account(mut)]
    pub dest2: UncheckedAccount<'info>,
    /// CHECK: verified against `instance.dests[3]`.
    #[account(mut)]
    pub dest3: UncheckedAccount<'info>,
    /// CHECK: address-constrained to the SPL Token program.
    #[account(address = SPL_TOKEN_ID)]
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(seeds = [b"instance", instance.seed_instance.as_ref()], bump)]
    pub instance: Account<'info, Instance>,
    #[account(mut, constraint = entry.seed_instance == instance.seed_instance @ KitError::InstanceMismatch)]
    pub entry: Account<'info, Entry>,
    /// CHECK: verified in the handler to be THIS entry's escrow PDA.
    #[account(mut)]
    pub escrow: UncheckedAccount<'info>,
    /// CHECK: verified in the handler to equal `entry.refund_account`.
    #[account(mut)]
    pub refund_dest: UncheckedAccount<'info>,
    /// CHECK: address-constrained to the SPL Token program.
    #[account(address = SPL_TOKEN_ID)]
    pub token_program: UncheckedAccount<'info>,
}

/// A baseline split (F4-d): the merchant-net seat + the four meed
/// destinations, all bound in `seed_split`, so `distribute` can pay only these.
#[account]
pub struct Split {
    pub seed_split: [u8; 32],
    pub merchant_key: [u8; 32],
    /// The merchant-net (99%) destination token account, bound in `seed_split`.
    pub merchant_net: Pubkey,
    /// The four schema-0x01 meed destination token accounts, bound in `seed_split`.
    pub dests: [Pubkey; 4],
    /// The settlement SPL mint, bound in `seed_split`.
    pub mint: Pubkey,
    /// Cumulative amount already claimed — seat 0 = merchant net, seats 1..4 = the meed
    /// roles (F7.3 recipient flooring at withdraw). Aggregated **by destination**: a meed
    /// destination's cumulative is recorded at its canonical (first-naming) seat slot, the
    /// shared later slots hold 0 (roles sharing a fund floor once on the combined weight,
    /// F7-d/F7.3; the merchant seat is a separate recipient). The split is a long-lived
    /// counterfactual address that receives MANY payments; each destination's entitlement
    /// floors over the **cumulative** total received (`vault + Σpaid` — layout-invariant,
    /// summed over ALL slots), so splitting a payment into sub-threshold amounts cannot
    /// strand the meed, and a re-claim with no new receipts owes nothing.
    pub paid: [u128; 5],
}

#[derive(Accounts)]
#[instruction(seed_split: [u8; 32])]
pub struct DeploySplit<'info> {
    /// The split data account — created + written prefund-tolerantly in the
    /// handler (Anchor `init` isn't prefund-tolerant; a public-quote dust would
    /// otherwise brick deploy).
    /// CHECK: PDA-derived here; allocated/assigned/serialized in the handler.
    #[account(mut, seeds = [b"split", seed_split.as_ref()], bump)]
    pub split: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SplitClaim<'info> {
    /// The split — `mut` (records the seat's cumulative paid) and declared with its
    /// seeds so the program signs the transfer as this PDA (the vault's SPL
    /// authority). Permissionless: no signer beyond the tx fee payer (unchecked).
    #[account(mut, seeds = [b"split", split.seed_split.as_ref()], bump)]
    pub split: Account<'info, Split>,
    /// The split PDA's ATA on the bound mint.
    /// CHECK: an SPL token account; validated `== ATA(split, mint)` in the handler.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    /// The seat's destination token account.
    /// CHECK: validated `== the seat's bound destination` in the handler.
    #[account(mut)]
    pub dest: UncheckedAccount<'info>,
    /// CHECK: address-constrained to the SPL Token program.
    #[account(address = SPL_TOKEN_ID)]
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(key: [u8; 32])]
pub struct FundClaimRecord<'info> {
    pub instance: Account<'info, Instance>,
    #[account(
        init,
        payer = funder,
        space = 8 + 16 + 4 * 16 + 16, // disc + amount + shares[4] + residue
        seeds = [b"claim", key.as_ref()],
        bump
    )]
    pub claim_record: Account<'info, ClaimRecord>,
    #[account(mut)]
    pub funder: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(channel_id: [u8; 8])]
pub struct AdvanceChannelMeed<'info> {
    /// The meed instance this channel settles to — declared with its own seeds so
    /// it is the canonical instance PDA (not a spoofed `Instance` account), and its
    /// `seed_instance` binds the watermark's address.
    #[account(seeds = [b"instance", instance.seed_instance.as_ref()], bump)]
    pub instance: Account<'info, Instance>,
    /// The per-channel cumulative meed watermark — created on first advance
    /// (prefund-tolerantly) and reused after; PDA-bound to `(seed_instance,
    /// CHANNEL_ID)`. CHECK: PDA-derived here; allocated/serialized in the handler
    /// (Anchor `init` isn't prefund-tolerant, and this address is public-derivable).
    #[account(
        mut,
        seeds = [b"chanmeed", instance.seed_instance.as_ref(), channel_id.as_ref()],
        bump
    )]
    pub channel_meed: UncheckedAccount<'info>,
    #[account(mut)]
    pub funder: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum KitError {
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("T_lapse already past")]
    LapsePast,
    #[msg("id does not recompute from the supplied parameters")]
    IdMismatch,
    #[msg("malformed ADDRESS_INPUTS preimage")]
    BadInputs,
    #[msg("entry does not belong to the supplied instance")]
    InstanceMismatch,
    #[msg("entry is in a terminal state")]
    Terminal,
    #[msg("entry has lapsed")]
    Lapsed,
    #[msg("window guard")]
    Window,
    #[msg("no valid detached ed25519 merchant attestation for this entry")]
    BadAttestation,
    #[msg("entry is not in a deliverable state (must be Attested or Lapsed)")]
    NotDeliverable,
    #[msg("entry already distributed")]
    AlreadyDistributed,
    #[msg("destination is not one the instance committed")]
    WrongDestination,
    #[msg("escrow is not this entry's bound escrow account")]
    WrongEscrow,
    #[msg("deposit mint is not the instance's bound settlement mint")]
    WrongMint,
    #[msg("entry is not in a refundable state (must be Cancelled or Reclaimed)")]
    NotRefundable,
    #[msg("arithmetic domain")]
    ArithmeticDomain,
    #[msg("vault is not the split PDA's associated token account on the bound mint")]
    WrongVault,
    #[msg("channel meed record does not belong to the supplied channel")]
    ChannelMismatch,
}
