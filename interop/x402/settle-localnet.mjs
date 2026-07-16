// M6.1c — the live on-chain settlement loop on a running local Agave validator.
//
// Proves the full baseline USP end-to-end on a REAL validator (real BPF loader /
// runtime, real SPL tooling), driven by the REAL x402 client's requirement
// selection:
//   1. derive the split address (as a merchant would: seed_split over
//      ADDRESS_INPUTS) and `deploy_split` the on-chain split;
//   2. build a shipped-x402-V1 402 whose `payTo` IS that split PDA; the real
//      `selectPaymentRequirements` (x402@1.2.0) selects it;
//   3. the buyer pays the selected `payTo` with a real exact-svm-shaped
//      `TransferChecked → ATA(split_PDA, mint)` under the shipped 3-instruction cap;
//   4. permissionless `split_claim` divides the vault 99/1 among the merchant
//      seat and the four meed roles — asserted on-chain.
//
// Prereqs: `solana-test-validator` running on :8899 with `paytp_kit` deployed at
// the program id below. Run: `node settle-localnet.mjs`.

import { createHash } from "node:crypto";
import {
  Connection, Keypair, PublicKey, SystemProgram, Transaction,
  TransactionInstruction, ComputeBudgetProgram, sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, createMint,
  getOrCreateAssociatedTokenAccount, getAssociatedTokenAddressSync, mintTo,
  getAccount, createTransferCheckedInstruction,
} from "@solana/spl-token";
import { PaymentRequirementsSchema } from "x402/types";
import { selectPaymentRequirements } from "x402/client";

const RPC = "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey("2ewaMFqZJDwyzeMCD4TZMfiofyydHsWftDvT2h81Boau");
const DECIMALS = 6;
const AMOUNT = 1_000_000n; // 1.0 token
const SCHEMA_01_BP = [50, 10, 30, 10];
const SPLIT_MERCHANT_BP = 10_000 - 100;

let failures = 0;
const ok = (cond, msg) => { console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); if (!cond) failures++; };

// --- Anchor / PayTP encodings ---
const anchorDisc = (name) => createHash("sha256").update(`global:${name}`).digest().subarray(0, 8);
const seedSplit = (preimage) =>
  createHash("sha256").update(Buffer.concat([Buffer.from("PayTPv1-split"), Buffer.from([0]), preimage])).digest();

async function fund(conn, pubkey, sol = 5) {
  const sig = await conn.requestAirdrop(pubkey, sol * 1e9);
  await conn.confirmTransaction(sig, "confirmed");
}

async function main() {
  const conn = new Connection(RPC, "confirmed");
  const payer = Keypair.generate(); // rent payer / mint authority — airdropped locally
  await fund(conn, payer.publicKey, 100);
  console.log(`payer ${payer.publicKey.toBase58()}  balance ${(await conn.getBalance(payer.publicKey)) / 1e9} SOL`);

  // 1. Mint + the buyer, funded with tokens.
  const mint = await createMint(conn, payer, payer.publicKey, null, DECIMALS);
  const buyer = Keypair.generate();
  await fund(conn, buyer.publicKey);
  const buyerAta = await getOrCreateAssociatedTokenAccount(conn, payer, mint, buyer.publicKey);
  await mintTo(conn, payer, mint, buyerAta.address, payer, Number(AMOUNT * 2n));

  // 2. The split's committed destinations (token accounts on the mint): the
  //    merchant-net seat + 4 meed roles. Each an ATA of a fresh owner.
  const owners = Array.from({ length: 5 }, () => Keypair.generate());
  const destAtas = [];
  for (const o of owners) {
    const a = await getOrCreateAssociatedTokenAccount(conn, payer, mint, o.publicKey);
    destAtas.push(a.address);
  }
  const [merchantNet, ...meedDests] = destAtas;
  const merchantKey = createHash("sha256").update("merchant-identity").digest(); // 32 bytes

  // 3. seed_split over the ADDRESS_INPUTS preimage → the split PDA + its vault ATA.
  const preimage = Buffer.concat([
    Buffer.from([0x00, 0x20]), merchantKey,
    merchantNet.toBuffer(),
    ...meedDests.map((d) => d.toBuffer()),
    mint.toBuffer(),
  ]);
  const seed = seedSplit(preimage);
  const [splitPda] = PublicKey.findProgramAddressSync([Buffer.from("split"), seed], PROGRAM_ID);
  const vault = getAssociatedTokenAddressSync(mint, splitPda, true); // PDA owner
  // Create the vault ATA (owned by the split PDA).
  await getOrCreateAssociatedTokenAccount(conn, payer, mint, splitPda, true);
  console.log(`split PDA ${splitPda.toBase58()}  vault ${vault.toBase58()}`);

  // 4. deploy_split(seed, preimage).
  const seedBuf = Buffer.from(seed);
  const lenLE = Buffer.alloc(4); lenLE.writeUInt32LE(preimage.length);
  const deployData = Buffer.concat([anchorDisc("deploy_split"), seedBuf, lenLE, preimage]);
  await sendAndConfirmTransaction(conn, new Transaction().add(new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: splitPda, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: deployData,
  })), [payer]);
  console.log("deploy_split confirmed");

  // 5. A shipped-x402-V1 402 whose payTo IS the split PDA; the REAL x402 client
  //    selects it. (network label is nominal for the local validator.)
  const requirement = {
    scheme: "exact", network: "solana-devnet",
    maxAmountRequired: AMOUNT.toString(), asset: mint.toBase58(), payTo: splitPda.toBase58(),
    resource: "https://api.example/localnet", description: "", mimeType: "application/json",
    maxTimeoutSeconds: 60,
  };
  ok(PaymentRequirementsSchema.safeParse(requirement).success, "the split 402 validates against real x402@1.2.0");
  const selected = selectPaymentRequirements([requirement], "solana-devnet", "exact");
  ok(selected?.payTo === splitPda.toBase58(), "real selectPaymentRequirements picked the split payTo");

  // 6. The buyer pays the SELECTED payTo — exact-svm-shaped: ComputeBudget×2 +
  //    TransferChecked → ATA(payTo, mint). This matches the shipped facilitator's
  //    3-instruction cap; no Memo instruction is added.
  const payToAta = getAssociatedTokenAddressSync(mint, new PublicKey(selected.payTo), true);
  ok(payToAta.equals(vault), "ATA(payTo, mint) == the split vault");
  const payTx = new Transaction().add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: 60_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
    createTransferCheckedInstruction(buyerAta.address, mint, vault, buyer.publicKey, Number(AMOUNT), DECIMALS),
  );
  await sendAndConfirmTransaction(conn, payTx, [buyer]);
  console.log(`buyer paid ${AMOUNT} to the split vault`);
  ok((await getAccount(conn, vault)).amount === AMOUNT, "vault received the payment on-chain");

  // 7. Permissionless split_claim for each of the 5 seats (a random cranker).
  const cranker = Keypair.generate();
  await fund(conn, cranker.publicKey);
  for (let seat = 0; seat < 5; seat++) {
    const dest = destAtas[seat];
    const data = Buffer.concat([anchorDisc("split_claim"), Buffer.from([seat])]);
    await sendAndConfirmTransaction(conn, new Transaction().add(new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: splitPda, isSigner: false, isWritable: true },
        { pubkey: vault, isSigner: false, isWritable: true },
        { pubkey: dest, isSigner: false, isWritable: true },
        { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data,
    })), [cranker]);
  }
  console.log("split_claim x5 confirmed (permissionless cranker)");

  // 8. Assert the on-chain 99/1 division.
  const bal = async (a) => (await getAccount(conn, a)).amount;
  const merchant = await bal(merchantNet);
  const roy = [];
  for (const d of meedDests) roy.push(await bal(d));
  const expectRoy = SCHEMA_01_BP.map((bp) => (AMOUNT * BigInt(bp)) / 10_000n);
  const expectMerchant = (AMOUNT * BigInt(SPLIT_MERCHANT_BP)) / 10_000n;
  ok(merchant === expectMerchant, `merchant seat got ${merchant} (99% = ${expectMerchant})`);
  ok(roy.every((r, i) => r === expectRoy[i]), `meed roles got ${roy.join("/")} (${expectRoy.join("/")})`);
  const residue = await bal(vault);
  ok(merchant + roy.reduce((a, b) => a + b, 0n) + residue === AMOUNT, "value conserved on-chain (paid + residue == amount)");

  console.log(`\n${failures === 0 ? "ALL CHECKS PASS" : failures + " FAILED"} — the baseline USP settles on a live Agave validator: real x402 client selects the split, buyer pays it, split_claim divides 99/1 on-chain.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
