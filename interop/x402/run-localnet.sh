#!/usr/bin/env bash
# M6.1c — start a local Agave validator, deploy paytp_kit, and run the live
# on-chain settlement loop (settle-localnet.mjs). Real BPF loader/runtime.
#
# Requires: solana-test-validator + the built program at
# contracts/target/deploy/paytp_kit.{so,-keypair.json} (cargo build-sbf), and
# `npm install` in this directory.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
contracts="$here/../../contracts"

ledger="$(mktemp -d)/test-ledger"
echo "starting solana-test-validator (ledger: $ledger) ..."
solana-test-validator --ledger "$ledger" --reset --quiet &
vpid=$!
trap 'kill $vpid 2>/dev/null || true' EXIT
sleep 8

solana config set --url http://127.0.0.1:8899 >/dev/null
echo "deploying paytp_kit ..."
solana program deploy "$contracts/target/deploy/paytp_kit.so" \
  --program-id "$contracts/target/deploy/paytp_kit-keypair.json" | sed 's/^/  /'

echo "running the settlement loop ..."
node "$here/settle-localnet.mjs"
