#!/usr/bin/env bash
# The M8 wedge demo, native (no Docker): build both binaries, start the metered
# API merchant, run the agent N times, and assert the settled meed. The
# agent's exit code is the assertion. Usage: ./run.sh [N]   (default 3)
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --bins
addr="127.0.0.1:8402"
WEDGE_ADDR="$addr" ./target/release/wedge-merchant &
mpid=$!
trap 'kill $mpid 2>/dev/null || true' EXIT

# Wait for the merchant to come up.
for _ in $(seq 1 30); do
  if WEDGE_URL="http://$addr" ./target/release/wedge-agent --healthcheck; then break; fi
  sleep 0.5
done

WEDGE_URL="http://$addr" ./target/release/wedge-agent "${1:-3}"

echo
./target/release/wedge-channel "${1:-3}"
