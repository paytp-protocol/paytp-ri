#!/usr/bin/env bash
# Rebuild the demo wasm facade and vendor its web files into the suite so it's testable
# out-of-the-box (open index.html via `node serve.mjs`). Run after changing demos/wasm/.
#
# PATH-CLEAN (do not remove): Rust bakes source-file paths into panic-location debug info,
# which would otherwise leak the local absolute build path (e.g. /Users/<you>/…) into the
# shipped .wasm. We `--remap-path-prefix` the repo root, CARGO_HOME, and RUSTUP_HOME to
# stable non-local prefixes, then self-check the binary. The public-export verify
# also fails closed on any surviving /Users or /home path — keep this remap in
# sync with that check.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"                 # the paytp-ri checkout (or worktree) root
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
# Prepend our remaps (preserve any caller RUSTFLAGS).
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$repo=paytp-ri --remap-path-prefix=$cargo_home=cargo --remap-path-prefix=$rustup_home=rustup"
( cd "$here/../wasm" && wasm-pack build --target web --release )
cp "$here"/../wasm/pkg/paytp_demo_wasm.js \
   "$here"/../wasm/pkg/paytp_demo_wasm_bg.wasm \
   "$here"/../wasm/pkg/paytp_demo_wasm.d.ts \
   "$here"/../wasm/pkg/paytp_demo_wasm_bg.wasm.d.ts \
   "$here/lib/"
echo "demo wasm rebuilt + vendored into demos/suite/lib/ ($(du -h "$here/lib/paytp_demo_wasm_bg.wasm" | cut -f1) wasm)"

# Fail-closed local check: no home path may survive in the shipped binary.
if strings "$here/lib/paytp_demo_wasm_bg.wasm" | grep -qE '/Users/|/home/'; then
  echo "✗ PATH LEAK: the rebuilt wasm still embeds a local path — do NOT commit." >&2
  strings "$here/lib/paytp_demo_wasm_bg.wasm" | grep -aoE '/Users/[^ ]*|/home/[^ ]*' | sort -u | sed 's/^/    /' >&2
  exit 1
fi
echo "✓ path-clean: no /Users or /home path embedded in the wasm."
