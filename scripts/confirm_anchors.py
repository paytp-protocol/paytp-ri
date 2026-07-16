#!/usr/bin/env python3
"""Independent SHA-256 confirmation of the hand-derived F10 crypto anchors.

F10.2's canonicalization discipline requires a *second, unrelated*
implementation to agree byte-for-byte before a vector is canonical. Rust
(paytp-core) computes these anchors from the spec; this script re-derives them
from the documented preimages using Python's stdlib `hashlib` — sharing no code
with the Rust crypto crates — and asserts equality against the values checked
into `conformance/`. CI runs it as a separate job.

Covers the three SHA-256-only seed anchors (H(s), transcript head_0, entry_id)
and the slice COVERED prefix. Ed25519/Poly1305/HPKE anchors are
generation-required and confirmed by a second *code* path at M1 (F10.2), not
here.
"""
import hashlib
import json
import pathlib
import sys

CONF = pathlib.Path(__file__).resolve().parent.parent / "conformance"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load(name: str) -> dict:
    with open(CONF / name) as f:
        return json.load(f)


def find(vectors, vid):
    for v in vectors["vectors"]:
        if v["id"] == vid:
            return v
    raise SystemExit(f"vector {vid} not found")


def check(label: str, got: str, want: str) -> bool:
    ok = got == want
    mark = "ok " if ok else "FAIL"
    print(f"  [{mark}] {label}")
    if not ok:
        print(f"        got:  {got}")
        print(f"        want: {want}")
    return ok


def main() -> int:
    ok = True

    # --- H(s) = SHA-256("PayTPv1-hs" ‖ s), s = 00×32 (F2-e) ---
    crypto = load("f1-crypto.json")
    v = find(crypto, "f1-crypto-hs-001")
    s = bytes.fromhex(v["inputs"]["s"])
    ok &= check("H(s), s=00x32", sha256(b"PayTPv1-hs" + s), v["expect"]["value"])

    # --- slice COVERED prefix = "PayTPv1-slice" ‖ 0x00 (F1.3/F10.3) ---
    v = find(crypto, "f1-crypto-slice-prefix-001")
    prefix = (b"PayTPv1-slice" + b"\x00").hex()
    ok &= check("slice COVERED prefix", prefix, v["expect"]["value"])

    # --- transcript head_0 = SHA-256("PayTPv1-transcript" ‖ 0x00 ‖ CHANNEL_ID) (F5-g) ---
    v = find(crypto, "f1-crypto-head0-001")
    cid = bytes.fromhex(v["inputs"]["channel_id"])
    ok &= check(
        "transcript head_0",
        sha256(b"PayTPv1-transcript" + b"\x00" + cid),
        v["expect"]["value"],
    )

    # --- entry_id (F4-c, REGENERATED with the full amount+deadline preimage) ---
    derive = load("f4-derive.json")
    v = find(derive, "f4-entry-id-001")
    i = v["inputs"]
    seed_instance = bytes.fromhex(i["seed_instance"])
    nonce = bytes.fromhex(i["nonce"])
    amt = int(i["amt"]).to_bytes(16, "big")
    t_open = int(i["t_open"]).to_bytes(8, "big")
    t_lapse = int(i["t_lapse"]).to_bytes(8, "big")
    contest = int(i["contest"]).to_bytes(8, "big")
    preimage = b"PayTPv1-entry" + b"\x00" + seed_instance + nonce + amt + t_open + t_lapse + contest
    ok &= check("entry_id (amount+deadline-in-key)", sha256(preimage), v["expect"]["value"])

    print()
    if ok:
        print("All SHA-256 anchors confirmed independently (python hashlib).")
        return 0
    print("ANCHOR MISMATCH — a vector disagrees with an independent derivation.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
