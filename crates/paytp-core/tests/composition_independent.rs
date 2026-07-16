//! F10.2 composition-vector independent confirmation (M7.5).
//!
//! F10.2 admits a PayTP-specific *composition* vector only when **two code paths
//! that share no code agree**. The standard primitives (SHA-256, HKDF, Poly1305,
//! Ed25519) are already RFC-confirmed (M0); what was still `pending-confirmation`
//! is the *composition* layer — how PayTP lays out `COVERED`, orders the HKDF
//! inputs of the `K_session`/`subkey` schedule, constructs the slice MAC input,
//! and frames `H(s)` / `BindSalt` / the transcript chain.
//!
//! This file is that independent second path: it re-derives each anchor **from the
//! spec construction**, using the primitive crates directly and **never calling
//! `paytp_core`'s crypto/envelope/slice/transcript code**. It then asserts the
//! re-derivation is byte-identical to (a) the pinned corpus anchors and (b)
//! `paytp_core`'s own output. A composition-layout bug in either path (a swapped
//! label, a mis-ordered HKDF `info`, a wrong MAC input) breaks the equality.

use hkdf::Hkdf;
use poly1305::universal_hash::KeyInit;
use sha2::{Digest, Sha256};

// Pinned test inputs (published with the corpus).
const PAYER_KEY: [u8; 32] = [0x01; 32];
const MERCHANT_KEY: [u8; 32] = [0x02; 32];
const S: [u8; 32] = [0x00; 32];
const CHANNEL_ID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

// ---- independent re-derivations (spec construction, no paytp_core code) ----

fn ind_sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// H(s) = SHA-256("PayTPv1-hs" ‖ s)  (F2-e).
fn ind_h_commit(s: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::new();
    v.extend_from_slice(b"PayTPv1-hs");
    v.extend_from_slice(s);
    ind_sha256(&v)
}

/// BindSalt = SHA-256(payer_key ‖ merchant_key)  (F1.6/F2.5, Change A).
fn ind_bind_salt(payer: &[u8; 32], merchant: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::new();
    v.extend_from_slice(payer);
    v.extend_from_slice(merchant);
    ind_sha256(&v)
}

fn ind_hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).unwrap();
    okm
}

/// K_session = HKDF(ikm=s, salt=BindSalt, info="PayTPv1-slice" ‖ channel_id) (F1.5).
fn ind_k_session(s: &[u8; 32], bind_salt: &[u8; 32], channel_id: &[u8; 8]) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(b"PayTPv1-slice");
    info.extend_from_slice(channel_id);
    ind_hkdf(s, bind_salt, &info)
}

/// subkey(SEQ) = HKDF(ikm=K_session, salt="", info=LE64(SEQ))  (F1.5).
fn ind_subkey(k_session: &[u8; 32], seq: u64) -> [u8; 32] {
    ind_hkdf(k_session, &[], &seq.to_le_bytes())
}

/// The slice COVERED prefix: "PayTPv1-slice" ‖ 0x00  (F1.3).
fn ind_slice_covered_prefix() -> Vec<u8> {
    let mut v = b"PayTPv1-slice".to_vec();
    v.push(0x00);
    v
}

/// The FULL slice `COVERED` bytes, reconstructed independently from the spec
/// (§5.3/F1.1): the prefix, then the canonical TLV object `0x00 SEQ(8 BE)` ‖
/// `0x01 AMT_µ(6 BE)` — each field `type ‖ leb128(len) ‖ value`, ascending type,
/// `TAG` excluded (F1-i). This does NOT call `paytp_core::slice`, so a wrong
/// SEQ/AMT encoding in the core would make this differ (and the equality below
/// would fail) rather than silently agree.
fn ind_slice_covered(seq: u64, amt_micro: u64) -> Vec<u8> {
    let mut v = ind_slice_covered_prefix();
    // 0x00 SEQ, len 8, 8-byte big-endian.
    v.push(0x00);
    v.push(0x08);
    v.extend_from_slice(&seq.to_be_bytes());
    // 0x01 AMT_µ, len 6, low 6 bytes big-endian.
    v.push(0x01);
    v.push(0x06);
    v.extend_from_slice(&amt_micro.to_be_bytes()[2..]);
    v
}

/// TAG = Poly1305(subkey(SEQ), COVERED(slice))  (F1.5).
fn ind_slice_tag(subkey: &[u8; 32], covered_slice: &[u8]) -> [u8; 16] {
    let mac = poly1305::Poly1305::new(poly1305::Key::from_slice(subkey));
    mac.compute_unpadded(covered_slice).into()
}

/// head_0 = SHA-256("PayTPv1-transcript" ‖ 0x00 ‖ channel_id)  (F5-g).
fn ind_head_0(channel_id: &[u8; 8]) -> [u8; 32] {
    let mut v = Vec::new();
    v.extend_from_slice(b"PayTPv1-transcript");
    v.push(0x00);
    v.extend_from_slice(channel_id);
    ind_sha256(&v)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- the confirmation: independent path == pinned anchor == paytp_core ----

#[test]
fn composition_anchors_confirmed_by_an_independent_path() {
    // (1) H(s) — matches the pinned anchor and paytp_core.
    let hs = ind_h_commit(&S);
    assert_eq!(
        hexs(&hs),
        "07beb2f81d0dedb77061989b03ec26b604fc3681c19bbc2ea5ab2b78bae54826"
    );
    assert_eq!(hs, paytp_core::crypto::h_commit(&S));

    // (2) slice COVERED — the prefix matches the pinned anchor, and the FULL
    // independently-reconstructed COVERED bytes equal paytp_core's, so a core
    // SEQ/AMT TLV bug cannot hide (the MAC below is over the INDEPENDENT bytes).
    assert_eq!(
        hexs(&ind_slice_covered_prefix()),
        "506179545076312d736c69636500"
    );
    let covered = ind_slice_covered(1, 10_000);
    assert_eq!(
        covered,
        paytp_core::slice::covered_bytes(1, 10_000),
        "independent slice COVERED must equal paytp_core's (F1.1 SEQ/AMT encoding)"
    );

    // (3) transcript head_0 — matches the pinned anchor and paytp_core.
    let head0 = ind_head_0(&CHANNEL_ID);
    assert_eq!(
        hexs(&head0),
        "620dd196e36ac87470bde0e0910b0750775cf57e015926fcc67d1d86a0ef7455"
    );
    assert_eq!(head0, paytp_core::transcript::head_0(&CHANNEL_ID));

    // (4) BindSalt — the independent path matches the pinned corpus anchor AND
    // paytp_core (generation-required composition now confirmed, F10.2).
    let bind = ind_bind_salt(&PAYER_KEY, &MERCHANT_KEY);
    assert_eq!(
        hexs(&bind),
        "f818afd37a6dc3bc92fb44731011277006db4efa6e9023cd7468c02335d22a4d"
    );
    assert_eq!(
        bind,
        paytp_core::crypto::bind_salt(&PAYER_KEY, &MERCHANT_KEY)
    );

    // (5) K_session schedule — pinned anchor and paytp_core.
    let k = ind_k_session(&S, &bind, &CHANNEL_ID);
    assert_eq!(
        hexs(&k),
        "dc64f703f9a5830faf61aa8f671f98182dc38722a5b0f21a6a601ad0a4133189"
    );
    assert_eq!(k, paytp_core::crypto::k_session(&S, &bind, &CHANNEL_ID));

    // (6) subkey(SEQ) + slice MAC — pinned anchors, paytp_core, and end-to-end the
    // tag a paytp_core-sealed slice carries (subkey + MAC input + Poly1305).
    let subkey = ind_subkey(&k, 1);
    assert_eq!(
        hexs(&subkey),
        "d95e6aa957821c2097935dbcca39f0516acd396b95c3a95b0ac8c36a16768704"
    );
    assert_eq!(subkey, paytp_core::crypto::slice_subkey(&k, 1));
    // MAC over the INDEPENDENTLY-reconstructed COVERED bytes (not core's).
    let tag = ind_slice_tag(&subkey, &covered);
    assert_eq!(hexs(&tag), "77f1d3796a6d837d22ad792449fb8851");
    assert_eq!(tag, paytp_core::crypto::slice_tag(&subkey, &covered));

    let slice = paytp_core::slice::Slice::seal(1, 10_000, &k).unwrap();
    assert_eq!(slice.tag, tag);
}
