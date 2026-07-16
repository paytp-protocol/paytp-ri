//! The cryptographic suite (**F1.4/F1.5/F1.6**, formalizing §5.5; F2.5 seal).
//!
//! This module is the narrow **crypto-provider boundary**: the concrete
//! crates (`sha2`, `ed25519-dalek`, `poly1305`, `hkdf`,
//! `hpke`) sit behind these stable functions and their test vectors, so a crate
//! can be swapped without the boundary or its anchors moving. One suite, no
//! v0.1 negotiation (F1.4).
//!
//! | Purpose | Algorithm |
//! |---|---|
//! | Signatures | Ed25519, strict verification (F1-d) |
//! | Hash | SHA-256 |
//! | Slice auth | Poly1305 under a per-slice HKDF subkey (F1.5) |
//! | Sealing | HPKE base, DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 |
//! | Key derivation | HKDF-SHA256 |

use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// SHA-256 — the only hash (F1.4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// `N` fresh bytes from the OS CSPRNG. Used for wallet-owned per-channel secrets
/// (F2.5): the session secret and the channel id are generated here, never taken from
/// the (untrusted) interaction layer.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::RngCore;
    let mut out = [0u8; N];
    rand_core::OsRng.fill_bytes(&mut out);
    out
}

/// The `CHANNEL_AUTH` session-secret commitment (GAP-FILL **F2-e**):
/// `H(s) = SHA-256("PayTPv1-hs" ‖ s)`. Its own derivation label, distinct from
/// every signing/registry label.
pub fn h_commit(s: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(10 + 32);
    input.extend_from_slice(b"PayTPv1-hs");
    input.extend_from_slice(s);
    sha256(&input)
}

// ---------------------------------------------------------------------------
// HKDF and the slice key schedule (F1.5)
// ---------------------------------------------------------------------------

/// HKDF-SHA256 extract-then-expand (RFC 5869). `salt = Some(&[])` is the
/// explicit-empty-salt case F1.5's `subkey` uses.
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .expect("HKDF output length within SHA-256 bound");
    okm
}

/// `K_session = HKDF(ikm = s, salt = BindSalt, info = "PayTPv1-slice" ‖ channel_id, L = 32)`
/// (F1.5/§5.5). `channel_id` is the 8 raw big-endian bytes of the §5.4 identifier;
/// `bind_salt` is the public relationship digest (see [`bind_salt`], Change A).
pub fn k_session(s: &[u8; 32], bind_salt: &[u8; 32], channel_id: &[u8; 8]) -> [u8; 32] {
    let mut info = Vec::with_capacity(13 + 8);
    info.extend_from_slice(b"PayTPv1-slice");
    info.extend_from_slice(channel_id);
    let okm = hkdf_sha256(s, Some(bind_salt), &info, 32);
    okm.try_into().expect("32-byte okm")
}

/// `subkey(SEQ) = HKDF(ikm = K_session, salt = "", info = LE64(SEQ), L = 32)`
/// (F1.5/§5.5) — one fresh 32-byte Poly1305 one-time key per slice.
pub fn slice_subkey(k_session: &[u8; 32], seq: u64) -> [u8; 32] {
    let info = seq.to_le_bytes(); // LE64(SEQ)
    let okm = hkdf_sha256(k_session, Some(&[]), &info, 32);
    okm.try_into().expect("32-byte okm")
}

/// The slice MAC: `TAG = Poly1305(subkey(SEQ), COVERED(slice))` (F1.5). The
/// caller passes the already-constructed `COVERED(slice)` bytes (envelope +
/// canonical slice content, `TAG` excluded).
pub fn slice_tag(subkey: &[u8; 32], covered_slice: &[u8]) -> [u8; 16] {
    use poly1305::universal_hash::KeyInit;
    let mac = poly1305::Poly1305::new(poly1305::Key::from_slice(subkey));
    mac.compute_unpadded(covered_slice).into()
}

/// Constant-time verify of a slice MAC (F1.5: "recomputes and compares in
/// constant time").
pub fn slice_tag_verify(subkey: &[u8; 32], covered_slice: &[u8], tag: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    let expected = slice_tag(subkey, covered_slice);
    // Audited constant-time compare (RustCrypto `subtle`), per the §3 crypto
    // pinning. `Choice` → `bool` only after the timing-independent comparison.
    expected.as_slice().ct_eq(tag.as_slice()).into()
}

// ---------------------------------------------------------------------------
// Relationship binding — BindSalt (F1.6/F2.5, Change A)
// ---------------------------------------------------------------------------

/// `BindSalt = SHA-256(payer_key ‖ merchant_key)` over the two raw 32-byte Ed25519
/// public keys — the **public relationship digest** used directly as the
/// [`k_session`] salt (Change A). Transport-independent: it is NOT a TLS
/// keying-material exporter (that path is gone). Merchant authentication (the
/// binding artifact) and `s` confidentiality (the one-shot HPKE seal) carry the
/// security; this salt just binds the key schedule to the (payer, merchant) pair.
pub fn bind_salt(payer_key: &[u8; 32], merchant_key: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(payer_key);
    input[32..].copy_from_slice(merchant_key);
    sha256(&input)
}

// ---------------------------------------------------------------------------
// Ed25519 (F1-d strict)
// ---------------------------------------------------------------------------

/// Deterministic Ed25519 signature (RFC 8032), for reproducible vectors.
pub fn ed25519_sign(signing_key_bytes: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(signing_key_bytes);
    sk.sign(msg).to_bytes()
}

/// The Ed25519 public key for a signing seed.
pub fn ed25519_public(signing_key_bytes: &[u8; 32]) -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::from_bytes(signing_key_bytes)
        .verifying_key()
        .to_bytes()
}

/// **Strict** Ed25519 verification (GAP-FILL F1-d): rejects non-canonical
/// scalars/points and non-canonical (`S ≥ L`, cofactored) signature encodings,
/// and rejects a small-order public key `A` or signature component `R`. All
/// conformant implementations then accept exactly the same set.
pub fn ed25519_verify_strict(public_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| Error::BadSignature)?;
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature)
        .map_err(|_| Error::BadSignature)
}

// ---------------------------------------------------------------------------
// HPKE seal (F1.4/F2.5)
// ---------------------------------------------------------------------------

type HpkeKem = hpke::kem::X25519HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;
type HpkeKdf = hpke::kdf::HkdfSha256;

/// The 32 low-order-producing X25519 inputs whose DH yields the all-zero shared
/// secret (RFC 7748 §6.1). A seal/unseal against such a recipient key MUST abort
/// (F2.5). We reject them defensively at the boundary rather than relying on the
/// AEAD crate to surface the zero-DH internally.
const X25519_SMALL_ORDER: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // The remaining canonical small-order points (Curve25519).
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn reject_small_order(pk: &[u8; 32]) -> Result<()> {
    // Compare against the small-order set ignoring the ignored high bit.
    let mut masked = *pk;
    masked[31] &= 0x7f;
    for so in X25519_SMALL_ORDER.iter() {
        let mut m = *so;
        m[31] &= 0x7f;
        if masked == m {
            return Err(Error::Seal);
        }
    }
    Ok(())
}

/// HPKE single-shot seal (F2.5): recipient key `pkR`, `info = "PayTPv1-seal"`,
/// AEAD `aad` = the canonical `CHANNEL_AUTH` bytes (F1.4). Returns the wire
/// value `enc ‖ ct` — the 32-byte encapsulated key followed by the ciphertext
/// (F2-f: 80 bytes total for a 32-byte plaintext).
pub fn hpke_seal(
    recipient_pub: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use hpke::{single_shot_seal, Deserializable, OpModeS, Serializable};
    reject_small_order(recipient_pub)?;
    let pk =
        <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient_pub).map_err(|_| Error::Seal)?;
    let mut csprng = rand_core::OsRng;
    let (encapped, ciphertext) = single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        &mut csprng,
    )
    .map_err(|_| Error::Seal)?;
    let mut out = encapped.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// HPKE single-shot open — the merchant side. `enc_ct` is `enc ‖ ct`.
pub fn hpke_open(
    recipient_secret: &[u8; 32],
    enc_ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use hpke::{single_shot_open, Deserializable, OpModeR};
    if enc_ct.len() < 32 {
        return Err(Error::Seal);
    }
    let (enc_bytes, ct) = enc_ct.split_at(32);
    // F2.5 / RFC 9180 §7.1.4: reject a small-order encapsulated key at the boundary —
    // its decap yields the all-zero shared secret. This mirrors `hpke_seal`'s
    // recipient-key check on the OPEN side, so the abort is enforced HERE (not merely
    // delegated to the AEAD crate's internal zero-DH surfacing, which a bad ct would
    // mask). A legitimate `enc` is a random full-order point, never small-order.
    let enc_arr: [u8; 32] = enc_bytes.try_into().expect("split_at(32) yields 32 bytes");
    reject_small_order(&enc_arr)?;
    let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(recipient_secret)
        .map_err(|_| Error::Seal)?;
    let encapped =
        <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(enc_bytes).map_err(|_| Error::Seal)?;
    single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &sk, &encapped, info, ct, aad)
        .map_err(|_| Error::Seal)
}

/// The fixed HPKE `info` string for the channel-secret seal (F2.5).
pub const SEAL_INFO: &[u8] = b"PayTPv1-seal";

/// Seal the 32-byte session secret `s` to the merchant's `ENC_KEY` with the
/// PayTP-fixed parameters (F2.5): `info = "PayTPv1-seal"`, plaintext `s`
/// (32 bytes), `aad` = the canonical `CHANNEL_AUTH` bytes. Returns the 80-byte
/// wire value `enc ‖ ct` (F2-f). This is the PayTP-pinned face of the generic
/// [`hpke_seal`] boundary — callers cannot pick a different `info` or plaintext
/// width by accident.
pub fn seal_session_secret(
    recipient_enc_key: &[u8; 32],
    channel_auth_canonical: &[u8],
    s: &[u8; 32],
) -> Result<Vec<u8>> {
    hpke_seal(recipient_enc_key, SEAL_INFO, channel_auth_canonical, s)
}

/// Open a sealed session secret (the merchant side of [`seal_session_secret`]),
/// returning the recovered 32-byte `s`.
pub fn open_session_secret(
    recipient_secret: &[u8; 32],
    enc_ct: &[u8],
    channel_auth_canonical: &[u8],
) -> Result<[u8; 32]> {
    let plaintext = hpke_open(recipient_secret, enc_ct, SEAL_INFO, channel_auth_canonical)?;
    plaintext.try_into().map_err(|_| Error::Seal) // s is exactly 32 bytes
}

/// Derive an X25519 recipient keypair (secret, public) from 32 seed bytes — for
/// deterministic seal round-trip vectors.
pub fn x25519_keypair_from_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hpke::Serializable;
    let (sk, pk) = <HpkeKem as hpke::Kem>::derive_keypair(seed);
    (
        sk.to_bytes().as_slice().try_into().expect("32-byte sk"),
        pk.to_bytes().as_slice().try_into().expect("32-byte pk"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn h_commit_anchor() {
        // F10.2 / F2-e: H(s) for s = 00×32.
        let s = [0u8; 32];
        assert_eq!(
            hexs(&h_commit(&s)),
            "07beb2f81d0dedb77061989b03ec26b604fc3681c19bbc2ea5ab2b78bae54826"
        );
    }

    #[test]
    fn ed25519_strict_roundtrip() {
        let seed = [7u8; 32];
        let pk = ed25519_public(&seed);
        let msg = b"paytp strict verify";
        let sig = ed25519_sign(&seed, msg);
        assert!(ed25519_verify_strict(&pk, msg, &sig).is_ok());
        // Tamper: flip a message byte.
        assert!(ed25519_verify_strict(&pk, b"paytp strict verifz", &sig).is_err());
    }

    #[test]
    fn ed25519_rejects_small_order_key() {
        // The all-zero public key is small order; verify_strict must reject it.
        let msg = b"x";
        let sig = [0u8; 64];
        assert!(ed25519_verify_strict(&[0u8; 32], msg, &sig).is_err());
    }

    #[test]
    fn hpke_seal_open_roundtrip_and_zero_dh_abort() {
        let (sk, pk) = x25519_keypair_from_seed(&[3u8; 32]);
        let info = b"PayTPv1-seal";
        let aad = b"canonical CHANNEL_AUTH bytes";
        let secret = [0x42u8; 32];
        let sealed = hpke_seal(&pk, info, aad, &secret).unwrap();
        assert_eq!(sealed.len(), 80, "enc(32) ‖ ct(48) = 80 (F2-f)");
        let opened = hpke_open(&sk, &sealed, info, aad).unwrap();
        assert_eq!(opened, secret);
        // Wrong aad fails.
        assert!(hpke_open(&sk, &sealed, info, b"other aad").is_err());
        // All-zero / small-order recipient key aborts (F2.5).
        assert!(hpke_seal(&[0u8; 32], info, aad, &secret).is_err());
    }

    #[test]
    fn hpke_open_rejects_small_order_encapsulated_key() {
        // F2.5 / RFC 9180 §7.1.4 — the OPEN side (merchant) MUST abort when the
        // encapsulated key `enc` is a small-order X25519 point (its decap yields the
        // all-zero shared secret). `hpke_open` runs `reject_small_order(enc)` FIRST —
        // before decap and the AEAD open — so this `Err` provably originates from the
        // small-order guard, not an incidental AEAD-tag failure on the dummy ciphertext
        // (which would let a regressed zero-DH decap pass unnoticed). The reject is thus
        // enforced in-repo, symmetric with `hpke_seal`'s recipient-key check.
        let (sk, _pk) = x25519_keypair_from_seed(&[9u8; 32]);
        let info = b"PayTPv1-seal";
        let aad = b"canonical CHANNEL_AUTH bytes";
        let ct = [0u8; 48]; // immaterial — the guard returns before the AEAD open
        for enc in X25519_SMALL_ORDER.iter() {
            let mut enc_ct = enc.to_vec();
            enc_ct.extend_from_slice(&ct);
            assert!(
                hpke_open(&sk, &enc_ct, info, aad).is_err(),
                "open MUST abort on a small-order encapsulated key (zero-DH), enc={}",
                hexs(enc)
            );
            // The PayTP-pinned wrapper propagates the abort.
            assert!(open_session_secret(&sk, &enc_ct, aad).is_err());
        }
        // Control: a full-order `enc` from a real seal passes the guard and round-trips,
        // proving the guard rejects ONLY small-order points (no false positive).
        let (rsk, rpk) = x25519_keypair_from_seed(&[3u8; 32]);
        let sealed = hpke_seal(&rpk, info, aad, &[0x42u8; 32]).unwrap();
        assert_eq!(hpke_open(&rsk, &sealed, info, aad).unwrap(), [0x42u8; 32]);
    }

    #[test]
    fn session_secret_seal_roundtrip() {
        // The PayTP-pinned wrapper: info + 32-byte plaintext + 80-byte wire fixed.
        let (sk, pk) = x25519_keypair_from_seed(&[5u8; 32]);
        let aad = b"canonical CHANNEL_AUTH bytes";
        let s = [0x77u8; 32];
        let sealed = seal_session_secret(&pk, aad, &s).unwrap();
        assert_eq!(sealed.len(), 80);
        assert_eq!(open_session_secret(&sk, &sealed, aad).unwrap(), s);
    }

    #[test]
    fn slice_key_schedule_is_deterministic() {
        let s = [1u8; 32];
        let salt = [2u8; 32]; // BindSalt
        let cid = [0, 0, 0, 0, 0, 0, 0, 1];
        let ks = k_session(&s, &salt, &cid);
        let sub0 = slice_subkey(&ks, 0);
        let sub1 = slice_subkey(&ks, 1);
        assert_ne!(sub0, sub1, "fresh subkey per SEQ");
        let covered = crate::envelope::covered(crate::envelope::DomainLabel::Slice, b"content");
        let tag = slice_tag(&sub0, &covered);
        assert!(slice_tag_verify(&sub0, &covered, &tag));
        assert!(!slice_tag_verify(&sub1, &covered, &tag));
    }
}
