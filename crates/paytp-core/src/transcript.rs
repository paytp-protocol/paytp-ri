//! The slice-transcript hash chain (**GAP-FILL F5-g**).
//!
//! ```text
//! head_0 = SHA-256("PayTPv1-transcript" ‖ 0x00 ‖ CHANNEL_ID)
//! head_i = SHA-256(head_{i-1} ‖ slice_i)
//! ```
//!
//! over each *accepted* slice's complete canonical bytes (`TAG` included — the
//! chain records what was accepted as received), in sequence order. Rejected
//! slices enter no chain (§6.3). `CHANNEL_ID` is the 8 raw big-endian bytes of
//! the §5.4 identifier.

use crate::crypto::sha256;

/// The genesis transcript head for a channel (F5-g).
pub fn head_0(channel_id: &[u8; 8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(18 + 1 + 8);
    input.extend_from_slice(b"PayTPv1-transcript");
    input.push(0x00); // F1-h delimiter
    input.extend_from_slice(channel_id);
    sha256(&input)
}

/// Advance the chain by one accepted slice: `head_i = SHA-256(head_{i-1} ‖ slice_i)`.
/// `slice_bytes` is the slice's complete canonical bytes (F1.5 `Slice::encode`).
pub fn advance(prev_head: &[u8; 32], slice_bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + slice_bytes.len());
    input.extend_from_slice(prev_head);
    input.extend_from_slice(slice_bytes);
    sha256(&input)
}

/// Fold a whole accepted-slice sequence from `head_0`.
pub fn fold(channel_id: &[u8; 8], accepted_slices: &[Vec<u8>]) -> [u8; 32] {
    let mut head = head_0(channel_id);
    for s in accepted_slices {
        head = advance(&head, s);
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn head_0_anchor() {
        // F10.3 / F5-g: channel_id = 0000000000000001.
        let cid = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            hexs(&head_0(&cid)),
            "620dd196e36ac87470bde0e0910b0750775cf57e015926fcc67d1d86a0ef7455"
        );
    }

    #[test]
    fn chain_advances_and_is_order_sensitive() {
        let cid = [0, 0, 0, 0, 0, 0, 0, 1];
        let a = vec![0xaau8, 0xbb];
        let b = vec![0xccu8, 0xdd];
        assert_ne!(fold(&cid, &[a.clone(), b.clone()]), fold(&cid, &[b, a]));
    }
}
