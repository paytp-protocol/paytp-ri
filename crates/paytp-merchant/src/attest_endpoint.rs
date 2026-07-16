//! The unauthenticated attestation-retrieval endpoint (**F2.6 / §5.6**).
//!
//! The merchant's control endpoint serves the signed redemption attestation at
//! `GET /attest?entry=<Base64url>&nonce=<Base64url>` (both REQUIRED, F2.6) —
//! unauthenticated — until the entry's windows have passed, or plain 404 while
//! none exists. Anyone (the funding wallet, a watcher) may retrieve it and post
//! it to the instance; the attestation is a merchant signature, so serving it
//! openly leaks nothing.

use paytp_core::tier0::attest::Signed;
use std::collections::HashMap;
use std::sync::Mutex;

/// The `(entry_id, nonce)` key an attestation is addressed by (F2.6).
type AttestKey = ([u8; 32], [u8; 32]);

/// A retention-bounded store of served attestations, keyed by `(entry_id, nonce)`.
#[derive(Default)]
pub struct AttestationEndpoint {
    by_key: Mutex<HashMap<AttestKey, Vec<u8>>>,
}

impl AttestationEndpoint {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish an attestation for retrieval (the merchant does this on redemption).
    pub fn post(&self, signed: &Signed) {
        self.by_key
            .lock()
            .unwrap()
            .insert((signed.entry_id, signed.nonce), signed.encode());
    }

    /// `GET /attest?entry=&nonce=` — the attestation TLV bytes, or `None` (404).
    pub fn get(&self, entry_id: &[u8; 32], nonce: &[u8; 32]) -> Option<Vec<u8>> {
        self.by_key
            .lock()
            .unwrap()
            .get(&(*entry_id, *nonce))
            .cloned()
    }

    /// Drop an entry's attestation once its windows have passed (F2.6 retention).
    pub fn prune(&self, entry_id: &[u8; 32], nonce: &[u8; 32]) {
        self.by_key.lock().unwrap().remove(&(*entry_id, *nonce));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::crypto;
    use paytp_core::tier0::attest::{Kind, Signed};

    #[test]
    fn serve_and_retrieve_attestation_unauthenticated() {
        let sk = [0x55; 32];
        let pk = crypto::ed25519_public(&sk);
        let ep = AttestationEndpoint::new();
        let (nonce, entry) = ([0x11; 32], [0x22; 32]);
        // 404 before it exists.
        assert!(ep.get(&entry, &nonce).is_none());
        // Merchant posts it on redemption.
        let att = Signed::create(Kind::Attestation, nonce, entry, &sk);
        ep.post(&att);
        // Anyone retrieves it; the bytes parse + verify as the attestation.
        let bytes = ep.get(&entry, &nonce).expect("served");
        let parsed = Signed::parse_verify(Kind::Attestation, &bytes, &pk).unwrap();
        assert_eq!(parsed.entry_id, entry);
        assert_eq!(parsed.nonce, nonce);
        // A mismatched query is 404.
        assert!(ep.get(&[0x33; 32], &nonce).is_none());
        // Pruned after the windows pass.
        ep.prune(&entry, &nonce);
        assert!(ep.get(&entry, &nonce).is_none());
    }
}
