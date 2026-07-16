//! The durable `MerchantStore` (**F4.4**, formalizing §5.6/§11.5).
//!
//! The consumed-nonce record is one durable, exactly-once decision made *before
//! delivery* "across whatever serves the traffic" — the concurrency property is
//! the guarantee, not an afterthought. The virtual-rail build uses an in-memory
//! map behind a mutex with the same compare-and-set semantics a real DB provides
//! (M3 adds the Postgres profile whose test exposes the write-race).

use paytp_core::tier0::Receipt;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

/// The outcome of an atomic nonce consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A mismatch against a consumed nonce, or a payment ref reused across
    /// nonces (`PAYTP_PAYMENT_PROOF_REPLAYED`, §5.6).
    Replayed,
    /// The durable store could NOT record the consumption (a write/sync failure, or a poisoned
    /// log) — nothing was consumed, so the merchant MUST NOT deliver. F4.4 "durable-or-fail: an
    /// operator that loses this state refuses what it can no longer adjudicate, never guesses." A
    /// retry against a recovered store consumes-and-delivers exactly once. Never returned by
    /// `InMemoryStore` (its consume cannot fail).
    Unavailable,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for StoreError {}

/// The durable decision recorded against a consumed nonce (F4.4): the payment
/// reference, the idempotency key, and the resource binding. Only a retry
/// matching this record **exactly** returns the stored receipt (§5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceRecord {
    pub payment_ref: String,
    pub idem: Vec<u8>,
    pub resource: String,
    /// The merchant signature over the quote this nonce was consumed under — so
    /// a *different* signed quote sharing the nonce/refs is a replay, not an
    /// idempotent retry (F4.4: only a retry matching the record exactly returns
    /// the stored receipt).
    pub quote_sig: [u8; 64],
}

/// The result of peeking at a nonce before re-verifying a payment (§5.6: a
/// retry matching the record exactly returns the stored response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peek {
    /// The nonce is unseen — proceed to verify and consume.
    Fresh,
    /// The nonce was consumed with an exactly-matching record — return this.
    Stored(Box<Receipt>),
    /// The nonce (or its payment ref) collides with a different decision.
    Replayed,
}

/// The `MerchantStore` surface M1 needs: an atomic consumed-nonce record.
pub trait MerchantStore {
    /// Peek at `nonce` against the decision `record` *without* consuming: a
    /// consumed nonce with a matching record short-circuits redemption to the
    /// stored receipt (so a retry does not re-verify a payment whose entry has
    /// since advanced). The atomic gate is still [`MerchantStore::consume_nonce`].
    fn peek(&self, nonce: [u8; 32], record: &NonceRecord) -> Peek;

    /// Atomically consume `nonce` bound to `record`, before delivery.
    ///
    /// - Fresh nonce → `build()` produces the receipt; the record + receipt are
    ///   stored keyed by the nonce, the payment ref is marked used, and the
    ///   receipt is returned.
    /// - Already consumed with an **exactly matching** record → the stored
    ///   receipt is returned (idempotent retry, no second charge).
    /// - Consumed with any mismatch, or a payment ref already used by another
    ///   nonce → [`StoreError::Replayed`].
    fn consume_nonce(
        &self,
        nonce: [u8; 32],
        record: &NonceRecord,
        build: &mut dyn FnMut() -> Receipt,
    ) -> Result<Receipt, StoreError>;
}

mod sealed {
    pub trait Sealed {}
}

/// A **durable, restart-surviving** consumed-nonce store — a *construction-proof* marker,
/// the [`crate::one_decision::DurableOneDecision`] analogue for Tier-0. Sealed:
/// only this crate's audited durable stores (the reference [`WalMerchantStore`], a future DB
/// profile) may implement it, so a proof redemption bounded on it cannot be satisfied by an
/// in-memory store claiming durability. Not implemented for `InMemoryStore`.
pub trait DurableMerchantStore: MerchantStore + sealed::Sealed {}

/// Canonical settlement references MUST NOT contain U+007C (`|`); it is reserved
/// for the store's two-leg combined meed/net replay key.
pub(crate) const PAYMENT_REF_DELIMITER: char = '|';

pub(crate) fn has_reserved_ref_delimiter(reference: &str) -> bool {
    reference.contains(PAYMENT_REF_DELIMITER)
}

fn used_ref_keys(payment_ref: &str) -> Vec<String> {
    let mut keys = vec![payment_ref.to_string()];
    if let Some((_, net_ref)) = payment_ref.rsplit_once(PAYMENT_REF_DELIMITER) {
        keys.push(net_ref.to_string());
    }
    keys
}

/// In-memory store (single file / single process) — the same compare-and-set a real DB gives.
/// **Not persistent** and **not** [`DurableMerchantStore`]: a proof build cannot name it
/// (`#[cfg]`-gated to tests / the `demo` feature). A restart loses its consumed-nonce records, so a
/// replayed payment proof would no longer be caught — hence its exclusion from proof paths.
#[cfg(any(test, feature = "demo"))]
#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

#[cfg(any(test, feature = "demo"))]
#[derive(Default)]
struct Inner {
    by_nonce: HashMap<[u8; 32], (NonceRecord, Receipt)>,
    used_refs: HashSet<String>,
}

#[cfg(any(test, feature = "demo"))]
impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(any(test, feature = "demo"))]
impl MerchantStore for InMemoryStore {
    fn peek(&self, nonce: [u8; 32], record: &NonceRecord) -> Peek {
        let inner = self.inner.lock().unwrap();
        if let Some((stored, receipt)) = inner.by_nonce.get(&nonce) {
            return if stored == record {
                Peek::Stored(Box::new(receipt.clone()))
            } else {
                Peek::Replayed
            };
        }
        if used_ref_keys(&record.payment_ref)
            .iter()
            .any(|r| inner.used_refs.contains(r))
        {
            return Peek::Replayed;
        }
        Peek::Fresh
    }

    fn consume_nonce(
        &self,
        nonce: [u8; 32],
        record: &NonceRecord,
        build: &mut dyn FnMut() -> Receipt,
    ) -> Result<Receipt, StoreError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some((stored, receipt)) = inner.by_nonce.get(&nonce) {
            // Idempotent retry only if the WHOLE decision record matches (F4.4).
            if stored == record {
                return Ok(receipt.clone());
            }
            return Err(StoreError::Replayed);
        }
        // Fresh nonce: the ref must not already back another nonce.
        let ref_keys = used_ref_keys(&record.payment_ref);
        if ref_keys.iter().any(|r| inner.used_refs.contains(r)) {
            return Err(StoreError::Replayed);
        }
        let receipt = build();
        inner
            .by_nonce
            .insert(nonce, (record.clone(), receipt.clone()));
        inner.used_refs.extend(ref_keys);
        Ok(receipt)
    }
}

// ---------------------------------------------------------------------------
// WalMerchantStore — the durable consumed-nonce store (F4.4)
// ---------------------------------------------------------------------------

/// A **reference durable** consumed-nonce store: an append-only write-ahead log, the Tier-0
/// analogue of [`crate::one_decision::WalOneDecision`]. Each consumption is ONE atomic,
/// length-framed, `sync_all`-ed record `{nonce ‖ NonceRecord ‖ receipt-JSON}` written **before
/// delivery** (F4.4). The `used_refs` guard is a **derived** index rebuilt from the same records at
/// [`WalMerchantStore::open`] — NOT a second key — so there is no "nonce written, ref not yet
/// written" crash window in which a different nonce could reuse one payment to buy twice.
/// A torn trailing record replays as unmade; a COMPLETE-but-unparseable record
/// **fails the open closed** (never silently skipped). A real deployment
/// swaps the DB profile; the on-disk log is the reference semantics a conforming store must match.
pub struct WalMerchantStore {
    inner: Mutex<Wal>,
}

struct Wal {
    by_nonce: HashMap<[u8; 32], (NonceRecord, Receipt)>,
    used_refs: HashSet<String>,
    file: File,
    /// Byte length of the durable (whole, synced) records — the append offset (as `WalOneDecision`).
    len: u64,
    /// Poisoned after a failed append whose truncation-recovery also failed — every later
    /// `consume_nonce` then returns `Unavailable`, so the log holds at most one torn tail a restart
    /// truncates cleanly. Recovery is a fresh `open`.
    poisoned: bool,
}

/// Why a durable consumed-nonce log could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// An I/O error opening/reading the log.
    Io(std::io::Error),
    /// A COMPLETE record whose payload does not parse — the log is corrupt. Refuse to open rather
    /// than silently forget a consumed nonce (which would double-deliver) — F4.4 durable-or-fail.
    Corrupt,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Io(e) => Some(e),
            OpenError::Corrupt => None,
        }
    }
}

impl From<std::io::Error> for OpenError {
    fn from(e: std::io::Error) -> Self {
        OpenError::Io(e)
    }
}

impl WalMerchantStore {
    /// Open (creating if absent) the log at `path`, replaying every complete record into memory
    /// under `merchant_key` (which reconstructs the stored receipts, F3.4). A torn trailing record
    /// is truncated; a complete-but-corrupt record fails the open (`OpenError::Corrupt`).
    pub fn open(path: impl AsRef<Path>, merchant_key: [u8; 32]) -> Result<Self, OpenError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (by_nonce, used_refs, valid_len) = replay(&bytes, &merchant_key)?;
        if valid_len != bytes.len() as u64 {
            file.set_len(valid_len)?;
        }
        file.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            inner: Mutex::new(Wal {
                by_nonce,
                used_refs,
                file,
                len: valid_len,
                poisoned: false,
            }),
        })
    }

    #[cfg(test)]
    pub fn is_poisoned(&self) -> bool {
        self.inner.lock().unwrap().poisoned
    }
}

fn frame(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Read one `[u32 len][bytes]` field advancing `off`; `None` if fewer than a whole field remains.
fn read_field(bytes: &[u8], off: &mut usize) -> Option<Vec<u8>> {
    let start = *off;
    let len_end = start.checked_add(4)?;
    let len_bytes = bytes.get(start..len_end)?;
    let len = u32::from_be_bytes(len_bytes.try_into().ok()?) as usize;
    let data_end = len_end.checked_add(len)?;
    let data = bytes.get(len_end..data_end)?;
    *off = data_end;
    Some(data.to_vec())
}

fn encode_record(r: &NonceRecord) -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, r.payment_ref.as_bytes());
    frame(&mut out, &r.idem);
    frame(&mut out, r.resource.as_bytes());
    out.extend_from_slice(&r.quote_sig);
    out
}

fn decode_record(bytes: &[u8]) -> Option<NonceRecord> {
    let mut off = 0usize;
    let payment_ref = String::from_utf8(read_field(bytes, &mut off)?).ok()?;
    let idem = read_field(bytes, &mut off)?;
    let resource = String::from_utf8(read_field(bytes, &mut off)?).ok()?;
    let sig_end = off.checked_add(64)?;
    let quote_sig: [u8; 64] = bytes.get(off..sig_end)?.try_into().ok()?;
    // A well-formed record consumes exactly its bytes — reject trailing garbage.
    if sig_end != bytes.len() {
        return None;
    }
    Some(NonceRecord {
        payment_ref,
        idem,
        resource,
        quote_sig,
    })
}

type ReplayMaps = (
    HashMap<[u8; 32], (NonceRecord, Receipt)>,
    HashSet<String>,
    u64,
);

/// Replay the byte log. A torn (incomplete) trailing record stops the scan and is truncated at
/// `valid_len`; a COMPLETE record whose payload does not decode is `OpenError::Corrupt` (fail
/// closed — never silently forgotten, unlike a torn tail).
fn replay(bytes: &[u8], merchant_key: &[u8; 32]) -> Result<ReplayMaps, OpenError> {
    let mut by_nonce = HashMap::new();
    let mut used_refs = HashSet::new();
    let mut off = 0usize;
    let mut valid = 0u64;
    // Each iteration reads one COMPLETE 3-frame record; a torn (incomplete) frame ends the scan.
    while let Some(nonce_bytes) = read_field(bytes, &mut off) {
        let Some(rec_bytes) = read_field(bytes, &mut off) else {
            break;
        };
        let Some(rcpt_bytes) = read_field(bytes, &mut off) else {
            break;
        };
        // All three frames fully present → a COMPLETE record: any decode failure is corruption,
        // NOT a torn tail — fail the open closed.
        let nonce: [u8; 32] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| OpenError::Corrupt)?;
        let record = decode_record(&rec_bytes).ok_or(OpenError::Corrupt)?;
        let json = std::str::from_utf8(&rcpt_bytes).map_err(|_| OpenError::Corrupt)?;
        let receipt = Receipt::parse_verify(json, merchant_key).map_err(|_| OpenError::Corrupt)?;
        // Fail closed on SEMANTIC corruption: a valid merchant signature over
        // a receipt whose nonce / idempotency / resource does NOT match this record's is still a
        // corrupt log — a conforming writer always stores the receipt FOR its own nonce record.
        // Accepting it would return a wrong receipt on an idempotent retry (or mis-key the guard).
        if receipt.nonce != nonce
            || receipt.idem != record.idem
            || receipt.resource != record.resource
        {
            return Err(OpenError::Corrupt);
        }
        used_refs.extend(used_ref_keys(&record.payment_ref));
        by_nonce.entry(nonce).or_insert((record, receipt));
        valid = off as u64;
    }
    Ok((by_nonce, used_refs, valid))
}

impl sealed::Sealed for WalMerchantStore {}
impl DurableMerchantStore for WalMerchantStore {}

impl MerchantStore for WalMerchantStore {
    fn peek(&self, nonce: [u8; 32], record: &NonceRecord) -> Peek {
        let wal = self.inner.lock().unwrap();
        if let Some((stored, receipt)) = wal.by_nonce.get(&nonce) {
            return if stored == record {
                Peek::Stored(Box::new(receipt.clone()))
            } else {
                Peek::Replayed
            };
        }
        if used_ref_keys(&record.payment_ref)
            .iter()
            .any(|r| wal.used_refs.contains(r))
        {
            return Peek::Replayed;
        }
        Peek::Fresh
    }

    fn consume_nonce(
        &self,
        nonce: [u8; 32],
        record: &NonceRecord,
        build: &mut dyn FnMut() -> Receipt,
    ) -> Result<Receipt, StoreError> {
        let mut wal = self.inner.lock().unwrap();
        // Poisoned → cannot durably record → refuse (F4.4 durable-or-fail; never deliver unrecorded).
        if wal.poisoned {
            return Err(StoreError::Unavailable);
        }
        if let Some((stored, receipt)) = wal.by_nonce.get(&nonce) {
            if stored == record {
                return Ok(receipt.clone());
            }
            return Err(StoreError::Replayed);
        }
        let ref_keys = used_ref_keys(&record.payment_ref);
        if ref_keys.iter().any(|r| wal.used_refs.contains(r)) {
            return Err(StoreError::Replayed);
        }
        // Fresh: build the receipt, then durably append ONE atomic record BEFORE returning (before
        // delivery, F4.4). `used_refs` is derived from this same record on replay — no two-key gap.
        let receipt = build();
        let mut rec = Vec::new();
        frame(&mut rec, &nonce);
        frame(&mut rec, &encode_record(record));
        frame(&mut rec, &receipt.to_json());
        if wal
            .file
            .write_all(&rec)
            .and_then(|_| wal.file.sync_all())
            .is_err()
        {
            // Truncate the torn tail + reset the cursor; poison if recovery fails.
            let len = wal.len;
            let set = wal.file.set_len(len);
            let seek = wal.file.seek(SeekFrom::Start(len));
            if set.is_err() || seek.is_err() {
                wal.poisoned = true;
            }
            return Err(StoreError::Unavailable);
        }
        wal.len += rec.len() as u64;
        wal.by_nonce
            .insert(nonce, (record.clone(), receipt.clone()));
        wal.used_refs.extend(ref_keys);
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::jcs::StrictValue;
    use paytp_core::tier0::PaidLeg;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn wal_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("paytp-merchstore-{}-{}.wal", std::process::id(), n))
    }

    const SK: [u8; 32] = [7u8; 32];

    fn record(reference: &str) -> NonceRecord {
        NonceRecord {
            payment_ref: reference.into(),
            idem: vec![1, 2, 3],
            resource: "https://example/res".into(),
            quote_sig: [9u8; 64],
        }
    }

    /// A minimal, validly-signed receipt (round-trips through `to_json`/`parse_verify`).
    fn receipt(nonce: [u8; 32], reference: &str) -> Receipt {
        let mut r = Receipt {
            nonce,
            idem: vec![1, 2, 3],
            resource: "https://example/res".into(),
            accept: StrictValue::Object(vec![]),
            paid: vec![PaidLeg {
                leg: "split".into(),
                network: "solana:dev".into(),
                reference: reference.into(),
            }],
            entry: None,
            ts: 100,
            signature: None,
        };
        r.sign(&SK);
        r
    }

    fn pk() -> [u8; 32] {
        paytp_core::crypto::ed25519_public(&SK)
    }

    #[test]
    fn wal_replays_consumed_nonces_across_restart() {
        // A consumed nonce + its receipt survive a restart — so a replayed payment proof after
        // the restart is caught (no double delivery), and an exact retry returns the STORED receipt.
        let path = wal_path();
        let nonce = [0x11u8; 32];
        let rec = record("txA");
        {
            let store = WalMerchantStore::open(&path, pk()).unwrap();
            let mut build = || receipt(nonce, "txA");
            let r = store.consume_nonce(nonce, &rec, &mut build).unwrap();
            assert_eq!(r.paid[0].reference, "txA");
        } // drop → crash / restart

        let store2 = WalMerchantStore::open(&path, pk()).unwrap();
        // The consumed nonce replayed: an exact retry is the idempotent stored receipt (no re-charge).
        match store2.peek(nonce, &rec) {
            Peek::Stored(r) => assert_eq!(r.paid[0].reference, "txA"),
            other => panic!("expected Stored, got {other:?}"),
        }
        // A consume retry returns the same receipt and does NOT double-deliver.
        let mut build = || panic!("must not rebuild — the stored receipt is returned");
        let r = store2.consume_nonce(nonce, &rec, &mut build).unwrap();
        assert_eq!(r.paid[0].reference, "txA");
        // A DIFFERENT nonce reusing the same payment ref is a replay (the derived used_refs survived).
        let mut build2 = || receipt([0x22u8; 32], "txA");
        assert_eq!(
            store2.consume_nonce([0x22u8; 32], &record("txA"), &mut build2),
            Err(StoreError::Replayed),
            "the used-ref guard rebuilt from the records blocks a cross-nonce reuse across restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delimiter_ambiguous_combined_ref_does_not_bypass_net_ref_dedup() {
        let store = InMemoryStore::new();
        let first = record("meed|evil|net");
        let mut build_first = || receipt([0x21u8; 32], "meed|evil|net");
        store
            .consume_nonce([0x21u8; 32], &first, &mut build_first)
            .unwrap();

        let second = record("other-meed|net");
        let mut build_second = || receipt([0x22u8; 32], "other-meed|net");
        assert_eq!(
            store.consume_nonce([0x22u8; 32], &second, &mut build_second),
            Err(StoreError::Replayed),
            "an embedded delimiter in the meed ref must not hide the real net ref from dedup"
        );
    }

    #[test]
    fn used_refs_survive_a_torn_tail_no_ref_without_nonce() {
        // The single atomic record means a torn tail leaves NEITHER a nonce NOR
        // its ref (never a nonce-without-ref that a different nonce could exploit). Seed one whole
        // record, append a torn tail, reopen: the whole record's nonce AND ref both replay; the torn
        // bytes are dropped; the used-ref guard still blocks a cross-nonce reuse.
        let path = wal_path();
        let nonce = [0x33u8; 32];
        {
            let store = WalMerchantStore::open(&path, pk()).unwrap();
            let mut build = || receipt(nonce, "txB");
            store
                .consume_nonce(nonce, &record("txB"), &mut build)
                .unwrap();
        }
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&(999u32).to_be_bytes()).unwrap(); // a length header promising bytes that never came
            f.write_all(b"tp").unwrap();
        }
        let store2 = WalMerchantStore::open(&path, pk()).unwrap();
        assert!(
            matches!(store2.peek(nonce, &record("txB")), Peek::Stored(_)),
            "the whole record survived the torn tail"
        );
        let mut build = || receipt([0x44u8; 32], "txB");
        assert_eq!(
            store2.consume_nonce([0x44u8; 32], &record("txB"), &mut build),
            Err(StoreError::Replayed),
            "used_refs rebuilt from the whole record — no ref-without-nonce window"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_complete_but_corrupt_record_fails_the_open_closed() {
        // A COMPLETE record with a corrupt payload must FAIL the open, not
        // be silently skipped (which would forget a consumed nonce → double-delivery). Craft a
        // complete 3-frame record whose receipt frame is not a valid signed receipt.
        let path = wal_path();
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap();
            let mut buf = Vec::new();
            frame(&mut buf, &[0x55u8; 32]); // nonce
            frame(&mut buf, &encode_record(&record("txC"))); // a valid NonceRecord
            frame(&mut buf, b"{not a receipt}"); // a COMPLETE but invalid receipt frame
            f.write_all(&buf).unwrap();
        }
        assert!(
            matches!(WalMerchantStore::open(&path, pk()), Err(OpenError::Corrupt)),
            "a complete-but-corrupt record must fail the open closed, not be skipped"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_receipt_not_matching_its_record_fails_the_open_closed() {
        // A receipt with a VALID merchant signature but whose nonce (or
        // idem/resource) does NOT match the record it is stored under is semantic corruption — a
        // conforming writer always stores the receipt FOR its own nonce record. Accepting it would
        // return a wrong receipt on an idempotent retry. Fail the open closed.
        let path = wal_path();
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap();
            let mut buf = Vec::new();
            frame(&mut buf, &[0x55u8; 32]); // the record's nonce = 0x55…
            frame(&mut buf, &encode_record(&record("txC")));
            // A validly-signed receipt for a DIFFERENT nonce (0x66…) than the record's.
            frame(&mut buf, &receipt([0x66u8; 32], "txC").to_json());
            f.write_all(&buf).unwrap();
        }
        assert!(
            matches!(WalMerchantStore::open(&path, pk()), Err(OpenError::Corrupt)),
            "a receipt whose nonce != the record's nonce is corrupt, not accepted"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_failed_append_whose_recovery_fails_poisons_and_refuses() {
        // A read-only handle makes the append AND set_len fail → poison → consume returns
        // Unavailable (never delivering an unrecorded consumption, F4.4).
        let path = wal_path();
        {
            let s = WalMerchantStore::open(&path, pk()).unwrap();
            let mut b = || receipt([0x66u8; 32], "seed");
            s.consume_nonce([0x66u8; 32], &record("seed"), &mut b)
                .unwrap();
        }
        // Reopen read-only by swapping the file handle: reuse WalOneDecision's trick is unavailable
        // here, so simulate by opening the log read-only underneath.
        let ro = {
            let file = OpenOptions::new()
                .read(true)
                .write(false)
                .open(&path)
                .unwrap();
            let mut f2 = file;
            let mut bytes = Vec::new();
            f2.read_to_end(&mut bytes).unwrap();
            let (by_nonce, used_refs, valid_len) = replay(&bytes, &pk()).unwrap();
            f2.seek(SeekFrom::Start(valid_len)).unwrap();
            WalMerchantStore {
                inner: Mutex::new(Wal {
                    by_nonce,
                    used_refs,
                    file: f2,
                    len: valid_len,
                    poisoned: false,
                }),
            }
        };
        let mut b = || receipt([0x77u8; 32], "fresh");
        assert_eq!(
            ro.consume_nonce([0x77u8; 32], &record("fresh"), &mut b),
            Err(StoreError::Unavailable),
            "a read-only (failing) durable store refuses the consume — never delivers unrecorded"
        );
        assert!(ro.is_poisoned(), "the failed append poisoned the log");
        let _ = std::fs::remove_file(&path);
    }
}
