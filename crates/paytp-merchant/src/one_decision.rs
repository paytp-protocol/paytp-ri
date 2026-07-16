//! The durable `OneDecisionStore` — the channel-plane exactly-once record that
//! survives a merchant **restart** and is shared **across whatever serves the traffic**.
//!
//! It generalizes the Tier-0 [`crate::MerchantStore`] CAS (the consumed-nonce record)
//! to every channel one-decision guard: a funding reference is credited once, a close disposition
//! (successor-import XOR refund) is set once, a close refund is issued once. The in-process `&mut
//! self` maps on the `Carriage` are the working cache; THIS store is the durable authority the
//! cache is replayed from at startup, so a crash between a decision and its side effect never
//! double-pays or double-refunds (the deferral the carriage comments name "the durable
//! store").
//!
//! **Write-ahead ordering.** A caller does the *idempotent* side effect FIRST (an on-chain
//! `release_keyed` the rail dedups), THEN [`OneDecisionStore::decide`] durably records it. A crash
//! in that window replays as *unrecorded* → the caller re-attempts the side effect → the rail
//! dedups it → the effect lands EXACTLY ONCE. A crash after the record replays as
//! [`Decision::AlreadyDecided`] → the caller skips. Either path is exactly-once.
//!
//! **Failure is not duplication.** A caller whose gated side effect is a *one-shot* mutation that
//! does NOT run before the record — a funding credit — records FIRST, then credits. For it, a
//! failed write ([`Decision::Failed`]) and a genuine duplicate ([`Decision::AlreadyDecided`]) are
//! opposite decisions: the duplicate means "already credited, skip"; the failure means "nothing
//! recorded, do NOT credit, retry". Conflating them acks a deposit the merchant never credited
//! (C1-3), so `decide` reports them distinctly and every money-path caller matches on all three.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

/// The outcome of claiming a decision key (F4.4 exactly-once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The key was unrecorded; `(key → value)` is now durably recorded. The caller performs the
    /// gated side effect exactly this once.
    Fresh,
    /// The key was already decided; here is the recorded value. The caller MUST NOT repeat the
    /// side effect (an idempotent replay, a cross-replica duplicate, or a post-restart retry).
    AlreadyDecided(Vec<u8>),
    /// The store could NOT durably record the decision (a write/sync error). **Nothing** was
    /// recorded and **no** prior decision exists — this is NOT [`Decision::AlreadyDecided`]. The
    /// distinction is load-bearing: a caller whose side effect is idempotent + rail-deduped (a
    /// keyed release) may skip and let a retry redo it, but a caller gating a **one-shot state
    /// mutation** (a funding credit) MUST reject/retry rather than mistake a failed write for a
    /// duplicate and ack success without crediting (C1-3). Never returned by the in-memory store.
    Failed,
}

/// A keyed, durable, exactly-once decision record. Implementations are `Send + Sync` so one store
/// backs every carriage that serves the channel (the F4.4 concurrency property, not an afterthought).
pub trait OneDecisionStore: Send + Sync {
    /// Atomically claim `key`: if unrecorded, DURABLY record `(key → value)` and return
    /// [`Decision::Fresh`]; else return [`Decision::AlreadyDecided`] with the stored value. This
    /// consolidates *decide* + *record* into one atomic, crash-safe step (a torn append replays as
    /// unrecorded) — the exactly-once gate. `value` may be empty for a bare present/absent guard.
    fn decide(&self, key: &[u8], value: &[u8]) -> Decision;

    /// The recorded value for `key`, if any — a read-only peek (a fast-path skip before re-doing an
    /// idempotent side effect). The atomic gate remains [`OneDecisionStore::decide`].
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Every recorded `(key, value)` — for replaying the durable log into a merchant's working
    /// maps at startup ([`crate::carriage::Carriage::proof`]).
    fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
}

mod sealed {
    pub trait Sealed {}
}

/// A **durable, restart-surviving** one-decision store — a *construction-proof* marker.
/// Sealed: only this crate's audited durable stores (the reference
/// [`WalOneDecision`], a future DB profile) may implement it, so a proof constructor bounded on
/// `DurableOneDecision` **cannot** be satisfied by an in-memory store that merely *claims*
/// durability (the operator-trust hole a public `is_durable() -> bool` would leave). Not
/// implemented for `InMemoryOneDecision`.
pub trait DurableOneDecision: OneDecisionStore + sealed::Sealed {}

impl sealed::Sealed for WalOneDecision {}
impl DurableOneDecision for WalOneDecision {}

/// In-memory store (single process) — the same compare-and-set a real DB gives, and the durable
/// WAL's replay target. **Not persistent** and **not** [`DurableOneDecision`]: a proof build cannot
/// name it (`#[cfg]`-gated to tests / the `demo` feature) and a proof constructor cannot accept it.
#[cfg(any(test, feature = "demo"))]
#[derive(Default)]
pub struct InMemoryOneDecision {
    inner: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

#[cfg(any(test, feature = "demo"))]
impl InMemoryOneDecision {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(any(test, feature = "demo"))]
impl OneDecisionStore for InMemoryOneDecision {
    fn decide(&self, key: &[u8], value: &[u8]) -> Decision {
        let mut m = self.inner.lock().unwrap();
        if let Some(v) = m.get(key) {
            return Decision::AlreadyDecided(v.clone());
        }
        m.insert(key.to_vec(), value.to_vec());
        Decision::Fresh
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().get(key).cloned()
    }

    fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// A **reference durable** store: an append-only write-ahead log on disk that replays into memory
/// at [`WalOneDecision::open`]. Each decision is one length-prefixed record `[u32 key_len][key][u32
/// val_len][val]` (big-endian), appended and `sync_all`-ed before `decide` returns — so a decision
/// is durable the instant the caller learns it is `Fresh`. A torn trailing record (a crash mid-
/// append) is detected and truncated on open, so a half-written decision replays as **unmade** and
/// the exactly-once side effect it gated (which had not run yet) is free to run on retry.
///
/// A real deployment swaps this for the DB profile (Postgres, M3); the on-disk log is the reference
/// semantics — first record wins, monotonic, replay-complete — a conforming store must match.
pub struct WalOneDecision {
    inner: Mutex<Wal>,
}

struct Wal {
    map: HashMap<Vec<u8>, Vec<u8>>,
    file: File,
    /// Byte length of the durable (whole, synced) records — the append offset. Tracked so a FAILED
    /// append (a partial write that advanced the OS cursor) can be truncated back to it, keeping the
    /// log free of torn framing that a later replay would otherwise truncate valid decisions behind.
    len: u64,
    /// Set once the log's framing integrity can no longer be guaranteed: a failed append whose
    /// truncation-recovery (`set_len`/`seek` back to `len`) ALSO failed, so a torn tail remains and
    /// the OS cursor may sit past it. Appending again would land a record BEHIND that torn framing,
    /// which `replay` truncates on the next open → the just-recorded decision is silently dropped
    /// → double-delivery. Once poisoned every `decide` fails closed
    /// (records nothing), so the on-disk log holds at most ONE torn tail and a restart truncates it
    /// cleanly, preserving every whole decision. Recovery is a fresh `open` (which truncates the tail).
    poisoned: bool,
}

impl WalOneDecision {
    /// Open (creating if absent) the log at `path`, REPLAY every complete record into memory, and
    /// truncate any torn trailing bytes. Returns a store positioned to append.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // append-only: preserve the existing log to replay it
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (map, valid_len) = replay(&bytes);
        // Drop a torn trailing record (a crash mid-append) so the log holds only whole decisions.
        if valid_len != bytes.len() as u64 {
            file.set_len(valid_len)?;
        }
        file.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            inner: Mutex::new(Wal {
                map,
                file,
                len: valid_len,
                poisoned: false,
            }),
        })
    }
}

/// Replay a byte log into a map, returning the map and the byte length of the last COMPLETE record
/// (everything past it is a torn tail to truncate). First writer of a key wins (append-only, so the
/// earliest record is the decision; a later duplicate — which `decide` never writes — is ignored).
fn replay(bytes: &[u8]) -> (HashMap<Vec<u8>, Vec<u8>>, u64) {
    let mut map = HashMap::new();
    let mut off = 0usize;
    let mut valid = 0u64;
    while let Some(key) = read_field(bytes, &mut off) {
        let Some(val) = read_field(bytes, &mut off) else {
            break; // key present but value torn → the whole record is incomplete
        };
        map.entry(key).or_insert(val);
        valid = off as u64;
    }
    (map, valid)
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

impl OneDecisionStore for WalOneDecision {
    fn decide(&self, key: &[u8], value: &[u8]) -> Decision {
        let mut wal = self.inner.lock().unwrap();
        // Poisoned (a prior failed append whose truncation-recovery also failed): fail closed and
        // record NOTHING, so the log keeps at most one torn tail that a restart truncates cleanly —
        // never a valid record stranded behind torn framing.
        if wal.poisoned {
            return Decision::Failed;
        }
        if let Some(v) = wal.map.get(key) {
            return Decision::AlreadyDecided(v.clone());
        }
        // Append the record and fsync BEFORE returning `Fresh` — the decision is durable the instant
        // the caller learns it. (A rail whose disk is lost has bigger problems than a double-refund;
        // the reference contract is: `Fresh` ⇒ recorded.)
        let mut rec = Vec::with_capacity(8 + key.len() + value.len());
        rec.extend_from_slice(&(key.len() as u32).to_be_bytes());
        rec.extend_from_slice(key);
        rec.extend_from_slice(&(value.len() as u32).to_be_bytes());
        rec.extend_from_slice(value);
        // On a write/sync error a PARTIAL write may have advanced the OS cursor past the last durable
        // record — TRUNCATE back to `len` (and re-seek there) so the log holds only whole, synced
        // records and the next append lands cleanly, never behind torn framing that a restart's
        // replay would truncate valid decisions behind. The
        // decision is NOT recorded (memory or disk), so it fails closed — but as [`Decision::Failed`],
        // NOT `AlreadyDecided`: a funding caller must distinguish "the disk failed, nothing consumed,
        // retry" from "another party already decided this, skip" (C1-3). Returning `AlreadyDecided`
        // here made `consume_ref` report a genuine first funding as a duplicate → the merchant acked
        // the deposit without crediting the window.
        if wal
            .file
            .write_all(&rec)
            .and_then(|_| wal.file.sync_all())
            .is_err()
        {
            // Truncate back to the last durable record and reset the cursor. If EITHER recovery op
            // fails (a still-failing disk), the torn tail cannot be removed and the cursor may sit
            // past it — POISON so no later append lands behind that framing (it would be dropped on
            // the next replay → double-decision). A poisoned store fails every subsequent decide.
            let len = wal.len;
            let set = wal.file.set_len(len);
            let seek = wal.file.seek(SeekFrom::Start(len));
            if set.is_err() || seek.is_err() {
                wal.poisoned = true;
            }
            return Decision::Failed;
        }
        wal.len += rec.len() as u64;
        wal.map.insert(key.to_vec(), value.to_vec());
        Decision::Fresh
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().map.get(key).cloned()
    }

    fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner
            .lock()
            .unwrap()
            .map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
impl WalOneDecision {
    /// Test-only: whether the log has poisoned itself (a failed append whose truncation-recovery
    /// also failed). A poisoned store fails every subsequent `decide` closed.
    pub fn is_poisoned(&self) -> bool {
        self.inner.lock().unwrap().poisoned
    }

    /// Test-only: open the log for reading but with a **read-only** file handle, so every `decide`
    /// append hits a real `write_all` error — the deterministic way to exercise the storage-failure
    /// branch (C1-3) without racing an actual disk. Existing records still replay (the read path is
    /// intact); only new appends fail.
    pub fn read_only_for_test(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        // Ensure the file exists (create it writable, then drop) so the read-only reopen succeeds.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut file = OpenOptions::new().read(true).write(false).open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (map, valid_len) = replay(&bytes);
        file.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            inner: Mutex::new(Wal {
                map,
                file,
                len: valid_len,
                poisoned: false,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique scratch WAL path (no `tempfile` dep): temp dir + pid + a process-local counter.
    fn wal_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "paytp-onedecision-{}-{}.wal",
            std::process::id(),
            n
        ))
    }

    fn both() -> Vec<Box<dyn OneDecisionStore>> {
        vec![
            Box::new(InMemoryOneDecision::new()),
            Box::new(WalOneDecision::open(wal_path()).unwrap()),
        ]
    }

    #[test]
    fn fresh_then_already_decided_returns_the_first_value() {
        for s in both() {
            assert_eq!(s.decide(b"k", b"v1"), Decision::Fresh);
            // A second decide on the same key NEVER overwrites — the first decision wins, and its
            // value is returned (idempotent; the caller's retry sees what it recorded).
            assert_eq!(
                s.decide(b"k", b"v2"),
                Decision::AlreadyDecided(b"v1".to_vec())
            );
            assert_eq!(s.get(b"k"), Some(b"v1".to_vec()));
            assert_eq!(s.get(b"absent"), None);
        }
    }

    #[test]
    fn empty_value_is_a_present_absent_guard() {
        for s in both() {
            assert_eq!(s.get(b"fund:ref9"), None);
            assert_eq!(s.decide(b"fund:ref9", b""), Decision::Fresh);
            assert_eq!(
                s.decide(b"fund:ref9", b""),
                Decision::AlreadyDecided(Vec::new())
            );
            assert_eq!(s.get(b"fund:ref9"), Some(Vec::new()));
        }
    }

    #[test]
    fn wal_replays_decisions_across_a_reopen_restart() {
        let path = wal_path();
        {
            let s = WalOneDecision::open(&path).unwrap();
            assert_eq!(s.decide(b"disp:chanA", b"committed"), Decision::Fresh);
            assert_eq!(s.decide(b"refund:chanB", b""), Decision::Fresh);
            assert_eq!(s.decide(b"fund:refX", b""), Decision::Fresh);
        } // drop → simulate a crash / process exit

        // Reopen the SAME log — the durable decisions REPLAY: a re-decide is AlreadyDecided.
        let s2 = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            s2.decide(b"disp:chanA", b"reconciled"),
            Decision::AlreadyDecided(b"committed".to_vec()),
            "the close disposition survived the restart — no re-decision"
        );
        assert_eq!(
            s2.decide(b"refund:chanB", b""),
            Decision::AlreadyDecided(Vec::new()),
            "the refund decision survived — a replay must not re-refund"
        );
        assert_eq!(s2.get(b"fund:refX"), Some(Vec::new()));
        // A brand-new key is still fresh after the restart.
        assert_eq!(s2.decide(b"fund:refY", b""), Decision::Fresh);

        let mut keys: Vec<_> = s2.entries().into_iter().map(|(k, _)| k).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                b"disp:chanA".to_vec(),
                b"fund:refX".to_vec(),
                b"fund:refY".to_vec(),
                b"refund:chanB".to_vec()
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wal_truncates_a_torn_trailing_record_and_replays_the_rest() {
        let path = wal_path();
        {
            let s = WalOneDecision::open(&path).unwrap();
            assert_eq!(s.decide(b"refund:done", b""), Decision::Fresh);
        }
        // Simulate a crash mid-append: a whole record, then a torn tail (a length header promising
        // more bytes than were written before the crash).
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&(99u32).to_be_bytes()).unwrap(); // claims a 99-byte key, but nothing follows
            f.write_all(b"tp").unwrap();
        }
        // Reopen: the torn tail is dropped, the complete record replays, and the log is appendable.
        let s2 = WalOneDecision::open(&path).unwrap();
        assert_eq!(s2.get(b"refund:done"), Some(Vec::new()));
        assert_eq!(s2.entries().len(), 1, "only the complete record survives");
        // The half-written decision replays as UNMADE → its key is free to decide fresh (the gated
        // side effect never ran, so it may run now).
        assert_eq!(s2.decide(b"refund:torn", b""), Decision::Fresh);
        // And that fresh decision is itself durable across another reopen.
        drop(s2);
        let s3 = WalOneDecision::open(&path).unwrap();
        assert_eq!(
            s3.decide(b"refund:torn", b""),
            Decision::AlreadyDecided(Vec::new())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_decide_across_shared_store_admits_one_winner() {
        // The F4.4 property: one store behind an Arc, many threads racing the SAME key → EXACTLY one
        // `Fresh`, the rest `AlreadyDecided` (across-whatever-serves-the-traffic exactly-once).
        use std::sync::Arc;
        let s: Arc<dyn OneDecisionStore> = Arc::new(WalOneDecision::open(wal_path()).unwrap());
        let fresh = Arc::new(AtomicU64::new(0));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let s = s.clone();
            let fresh = fresh.clone();
            hs.push(std::thread::spawn(move || {
                if s.decide(b"refund:race", b"") == Decision::Fresh {
                    fresh.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(
            fresh.load(Ordering::Relaxed),
            1,
            "exactly one thread wins the one-decision race"
        );
    }

    #[test]
    fn decide_reports_failed_on_a_write_error_not_a_phantom_duplicate() {
        // C1-3: when the durable append fails, `decide` MUST report `Failed` (nothing recorded,
        // retry) — NOT `AlreadyDecided` (a duplicate the caller skips). The old code returned
        // `AlreadyDecided(Vec::new())`, which a funding caller reads as "already credited" and so
        // acks a deposit it never credited.
        let path = wal_path();
        // Seed one real, durable record through a WRITABLE store, then drop it.
        {
            let s = WalOneDecision::open(&path).unwrap();
            assert_eq!(s.decide(b"funded", b""), Decision::Fresh);
        }
        // Reopen read-only: the append path now fails for real; the read path still works.
        let ro = WalOneDecision::read_only_for_test(&path).unwrap();
        assert_eq!(
            ro.get(b"funded"),
            Some(Vec::new()),
            "the previously-recorded decision still replays (read path intact)"
        );
        // A genuinely-fresh key cannot be recorded → Failed, and NOTHING is recorded, so the key
        // stays absent and a retry against a recovered store can record it exactly once.
        assert_eq!(ro.decide(b"fresh-ref", b""), Decision::Failed);
        assert_eq!(
            ro.get(b"fresh-ref"),
            None,
            "a failed decide records nothing — the key is still free to decide on retry"
        );
        // Recovery: a writable store over the same log records the ref cleanly (exactly once).
        drop(ro);
        let rw = WalOneDecision::open(&path).unwrap();
        assert_eq!(rw.decide(b"fresh-ref", b""), Decision::Fresh);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_failed_append_whose_recovery_fails_poisons_the_log() {
        // If a failed `write_all` leaves a torn tail AND the truncation
        // recovery (`set_len`/`seek`) ALSO fails, a later append would land BEHIND the torn framing
        // and be dropped on the next replay → double-decision. The fix POISONS the log on a
        // recovery failure, so every subsequent decide fails closed (records nothing) — the log
        // holds at most one torn tail a restart truncates cleanly. A read-only handle makes both the
        // append AND `set_len` fail (a read-only fd cannot truncate), the deterministic trigger.
        let path = wal_path();
        // Seed one durable record so the log is non-empty (the torn tail would follow it).
        {
            let s = WalOneDecision::open(&path).unwrap();
            assert_eq!(s.decide(b"valid-1", b""), Decision::Fresh);
        }
        let ro = WalOneDecision::read_only_for_test(&path).unwrap();
        assert!(!ro.is_poisoned(), "not poisoned until a recovery fails");
        // The append fails (read-only) and `set_len` fails (read-only) → poison.
        assert_eq!(ro.decide(b"would-corrupt", b""), Decision::Failed);
        assert!(
            ro.is_poisoned(),
            "a failed append whose set_len recovery also failed poisons the log"
        );
        // Every subsequent decide now fails closed WITHOUT attempting an append — so no record can
        // land behind the torn tail. The previously-recorded decision is untouched (read path intact).
        assert_eq!(ro.decide(b"also-refused", b""), Decision::Failed);
        assert_eq!(ro.get(b"valid-1"), Some(Vec::new()));
        let _ = std::fs::remove_file(&path);
    }
}
