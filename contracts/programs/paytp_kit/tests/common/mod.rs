//! Shared test helpers for the `paytp_kit` LiteSVM proofs.

use std::path::Path;
use std::time::SystemTime;

/// The built-program path the LiteSVM proofs load, relative to this crate's manifest.
pub const SO_REL_PATH: &str = "/../../target/deploy/paytp_kit.so";

/// Fail **LOUDLY** if the built `paytp_kit.so` is missing or STALE — older than any contract
/// source under `src/`. LiteSVM loads pre-built SBF bytecode, so a stale `.so` silently runs the
/// proofs against OUTDATED code and can pass a build that no longer matches the source. Every
/// `load()` calls this first, so `cargo test` refuses to render a green proof over stale bytecode:
/// run `cargo build-sbf` to rebuild before testing.
pub fn assert_so_fresh() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let so_path = format!("{manifest}{SO_REL_PATH}");
    let so_mtime = std::fs::metadata(&so_path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| {
            panic!("missing {so_path} — run `cargo build-sbf` first to produce paytp_kit.so")
        });
    let src_dir = format!("{manifest}/src");
    if let Some(newest_src) = newest_mtime(Path::new(&src_dir)) {
        if newest_src > so_mtime {
            panic!(
                "STALE paytp_kit.so: a source file under {src_dir} is newer than the built \
                 target/deploy/paytp_kit.so — run `cargo build-sbf` to rebuild before testing \
                 (LiteSVM would otherwise prove outdated bytecode)"
            );
        }
    }
}

/// The newest modification time of any file in `dir` (recursively), or `None` if unreadable.
fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        let mtime = if path.is_dir() {
            newest_mtime(&path)
        } else {
            std::fs::metadata(&path).and_then(|m| m.modified()).ok()
        };
        if let Some(t) = mtime {
            newest = Some(newest.map_or(t, |cur| cur.max(t)));
        }
    }
    newest
}
