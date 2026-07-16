# Vendored, pinned data — `paytp-host`

## `public_suffix_list.dat`

The Mozilla **Public Suffix List**, vendored verbatim and **pinned** so the
registrable-domain resolution (and therefore the payer-key derivation scope, F1-f/
F2.3) is byte-reproducible across builds.

- **Source (only supported):** <https://publicsuffix.org/list/public_suffix_list.dat>
- **Pinned version:** `2026-07-14_09-26-39_UTC` (the file's own `// VERSION:` line;
  mirrored in `paytp_host::PSL_VERSION` / `psl::PSL_VERSION`).
- **License:** Mozilla Public License v2.0 (the list's own header block; retained
  verbatim in the file).
- **Both sections are loaded** and treated as public suffixes ("include private
  domains" mode), so a private-section suffix (e.g. `github.io`) is a registrable-
  domain boundary — the unlinkability boundary two tenants of one host provider need.

### Refreshing the pin (deliberate, reviewed)

Refreshing the list is a **data-version bump**, never a silent float:

1. Re-download from the source URL above.
2. Replace this file.
3. Update `PSL_VERSION` in `crates/paytp-host/src/psl.rs` to the new `// VERSION:` line.
4. Re-run `cargo test -p paytp-host` (the parse floor + eTLD+1 cases).

Because a refresh can change which host resolves to which registrable domain, and
thus which payer key a wallet derives, treat it like any other derivation change:
version it and document it (it is a **re-key**, by design — see the payer-key
derivation version in `paytp-wallet/src/custody.rs`).

## UTS#46 / Unicode table

Not a file here — it is the pinned `idna` crate (`=1.1.0`) and its ICU4X data,
locked in the workspace `Cargo.lock`. It provides non-transitional UTS#46 + STD3 +
bidi/joiner processing. Bumping `idna` is the analogous deliberate table-version
change on the Unicode side.
