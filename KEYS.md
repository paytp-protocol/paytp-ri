# Key hygiene policy (paytp-ri)

This file governs every key
this repository or its CI ever touches.

## Rules

1. **Throwaway deployer keys only.** Any key used to deploy or fund a contract
   on a devnet/testnet is generated for that purpose and disposable. Never a
   personal wallet key, never a key with mainnet value.
2. **Nothing secret is committed.** No private keys, no seed phrases, no funded
   accounts, no RPC keys with write authority in the repo or in CI config.
   Secrets reach CI only through the CI provider's secret store, never a file.
3. **Test vectors are public by construction.** The F10 conformance corpus
   publishes *test* keys and deterministic signatures (F10.2). Those are fixed,
   documented, valueless test keys — they are NOT covered by rule 1/2 and are
   meant to be checked in so a second implementation can reproduce the vectors.
   A test key file MUST say `TEST KEY — NO VALUE` in a header.
4. **M0 uses no live keys at all.** M0 is pure encoding, arithmetic, and
   local crypto against RFC/hand-derived vectors. The first real key appears at
   M0.5 (the testnet contract spike), under rules 1–2.

## Where test keys live

`conformance/` holds the pinned test inputs. Generation-required vectors
(Ed25519/Poly1305/HPKE/exporter) publish their deterministic test keys beside
the vectors they produce (F10.2), added when M1's independent crypto path
confirms them.
