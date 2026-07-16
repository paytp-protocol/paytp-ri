//! The normative x402-named-network ↔ CAIP-2 table (**F3-j rule 3**).
//!
//! The shipped x402 tooling encodes `network` as a **named enum** (`"solana"`,
//! `"base"`, …), while PayTP's own `paytp.baseline` stays **CAIP-2** (F3-j rule
//! 1). This fixed, **1:1** table bridges them for the two directions the RI
//! needs:
//! - **emit** (`caip2_to_x402`): the merchant renders a baseline offer's CAIP-2
//!   `baseline` as the x402 named network in the mirrored accepts entry;
//! - **rail check** (`x402_to_caip2`): a PayTP-aware wallet maps the envelope's
//!   named network back to CAIP-2 to confirm it equals `paytp.baseline`
//!   (F3-j rule 2 — baseline offers only).
//!
//! **Fail-closed** (F3-j rule 3): an unknown name/id returns `None`; the caller
//! refuses the offer. **Strict mainnet/testnet** — `solana` and `solana-devnet`
//! are distinct genesis hashes, never conflated. This table is owned/versioned by
//! the PayTP extension registration; the entries here are the RI's pinned copy
//! (EVM CAIP-2 from the x402 chain ids; Solana CAIP-2 from the genesis prefixes).

/// The fixed 1:1 mapping: `(x402 named network, CAIP-2 identifier)`.
const TABLE: &[(&str, &str)] = &[
    // Solana (strict mainnet vs devnet — F3-j rule 3).
    ("solana", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
    ("solana-devnet", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
    // EVM (CAIP-2 `eip155:<chainId>`, chain ids from x402's `getNetworkId`).
    ("base", "eip155:8453"),
    ("base-sepolia", "eip155:84532"),
    ("avalanche", "eip155:43114"),
    ("avalanche-fuji", "eip155:43113"),
    ("polygon", "eip155:137"),
    ("polygon-amoy", "eip155:80002"),
];

/// CAIP-2 → the x402 named network (for emission). Fail-closed: `None` if the
/// CAIP-2 identifier is not in the table.
pub fn caip2_to_x402(caip2: &str) -> Option<&'static str> {
    TABLE.iter().find(|(_, c)| *c == caip2).map(|(n, _)| *n)
}

/// x402 named network → CAIP-2 (for the wallet's baseline rail check). Fail-closed.
pub fn x402_to_caip2(name: &str) -> Option<&'static str> {
    TABLE.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_strict() {
        for (name, caip2) in TABLE {
            assert_eq!(caip2_to_x402(caip2), Some(*name));
            assert_eq!(x402_to_caip2(name), Some(*caip2));
        }
    }

    #[test]
    fn mainnet_and_testnet_never_conflated() {
        assert_ne!(x402_to_caip2("solana"), x402_to_caip2("solana-devnet"));
        assert_eq!(
            x402_to_caip2("solana"),
            Some("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
        );
        assert_eq!(
            x402_to_caip2("solana-devnet"),
            Some("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
        );
    }

    #[test]
    fn unknown_fails_closed() {
        assert_eq!(x402_to_caip2("ethereum"), None); // no such x402 name
        assert_eq!(caip2_to_x402("eip155:1"), None); // mainnet-ETH not an x402 network
        assert_eq!(caip2_to_x402("solana:deadbeef"), None);
        assert_eq!(x402_to_caip2(""), None);
    }

    #[test]
    fn table_is_one_to_one() {
        // No duplicate names and no duplicate CAIP-2 ids (1:1, F3-j rule 3).
        for (a, (name_a, caip_a)) in TABLE.iter().enumerate() {
            for (name_b, caip_b) in TABLE.iter().skip(a + 1) {
                assert_ne!(name_a, name_b);
                assert_ne!(caip_a, caip_b);
            }
        }
    }
}
