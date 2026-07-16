//! Relay + external-wallet selection (C3 — §10.3 / §10.4).
//!
//! §10.3: the interaction layer asserts its own `0x10` entry and **cross-checks**
//! the `0x11` OS entry against the platform it actually runs on ("which knows the
//! platform it runs on") — it will not relay a role set claiming a foreign IL
//! destination or an OS the platform contradicts. A false OS assertion cannot move
//! value to the asserter (the destinations are pinned, §10.1); the IL's cross-check
//! is the honest-assembly guardrail before the merchant ever sees the set.
//!
//! §10.4: **external-wallet selection is structural.** The IL never bundles a
//! wallet; every flow (see [`crate::flow`]) drives whatever wallet the operator
//! passes, behind the [`paytp_wallet::WalletPolicy`] trait. Substitution is the
//! conformance requirement, and here it is simply "the wallet is a parameter."

use paytp_core::consts::{ROLE_INTERACTION_LAYER, ROLE_OS};
use paytp_core::tier0::roles::Roles;

use crate::discovery::assemble_roles;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// A `0x10` assertion naming a destination that is not this IL's own (§10.3 —
    /// an IL cannot assert another layer's role).
    ForeignInteractionLayer,
    /// A `0x11` assertion contradicting the platform the IL knows it runs on.
    OsAssertionContradictsPlatform,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RelayError {}

/// The interaction layer: its own role destination and the OS it knows it runs on.
pub struct InteractionLayer {
    il_dest: String,
    /// The OS registry identifier the IL knows for its platform, if any. `None`
    /// means a headless environment with no approved OS — the OS share routes to
    /// the independent open-source fund (§10.1), not an asserted recipient.
    platform_os: Option<String>,
}

impl InteractionLayer {
    pub fn new(il_dest: impl Into<String>) -> Self {
        InteractionLayer {
            il_dest: il_dest.into(),
            platform_os: None,
        }
    }

    /// Declare the OS registry identifier the IL's platform maps to (§10.3 — the
    /// IL "knows the platform it runs on").
    pub fn with_platform_os(mut self, os_identifier: impl Into<String>) -> Self {
        self.platform_os = Some(os_identifier.into());
        self
    }

    pub fn il_dest(&self) -> &str {
        &self.il_dest
    }

    /// The `PayTP-Roles` set this IL asserts (its own `0x10`, its platform `0x11`
    /// if any, and the selected wallet's `0x12` if provided).
    pub fn roles(&self, wallet_dest: Option<&str>) -> Roles {
        assemble_roles(&self.il_dest, self.platform_os.as_deref(), wallet_dest)
    }

    /// §10.3 relay validation: refuse to relay a role set whose `0x10` entry is not
    /// this IL's own destination, or whose `0x11` OS entry contradicts the platform
    /// the IL knows.
    pub fn validate_for_relay(&self, roles: &Roles) -> Result<(), RelayError> {
        for a in &roles.items {
            if a.role == ROLE_INTERACTION_LAYER && a.value != self.il_dest {
                return Err(RelayError::ForeignInteractionLayer);
            }
            if a.role == ROLE_OS {
                match &self.platform_os {
                    Some(known) if &a.value == known => {}
                    // A headless IL (no known OS) or a mismatch: the IL will not
                    // vouch for an OS assertion it cannot confirm.
                    _ => return Err(RelayError::OsAssertionContradictsPlatform),
                }
            }
        }
        // Strip-by-omission guard (§10.3): if the IL knows its platform OS, the set
        // it relays MUST carry the matching `0x11` assertion — an upstream that
        // omits it silently strips the OS its share (routing it to the fallback).
        if let Some(known) = &self.platform_os {
            let has_os = roles
                .items
                .iter()
                .any(|a| a.role == ROLE_OS && &a.value == known);
            if !has_os {
                return Err(RelayError::OsAssertionContradictsPlatform);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paytp_core::tier0::roles::{RoleAssertion, Roles};

    #[test]
    fn relays_own_roles_and_rejects_foreign_il() {
        let il = InteractionLayer::new("eip155:1:0xIL").with_platform_os("os.apple.ios");
        // Its own assembled set validates.
        assert_eq!(
            il.validate_for_relay(&il.roles(Some("eip155:1:0xW"))),
            Ok(())
        );
        // A set claiming a foreign IL destination is refused (§10.3).
        let foreign = Roles {
            items: vec![RoleAssertion {
                role: 0x10,
                value: "eip155:1:0xATTACKER".into(),
            }],
        };
        assert_eq!(
            il.validate_for_relay(&foreign),
            Err(RelayError::ForeignInteractionLayer)
        );
    }

    #[test]
    fn os_assertion_is_cross_checked_against_the_platform() {
        let il = InteractionLayer::new("eip155:1:0xIL").with_platform_os("os.apple.ios");
        let wrong_os = Roles {
            items: vec![
                RoleAssertion {
                    role: 0x10,
                    value: "eip155:1:0xIL".into(),
                },
                RoleAssertion {
                    role: 0x11,
                    value: "os.google.android".into(),
                },
            ],
        };
        assert_eq!(
            il.validate_for_relay(&wrong_os),
            Err(RelayError::OsAssertionContradictsPlatform)
        );
        // A headless IL (no known OS) will not vouch for ANY OS assertion.
        let headless = InteractionLayer::new("eip155:1:0xIL");
        let any_os = Roles {
            items: vec![RoleAssertion {
                role: 0x11,
                value: "os.apple.ios".into(),
            }],
        };
        assert_eq!(
            headless.validate_for_relay(&any_os),
            Err(RelayError::OsAssertionContradictsPlatform)
        );
    }
}
