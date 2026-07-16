//! Discovery (C1): the control-path / resource-suffix joining rule (F2) and
//! `PayTP-Roles` assembly (F3.3).
//!
//! F2 fixes resource-path joining deterministically: the advertised control path
//! **MUST NOT end in `/`**, and each PayTP resource is the control path with the
//! listed suffix appended. A trailing slash would make `control + "/attest"`
//! ambiguous (`//attest`), so it is a hard reject, never repaired.

use paytp_core::consts::{ROLE_INTERACTION_LAYER, ROLE_OS, ROLE_WALLET};
use paytp_core::tier0::roles::{RoleAssertion, Roles};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The advertised control path ended in `/` (F2 — rejected, never repaired).
    ControlPathTrailingSlash,
    /// The control path was empty.
    ControlPathEmpty,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DiscoveryError {}

/// Validate an advertised control path (F2): non-empty and no trailing `/`.
pub fn validate_control_path(control: &str) -> Result<(), DiscoveryError> {
    if control.is_empty() {
        return Err(DiscoveryError::ControlPathEmpty);
    }
    if control.ends_with('/') {
        return Err(DiscoveryError::ControlPathTrailingSlash);
    }
    Ok(())
}

/// Join a validated control path with a resource suffix deterministically
/// (F2): `control + "/" + suffix`. The suffix's own leading `/`, if any, is not
/// doubled.
pub fn resource_path(control: &str, suffix: &str) -> Result<String, DiscoveryError> {
    validate_control_path(control)?;
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    Ok(format!("{control}/{suffix}"))
}

/// Assemble the `PayTP-Roles` header the interaction layer sends (F3.3): its own
/// `0x10` destination, optionally the `0x11` OS registry identifier, and
/// optionally the `0x12` wallet destination — in ascending role order (the
/// encoder enforces the ordering/one-per-role rules).
pub fn assemble_roles(
    il_dest: &str,
    os_identifier: Option<&str>,
    wallet_dest: Option<&str>,
) -> Roles {
    let mut items = vec![RoleAssertion {
        role: ROLE_INTERACTION_LAYER,
        value: il_dest.to_string(),
    }];
    if let Some(os) = os_identifier {
        items.push(RoleAssertion {
            role: ROLE_OS,
            value: os.to_string(),
        });
    }
    if let Some(w) = wallet_dest {
        items.push(RoleAssertion {
            role: ROLE_WALLET,
            value: w.to_string(),
        });
    }
    items.sort_by_key(|a| a.role);
    Roles { items }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_path_must_not_end_in_slash() {
        assert_eq!(validate_control_path("https://api.example/paytp"), Ok(()));
        assert_eq!(
            validate_control_path("https://api.example/paytp/"),
            Err(DiscoveryError::ControlPathTrailingSlash)
        );
        assert_eq!(
            validate_control_path(""),
            Err(DiscoveryError::ControlPathEmpty)
        );
    }

    #[test]
    fn resource_suffix_joining_is_deterministic() {
        assert_eq!(
            resource_path("https://api.example/paytp", "attest").unwrap(),
            "https://api.example/paytp/attest"
        );
        // A leading slash on the suffix is not doubled.
        assert_eq!(
            resource_path("https://api.example/paytp", "/attest").unwrap(),
            "https://api.example/paytp/attest"
        );
        assert!(resource_path("https://api.example/paytp/", "attest").is_err());
    }

    #[test]
    fn roles_assemble_ascending_and_encode() {
        let roles = assemble_roles(
            "eip155:1:0xIL",
            Some("os.apple.ios"),
            Some("eip155:1:0xWallet"),
        );
        let ids: Vec<u8> = roles.items.iter().map(|a| a.role).collect();
        assert_eq!(ids, vec![0x10, 0x11, 0x12]); // ascending role ids
                                                 // The canonical encoder accepts the assembled set.
        assert!(roles.encode().is_ok());
        // IL-only (headless, no OS) also encodes.
        assert!(assemble_roles("eip155:1:0xIL", None, None).encode().is_ok());
    }
}
