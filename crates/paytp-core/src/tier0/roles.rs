//! The `PayTP-Roles` header (**F3.3 / DECISION F3-e**, formalizing §5.6 step 1).
//!
//! An unsigned TLV object — an assertion input the merchant bakes into the quote
//! it signs, not an authenticated object. One TLV, type `0x00 ROLES`, whose
//! value is a count-prefixed ascending list of `role_id (1) ‖ len ‖ value`.
//! For `0x10` (interaction layer) / `0x12` (wallet): `value` is a destination
//! pointer (F9-a). For `0x11` (OS): `value` is a registry recipient identifier
//! (F9-b). Absence is never an error — it routes to the fallback (§5.6).

use crate::consts::{ROLE_INTERACTION_LAYER, ROLE_OS, ROLE_WALLET};
use crate::error::{Error, Result};
use crate::pointer::Pointer;
use crate::registry::validate_identifier;
use crate::tlv::{self, Field, Object, Openness, Schema};

const T_ROLES: u8 = 0x00;

/// One asserted role and its value (a pointer for IL/wallet, an identifier for OS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssertion {
    pub role: u8,
    pub value: String,
}

/// The parsed `PayTP-Roles` assertion set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roles {
    pub items: Vec<RoleAssertion>,
}

impl Roles {
    /// Encode to the canonical unsigned TLV object.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let items: Vec<Vec<u8>> = self
            .items
            .iter()
            .map(|a| {
                let mut out = vec![a.role];
                let v = a.value.as_bytes();
                crate::leb128::encode_into(v.len() as u64, &mut out);
                out.extend_from_slice(v);
                out
            })
            .collect();
        let obj = Object::from_fields(vec![Field::new(
            T_ROLES,
            false,
            tlv::build_count_prefixed(&items),
        )])?;
        Ok(obj.encode())
    }

    /// Parse and validate the header (F3-e): ascending role id, at most one per
    /// role, each value well-formed for its role.
    pub fn parse(buf: &[u8]) -> Result<Roles> {
        let obj = Object::parse(buf)?;
        obj.validate(&Schema::new(Openness::Closed, &[(T_ROLES, false)]))?;
        let value = &obj.get(T_ROLES).ok_or(Error::MissingField)?.value;
        let items: Vec<RoleAssertion> = tlv::parse_count_prefixed(value, |b| {
            if b.is_empty() {
                return Err(Error::CountMismatch);
            }
            let role = b[0];
            let (len, n) = crate::leb128::decode(&b[1..])?;
            let start = 1 + n;
            let end = start
                .checked_add(len as usize)
                .ok_or(Error::LengthOverrun)?;
            if end > b.len() {
                return Err(Error::LengthOverrun);
            }
            let value = std::str::from_utf8(&b[start..end])
                .map_err(|_| Error::TextNotUtf8)?
                .to_string();
            Ok((RoleAssertion { role, value }, end))
        })?;
        // Ascending, unique roles.
        for w in items.windows(2) {
            if w[0].role >= w[1].role {
                return Err(Error::TypeOrder);
            }
        }
        // Value well-formedness per role.
        for a in &items {
            match a.role {
                ROLE_INTERACTION_LAYER | ROLE_WALLET => {
                    Pointer::parse(&a.value)?;
                }
                ROLE_OS => {
                    validate_identifier(&a.value)?;
                }
                _ => {} // a merchant ignores items for roles the schema doesn't price
            }
        }
        Ok(Roles { items })
    }

    /// The asserted OS recipient identifier, if any (for registry resolution).
    pub fn asserted_os(&self) -> Option<&str> {
        self.items
            .iter()
            .find(|a| a.role == ROLE_OS)
            .map(|a| a.value.as_str())
    }

    /// The asserted `0x10` interaction-layer destination pointer, if any — the IL's own
    /// expected meed pointer, used to self-defend `0x10` against a hostile merchant
    /// rerouting it (F5-o payer-side self-defense).
    pub fn asserted_il(&self) -> Option<&str> {
        self.items
            .iter()
            .find(|a| a.role == ROLE_INTERACTION_LAYER)
            .map(|a| a.value.as_str())
    }

    /// The asserted `0x12` wallet destination pointer, if any. NOTE: a wallet defending
    /// its OWN `0x12` share must use its OWN configured pointer, **not** this (the
    /// header is assembled by the untrusted interaction layer, F3.3); this accessor is
    /// for a party cross-checking what the header claims, never the wallet's authority.
    pub fn asserted_wallet(&self) -> Option<&str> {
        self.items
            .iter()
            .find(|a| a.role == ROLE_WALLET)
            .map(|a| a.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_ordering() {
        let roles = Roles {
            items: vec![
                RoleAssertion {
                    role: 0x10,
                    value: "eip155:1:0xIL".into(),
                },
                RoleAssertion {
                    role: 0x11,
                    value: "apple".into(),
                },
                RoleAssertion {
                    role: 0x12,
                    value: "eip155:1:0xWallet".into(),
                },
            ],
        };
        let bytes = roles.encode().unwrap();
        assert_eq!(Roles::parse(&bytes).unwrap(), roles);
        assert_eq!(Roles::parse(&bytes).unwrap().asserted_os(), Some("apple"));
    }

    #[test]
    fn reject_bad_os_identifier_and_bad_pointer() {
        let bad_os = Roles {
            items: vec![RoleAssertion {
                role: 0x11,
                value: "NotAnId!".into(),
            }],
        };
        assert!(Roles::parse(&bad_os.encode().unwrap()).is_err());
        let bad_ptr = Roles {
            items: vec![RoleAssertion {
                role: 0x10,
                value: "not a pointer".into(),
            }],
        };
        assert!(Roles::parse(&bad_ptr.encode().unwrap()).is_err());
    }

    #[test]
    fn absent_is_empty_not_error() {
        let empty = Roles::default();
        let bytes = empty.encode().unwrap();
        assert_eq!(Roles::parse(&bytes).unwrap().items.len(), 0);
    }
}
