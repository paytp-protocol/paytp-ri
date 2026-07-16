//! The Tier 0 flow (C2) + the §10.4 external-wallet selection seam.
//!
//! §10.4 requires the interaction layer to let the operator select an **external
//! wallet**. In code that is the [`PayerWallet`] trait: the IL calls a wallet
//! through this trait and never bundles a concrete one, so any wallet — the
//! reference `paytp_wallet::Wallet` or a wholly independent implementation — can be
//! substituted. The client's own duties are C2 (verify the merchant signature) and
//! binding the verified quote to the resource the operator actually requested (so a
//! compromised IL cannot hand over a valid quote for a *different* resource).

use paytp_core::channel::establish::AcceptedBinding;
use paytp_core::tier0::quote::{ExpectedDest, Quote};
use paytp_core::x402::PaymentRequirements;
use paytp_rail::VirtualRail;
use paytp_wallet::{BaselinePayment, PayerScope, Wallet, WalletPolicy};

use crate::relay::{InteractionLayer, RelayError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The merchant-signed quote failed client-side verification (C2).
    QuoteInvalid,
    /// The verified quote is for a different resource than the one requested — a
    /// cross-resource substitution attempt by the interaction layer (§5.4/F3.4).
    ResourceMismatch,
    /// The authenticated merchant origin host is not the host of the requested resource.
    OriginResourceMismatch,
    /// The selected wallet declined or failed (opaque at the IL boundary).
    Wallet(String),
    /// The role set could not be relayed (§10.3).
    Relay(RelayError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Relay(e) => Some(e),
            _ => None,
        }
    }
}

/// The interaction-layer ⇆ wallet boundary (§10.4). The IL drives *any* wallet
/// behind this trait; substitution is a conformance requirement, so the concrete
/// wallet is never bundled. The reference `paytp_wallet::Wallet` implements it
/// below, and a second, independent implementation drives the same flows in the
/// M7 substitution test.
pub trait PayerWallet {
    /// The payer identity this wallet presents **at a given merchant scope**
    /// (F1-f/F2.3 unlinkability): the key is derived per-`(merchant, registrable-
    /// domain)`, so there is no single global payer identity to return.
    fn payer_key(&self, scope: &PayerScope) -> [u8; 32];
    /// Authenticate a candidate merchant key to the origin connection the operator
    /// intends to pay over. Conformant Tier-0 wallets accept quotes only through the
    /// returned binding, never through a raw discovery-context merchant key.
    fn accept_origin(
        &self,
        candidate_merchant_key: &[u8; 32],
        artifact_bytes: &[u8],
        conn_cert_hash: &[u8; 32],
        conn_host: &str,
        now: u64,
    ) -> Result<AcceptedBinding, String>;
    /// Prepare a baseline quote payment from its **raw signed bytes** (`quote_json`), returning
    /// the payment authorization the merchant will settle (or an opaque error string). The wallet verifies the
    /// merchant signature itself against the authenticated binding, binds the verified quote to
    /// the operator's `requested_resource` (F3.4 — refusing a valid quote for a
    /// *different* resource), and reads the amount/asset from the verified quote — so
    /// the interaction layer cannot forge a `Quote` struct, substitute a different-
    /// resource quote, or influence what is paid beyond selecting the raw quote. The
    /// resource binding is a boundary CONTRACT: every conformant wallet enforces it
    /// itself, so a hostile IL calling a wallet directly (bypassing the [`Client`])
    /// still cannot make it pay for a resource the operator never requested.
    ///
    /// `accept` is the outer x402 `accepts[]` entry the operator approved. Every
    /// conformant wallet enforces the F3-a mirror rule itself — it applies PayTP
    /// execution only to a signed offer that mirrors `accept` — so a hostile IL that
    /// substitutes a different validly-signed same-resource quote for the priced one
    /// is refused at the wallet boundary, not just at the client.
    fn pay_baseline_quote(
        &self,
        rail: &VirtualRail,
        quote_json: &str,
        accept: &PaymentRequirements,
        binding: &AcceptedBinding,
        requested_resource: &str,
    ) -> Result<BaselinePayment, String>;
}

/// The origin-authentication material for the connection the wallet intends to
/// pay over: candidate merchant identity, signed artifact bytes, and the verified
/// TLS leaf/host context.
#[derive(Clone, Copy)]
pub struct OriginContext<'a> {
    pub candidate_merchant_key: &'a [u8; 32],
    pub artifact_bytes: &'a [u8],
    pub conn_cert_hash: &'a [u8; 32],
    pub conn_host: &'a str,
    pub now: u64,
}

// The reference wallet is one implementor of the boundary.
impl<P: WalletPolicy> PayerWallet for Wallet<'_, P> {
    fn payer_key(&self, scope: &PayerScope) -> [u8; 32] {
        Wallet::payer_key(self, scope)
    }
    fn accept_origin(
        &self,
        candidate_merchant_key: &[u8; 32],
        artifact_bytes: &[u8],
        conn_cert_hash: &[u8; 32],
        conn_host: &str,
        now: u64,
    ) -> Result<AcceptedBinding, String> {
        Wallet::accept_origin(
            self,
            candidate_merchant_key,
            artifact_bytes,
            conn_cert_hash,
            conn_host,
            now,
        )
        .map_err(|e| format!("{e:?}"))
    }
    fn pay_baseline_quote(
        &self,
        rail: &VirtualRail,
        quote_json: &str,
        accept: &PaymentRequirements,
        binding: &AcceptedBinding,
        requested_resource: &str,
    ) -> Result<BaselinePayment, String> {
        self.pay_baseline(rail, quote_json, accept, binding, requested_resource)
            .map_err(|e| format!("{e:?}"))
    }
}

/// An interaction-layer client. Holds the IL identity; drives an operator-selected
/// wallet through the [`PayerWallet`] boundary.
pub struct Client {
    il: InteractionLayer,
}

impl Client {
    pub fn new(il: InteractionLayer) -> Self {
        Client { il }
    }

    pub fn interaction_layer(&self) -> &InteractionLayer {
        &self.il
    }

    /// Verify a merchant-signed baseline quote, bind it to the requested resource,
    /// and prepare its payment through the operator-selected `wallet` (§10.4 — any
    /// [`PayerWallet`] implementation works). The amount/asset are the merchant's
    /// signed terms (the wallet reads them from the quote), so the IL's only
    /// influence is selecting the verified quote for the requested resource.
    ///
    /// The client checks the resource binding here AND passes `requested_resource`
    /// through to the wallet, which re-checks it independently (F3.4): the client's
    /// check is belt-and-suspenders, since a hostile IL can bypass the client and
    /// drive the wallet directly — so the binding must not live only here.
    ///
    /// `accept` is the outer x402 `accepts[]` entry the operator approved; it is passed
    /// through to the wallet, which enforces the F3-a mirror rule (it applies PayTP
    /// execution only to a signed offer mirroring `accept`). Like the resource bind, the
    /// enforcement lives in the wallet so a hostile IL bypassing the client cannot evade it.
    pub fn pay_baseline(
        &self,
        wallet: &dyn PayerWallet,
        rail: &VirtualRail,
        quote_json: &str,
        accept: &PaymentRequirements,
        origin: OriginContext<'_>,
        requested_resource: &str,
    ) -> Result<BaselinePayment, ClientError> {
        let binding = wallet
            .accept_origin(
                origin.candidate_merchant_key,
                origin.artifact_bytes,
                origin.conn_cert_hash,
                origin.conn_host,
                origin.now,
            )
            .map_err(ClientError::Wallet)?;
        require_binding_host_matches_resource(&binding, requested_resource)?;
        // C2: verify the merchant signature and bind the requested resource. The
        // wallet independently re-verifies the signature (it does not trust this
        // parse), so a compromised IL bypassing the client still cannot forge terms.
        let quote = Quote::parse_verify(quote_json, binding.merchant_key())
            .map_err(|_| ClientError::QuoteInvalid)?;
        if quote.resource != requested_resource {
            return Err(ClientError::ResourceMismatch);
        }
        // F5-o payer-side self-defense for the interaction layer's OWN `0x10` share: a hostile
        // merchant must not reroute the IL's meed to itself. The client is the party that holds
        // the IL identity, so it checks the signed vector's `0x10` against the IL's own
        // destination here (the wallet defends its own `0x12` in `pay_baseline_quote`). Each
        // pointer-free share is thus defended by the party whose share it is (F5-o).
        quote
            .validate_payer_side(
                ExpectedDest::Asserted(self.il.il_dest()),
                ExpectedDest::Unchecked,
            )
            .map_err(|_| ClientError::QuoteInvalid)?;
        wallet
            .pay_baseline_quote(rail, quote_json, accept, &binding, requested_resource)
            .map_err(ClientError::Wallet)
    }

    /// Assemble and relay-validate the `PayTP-Roles` for a purchase (§10.3), naming
    /// the operator-selected wallet's destination.
    pub fn roles_for(
        &self,
        wallet_dest: Option<&str>,
    ) -> Result<paytp_core::tier0::roles::Roles, ClientError> {
        let roles = self.il.roles(wallet_dest);
        self.il
            .validate_for_relay(&roles)
            .map_err(ClientError::Relay)?;
        Ok(roles)
    }
}

fn require_binding_host_matches_resource(
    binding: &AcceptedBinding,
    requested_resource: &str,
) -> Result<(), ClientError> {
    let resource_host = normalized_resource_host(requested_resource)?;
    if binding.host() != resource_host {
        return Err(ClientError::OriginResourceMismatch);
    }
    Ok(())
}

fn normalized_resource_host(resource: &str) -> Result<&str, ClientError> {
    let host = resource_url_host(resource).ok_or(ClientError::OriginResourceMismatch)?;
    paytp_host::validate_normalized_host(host).map_err(|_| ClientError::OriginResourceMismatch)?;
    Ok(host)
}

fn resource_url_host(resource: &str) -> Option<&str> {
    let (_, rest) = resource.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..authority_end)?;
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() || host_port.starts_with('[') {
        return None;
    }
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        Some(host)
    } else {
        Some(host_port)
    }
}
