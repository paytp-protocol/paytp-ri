use paytp_core::channel::establish::BindingArtifact;
use paytp_core::consts::{DEV_FUND_DEST_PLACEHOLDER, INDEPENDENT_OS_FUND_DEST_PLACEHOLDER};
use paytp_core::tier0::quote::MeedEntry;
use paytp_merchant::{BaselineParams, Merchant};
use paytp_rail::VirtualRail;
use paytp_wallet::{Custody, StaticPolicy, Wallet};

const RESOURCE: &str = "https://honest.example.com/premium";
const ASSET: &str = "eip155:1/native";
const IL_DEST: &str = "eip155:1:0xInteractionLayer";
const WALLET_DEST: &str = "eip155:1:0xWalletProvider";
const HOST_O: &str = "honest.example.com";
const HOST_IL: &str = "interloper.example.net";
const NOW: u64 = 1_700_000_000;

fn vector() -> Vec<MeedEntry> {
    vec![
        MeedEntry {
            role: 0x10,
            bp: 50,
            dest: IL_DEST.into(),
        },
        MeedEntry {
            role: 0x11,
            bp: 10,
            dest: INDEPENDENT_OS_FUND_DEST_PLACEHOLDER.into(),
        },
        MeedEntry {
            role: 0x12,
            bp: 30,
            dest: WALLET_DEST.into(),
        },
        MeedEntry {
            role: 0x13,
            bp: 10,
            dest: DEV_FUND_DEST_PLACEHOLDER.into(),
        },
    ]
}

fn params(nonce: [u8; 32]) -> BaselineParams<'static> {
    BaselineParams {
        resource: RESOURCE,
        nonce,
        exp: 1_000_000_500,
        idem: b"idem-origin".to_vec(),
        registry_version: 5,
        baseline_network: "eip155:8453",
        asset: ASSET,
        amount: 1_000_000,
        finality: "final",
        grace: 300,
        retry: 600,
        max_timeout_seconds: 60,
        extra: None,
        vector: vector(),
    }
}

fn artifact(sk: [u8; 32], host: &str, cert_hash: [u8; 32]) -> Vec<u8> {
    let mut art = BindingArtifact {
        host: host.into(),
        cert_hash,
        enc_key: [0xE5; 32],
        not_before: 0,
        not_after: (1u64 << 53) - 1,
        sig: None,
    };
    art.sign(&sk).unwrap();
    art.encode().unwrap()
}

fn wallet<'a>(custody: &'a Custody) -> Wallet<'a, StaticPolicy> {
    Wallet::new(custody, StaticPolicy::new(ASSET, 2_000_000)).with_meed_dest(WALLET_DEST)
}

#[test]
fn origin_substitution_artifact_is_rejected_before_payment() {
    let rail = VirtualRail::new(0);
    let honest = Merchant::new([0x11; 32], "merchant-payout");
    let interloper = Merchant::new([0x22; 32], "interloper-payout");
    let cert_o = [0xA1; 32];
    let cert_il = [0xB2; 32];
    let art_o = artifact([0x11; 32], HOST_O, cert_o);
    let art_il = artifact([0x22; 32], HOST_IL, cert_il);
    let custody = Custody::from_root(&[0x44; 32]);
    let wallet = wallet(&custody);

    let attack = wallet.accept_origin(&interloper.key, &art_il, &cert_o, HOST_O, NOW);
    assert!(
        attack.is_err(),
        "origin substitution must fail: the wallet intends honest.example.com with cert O"
    );

    let binding = wallet
        .accept_origin(&honest.key, &art_o, &cert_o, HOST_O, NOW)
        .expect("honest origin artifact is accepted");
    let quote = honest.build_baseline_quote(&rail, params([0xA0; 32]));
    let json = String::from_utf8(quote.quote.to_json()).unwrap();
    assert!(
        wallet
            .pay_baseline(&rail, &json, &quote.accept_reqs, &binding, RESOURCE)
            .is_ok(),
        "after origin authentication the wallet can pay the honest quote"
    );
}

#[test]
fn tls_terminating_endpoint_with_its_own_valid_artifact_is_the_wallets_chosen_origin() {
    let interloper = Merchant::new([0x22; 32], "interloper-payout");
    let cert_il = [0xB2; 32];
    let art_il = artifact([0x22; 32], HOST_IL, cert_il);
    let custody = Custody::from_root(&[0x44; 32]);
    let wallet = wallet(&custody);

    // This documents P1's honest limit: if the wallet intentionally authenticates
    // the TLS terminator as the endpoint, F2.2 correctly accepts that endpoint's
    // own key/artifact. The protection is for the intended merchant identity.
    let binding = wallet.accept_origin(&interloper.key, &art_il, &cert_il, HOST_IL, NOW);
    assert!(binding.is_ok());
}

#[test]
fn accepted_interloper_origin_cannot_pay_honest_host_resource() {
    let rail = VirtualRail::new(0);
    let interloper = Merchant::new([0x22; 32], "interloper-payout");
    let cert_il = [0xB2; 32];
    let art_il = artifact([0x22; 32], HOST_IL, cert_il);
    let custody = Custody::from_root(&[0x44; 32]);
    let wallet = wallet(&custody);

    let binding = wallet
        .accept_origin(&interloper.key, &art_il, &cert_il, HOST_IL, NOW)
        .expect("self-consistent interloper origin is accepted");
    let quote = interloper.build_baseline_quote(&rail, params([0xA1; 32]));
    let json = String::from_utf8(quote.quote.to_json()).unwrap();

    assert_eq!(
        wallet.pay_baseline(&rail, &json, &quote.accept_reqs, &binding, RESOURCE),
        Err(paytp_wallet::WalletError::OriginResourceMismatch),
        "payment must bind the accepted origin host to the requested-resource host"
    );
}
