use crate::{api::idscp2_config::AttestationConfig, driver::daps_driver::DapsDriver};
use std::{marker::PhantomData, time::Duration, vec};

use super::fsm::*;

struct TestDaps {
    is_valid: bool,
}

impl DapsDriver for TestDaps {
    fn is_valid(&self) -> bool {
        self.is_valid
    }

    fn get_token(&self) -> String {
        "valid".to_string()
    }

    fn verify_token(&mut self, token_bytes: &[u8]) -> Option<Duration> {
        let token = String::from_utf8_lossy(token_bytes);
        if token.eq("valid") {
            self.is_valid = true;
            Some(Duration::from_secs(1))
        } else {
            None
        }
    }
}

#[test]
fn normal_sequence() {
    let mut daps_driver = TestDaps { is_valid: false };
    let ra_config = AttestationConfig {
        supported_attestation_suite: vec!["TestRatProver".to_string()],
        expected_attestation_suite: vec!["TestRatProver".to_string()],
        ra_timeout: Duration::from_secs(30),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &ra_config);

    // TLA Action Start
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
        .unwrap();
    assert!(actions.len() == 1);
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected hello message"),
    };

    // TLA Action ReceiveHello
    let idscp_hello = hello_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            idscp_hello,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(&actions[0], FsmAction::SetDatTimeout(_)));

    // TLA Action SendVerifierMsg
    let actions = fsm
        .process_event(FsmEvent::FromRaVerifier(RaMessage::RawData(
            "nonce".as_bytes().to_owned(),
            PhantomData,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    let verif_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(verif_msg)) => verif_msg,
        _ => panic!("expected verifier message"),
    };
    assert!(verif_msg.has_idscpRaVerifier());

    // TLA Action ReceiveVerifierMsg
    let verif_msg = verif_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            verif_msg,
        )))
        .unwrap();
    assert!(matches!(&actions[0], FsmAction::ToProver(_)));

    // TLA Action SendProverMsg
    let actions = fsm
        .process_event(FsmEvent::FromRaProver(RaMessage::RawData(
            "attestation_report".as_bytes().to_owned(),
            PhantomData,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    let prover_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(prover_msg)) => prover_msg,
        _ => panic!("expected prover message"),
    };
    assert!(prover_msg.has_idscpRaProver());

    // TLA Action ReceiveProverMsg
    let prover_msg = prover_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            prover_msg,
        )))
        .unwrap();
    assert!(matches!(&actions[0], FsmAction::ToVerifier(_)));
}
