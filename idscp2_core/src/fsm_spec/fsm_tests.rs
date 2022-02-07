use crate::{
    api::idscp2_config::{AttestationConfig, IdscpConfig},
    driver::daps_driver::DapsDriver,
    messages::{idscp_message_factory, idscpv2_messages::IdscpMessage_oneof_message},
};
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

    fn invalidate(&mut self) {
        self.is_valid = false;
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
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    // TLA Action Start
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
        .unwrap();
    assert!(actions.len() == 1);
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    // TLA Action ReceiveHello
    let idscp_hello = hello_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &idscp_hello,
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
        _ => panic!("expected Secure Channel message"),
    };
    assert!(verif_msg.has_idscpRaVerifier());

    // TLA Action ReceiveVerifierMsg
    let verif_msg = verif_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &verif_msg,
        )))
        .unwrap();
    assert!(actions.len() == 1);
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
        _ => panic!("expected Secure Channel message"),
    };
    assert!(prover_msg.has_idscpRaProver());

    // TLA Action ReceiveProverMsg
    let prover_msg = prover_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &prover_msg,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(&actions[0], FsmAction::ToVerifier(_)));

    // TLA Action Verifier Success
    let actions = fsm
        .process_event(FsmEvent::FromRaVerifier(RaMessage::Ok(
            "attestation successful".as_bytes().to_owned(),
        )))
        .unwrap();
    assert!(actions.len() == 2);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpRaVerifier(_)
    ));
    assert!(matches!(&actions[1], FsmAction::SetRaTimeout(_)));

    // Action ProverSuccess (which is only implicitly defined in TLA Spec)
    let actions = fsm
        .process_event(FsmEvent::FromRaProver(RaMessage::Ok(
            "attestation successful".as_bytes().to_owned(),
        )))
        .unwrap();
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpRaProver(_)
    ));

    // TLA Action SendData
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::Data(
            "hello world!".as_bytes().to_owned(),
        )))
        .unwrap();
    assert!(actions.len() == 2);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    match msg.message.as_ref().unwrap() {
        IdscpMessage_oneof_message::idscpData(data) => {
            assert_eq!(data.alternating_bit, true)
        }
        _ => panic!("expected IdscpData"),
    }
    assert!(matches!(&actions[1], FsmAction::SetResendDataTimeout(_)));

    // TLA Action ReceiveData
    let msg = idscp_message_factory::create_idscp_data("foo bar".as_bytes().to_owned(), true);
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            msg.message.as_ref().unwrap(),
        )))
        .unwrap();
    assert!(actions.len() == 2);
    assert!(matches!(&actions[0], FsmAction::NotifyUserData(_)));
    let msg = match &actions[1] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    match msg.message.as_ref().unwrap() {
        IdscpMessage_oneof_message::idscpAck(idscp_ack) => {
            assert_eq!(idscp_ack.alternating_bit, true)
        }
        _ => panic!("expected IdscpAck"),
    }

    // TLA Action ResendData
    let actions = fsm.process_event(FsmEvent::ResendTimout).unwrap();
    assert!(actions.len() == 2);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    match msg.message.as_ref().unwrap() {
        IdscpMessage_oneof_message::idscpData(data) => {
            assert_eq!(data.alternating_bit, true)
        }
        _ => panic!("expected IdscpData"),
    }
    assert!(matches!(&actions[1], FsmAction::SetResendDataTimeout(_)));

    // TLA Action ReceiveAck
    let msg = idscp_message_factory::create_idscp_ack(true);
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            msg.message.as_ref().unwrap(),
        )))
        .unwrap();
    assert!(matches!(&actions[0], FsmAction::StopResendDataTimeout));

    // TLA Action DatExpired
    let actions = fsm.process_event(FsmEvent::DatExpired).unwrap();
    assert!(actions.len() == 3);
    assert!(matches!(actions[0], FsmAction::StopRaTimeout));
    assert!(matches!(actions[1], FsmAction::StopDatTimeout));
    let dat_exp_msg = match &actions[2] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        dat_exp_msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpDatExpired(_)
    ));

    // TLA Action ReceiveDatExpired
    let msg = dat_exp_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &msg,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    let dat_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        dat_msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpDat(_)
    ));

    // TLA Action ReceiveDat
    let msg = dat_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &msg,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(actions[0], FsmAction::SetDatTimeout(_)));

    // TLA Action Verifier Success
    let actions = fsm
        .process_event(FsmEvent::FromRaVerifier(RaMessage::Ok(
            "attestation successful".as_bytes().to_owned(),
        )))
        .unwrap();
    assert!(actions.len() == 2);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpRaVerifier(_)
    ));
    assert!(matches!(&actions[1], FsmAction::SetRaTimeout(_)));

    // Action ProverSuccess (which is only implicitly defined in TLA Spec)
    let actions = fsm
        .process_event(FsmEvent::FromRaProver(RaMessage::Ok(
            "attestation successful".as_bytes().to_owned(),
        )))
        .unwrap();
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpRaProver(_)
    ));

    // TLA Action RequestReattestation
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::RequestReattestation("")))
        .unwrap();
    assert!(actions.len() == 2);
    assert!(matches!(actions[0], FsmAction::StopRaTimeout));
    let re_ra_msg = match &actions[1] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        re_ra_msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpReRa(_)
    ));

    // TLA Action ReceiveReattestation
    let msg = re_ra_msg.clone().message.unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &msg,
        )))
        .unwrap();
    assert!(actions.is_empty());

    // TLA Action CloseConnection
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::CloseConnection))
        .unwrap();
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpClose(_)
    ));
}

#[test]
fn verifier_error_sequence() {
    let mut daps_driver = TestDaps { is_valid: false };
    let ra_config = AttestationConfig {
        supported_attestation_suite: vec!["TestRatProver".to_string()],
        expected_attestation_suite: vec!["TestRatProver".to_string()],
        ra_timeout: Duration::from_secs(30),
    };
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
        .unwrap();
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    let idscp_hello = hello_msg.clone().message.unwrap();
    let _ = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            &idscp_hello,
        )))
        .unwrap();

    // TLA Action VerifierError
    let actions = fsm
        .process_event(FsmEvent::FromRaVerifier(RaMessage::Failed()))
        .unwrap();
    assert!(actions.len() == 1);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpClose(_)
    ));
}
