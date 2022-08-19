use crate::driver::ra_driver::tests::get_test_cert;
use crate::msg_factory::create_idscp_hello;
use crate::{
    api::idscp2_config::{AttestationConfig, IdscpConfig},
    driver::daps_driver::DapsDriver,
    messages::{idscp_message_factory, idscpv2_messages::IdscpMessage_oneof_message},
};
use bytes::Bytes;
use std::{marker::PhantomData, time::Duration, vec};
use crate::messages::idscpv2_messages::IdscpClose_CloseCause;

use super::fsm::*;

pub(crate) struct TestDaps {
    is_valid: bool,
    timeout: Duration,
}

impl Default for TestDaps {
    fn default() -> Self {
        Self {
            is_valid: false,
            timeout: Duration::from_secs(1),
        }
    }
}

impl TestDaps {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            is_valid: false,
            timeout,
        }
    }
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
            Some(self.timeout)
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
    let mut daps_driver = TestDaps::default();
    let ra_config = AttestationConfig {
        supported_provers: vec!["TestRatProver"],
        expected_verifiers: vec!["TestRatProver"],
        prover_registry: &Default::default(),
        ra_timeout: Duration::from_secs(30),
        verifier_registry: &Default::default(),
        peer_cert: get_test_cert(),
    };
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    // TLA Action Start
    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
    assert_eq!(actions.len(), 1);
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    // TLA Action ReceiveHello
    let idscp_hello = hello_msg.clone().message.unwrap();
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        idscp_hello,
    )));
    assert_eq!(actions.len(), 3);
    assert!(matches!(&actions[0], FsmAction::SetDatTimeout(_)));
    assert!(matches!(
        &actions[1],
        FsmAction::StartProver("TestRatProver")
    ));
    assert!(matches!(
        &actions[2],
        FsmAction::StartVerifier("TestRatProver")
    ));

    // TLA Action SendVerifierMsg
    let actions = fsm.process_event(FsmEvent::FromRaVerifier(RaMessage::RawData(
        Bytes::from("nonce"),
        PhantomData,
    )));
    assert_eq!(actions.len(), 1);
    let verif_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(verif_msg)) => verif_msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(verif_msg.has_idscpRaVerifier());

    // TLA Action ReceiveVerifierMsg
    let verif_msg = verif_msg.clone().message.unwrap();
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        verif_msg,
    )));
    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0], FsmAction::ToProver(_)));

    // TLA Action SendProverMsg
    let actions = fsm.process_event(FsmEvent::FromRaProver(RaMessage::RawData(
        Bytes::from("attestation_report"),
        PhantomData,
    )));
    assert_eq!(actions.len(), 1);
    let prover_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(prover_msg)) => prover_msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(prover_msg.has_idscpRaProver());

    // TLA Action ReceiveProverMsg
    let prover_msg = prover_msg.clone().message.unwrap();
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        prover_msg,
    )));
    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0], FsmAction::ToVerifier(_)));

    // TLA Action Verifier Success
    let actions = fsm.process_event(FsmEvent::FromRaVerifier(RaMessage::Ok(Bytes::from(
        "attestation successful",
    ))));
    assert_eq!(actions.len(), 2);
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
    let actions = fsm.process_event(FsmEvent::FromRaProver(RaMessage::Ok(Bytes::from(
        "attestation successful",
    ))));
    assert_eq!(actions.len(), 0);
    // let msg = match &actions[0] {
    //     FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
    //     _ => panic!("expected Secure Channel message"),
    // };
    // assert!(matches!(
    //     msg.clone().message.unwrap(),
    //     IdscpMessage_oneof_message::idscpRaProver(_)
    // ));

    // TLA Action SendData
    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::Data(Bytes::from(
        "hello world!",
    ))));
    assert_eq!(actions.len(), 2);
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
    let msg = idscp_message_factory::create_idscp_data(Bytes::from("foo bar"), true);
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        msg.message.unwrap(),
    )));
    assert_eq!(actions.len(), 2);
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
    let actions = fsm.process_event(FsmEvent::ResendTimout);
    assert_eq!(actions.len(), 2);
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
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        msg.message.unwrap(),
    )));
    assert!(matches!(&actions[0], FsmAction::StopResendDataTimeout));

    // TLA Action DatExpired
    let actions = fsm.process_event(FsmEvent::DatExpired);
    assert_eq!(actions.len(), 3);
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
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        msg,
    )));
    assert_eq!(actions.len(), 2);
    assert!(matches!(actions[0], FsmAction::RestartProver));
    let dat_msg = match &actions[1] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        dat_msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpDat(_)
    ));

    // TLA Action ReceiveDat
    let msg = dat_msg.clone().message.unwrap();
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        msg,
    )));
    assert_eq!(actions.len(), 2);
    assert!(matches!(actions[0], FsmAction::SetDatTimeout(_)));
    assert!(matches!(actions[1], FsmAction::RestartVerifier));

    // TLA Action Verifier Success
    let actions = fsm.process_event(FsmEvent::FromRaVerifier(RaMessage::Ok(Bytes::from(
        "attestation successful",
    ))));
    assert_eq!(actions.len(), 2);
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
    let actions = fsm.process_event(FsmEvent::FromRaProver(RaMessage::Ok(Bytes::from(
        "attestation successful",
    ))));
    assert_eq!(actions.len(), 0);
    // let msg = match &actions[0] {
    //     FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
    //     _ => panic!("expected Secure Channel message"),
    // };
    // assert!(matches!(
    //     msg.clone().message.unwrap(),
    //     IdscpMessage_oneof_message::idscpRaProver(_)
    // ));

    // TLA Action RequestReattestation
    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::RequestReattestation("")));
    assert_eq!(actions.len(), 3);
    assert!(matches!(actions[0], FsmAction::StopRaTimeout));
    let re_ra_msg = match &actions[1] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        re_ra_msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpReRa(_)
    ));
    assert!(matches!(actions[2], FsmAction::RestartVerifier));

    // TLA Action ReceiveReattestation
    let msg = re_ra_msg.clone().message.unwrap();
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        msg,
    )));
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], FsmAction::RestartProver));

    // TLA Action CloseConnection
    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::CloseConnection));
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
fn ra_driver_match_complex_sequence() {
    let mut daps_driver = TestDaps::default();
    let ra_config = AttestationConfig {
        supported_provers: vec!["Unmatched1", "Unmatched2", "TestRatProver", "Unmatched3"],
        expected_verifiers: vec!["TestRatProver", "Unmatched1", "Unmatched2"],
        prover_registry: &Default::default(),
        ra_timeout: Duration::from_secs(30),
        verifier_registry: &Default::default(),
        peer_cert: get_test_cert(),
    };
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    // set the supported/expected fields
    let expected_drivers = vec!["TestRatProver", "Unmatched1"];
    let supported_drivers = vec!["Unmatched1", "TestRatProver"];
    let dat = if let Some(IdscpMessage_oneof_message::idscpHello(hello)) = &hello_msg.message {
        hello.dynamicAttributeToken.as_ref().unwrap().token.clone()
    } else {
        panic!("expected IdscpHello")
    };

    let idscp_hello = create_idscp_hello(dat, &expected_drivers, &supported_drivers);
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        idscp_hello.message.unwrap(),
    )));

    if let FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) = &actions[0] {
        if let IdscpMessage_oneof_message::idscpClose(close_msg)= msg.message.as_ref().unwrap() {
            panic!("{:?}", close_msg.cause_code);
        }
    }
    assert_eq!(actions.len(), 3);
    assert!(matches!(
        actions[1],
        FsmAction::StartProver("TestRatProver"),
    ));
    assert!(matches!(
        actions[2],
        FsmAction::StartVerifier("TestRatProver"),
    ));
}

#[test]
fn ra_driver_match_error_sequence() {
    let mut daps_driver = TestDaps::default();
    let ra_config = AttestationConfig {
        supported_provers: vec!["Unmatched3", "TestRatProver", "Unmatched4", "Unmatched5"],
        expected_verifiers: vec!["Unmatched3", "TestRatProver", "Unmatched4", "Unmatched5"],
        prover_registry: &Default::default(),
        ra_timeout: Duration::from_secs(30),
        verifier_registry: &Default::default(),
        peer_cert: get_test_cert(),
    };
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    // set the supported/expected fields
    let expected_drivers = vec!["TestRatProver", "Unmatched1"];
    let supported_drivers = vec!["Unmatched1", "Unmatched2"];
    let dat = if let Some(IdscpMessage_oneof_message::idscpHello(hello)) = &hello_msg.message {
        hello.dynamicAttributeToken.as_ref().unwrap().token.clone()
    } else {
        panic!("expected IdscpHello")
    };

    let idscp_hello = create_idscp_hello(dat, &expected_drivers, &supported_drivers);
    let actions = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        idscp_hello.message.unwrap(),
    )));

    assert_eq!(actions.len(), 1);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    let cause_code = match msg.clone().message.unwrap() {
        IdscpMessage_oneof_message::idscpClose(close_msg) => close_msg.cause_code,
        _ => panic!("expected IdscpClose"),
    };
    assert_eq!(
        cause_code,
        IdscpClose_CloseCause::NO_RA_MECHANISM_MATCH_VERIFIER,
    );
}

#[test]
fn verifier_error_sequence() {
    let mut daps_driver = TestDaps::default();
    let ra_config = AttestationConfig {
        supported_provers: vec!["TestRatProver"],
        expected_verifiers: vec!["TestRatProver"],
        prover_registry: &Default::default(),
        ra_timeout: Duration::from_secs(30),
        verifier_registry: &Default::default(),
        peer_cert: get_test_cert(),
    };
    let config = IdscpConfig {
        ra_config: &ra_config,
        resend_timeout: Duration::from_secs(5),
    };
    let mut fsm = Fsm::new(&mut daps_driver, &config);

    let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
    let hello_msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };

    let idscp_hello = hello_msg.clone().message.unwrap();
    let _ = fsm.process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
        idscp_hello,
    )));

    // TLA Action VerifierError
    let actions = fsm.process_event(FsmEvent::FromRaVerifier(RaMessage::Failed()));
    assert_eq!(actions.len(), 1);
    let msg = match &actions[0] {
        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => msg,
        _ => panic!("expected Secure Channel message"),
    };
    assert!(matches!(
        msg.clone().message.unwrap(),
        IdscpMessage_oneof_message::idscpClose(_)
    ));
}
