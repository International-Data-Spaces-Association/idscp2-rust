use crate::{
    api::idscp2_config::AttestationConfig,
    driver::daps_driver::DapsDriver,
    messages::{
        idscp_message_factory,
    },
};
use std::{time::Duration, vec};

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

    fn verify_token(&self, token_bytes: &[u8]) -> Option<Duration> {
        let token = String::from_utf8_lossy(token_bytes);
        if token.eq("valid") {
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
    assert!(matches!(&actions[0], FsmAction::SecureChannelAction { .. }));

    // TLA Action ReceiveHello
    let idscp_hello = idscp_message_factory::create_idscp_hello(
        "valid".as_bytes().to_owned(),
        &vec!["TestRatProver".to_string()],
        &vec!["TestRatProver".to_string()],
    )
    .message
    .unwrap();
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            idscp_hello,
        )))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(&actions[0], FsmAction::SetDatTimeout(_)))
}
