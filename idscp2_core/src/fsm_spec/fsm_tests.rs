use crate::driver::daps_driver::DapsDriver;
use std::time::Duration;

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

    fn verify_token(&self, token: &str) -> Option<Duration> {
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
    let mut fsm = Fsm::new(&mut daps_driver);

    // TLA Action Start
    let actions = fsm
        .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(&actions[0], FsmAction::SecureChannelAction { .. }));

    // TLA Action ReceiveHello
    let actions = fsm
        .process_event(FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
            IdscpMessage {
                msg_type: IdscpMessageType::IdscpHello("valid".to_string()),
            },
        )))
        .unwrap();
    assert!(actions.len() == 1);
    assert!(matches!(&actions[0], FsmAction::SetDatTimeout(_)))
}
