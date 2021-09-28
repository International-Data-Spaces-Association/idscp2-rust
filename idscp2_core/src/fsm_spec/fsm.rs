use std::marker::PhantomData;

use crate::fsm::FsmError;

enum ProtocolState {
    Closed,
    WaitForHello,
    Running,
    Terminated,
}

pub(crate) enum FsmAction {
    SecureChannelAction(SecureChannelEvent),
    // NotifyUserData(Vec<u8>),
}

pub(crate) enum FsmEvent {
    // USER EVENTS
    FromUpper(UserEvent),

    // SECURE CHANNEL EVENTS
    FromSecureChannel(SecureChannelEvent),
}

#[derive(Debug, Clone)]
pub(crate) enum SecureChannelEvent {
    // Close,
    Hello(String),
    Data(Vec<u8>),
}

#[derive(Debug, Clone)]
pub(crate) enum UserEvent {
    StartHandshake,
    // Stop,
    Data(Vec<u8>),
}

trait RaType {}
struct RaProverType {}
impl RaType for RaProverType {}
struct RaVerifierType {}
impl RaType for RaVerifierType {}

enum RaState<RaType> {
    Inactive(PhantomData<RaType>),
    Working,
    Done,
    Terminated,
}

enum DatState {
    Valid,
    Invalid,
}

enum TimeoutState<T> {
    Active(T),
    Inactive,
}

type ResendTimeout = u64; //TODO!

pub(crate) struct Fsm {
    state: ProtocolState,
    prover: RaState<RaProverType>,
    verifier: RaState<RaVerifierType>,
    dat: DatState,
    dat_timeout: TimeoutState<()>,
    ra_timeout: TimeoutState<()>,
    resend_timeout: TimeoutState<ResendTimeout>,
}

impl Fsm {
    pub(crate) fn new() -> Fsm {
        Fsm {
            state: ProtocolState::Closed,
            prover: RaState::Inactive(PhantomData {}),
            verifier: RaState::Inactive(PhantomData {}),
            dat: DatState::Invalid,
            dat_timeout: TimeoutState::Inactive,
            ra_timeout: TimeoutState::Inactive,
            resend_timeout: TimeoutState::Inactive,
        }
    }

    pub(crate) fn process_event(&mut self, event: FsmEvent) -> Result<Vec<FsmAction>, FsmError> {
        match (
            &self.state,
            &event,
            &self.prover,
            &self.verifier,
            &self.dat,
            &self.dat_timeout,
            &self.ra_timeout,
            &self.resend_timeout,
        ) {
            // Action "Start"
            (   
                ProtocolState::Closed,
                FsmEvent::FromUpper(UserEvent::StartHandshake),
                RaState::Inactive(_),
                RaState::Inactive(_),
                DatState::Invalid,
                TimeoutState::Inactive,
                TimeoutState::Inactive,
                TimeoutState::Inactive,
            ) => {
                self.state = ProtocolState::WaitForHello;
                Ok(vec![FsmAction::SecureChannelAction(
                    SecureChannelEvent::Hello("hello".to_string()),
                )])
            }



            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod action_tests {
    use super::*;
    #[test]
    fn start_action() {
        let mut fsm = Fsm::new();
        let action = fsm
            .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
            .unwrap();
    }
}
