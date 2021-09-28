#![allow(dead_code)]

use std::marker::PhantomData;
use std::time::Duration;

use crate::driver::daps_driver::DapsDriver;
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
    SetDatTimeout(Duration),
}

pub(crate) enum FsmEvent {
    // USER EVENTS
    FromUpper(UserEvent),

    // SECURE CHANNEL EVENTS
    FromSecureChannel(SecureChannelEvent),
}

#[derive(Debug)]
// TODO implement with Protobuf
pub(crate) struct IdscpMessage {
    pub(super) msg_type: IdscpMessageType,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum IdscpMessageType {
    IdscpHello(String),
    IdscpReAttest,
    IdscpProverMsg,
    IdscpDat,
    IdscpAck,
    IdscpVerifierMsg,
    IdscpDatExpired,
    IdscpData,
    IdscpClose,
}

#[derive(Debug)]
pub(crate) enum SecureChannelEvent {
    Message(IdscpMessage),
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

enum TimeoutState<T> {
    Active(T),
    Inactive,
}

type ResendTimeout = u64; //TODO!

pub(crate) struct Fsm<'daps> {
    state: ProtocolState,
    prover: RaState<RaProverType>,
    verifier: RaState<RaVerifierType>,
    daps_driver: &'daps mut dyn DapsDriver,
    dat_timeout: TimeoutState<()>,
    ra_timeout: TimeoutState<()>,
    resend_timeout: TimeoutState<ResendTimeout>,
}

impl<'daps> Fsm<'daps> {
    pub(crate) fn new(daps_driver: &'daps mut dyn DapsDriver) -> Fsm {
        Fsm {
            state: ProtocolState::Closed,
            prover: RaState::Inactive(PhantomData {}),
            verifier: RaState::Inactive(PhantomData {}),
            daps_driver,
            dat_timeout: TimeoutState::Inactive,
            ra_timeout: TimeoutState::Inactive,
            resend_timeout: TimeoutState::Inactive,
        }
    }

    pub(crate) fn process_event(&mut self, event: FsmEvent) -> Result<Vec<FsmAction>, FsmError> {
        let dat = self.daps_driver.is_valid();
        match (
            &self.state,
            &self.prover,
            &self.verifier,
            dat,
            &self.dat_timeout,
            &self.ra_timeout,
            &self.resend_timeout,
            &event,
        ) {
            // TLA Action "Start"
            (
                ProtocolState::Closed,
                RaState::Inactive(_),   // Prover state
                RaState::Inactive(_),   // Verifier state
                false,                  // DAT is valid?
                TimeoutState::Inactive, // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                TimeoutState::Inactive, // Resend timeout
                FsmEvent::FromUpper(UserEvent::StartHandshake),
            ) => {
                self.state = ProtocolState::WaitForHello;
                Ok(vec![FsmAction::SecureChannelAction(
                    SecureChannelEvent::Message(IdscpMessage {
                        msg_type: IdscpMessageType::IdscpHello("hello".to_string()),
                    }),
                )])
            }

            // TLA Action "Receive Hallo"
            (
                ProtocolState::WaitForHello,
                RaState::Inactive(_),   // Prover state
                RaState::Inactive(_),   // Verifier state
                false,                  // DAT is valid?
                TimeoutState::Inactive, // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                TimeoutState::Inactive, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(IdscpMessage {
                    msg_type: IdscpMessageType::IdscpHello(dat),
                })),
            ) => {
                let mut actions = vec![];
                match self.daps_driver.verify_token(dat) {
                    Some(dat_timeout) => {
                        self.state = ProtocolState::Running;
                        self.prover = RaState::Working; // TODO: do it with real driver
                        self.verifier = RaState::Working;
                        actions.push(FsmAction::SetDatTimeout(dat_timeout));
                    }
                    None => {
                        actions.push(FsmAction::SecureChannelAction(SecureChannelEvent::Message(
                            IdscpMessage {
                                msg_type: IdscpMessageType::IdscpClose,
                            },
                        )));
                        self.cleanup();
                    }
                }
                Ok(actions)
            }

            _ => unimplemented!(),
        }
    }

    // Implements the TLA spec's action "Close"
    fn cleanup(&mut self) {
        self.state = ProtocolState::Terminated;
        self.verifier = RaState::Terminated;
        self.prover = RaState::Terminated;
        self.dat_timeout = TimeoutState::Inactive;
        self.ra_timeout = TimeoutState::Inactive;
        self.resend_timeout = TimeoutState::Inactive;

        //TODO do we need to implement the other cleanup steps from the spec?
    }
}
