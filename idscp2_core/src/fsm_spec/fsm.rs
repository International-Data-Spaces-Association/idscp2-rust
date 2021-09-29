#![allow(dead_code)]

use std::marker::PhantomData;
use std::time::Duration;

use crate::api::idscp2_config::AttestationConfig;
use crate::driver::daps_driver::DapsDriver;
use crate::fsm::FsmError;
use crate::messages::idscp_message_factory;
use crate::messages::idscpv2_messages::{
    IdscpClose_CloseCause, IdscpMessage, IdscpMessage_oneof_message,
};

enum ProtocolState {
    Closed,
    WaitForHello,
    Running,
    Terminated,
}

pub(crate) enum FsmAction {
    SecureChannelAction(SecureChannelAction),
    // NotifyUserData(Vec<u8>),
    SetDatTimeout(Duration),
}

pub(crate) enum RaMessage<RaType> {
    Ok,
    Failed,
    RawData(Vec<u8>, PhantomData<RaType>),
}

#[allow(clippy::enum_variant_names)]
pub(crate) enum FsmEvent {
    // USER EVENTS
    FromUpper(UserEvent),

    // SECURE CHANNEL EVENTS
    FromSecureChannel(SecureChannelEvent),

    // RA DRIVER EVENTS
    FromRaProver(RaMessage<RaProverType>),
    FromRaVerifier(RaMessage<RaVerifierType>),
}

/*pub(crate) enum FsmIdscpMessageType {
    Hello,
    Close,
    Data
}

impl Into<FsmIdscpMessageType> for &IdscpMessage {
    fn into(self) -> FsmIdscpMessageType {
        if match self.message
    }
}
*/

#[derive(Debug)]
pub(crate) enum SecureChannelEvent {
    Message(IdscpMessage_oneof_message),
}

#[derive(Debug)]
pub(crate) enum SecureChannelAction {
    Message(IdscpMessage),
}

#[derive(Debug, Clone)]
pub(crate) enum UserEvent {
    StartHandshake,
    // Stop,
    Data(Vec<u8>),
}

trait RaType {}
pub(crate) struct RaProverType {}
impl RaType for RaProverType {}
pub(crate) struct RaVerifierType {}
impl RaType for RaVerifierType {}

enum RaState<RaType> {
    Inactive(PhantomData<RaType>),
    Working,
    Done,
    Terminated,
}

enum TimeoutState {
    Active,
    Inactive,
}

type ResendTimeout = u64; //TODO!

pub(crate) struct Fsm<'daps, 'config> {
    /* all of the variables that make up the whole state space of the FSM */
    state: ProtocolState,
    prover: RaState<RaProverType>,
    verifier: RaState<RaVerifierType>,
    daps_driver: &'daps mut dyn DapsDriver,
    dat_timeout: TimeoutState,
    ra_timeout: TimeoutState,
    resend_timeout: TimeoutState,
    /* configs */
    ra_config: &'config AttestationConfig,
}

impl<'daps, 'config> Fsm<'daps, 'config> {
    pub(crate) fn new(
        daps_driver: &'daps mut dyn DapsDriver,
        ra_config: &'config AttestationConfig,
    ) -> Fsm<'daps, 'config> {
        Fsm {
            state: ProtocolState::Closed,
            prover: RaState::Inactive(PhantomData {}),
            verifier: RaState::Inactive(PhantomData {}),
            daps_driver,
            dat_timeout: TimeoutState::Inactive,
            ra_timeout: TimeoutState::Inactive,
            resend_timeout: TimeoutState::Inactive,
            ra_config,
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
            event,
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
                let hello_msg = idscp_message_factory::create_idscp_hello(
                    self.daps_driver.get_token().into_bytes(),
                    &self.ra_config.expected_attestation_suite,
                    &self.ra_config.supported_attestation_suite,
                );

                self.state = ProtocolState::WaitForHello;
                Ok(vec![FsmAction::SecureChannelAction(
                    SecureChannelAction::Message(hello_msg),
                )])
            }

            // TLA Action "ReceiveHallo"
            (
                ProtocolState::WaitForHello,
                RaState::Inactive(_),   // Prover state
                RaState::Inactive(_),   // Verifier state
                false,                  // DAT is valid?
                TimeoutState::Inactive, // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                TimeoutState::Inactive, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpHello(hello_msg),
                )),
            ) => {
                let dat = hello_msg.get_dynamicAttributeToken();
                let mut actions = vec![];
                match self.daps_driver.verify_token(dat.get_token()) {
                    Some(dat_timeout) => {
                        self.state = ProtocolState::Running;
                        self.prover = RaState::Working; // TODO: do it with real driver
                        self.verifier = RaState::Working;
                        actions.push(FsmAction::SetDatTimeout(dat_timeout));
                        self.dat_timeout = TimeoutState::Active // TODO: make it one operation with SetDatTimeout
                    }
                    None => {
                        actions.push(FsmAction::SecureChannelAction(
                            SecureChannelAction::Message(
                                idscp_message_factory::create_idscp_close(
                                    IdscpClose_CloseCause::NO_VALID_DAT,
                                    "",
                                ),
                            ),
                        ));
                        self.cleanup();
                    }
                }
                Ok(actions)
            }

            // TLA Action "SendProverMsg"
            (
                ProtocolState::Running,
                RaState::Working, // Prover state
                _,                // Verifier state
                _,                // DAT is valid?
                _,                // Dat timeout
                _,                // Ra timeout
                _,                // Resend timeout
                FsmEvent::FromRaProver(RaMessage::RawData(bytes, _)),
            ) => {
                let msg = idscp_message_factory::create_idscp_ra_prover(bytes);
                let action = FsmAction::SecureChannelAction(SecureChannelAction::Message(msg));
                Ok(vec![action])
            }

            // TLA Action "SendVerifierMsg"
            (
                ProtocolState::Running,
                _,                      // Prover state
                RaState::Working,       // Verifier state
                true,                   // DAT is valid?
                TimeoutState::Active,   // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                _,                      // Resend timeout
                FsmEvent::FromRaVerifier(RaMessage::RawData(bytes, _)),
            ) => {
                let msg = idscp_message_factory::create_idscp_ra_verifier(bytes);
                let action = FsmAction::SecureChannelAction(SecureChannelAction::Message(msg));
                Ok(vec![action])
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
