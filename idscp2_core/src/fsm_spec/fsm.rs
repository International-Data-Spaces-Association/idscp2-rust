#![allow(dead_code)]

use std::marker::PhantomData;
use std::time::Duration;
use std::vec;

use crate::api::idscp2_config::IdscpConfig;
use crate::driver::daps_driver::DapsDriver;
use crate::fsm::FsmError;
use crate::messages::idscp_message_factory;
use crate::messages::idscpv2_messages::{
    IdscpClose_CloseCause, IdscpData, IdscpMessage, IdscpMessage_oneof_message,
};

enum ProtocolState {
    Closed,
    WaitForHello,
    Running,
    Terminated,
}

pub(crate) enum FsmAction<'received_data> {
    SecureChannelAction(SecureChannelAction),
    NotifyUserData(&'received_data [u8]),
    SetDatTimeout(Duration),
    SetRaTimeout(Duration),
    SetResendDataTimeout(Duration),
    ToProver(Vec<u8>),
    ToVerifier(Vec<u8>),
}

pub(crate) enum RaMessage<RaType> {
    Ok(Vec<u8>), // TODO: make reference? // TODO: maybe make the inner type an Option<Vec<u8>> to not send packet with empty data,
    Failed(),
    RawData(Vec<u8>, PhantomData<RaType>),
}

#[allow(clippy::enum_variant_names)]
pub(crate) enum FsmEvent<'msg> {
    // USER EVENTS
    FromUpper(UserEvent),

    // SECURE CHANNEL EVENTS
    FromSecureChannel(SecureChannelEvent<'msg>),

    // RA DRIVER EVENTS
    FromRaProver(RaMessage<RaProverType>),
    FromRaVerifier(RaMessage<RaVerifierType>),

    // TIMEOUT EVENTS
    ResendTimout,
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
pub(crate) enum SecureChannelEvent<'msg> {
    Message(&'msg IdscpMessage_oneof_message),
}

#[derive(Debug)]
pub(crate) enum SecureChannelAction {
    Message(IdscpMessage), // TODO: make reference?
}

#[derive(Debug, Clone)]
pub(crate) enum UserEvent {
    StartHandshake,
    // Stop,
    Data(Vec<u8>), // TODO: make reference?
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

#[derive(PartialEq)]
enum AckBit {
    Unset,
    Set,
}

impl AckBit {
    /// this resembles the operiation : 1 - other
    fn from_other_flipped(other: &AckBit) -> AckBit {
        match other {
            AckBit::Set => AckBit::Unset,
            AckBit::Unset => AckBit::Set,
        }
    }
}

impl From<AckBit> for bool {
    fn from(x: AckBit) -> bool {
        match x {
            AckBit::Unset => false,
            AckBit::Set => true,
        }
    }
}

impl From<bool> for AckBit {
    fn from(x: bool) -> AckBit {
        match x {
            false => AckBit::Unset,
            true => AckBit::Set,
        }
    }
}

struct ResendMetadata {
    msg: Option<IdscpData>,
}
impl ResendMetadata {
    fn new() -> ResendMetadata {
        ResendMetadata { msg: None }
    }

    fn set(&mut self, msg: IdscpData) {
        self.msg = Some(msg)
    }

    fn get_ack_bit(&self) -> AckBit {
        match &self.msg {
            Some(msg) => msg.alternating_bit.into(),
            None => AckBit::Unset, // In the Specification, ack bit is initialized to 0/false
        }
    }
}

struct LastDataSent(ResendMetadata);
struct LastDataReceived(ResendMetadata);

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
    last_ack_received: AckBit,
    last_data_sent: LastDataSent,
    last_data_received: LastDataReceived,
    /* configs */
    config: &'config IdscpConfig<'config>,
}

impl<'daps, 'config> Fsm<'daps, 'config> {
    pub(crate) fn new(
        daps_driver: &'daps mut dyn DapsDriver,
        config: &'config IdscpConfig<'config>,
    ) -> Fsm<'daps, 'config> {
        Fsm {
            state: ProtocolState::Closed,
            prover: RaState::Inactive(PhantomData {}),
            verifier: RaState::Inactive(PhantomData {}),
            daps_driver,
            dat_timeout: TimeoutState::Inactive,
            ra_timeout: TimeoutState::Inactive,
            resend_timeout: TimeoutState::Inactive,
            last_ack_received: AckBit::Unset,
            last_data_sent: LastDataSent(ResendMetadata::new()),
            last_data_received: LastDataReceived(ResendMetadata::new()),
            config,
        }
    }

    //TODO: make returned Result a stack-allocated vector of FsmAction because we expect this Vector to be small (one or two elements)
    pub(crate) fn process_event<'event_data>(
        &mut self,
        event: FsmEvent<'event_data>,
    ) -> Result<Vec<FsmAction<'event_data>>, FsmError> {
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
                    &self.config.ra_config.expected_attestation_suite,
                    &self.config.ra_config.supported_attestation_suite,
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

            // TLA Action "ReceiveVerifierMsg"
            (
                ProtocolState::Running,
                RaState::Working, // Prover state
                _,                // Verifier state
                _,                // DAT is valid?
                _,                // Dat timeout
                _,                // Ra timeout
                _,                // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpRaVerifier(msg),
                )),
            ) => {
                let action = FsmAction::ToProver(msg.data.to_vec());
                Ok(vec![action])
            }

            // TLA Action "ReceiveProverMsg"
            (
                ProtocolState::Running,
                _,                      // Prover state
                RaState::Working,       // Verifier state
                true,                   // DAT is valid?
                TimeoutState::Active,   // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                _,                      // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpRaProver(msg),
                )),
            ) => {
                let action = FsmAction::ToVerifier(msg.data.to_vec());
                Ok(vec![action])
            }

            // TLA Action "VerifierSuccess"
            (
                ProtocolState::Running,
                _,                                            // Prover state
                RaState::Working,                             // Verifier state
                true,                                         // DAT is valid?
                TimeoutState::Active,                         // Dat timeout
                TimeoutState::Inactive,                       // Ra timeout
                _,                                            // Resend timeout
                FsmEvent::FromRaVerifier(RaMessage::Ok(msg)), // TODO: adapt specification to make clear that Verifier signals success?
            ) => {
                self.verifier = RaState::Done;
                let msg = idscp_message_factory::create_idscp_ra_verifier(msg);
                let send_action = FsmAction::SecureChannelAction(SecureChannelAction::Message(msg));
                let ra_timeout_action = FsmAction::SetRaTimeout(self.config.ra_config.ra_timeout);
                self.ra_timeout = TimeoutState::Active; // TODO: make it one operation with SetRaTimeout
                Ok(vec![send_action, ra_timeout_action])
            }

            // TODO: TLA Action VerifierError

            // TLA Action "ProverSuccess"
            // We need an action "ProverSuccess" which is not obviously represented in the specification!
            // Otherwhise prover_state is never set to "done"
            (
                ProtocolState::Running,
                RaState::Working,                           // Prover state
                _,                                          // Verifier state
                _,                                          // DAT is valid?
                _,                                          // Dat timeout
                _,                                          // Ra timeout
                _,                                          // Resend timeout
                FsmEvent::FromRaProver(RaMessage::Ok(msg)), // TODO: adapt specification to make clear that Verifier signals success?
            ) => {
                self.prover = RaState::Done;
                let msg = idscp_message_factory::create_idscp_ra_prover(msg);
                Ok(vec![FsmAction::SecureChannelAction(
                    SecureChannelAction::Message(msg),
                )])
            }

            // TODO: TLA Action DatExpired
            // TODO: TLA Action ReceiveDatExpired
            // TODO: TLA Action ReceiveDat

            // TLA Action SendData
            (
                ProtocolState::Running,
                RaState::Done,                              // Prover state
                RaState::Done,                              // Verifier state
                true,                                       // DAT is valid?
                TimeoutState::Active,                       // Dat timeout
                TimeoutState::Active,                       // Ra timeout
                TimeoutState::Inactive,                     // Resend timeout
                FsmEvent::FromUpper(UserEvent::Data(data)), // TODO: adapt specification to make clear that Verifier signals success?
            ) => {
                if self.last_ack_received == self.last_data_sent.0.get_ack_bit() {
                    let msg = idscp_message_factory::create_idscp_data(
                        data,
                        AckBit::from_other_flipped(&self.last_ack_received).into(),
                    );
                    self.last_data_sent.0.set(msg.get_idscpData().clone()); //TODO: maybe use (and clone) Boxes instead of cloning the data
                    self.resend_timeout = TimeoutState::Active;
                    Ok(vec![
                        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)),
                        FsmAction::SetResendDataTimeout(self.config.resend_timeout),
                    ])
                } else {
                    self.no_matching_event()
                }
            }

            // TLA Action ResendData
            (
                ProtocolState::Running,
                RaState::Done,        // Prover state
                RaState::Done,        // Verifier state
                true,                 // DAT is valid?
                TimeoutState::Active, // Dat timeout
                TimeoutState::Active, // Ra timeout
                TimeoutState::Active, // Resend timeout
                FsmEvent::ResendTimout,
            ) => {
                if let Some(resend_msg) = &self.last_data_sent.0.msg {
                    if self.last_ack_received != self.last_data_sent.0.get_ack_bit() {
                        let mut msg = IdscpMessage::new();
                        msg.set_idscpData(resend_msg.clone()); //TODO: maybe use (and clone) Boxes instead of cloning the data
                        Ok(vec![
                            FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)),
                            FsmAction::SetResendDataTimeout(self.config.resend_timeout), // Resetting the timout
                        ])
                    } else {
                        self.no_matching_event()
                    }
                } else {
                    self.no_matching_event()
                }
            }

            // TLA Action ReceiveData
            (
                ProtocolState::Running,
                RaState::Done,        // Prover state
                RaState::Done,        // Verifier state
                true,                 // DAT is valid?
                TimeoutState::Active, // Dat timeout
                TimeoutState::Active, // Ra timeout
                _,                    // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpData(idscp_data),
                )),
            ) => {
                if AckBit::from(idscp_data.get_alternating_bit())
                    != self.last_data_received.0.get_ack_bit()
                {
                    self.last_data_received.0.set(idscp_data.clone()); //TODO: maybe use (and clone) Boxes instead of cloning the data
                }

                let ack_msg = idscp_message_factory::create_idscp_ack(bool::from(
                    self.last_data_received.0.get_ack_bit(),
                ));
                Ok(vec![
                    FsmAction::NotifyUserData(idscp_data.get_data()),
                    FsmAction::SecureChannelAction(SecureChannelAction::Message(ack_msg)),
                ])
            }

            _ => unimplemented!(),
        }
    }

    /// This function is needed because Rust's match statement cannot express all Condtions encoded in the IDSCP2 Specification.
    /// Rust's match statement can only compare a variable to static value of the same type, e.g. protocol_state == ProtocolState::Running.
    /// It CANNOT compare two variables (e.g. lastAckReceived == lastDataSent.ack).
    /// Therefore we need to make this check within the body of the match arm.
    /// If this check does not succeed, we call this method to have a common place to ignore events that do not trigger
    /// an action in the current FSM state.
    fn no_matching_event<'a>(&self) -> Result<Vec<FsmAction<'a>>, FsmError> {
        unimplemented!()
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
