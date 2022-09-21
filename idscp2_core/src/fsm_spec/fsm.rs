use bytes::Bytes;
use std::marker::PhantomData;
use std::time::Duration;
use tinyvec::{array_vec, ArrayVec};

use crate::api::idscp2_config::IdscpConfig;
use crate::driver::daps_driver::DapsDriver;
use crate::driver::ra_driver::DriverId;
use crate::messages::idscp_message_factory;
use crate::messages::idscpv2_messages::{
    IdscpClose_CloseCause, IdscpData, IdscpMessage, IdscpMessage_oneof_message,
};

#[derive(Debug, PartialEq, Eq)]
enum ProtocolState {
    Closed,
    WaitForHello,
    Running,
    Terminated,
}

pub(crate) enum FsmAction {
    None, // TODO we use this to implement a meaningless Default for the safe ArrayVec
    SecureChannelAction(SecureChannelAction),
    NotifyUserData(Bytes),
    SetDatTimeout(Duration),
    SetRaTimeout(Duration),
    SetResendDataTimeout(Duration),
    StopDatTimeout,
    StopRaTimeout,
    StopResendDataTimeout,
    StartProver(DriverId),
    StartVerifier(DriverId),
    RestartProver,
    RestartVerifier,
    ToProver(Bytes),
    ToVerifier(Bytes),
}

impl Default for FsmAction {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug)]
pub enum RaMessage<RaType> {
    Ok(Bytes),
    Failed(),
    RawData(Bytes, PhantomData<RaType>),
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum FsmEvent {
    // USER EVENTS
    FromUpper(UserEvent),

    // SECURE CHANNEL EVENTS
    FromSecureChannel(SecureChannelEvent),

    // RA DRIVER EVENTS
    FromRaProver(RaMessage<RaProverType>),
    FromRaVerifier(RaMessage<RaVerifierType>),

    // TIMEOUT EVENTS
    ResendTimout,
    DatExpired,
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
    Message(IdscpMessage), // TODO: make reference?
}

#[derive(Debug, Clone)]
pub(crate) enum UserEvent {
    StartHandshake,
    #[allow(dead_code)] // FIXME use this in destructor/close
    CloseConnection,
    RequestReattestation(&'static str), //includes cause
    Data(Bytes),                        // ref-counted
}

trait RaType {}
#[derive(Debug, PartialEq)]
pub struct RaProverType {}
impl RaType for RaProverType {}
#[derive(Debug, PartialEq)]
pub struct RaVerifierType {}
impl RaType for RaVerifierType {}

#[derive(Debug, PartialEq)]
enum RaState<RaType> {
    Inactive(PhantomData<RaType>),
    Working,
    Done,
    Terminated,
}

#[derive(Debug, PartialEq)]
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
    pub(crate) const EVENT_VEC_LEN: usize = 3;

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

    pub(crate) fn process_event(
        &mut self,
        event: FsmEvent,
    ) -> ArrayVec<[FsmAction; Fsm::EVENT_VEC_LEN]> {
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
                    Bytes::from(self.daps_driver.get_token()),
                    &self.config.ra_config.expected_verifiers,
                    &self.config.ra_config.supported_provers,
                );

                self.state = ProtocolState::WaitForHello;
                let action =
                    FsmAction::SecureChannelAction(SecureChannelAction::Message(hello_msg));
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action]
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
                let mut actions = ArrayVec::default();

                let dat_timeout = match self.daps_driver.verify_token(dat.get_token()) {
                    Some(dat_timeout) => dat_timeout,
                    None => {
                        let action = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                            idscp_message_factory::create_idscp_close(
                                IdscpClose_CloseCause::NO_VALID_DAT,
                                "",
                            ),
                        ));
                        self.cleanup();
                        return array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action];
                    }
                };

                self.state = ProtocolState::Running;
                actions.push(FsmAction::SetDatTimeout(dat_timeout));
                self.dat_timeout = TimeoutState::Active; // TODO: make it one operation with SetDatTimeout

                match Self::find_ra_match_from_secondary(
                    hello_msg.expectedRaSuite.as_slice(),
                    &self.config.ra_config.supported_provers,
                ) {
                    Some(prover) => actions.push(FsmAction::StartProver(prover)),
                    None => {
                        let action = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                            idscp_message_factory::create_idscp_close(
                                IdscpClose_CloseCause::NO_RA_MECHANISM_MATCH_PROVER,
                                "",
                            ),
                        ));
                        self.cleanup();
                        return array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action];
                    }
                }

                match Self::find_ra_match_from_primary(
                    &self.config.ra_config.expected_verifiers,
                    hello_msg.supportedRaSuite.as_slice(),
                ) {
                    Some(verifier) => actions.push(FsmAction::StartVerifier(verifier)),
                    None => {
                        let action = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                            idscp_message_factory::create_idscp_close(
                                IdscpClose_CloseCause::NO_RA_MECHANISM_MATCH_VERIFIER,
                                "",
                            ),
                        ));
                        self.cleanup();
                        return array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action];
                    }
                }

                self.prover = RaState::Working;
                self.verifier = RaState::Working;

                actions
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
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action]
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
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action]
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
                let action = FsmAction::ToProver(msg.data);
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action]
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
                let action = FsmAction::ToVerifier(msg.data);
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => action]
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
                FsmEvent::FromRaVerifier(RaMessage::Ok(msg)),
            ) => {
                self.verifier = RaState::Done;
                let msg = idscp_message_factory::create_idscp_ra_verifier(msg);
                // let msg = idscp_message_factory::create_idscp_ra_complete(msg);
                let send_action = FsmAction::SecureChannelAction(SecureChannelAction::Message(msg));
                let ra_timeout_action = FsmAction::SetRaTimeout(self.config.ra_config.ra_timeout);
                self.ra_timeout = TimeoutState::Active; // TODO: make it one operation with SetRaTimeout
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => send_action, ra_timeout_action]
            }

            // TLA Action "VerifierError"
            (
                ProtocolState::Running,
                _,                      // Prover state
                RaState::Working,       // Verifier state
                true,                   // DAT is valid?
                TimeoutState::Active,   // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                _,                      // Resend timeout
                FsmEvent::FromRaVerifier(RaMessage::Failed()),
            ) => {
                let send_action = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                    idscp_message_factory::create_idscp_close(
                        IdscpClose_CloseCause::RA_VERIFIER_FAILED,
                        "",
                    ),
                ));
                self.cleanup();
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => send_action]
            }

            // TLA Action "ProverSuccess"
            // We need an action "ProverSuccess" which is not obviously represented in the specification!
            // Otherwhise prover_state is never set to "done"
            (
                ProtocolState::Running,
                RaState::Working,                            // Prover state
                _,                                           // Verifier state
                _,                                           // DAT is valid?
                _,                                           // Dat timeout
                _,                                           // Ra timeout
                _,                                           // Resend timeout
                FsmEvent::FromRaProver(RaMessage::Ok(_msg)), // TODO what is msg
            ) => {
                self.prover = RaState::Done;
                ArrayVec::default()
            }

            // TLA Action "ProverError"
            // See above
            (
                ProtocolState::Running,
                RaState::Working,                            // Prover state
                _,                                           // Verifier state
                _,                                           // DAT is valid?
                _,                                           // Dat timeout
                _,                                           // Ra timeout
                _,                                           // Resend timeout
                FsmEvent::FromRaProver(RaMessage::Failed()),
            ) => {
                let send_action = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                    idscp_message_factory::create_idscp_close(
                        IdscpClose_CloseCause::RA_VERIFIER_FAILED,
                        "",
                    ),
                ));
                self.cleanup();
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => send_action]
            }

            // TLA Action DatExpired
            (
                ProtocolState::Running,
                _,    // Prover state
                _,    // Verifier state
                true, // DAT is valid?
                _,    // Dat timeout
                _,    // Ra timeout
                _,    // Resend timeout
                FsmEvent::DatExpired,
            ) => {
                self.verifier = RaState::Inactive(PhantomData {});
                self.daps_driver.invalidate();
                self.ra_timeout = TimeoutState::Inactive;
                self.dat_timeout = TimeoutState::Inactive;
                let actions = array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                    FsmAction::StopRaTimeout,
                    FsmAction::StopDatTimeout,
                    FsmAction::SecureChannelAction(SecureChannelAction::Message(
                        idscp_message_factory::create_idscp_dat_exp(),
                    )),
                ];
                actions
            }

            // TLA Action ReceiveDatExpired
            (
                ProtocolState::Running,
                _, // Prover state
                _, // Verifier state
                _, // DAT is valid?
                _, // Dat timeout
                _, // Ra timeout
                _, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpDatExpired(_),
                )),
            ) => {
                let mut actions = ArrayVec::default();

                self.prover = RaState::Working;
                actions.push(FsmAction::RestartProver);
                actions.push(FsmAction::SecureChannelAction(
                    SecureChannelAction::Message(idscp_message_factory::create_idscp_dat(
                        Bytes::from(self.daps_driver.get_token()),
                    )),
                ));
                actions
            }

            // TLA Action ReceiveDat
            (
                ProtocolState::Running,
                _,                      // Prover state
                RaState::Inactive(_),   // Verifier state
                false,                  // DAT is valid?
                TimeoutState::Inactive, // Dat timeout
                TimeoutState::Inactive, // Ra timeout
                _,                      // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpDat(dat),
                )),
            ) => {
                let mut actions = ArrayVec::default();
                match self.daps_driver.verify_token(dat.get_token()) {
                    Some(dat_timeout) => {
                        self.dat_timeout = TimeoutState::Active;
                        actions.push(FsmAction::SetDatTimeout(dat_timeout));
                        self.verifier = RaState::Working;
                        actions.push(FsmAction::RestartVerifier);
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
                actions
            }

            // TLA Action SendData
            (
                ProtocolState::Running,
                RaState::Done,          // Prover state
                RaState::Done,          // Verifier state
                true,                   // DAT is valid?
                TimeoutState::Active,   // Dat timeout
                TimeoutState::Active,   // Ra timeout
                TimeoutState::Inactive, // Resend timeout
                FsmEvent::FromUpper(UserEvent::Data(data)),
            ) => {
                if self.last_ack_received == self.last_data_sent.0.get_ack_bit() {
                    let msg = idscp_message_factory::create_idscp_data(
                        data,
                        AckBit::from_other_flipped(&self.last_ack_received).into(),
                    );
                    self.last_data_sent.0.set(msg.get_idscpData().clone()); // zero-copy clone
                    self.resend_timeout = TimeoutState::Active;
                    array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                        FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)),
                        FsmAction::SetResendDataTimeout(self.config.resend_timeout),
                    ]
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
                        msg.set_idscpData(resend_msg.clone()); // zero-copy clone
                        array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                            FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)),
                            FsmAction::SetResendDataTimeout(self.config.resend_timeout), // Resetting the timout
                        ]
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
                _,                    // Prover state
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
                    self.last_data_received.0.set(idscp_data.clone());
                }

                let ack_msg = idscp_message_factory::create_idscp_ack(bool::from(
                    self.last_data_received.0.get_ack_bit(),
                ));
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                    FsmAction::NotifyUserData(idscp_data.data),
                    FsmAction::SecureChannelAction(SecureChannelAction::Message(ack_msg)),
                ]
            }

            // TLA Action ReceiveAck
            (
                ProtocolState::Running,
                _, // Prover state
                _, // Verifier state
                _, // DAT is valid?
                _, // Dat timeout
                _, // Ra timeout
                _, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpAck(idscp_ack),
                )),
            ) => {
                let received_ack = AckBit::from(idscp_ack.alternating_bit);
                if self.last_ack_received != received_ack {
                    // can be simplified in the Spec.
                    self.last_ack_received = received_ack;
                    self.resend_timeout = TimeoutState::Inactive;
                }

                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => FsmAction::StopResendDataTimeout]
            }

            // TLA Action CloseConnection
            (
                ProtocolState::Running | ProtocolState::WaitForHello,
                _, // Prover state
                _, // Verifier state
                _, // DAT is valid?
                _, // Dat timeout
                _, // Ra timeout
                _, // Resend timeout
                FsmEvent::FromUpper(UserEvent::CloseConnection),
            ) => {
                let msg = FsmAction::SecureChannelAction(SecureChannelAction::Message(
                    idscp_message_factory::create_idscp_close(
                        IdscpClose_CloseCause::USER_SHUTDOWN,
                        "",
                    ),
                ));
                self.cleanup();
                array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] => msg]
            }

            // TLA Action ReceiveClose
            (
                ProtocolState::Running | ProtocolState::WaitForHello,
                _, // Prover state
                _, // Verifier state
                _, // DAT is valid?
                _, // Dat timeout
                _, // Ra timeout
                _, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpClose(_),
                )),
            ) => {
                self.cleanup();
                // TODO: The other actors should probably be notified about that
                ArrayVec::default()
            }

            // TLA Action RequestReattestation
            (
                ProtocolState::Running,
                _,                    // Prover state
                RaState::Done,        // Verifier state
                true,                 // DAT is valid?
                TimeoutState::Active, // Dat timeout
                TimeoutState::Active, // Ra timeout
                _,                    // Resend timeout
                FsmEvent::FromUpper(UserEvent::RequestReattestation(cause)),
            ) => {
                self.verifier = RaState::Working;
                self.ra_timeout = TimeoutState::Inactive;
                let actions = array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                    FsmAction::StopRaTimeout,
                    FsmAction::SecureChannelAction(SecureChannelAction::Message(
                        idscp_message_factory::create_idscp_re_rat(cause),
                    )),
                    FsmAction::RestartVerifier,
                ];
                actions
            }

            // TLA Action ReceiveReattestation
            (
                ProtocolState::Running,
                _, // Prover state
                _, // Verifier state
                _, // DAT is valid?
                _, // Dat timeout
                _, // Ra timeout
                _, // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(
                    IdscpMessage_oneof_message::idscpReRa(_),
                )),
            ) => {
                self.prover = RaState::Working;
                let actions = array_vec![[FsmAction; Fsm::EVENT_VEC_LEN] =>
                    FsmAction::RestartProver,
                ];
                actions
            }

            // Unknown message
            (
                _,                                                           // FSM state
                _,                                                           // Prover state
                _,                                                           // Verifier state
                _,                                                           // DAT is valid?
                _,                                                           // Dat timeout
                _,                                                           // Ra timeout
                _,                                                           // Resend timeout
                FsmEvent::FromSecureChannel(SecureChannelEvent::Message(_)), // TODO only match on messages?
            ) => {
                // nothing to process
                ArrayVec::default()
            }

            (state, prover, verifier, dat, dat_timeout, ra_timeout, resend_timeout, event) => {
                unimplemented!(
                    "\n(\
                state: {:?},\n\
                prover: {:?},\n\
                verifier: {:?},\n\
                dat: {:?},\n\
                dat_timeout: {:?},\n\
                ra_timeout: {:?},\n\
                resend_timeout: {:?},\n\
                event: {:?},\n\
                )",
                    state,
                    prover,
                    verifier,
                    dat,
                    dat_timeout,
                    ra_timeout,
                    resend_timeout,
                    event
                )
            }
        }
    }

    /// This function is needed because Rust's match statement cannot express all Condtions encoded in the IDSCP2 Specification.
    /// Rust's match statement can only compare a variable to static value of the same type, e.g. protocol_state == ProtocolState::Running.
    /// It CANNOT compare two variables (e.g. lastAckReceived == lastDataSent.ack).
    /// Therefore we need to make this check within the body of the match arm.
    /// If this check does not succeed, we call this method to have a common place to ignore events that do not trigger
    /// an action in the current FSM state.
    fn no_matching_event(&self) -> ArrayVec<[FsmAction; Fsm::EVENT_VEC_LEN]> {
        unimplemented!()
    }

    /// Returns `true` if a connection to another peer is set up and not closed.
    /// Does not check if the connection has been validated.
    pub(crate) fn is_open(&self) -> bool {
        self.state == ProtocolState::Running
    }

    /// Returns `true` if the connection is verified and can be used to exchange data.
    pub(crate) fn is_attested(&self) -> bool {
        self.is_open()
            && self.dat_timeout == TimeoutState::Active
            && self.prover == RaState::Done
            && self.verifier == RaState::Done
            && self.daps_driver.is_valid()
    }

    /// Returns `true` if data can be sent in the current state.
    /// This is the case, if the connection is verified and all sent data has been acknowledged by the connected peer.
    pub(crate) fn is_ready_to_send(&self) -> bool {
        self.is_attested() && self.resend_timeout == TimeoutState::Inactive
    }

    // workaround

    /// Finds the attestation id match between two capability lists
    fn find_ra_match_from_primary<T: AsRef<str>>(
        primary: &[DriverId],
        secondary: &[T],
    ) -> Option<DriverId> {
        for p in primary {
            for s in secondary {
                if *p == s.as_ref() {
                    // no check against registry at this point anymore
                    return Some(p);
                }
            }
        }
        None
    }

    /// Finds the attestation id match between two capability lists
    fn find_ra_match_from_secondary<T: AsRef<str>>(
        primary: &[T],
        secondary: &[DriverId],
    ) -> Option<DriverId> {
        for p in primary {
            for s in secondary {
                if p.as_ref() == *s {
                    // no check against registry at this point anymore
                    return Some(s);
                }
            }
        }
        None
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
