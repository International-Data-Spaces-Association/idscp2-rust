use thiserror::Error;

pub(crate) enum FsmAction {
    SecureChannelAction(SecureChannelEvent),
    // NotifyUserData(Vec<u8>),
}
// FSM Events
#[derive(Debug, Clone)]
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

// FSM States
#[derive(Debug, PartialEq, Clone)]
enum FsmState {
    Closed,       //nothing active
    WaitForHello, //handshake active
    Established,  //nothing active
}

pub(crate) struct Fsm {
    current_state: FsmState,
    name: String,
}

#[derive(Error, Debug)]
pub enum FsmError {
    #[error("No transition available for the given event")]
    UnknownTransition,
    #[error(
        "Action failed because FSM was started but is currently not connected. Try it later again"
    )]
    NotConnected,
}

impl Fsm {
    pub(crate) fn new(config: String) -> Fsm {
        Fsm {
            current_state: FsmState::Closed,
            name: config,
        }
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.current_state == FsmState::Established
    }

    pub(crate) fn process_event(&mut self, event: FsmEvent) -> Result<Option<FsmAction>, FsmError> {
        log::info!(
            "FSM triggered by event{:?} in state {:?}",
            event,
            self.current_state
        );

        match &self.current_state {
            FsmState::Closed => match event {
                FsmEvent::FromSecureChannel(SecureChannelEvent::Hello(peername)) => {
                    log::debug!("received hello from {}", peername);
                    self.current_state = FsmState::Established;
                    Ok(Some(FsmAction::SecureChannelAction(
                        SecureChannelEvent::Hello(self.name.clone()),
                    )))
                }

                FsmEvent::FromUpper(UserEvent::StartHandshake) => {
                    self.current_state = FsmState::WaitForHello;
                    Ok(Some(FsmAction::SecureChannelAction(
                        SecureChannelEvent::Hello(self.name.clone()),
                    )))
                }

                _ => {
                    log::warn!(
                        "unimplemented transition for {:?} <- {:?}",
                        &self.current_state,
                        event
                    );
                    unimplemented!();
                }
            },

            FsmState::WaitForHello => match event {
                FsmEvent::FromSecureChannel(SecureChannelEvent::Hello(peername)) => {
                    log::debug!("received hello from {}", peername);
                    self.current_state = FsmState::Established;
                    Ok(None)
                }

                _ => {
                    log::warn!(
                        "unimplemented transition for {:?} <- {:?}",
                        &self.current_state,
                        event
                    );
                    unimplemented!();
                }
            },

            FsmState::Established => match event {
                FsmEvent::FromUpper(UserEvent::Data(data)) => {
                    log::debug!("sending payload data to peer: {:?}", data);
                    Ok(Some(FsmAction::SecureChannelAction(
                        SecureChannelEvent::Data(data),
                    )))
                }

                /*FsmEvent::FromSecureChannel(SecureChannelEvent::Data(data)) => {
                    log::debug!("receiving idscp_message from peer: {:?}", data);
                    Ok(Some(FsmAction::NotifyUserData(data)))
                }*/
                _ => {
                    log::warn!(
                        "unimplemented transition for {:?} <- {:?}",
                        &self.current_state,
                        event
                    );
                    unimplemented!();
                }
            },

            _ => {
                log::warn!(
                    "unimplemented transition for {:?} <- {:?}",
                    &self.current_state,
                    event
                );
                unimplemented!();
            }
        }
    }
}
