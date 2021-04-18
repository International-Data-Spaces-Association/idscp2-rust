use thiserror::Error;

pub(crate) enum FsmAction {
    SecureChannelAction(SecureChannelEvent),
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
    Close,
    Hello(String),
    Data(Vec<u8>),
}

#[derive(Debug, Clone)]
pub(crate) enum UserEvent {
    StartHandshake,
    Stop,
    Data(Vec<u8>),
}

// FSM States
#[derive(Debug, PartialEq, Clone)]
enum FsmState {
    Closed,       //nothing active
    WaitForHello, //handshake active
    Established,  //nothing active
}

pub(crate) struct FSM {
    current_state: FsmState,
    name: String,
}

#[derive(Error, Debug)]
pub enum FsmError {
    #[error("No transition available for the given event")]
    UnknownTransition,
    #[error("FSM is locked forever")]
    WouldBlock,
    #[error(
        "Action failed because FSM was started but is currently not connected. Try it later again"
    )]
    NotConnected,
    #[error("IdscpData must be buffered in state 'WaitForAck'")]
    IdscpDataNotCached,
}

impl FSM {
    pub(crate) fn new(config: String) -> FSM {
        FSM {
            current_state: FsmState::Closed,
            name: config,
        }
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
                    log::debug!("unexpected event");
                    Ok(None)
                }
            },

            _ => unimplemented!(),
        }
    }
}