// Copyright (c) 2020, Fraunhofer AISEC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::IdscpError;
use crate::fsm::{FiniteStateMachine, FsmError, UserEvent};
use std::sync::mpsc::{channel, Iter, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

pub enum IdscpEvent {
    Message(Vec<u8>), // TODO shouldn't this be &[u8] to avoid cloning?
    ConnectionClosed,
}

pub struct Idscp2Connection {
    pub(crate) inner: Arc<Mutex<InnerIdscp2connection>>,
    pub(crate) incoming_message_rx: Receiver<IdscpEvent>,
}

impl Idscp2Connection {
    //toDo make msg &[u8] to avoid cloning in FSM and inner connection
    pub fn blocking_send(
        &self,
        msg: Vec<u8>,
        timeout: Duration,
        retry_interval: Option<Duration>,
    ) -> Result<(), IdscpError> {
        let guard = self.inner.lock().unwrap();
        let inner_connection = &*guard;
        inner_connection.blocking_send(msg, timeout, retry_interval)
    }

    pub fn close(&mut self) -> Result<(), IdscpError> {
        let guard = self.inner.lock().unwrap();
        let inner_connection = &*guard;
        inner_connection.close()
    }

    pub fn is_connected(&self) -> bool {
        let guard = self.inner.lock().unwrap();
        let inner_connection = &*guard;
        inner_connection.is_connected()
    }

    pub fn incoming_messages(&self) -> Iter<IdscpEvent> {
        self.incoming_message_rx.iter()
    }

    pub fn recv_incoming_msg_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<IdscpEvent, RecvTimeoutError> {
        self.incoming_message_rx.recv_timeout(timeout)
    }

    pub fn repeat_rat(&self) -> Result<(), IdscpError> {
        let guard = self.inner.lock().unwrap();
        let inner_connection = &*guard;
        inner_connection.repeat_rat()
    }
}

pub(crate) struct InnerIdscp2connection {
    fsm: Arc<Mutex<FiniteStateMachine>>,
    incoming_msg_tx: Sender<IdscpEvent>,
}

impl InnerIdscp2connection {
    pub fn new(
        fsm: Arc<Mutex<FiniteStateMachine>>,
    ) -> (InnerIdscp2connection, Receiver<IdscpEvent>) {
        let (incoming_msg_tx, incoming_msg_rx) = channel();
        let inner = InnerIdscp2connection {
            fsm,
            incoming_msg_tx,
        };

        (inner, incoming_msg_rx)
    }

    fn close(&self) -> Result<(), IdscpError> {
        //terminate fsm
        log::debug!("closing IDSCP connection");

        let mut guard = match self.fsm.lock() {
            Err(e) => {
                log::error!("Cannot access fsm {}", e);
                return Err(IdscpError::ConnectionNotAccessible);
            }
            Ok(guard) => guard,
        };

        // check if fsm is still active
        if guard.is_closed() {
            return Ok(());
        }

        // ignore result, UserEvent::Stop will always succeed or Fsm is already closed
        match (*guard).feed_user_event(UserEvent::Stop) {
            Ok(_) => Ok(()),
            Err(e) => match e {
                FsmError::FsmNotStarted => Err(IdscpError::ConnectionNotStarted),
                _ => Ok(()),
            },
        }
    }

    fn is_connected(&self) -> bool {
        match self.fsm.lock() {
            Err(e) => {
                log::error!("Cannot access fsm {}", e);
                false
            }
            Ok(guard) => (*guard).is_connected(),
        }
    }

    fn blocking_send(
        &self,
        msg: Vec<u8>,
        timeout: Duration,
        retry_interval: Option<Duration>,
    ) -> Result<(), IdscpError> {
        log::debug!("Send Idscp data");
        let start_time = std::time::Instant::now();

        // TODO: if no retry_interval is specified:
        // at the end of the loop, the fsm-lock is released and almost immediately re-aquired in
        // the next loop iteration. Could there be an issue with Mutex-Unfairness?:
        // https://stackoverflow.com/questions/56924866/why-do-rust-mutexes-not-seem-to-give-the-lock-to-the-thread-that-wanted-to-lock
        loop {
            let now = std::time::Instant::now();
            if now >= start_time + timeout {
                return Err(IdscpError::ConnectionTemporaryNotAvailable);
            }
            let mut guard = match self.fsm.lock() {
                Err(e) => {
                    log::error!("Cannot access fsm {}", e);
                    return Err(IdscpError::ConnectionNotAccessible);
                }
                Ok(guard) => guard,
            };

            match (*guard).feed_user_event(UserEvent::Data(msg.clone())) {
                Ok(()) => return Ok(()),
                Err(e) => match e {
                    FsmError::WouldBlock => {
                        /* wait and repeat */
                        if let Some(val) = retry_interval {
                            drop(guard); // release lock before sleeping to let other threads access the fsm
                            sleep(val);
                        }
                        continue;
                    }
                    FsmError::FsmNotStarted => return Err(IdscpError::ConnectionNotStarted),
                    FsmError::FsmLocked => return Err(IdscpError::ConnectionAborted(e)),
                    FsmError::NotConnected => {
                        return Err(IdscpError::ConnectionTemporaryNotAvailable)
                    }
                    FsmError::IoError(_) => return Err(IdscpError::ConnectionAborted(e)),
                    _ => return Err(IdscpError::Other(anyhow::Error::new(e))),
                },
            }
        }
    }

    fn repeat_rat(&self) -> Result<(), IdscpError> {
        log::debug!("triggering re-attestation");

        let mut guard = match self.fsm.lock() {
            Err(e) => {
                log::error!("Cannot access fsm {}", e);
                return Err(IdscpError::ConnectionNotAccessible);
            }
            Ok(guard) => guard,
        };

        match (*guard).feed_user_event(UserEvent::RepeatRat) {
            Ok(()) => Ok(()),
            Err(e) => match e {
                FsmError::FsmLocked => Err(IdscpError::ConnectionAborted(e)),
                FsmError::FsmNotStarted => Err(IdscpError::ConnectionNotStarted),
                FsmError::IoError(_) => Err(IdscpError::ConnectionAborted(e)),
                FsmError::RatError(_) => Err(IdscpError::RatError),
                _ => Err(IdscpError::Other(anyhow::Error::new(e))),
            },
        }
    }

    pub(crate) fn on_close(&mut self) {
        self.incoming_msg_tx
            .send(IdscpEvent::ConnectionClosed)
            .expect("receiving end should be alive in IDSCP2Connection");
    }

    pub(crate) fn on_message(&self, msg: Vec<u8>) {
        self.incoming_msg_tx
            .send(IdscpEvent::Message(msg))
            .expect("receiving end should be alive in IDSCP2Connection");
    }
}

impl Drop for Idscp2Connection {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
