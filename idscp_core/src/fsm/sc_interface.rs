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

use super::{FiniteStateMachine, FsmEvent, SecureChannelEvent};
use crate::drivers::secure_channel::SecureChannel;
use crate::messages::idscp2_messages::{IdscpMessage, IdscpMessage_oneof_message};
use protobuf::parse_from_bytes;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScIfError {
    #[error("Secure Channel interface is inactive")]
    ScInterfaceInactive,
    #[error("Action failed due to secure channel failure")]
    SecureChannelFailure(#[from] std::io::Error),
}

//TODO(obr): maybe find a better name for content
struct InterfaceContent {
    listener: SecureChannelListener,
    secure_channel: Arc<dyn SecureChannel + Send + Sync>,
}

//TODO(obr): maybe name SecureChannelProxy to avoid ambiguity
pub(super) struct SecureChannelInterface {
    pub(super) fsm: Weak<Mutex<FiniteStateMachine>>,
    content: Option<InterfaceContent>,
}

impl SecureChannelInterface {
    // create a new secure channel interface within a mutex
    pub(super) fn create() -> Arc<Mutex<SecureChannelInterface>> {
        Arc::new(Mutex::new(SecureChannelInterface {
            fsm: Weak::new(),
            content: None,
        }))
    }

    pub(super) fn init(
        &mut self,
        sc: Arc<dyn SecureChannel + Send + Sync>,
        interface_ref: Weak<Mutex<SecureChannelInterface>>,
    ) {
        log::debug!("Init secure channel interface");
        let c = InterfaceContent {
            listener: SecureChannelListener::create(
                Weak::clone(&self.fsm),
                interface_ref,
                Arc::clone(&sc),
            ),
            secure_channel: sc,
        };

        //start listener
        c.listener.listen();

        //set content
        self.content = Some(c);
    }

    pub(super) fn unlock(&mut self) -> Result<(), ScIfError> {
        // unlock interface after idscp_handshake was started
        match &mut self.content {
            None => Err(ScIfError::ScInterfaceInactive),
            Some(c) => {
                let &(ref lock, ref cvar) = &*c.listener.unlocked_cond_var;
                let mut unlock = lock.lock().unwrap();
                (*unlock) = true;
                cvar.notify_one();
                Ok(())
            }
        }
    }

    pub(super) fn write(&self, data: Vec<u8>) -> Result<(), ScIfError> {
        match &self.content {
            None => Err(ScIfError::ScInterfaceInactive),
            Some(c) => {
                log::debug!("sending data over secure channel");
                match c.secure_channel.send_msg(data) {
                    Err(e) => Err(ScIfError::SecureChannelFailure(e)),
                    Ok(_) => {
                        log::debug!("Sent data via secure channel");
                        Ok(())
                    }
                }
            }
        }
    }

    pub(super) fn stop(&mut self) {
        //close sc forever
        match self.content.take() {
            None => {
                //already closed
            }
            Some(c) => {
                log::debug!("Stop secure channel via the secure channel interface");
                c.secure_channel.terminate();
                drop(c.listener);
                drop(c.secure_channel);
            }
        }
    }
}

/*
 * A secure channel listener that listens to incoming messages from the secure channel
 * and notifies fsm
 */
struct SecureChannelListener {
    fsm: Weak<Mutex<FiniteStateMachine>>,
    interface: Weak<Mutex<SecureChannelInterface>>,
    sc: Arc<dyn SecureChannel + Send + Sync>,
    unlocked_cond_var: Arc<(Mutex<bool>, Condvar)>,
}

impl SecureChannelListener {
    fn create(
        fsm: Weak<Mutex<FiniteStateMachine>>,
        interface: Weak<Mutex<SecureChannelInterface>>,
        sc: Arc<dyn SecureChannel + Send + Sync>,
    ) -> SecureChannelListener {
        SecureChannelListener {
            fsm,
            interface,
            sc,
            unlocked_cond_var: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn listen(&self) {
        //start a listener thread that calls the blocking recv
        // function within a loop and terminate on error
        log::debug!("Start listening the secure channel listener on secure channel messages");

        let fsm_clone = Weak::clone(&self.fsm);
        let if_clone = Weak::clone(&self.interface);
        let sc_clone = Arc::clone(&self.sc);
        let unlocked_clone = Arc::clone(&self.unlocked_cond_var);

        thread::spawn(move || {
            let unregister_listener = || match if_clone.upgrade() {
                None => {}
                Some(interface) => {
                    log::debug!("Stopping secure channel interface listener");
                    interface.lock().unwrap().stop();
                }
            };

            loop {
                let recv_result = sc_clone.recv_msg();
                match recv_result {
                    Err(_) => {
                        log::warn!(
                            "Secure Channel was closed. Shutting down SecureChannelInterface"
                        );
                        //unregister listener to interface
                        unregister_listener();
                        //hand over error to the fsm if it is still available
                        match fsm_clone.upgrade() {
                            None => {
                                log::debug!("SecureChannelInterface is terminating. FSM is not available anymore");
                                return;
                            }
                            Some(fsm_strong) => match fsm_strong.lock() {
                                Err(e) => log::error!("Cannot access fsm lock {}", e),
                                Ok(mut guard) => {
                                    let _ = (*guard).process_event(FsmEvent::FromSecureChannel(
                                        SecureChannelEvent::Error,
                                    ));
                                }
                            },
                        }
                        return;
                    }
                    Ok(data) => {
                        log::debug!(
                            "Secure Channel Interface listener received new data: {:?}",
                            data
                        );

                        //parse data
                        let body = match parse_from_bytes::<IdscpMessage>(&data) {
                            Err(_) => {
                                log::warn!(
                                    "Cannot parse IDSCP2 message in secure channel interface"
                                );
                                return;
                            }
                            Ok(msg) => match msg.message {
                                None => {
                                    log::warn!("Received IDSCP2 msg is empty");
                                    return;
                                }
                                Some(b) => b,
                            },
                        };

                        //create event
                        let sc_event = match body {
                            IdscpMessage_oneof_message::idscpClose(data) => {
                                SecureChannelEvent::Close(data)
                            }

                            IdscpMessage_oneof_message::idscpHello(data) => {
                                SecureChannelEvent::Hello(data)
                            }

                            IdscpMessage_oneof_message::idscpDat(data) => {
                                SecureChannelEvent::Dat(data)
                            }

                            IdscpMessage_oneof_message::idscpDatExpired(data) => {
                                SecureChannelEvent::DatExp(data)
                            }

                            IdscpMessage_oneof_message::idscpRaProver(data) => {
                                SecureChannelEvent::RaProver(data)
                            }

                            IdscpMessage_oneof_message::idscpRaVerifier(data) => {
                                SecureChannelEvent::RaVerifier(data)
                            }

                            IdscpMessage_oneof_message::idscpReRa(data) => {
                                SecureChannelEvent::ReRa(data)
                            }

                            IdscpMessage_oneof_message::idscpData(data) => {
                                SecureChannelEvent::Data(data)
                            }

                            IdscpMessage_oneof_message::idscpAck(data) => {
                                SecureChannelEvent::Ack(data)
                            }
                        };

                        // wait until the fsm was started by the user or closed forever
                        let &(ref lock, ref cvar) = &*unlocked_clone;
                        log::debug!("try to aquire lock");
                        let lock_result = lock.lock();
                        log::debug!("lock aquired");
                        match lock_result {
                            Err(e) => {
                                log::error!("Cannot acquire unlocked condition lock: {}", e);
                            }

                            Ok(mut unlocked) => {
                                log::debug!("lock not poisoned");
                                while !*unlocked {
                                    log::debug!("wait on conditional variable");
                                    unlocked = match cvar.wait(unlocked) {
                                        Err(e) => {
                                            log::error!(
                                                "Waiting for unlocked condition failed: {}",
                                                e
                                            );
                                            return;
                                        }
                                        Ok(guard) => {
                                            log::debug!("got access to conditional variable");
                                            guard
                                        }
                                    }
                                }
                            }
                        }

                        //hand data to fsm if available
                        log::debug!("check if fsm available");
                        match fsm_clone.upgrade() {
                            None => {
                                // fsm is not available anymore
                                // unregister at listener interface and quit listener
                                log::warn!("Fsm is not available anymore");
                                unregister_listener();
                                return;
                            }
                            Some(fsm_strong) => {
                                log::debug!("try to get lock on fsm");
                                let lock_result = fsm_strong.lock();
                                log::debug!("got lock on fsm");
                                match lock_result {
                                    Err(e) => {
                                        log::error!("Cannot access fsm lock {}", e);
                                        return;
                                    }
                                    Ok(mut guard) => {
                                        let _ = (*guard)
                                            .process_event(FsmEvent::FromSecureChannel(sc_event));
                                    }
                                }
                            }
                        };
                    }
                }
            }
        });
    }
}
