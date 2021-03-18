#![forbid(unsafe_code)]
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

use crate::api::idscp_configuration::Idscp2Configuration;
use crate::api::idscp_connection::{Idscp2Connection, InnerIdscp2connection};
use crate::drivers::secure_channel::{SecureChannel, SecureChannelClient};
use crate::fsm::{FiniteStateMachine, HandshakeResult, UserEvent};
use std::sync::{Arc, Condvar, Mutex};

pub mod api;
pub mod drivers;
mod fsm;
mod messages;

pub fn connect<SCC: SecureChannelClient>(
    secure_channel_client: SCC,
    server_addr: &SCC::AddrType,
    config: &Idscp2Configuration,
) -> Result<Idscp2Connection, &'static str>
where
    SCC::SC: SecureChannel + Send + Sync,
{
    log::info!("Connect to IDSCP peer");

    //create secure channel via connect
    let sc = match secure_channel_client.connect(server_addr) {
        Err(e) => {
            log::warn!("Cannot establish secure channel: {}", e);
            return Err("Cannot establish secure channel");
        }
        Ok(secure_channel) => Arc::new(secure_channel),
    };

    create_new_idscp2_connection(sc, &config)
}

//TODO(lbe): check clippy lints for this function, maybe rewrite?
fn block_until_handshake_done(
    handshake_cond: Arc<(Mutex<HandshakeResult>, Condvar)>,
) -> Result<HandshakeResult, &'static str> {
    let &(ref lock, ref cvar) = &*handshake_cond;

    match lock.lock() {
        Err(_) => {
            return Err("Cannot acquire hanndshake result lock");
        }

        Ok(mut available) => loop {
            // first check if already available
            match *available {
                HandshakeResult::NotAvailable => {}
                HandshakeResult::Failed => {
                    return Ok(HandshakeResult::Failed);
                }
                HandshakeResult::Successful => {
                    return Ok(HandshakeResult::Successful);
                }
            }

            // then wait
            available = match cvar.wait(available) {
                Err(_) => {
                    return Err("Waiting for handshake result failed");
                }
                Ok(guard) => guard,
            };
        },
    };
}

fn create_new_idscp2_connection(
    sc: Arc<dyn SecureChannel + Send + Sync + 'static>,
    config: &Idscp2Configuration,
) -> Result<Idscp2Connection, &'static str> {
    //create condition variable for idscp handshake
    let handshake_wait = Arc::new((Mutex::new(HandshakeResult::NotAvailable), Condvar::new()));

    //create fsm
    let fsm = FiniteStateMachine::create(
        sc,
        config.prover_registry.clone(),
        config.verifier_registry.clone(),
        Arc::clone(&config.daps),
        Arc::clone(&handshake_wait),
        config.handshake_timeout,
        config.ack_timeout,
        config.rat_config.clone(),
    );

    //start fsm handshake
    match fsm.lock() {
        Err(e) => {
            log::error!("Cannot acquire fsm lock: {}", e);
            return Err("Cannot acquire fsm lock");
        }

        Ok(mut fsm_guard) => {
            log::debug!("Start Idscp2 handshake");
            match (*fsm_guard).feed_user_event(UserEvent::StartHandshake) {
                Ok(()) => {}
                Err(e) => {
                    log::warn!("Cannot start handshake: {}", e);
                }
            }
        }
    }

    //block until result is available
    match block_until_handshake_done(handshake_wait) {
        Err(e) => {
            return Err(e);
        }
        Ok(result) => match result {
            HandshakeResult::Successful => {
                log::debug!("Idscp2 handshake successful");

                // if handshake was successful create new Idscp2Connection
                let (inner, incoming_msg_rx) = InnerIdscp2connection::new(Arc::clone(&fsm));
                let inner_wrapper = Arc::new(Mutex::new(inner));

                // make inner idscp connection available in fsm
                match fsm.lock() {
                    Err(e) => {
                        log::error!("Cannot acquire fsm lock: {}", e);
                        return Err("Cannot acquire fsm lock");
                    }
                    Ok(mut fsm_guard) => {
                        (*fsm_guard).set_connection(Some(Arc::downgrade(&inner_wrapper)));
                    }
                }

                let idscp_connection = Idscp2Connection {
                    inner: inner_wrapper,
                    incoming_message_rx: incoming_msg_rx,
                };
                return Ok(idscp_connection);
            }

            _ => {
                log::debug!("Idscp2 handshake failed");
                return Err("Idscp2 handshake failed");
            }
        },
    };
}
