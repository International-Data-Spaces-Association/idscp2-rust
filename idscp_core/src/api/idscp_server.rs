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
use crate::api::idscp_connection::Idscp2Connection;
use crate::create_new_idscp2_connection;
use crate::drivers::secure_channel::{SecureChannel, SecureChannelServer};
use std::sync::mpsc::{channel, Iter, Receiver};
use std::sync::{Arc, Mutex};

pub struct Idscp2Server<SCS>
where
    SCS: SecureChannelServer + Send + Sync,
    SCS::SC: SecureChannel + Send + Sync,
{
    secure_channel_server: SCS,
    incoming_connection_rx: Receiver<Idscp2Connection>,
}

impl<SCS> Idscp2Server<SCS>
where
    SCS: SecureChannelServer + Send + Sync,
    SCS::SC: SecureChannel + Send + Sync,
{
    pub fn listen(
        mut secure_channel_server: SCS,
        addr: SCS::AddrType,
        idscp_config: &Idscp2Configuration,
    ) -> Result<Idscp2Server<SCS>, &'static str>
    where
        SCS: SecureChannelServer + Send + Sync,
        SCS::SC: SecureChannel + Send + Sync,
    {
        log::info!("Starting new Idscp2 server");
        let config = idscp_config.clone();
        let (incoming_connection_tx, incoming_connection_rx) = channel();
        secure_channel_server.listen(
            addr,
            Arc::new(Mutex::new(Box::new(move |sc| {
                let connection = create_new_idscp2_connection(sc, &config).unwrap();
                incoming_connection_tx
                    .send(connection)
                    .expect("receiving end should be alive in IDSCP2Server");
            }))),
        )?;

        Ok(Idscp2Server {
            secure_channel_server,
            incoming_connection_rx,
        })
    }

    pub fn incoming_connections(&self) -> Iter<Idscp2Connection> {
        self.incoming_connection_rx.iter()
    }

    pub fn terminate(&mut self) {
        log::info!("Terminating idscp server");
        self.secure_channel_server.stop();
    }
}

impl<SCS> Drop for Idscp2Server<SCS>
where
    SCS: SecureChannelServer + Send + Sync,
    SCS::SC: SecureChannel + Send + Sync,
{
    fn drop(&mut self) {
        self.terminate();
    }
}
