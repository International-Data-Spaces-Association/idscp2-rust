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

use idscp_core::api::idscp_connection::{Idscp2Connection, IdscpEvent};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

pub(super) fn connection_handler(connection: Idscp2Connection) {
    let (std_in_tx, std_in_rx) = channel();
    thread::spawn(move || {
        let std_in = std::io::stdin();
        let mut line = String::default();
        println!("You can now type in your messages");
        loop {
            std_in.read_line(&mut line).unwrap();
            std_in_tx.send(line.clone()).unwrap();
            line.clear();
        }
    });

    loop {
        if let Ok(idscp_event) = connection.recv_incoming_msg_with_timeout(Duration::from_millis(1))
        {
            match idscp_event {
                IdscpEvent::Message(msg) => {
                    println!("received {:?}", String::from_utf8_lossy(&msg))
                }
                IdscpEvent::ConnectionClosed => {
                    println!("Connection closed. Exiting");
                    break;
                }
            }
        }
        if let Ok(msg) = std_in_rx.recv_timeout(Duration::from_millis(1)) {
            connection
                .blocking_send(
                    msg.into_bytes(),
                    Duration::from_secs(3),
                    Some(Duration::from_millis(100)),
                )
                .unwrap();
        }
    }
}
