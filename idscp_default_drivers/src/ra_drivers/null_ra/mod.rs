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

use idscp_core::drivers::ra_driver::{RaDriver, RaIcm, RaMessage};
use openssl::x509::X509;
use std::sync::mpsc::{Receiver, Sender};

pub struct NullRaProver {}
pub struct NullRaVerifier {}
impl RaDriver for NullRaProver {
    fn execute(&self, tx: Sender<RaMessage>, rx: Receiver<RaMessage>, _peer_cert: X509) {
        tx.send(RaMessage::RawData(b"".to_vec())).unwrap();
        rx.recv().unwrap();
        if tx.send(RaMessage::ControlMessage(RaIcm::OK)).is_err() {
            log::warn!("Prover was terminated from fsm");
        }
    }

    fn get_id(&self) -> &'static str {
        "NullRa"
    }
}

impl RaDriver for NullRaVerifier {
    fn execute(&self, tx: Sender<RaMessage>, rx: Receiver<RaMessage>, _peer_cert: X509) {
        rx.recv().unwrap();
        tx.send(RaMessage::RawData(b"".to_vec())).unwrap();
        if tx.send(RaMessage::ControlMessage(RaIcm::OK)).is_err() {
            log::warn!("Prover was terminated from fsm");
        }
    }

    fn get_id(&self) -> &'static str {
        "NullRa"
    }
}
