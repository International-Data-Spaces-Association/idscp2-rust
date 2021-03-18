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

use openssl::x509::X509;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone)]
pub enum RatIcm {
    OK,
    Failed,
}

#[derive(Debug, PartialEq, Clone)]
pub enum RatMessage {
    ControlMessage(RatIcm),
    RawData(Vec<u8>),
}

pub trait RatDriver {
    fn execute(&self, tx: Sender<RatMessage>, rx: Receiver<RatMessage>, cert: X509);
    fn get_id(&self) -> &'static str;
}

// *********** Rat Registry *********** //
#[derive(Clone)]
pub struct RatRegistry {
    drivers: HashMap<&'static str, Arc<dyn RatDriver + Send + Sync>>,
}

impl RatRegistry {
    pub fn new() -> RatRegistry {
        log::info!("Create new rat driver registry");
        RatRegistry {
            drivers: HashMap::<&'static str, Arc<dyn RatDriver + Send + Sync>>::new(),
        }
    }

    pub fn register_driver(&mut self, driver: Arc<dyn RatDriver + Send + Sync>) {
        // TODO: return error if there already exists a driver with that ID, because there should be no ambiguity
        let id = driver.get_id();
        self.drivers.insert(id, driver);
        log::info!(
            "New rat driver with id '{}' was registered in registry and is now available",
            id
        );
    }

    pub fn unregister_driver(&mut self, id: &'static str) {
        log::info!("Try to remove rat driver with id '{}' from registry", id);
        self.drivers.remove(id);
    }

    pub fn get_driver(&self, id: &str) -> Option<&Arc<dyn RatDriver + Send + Sync>> {
        self.drivers.get(id)
    }

    pub fn get_all_driver_ids(&self) -> Vec<&&str> {
        self.drivers.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::drivers::rat_driver::{RatDriver, RatIcm, RatMessage, RatRegistry};
    use openssl::x509::X509;
    use std::path::PathBuf;
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{mpsc, Arc};
    use std::{fs, thread};

    const TEST_DRIVER_ID: &'static str = "test.driver.id";

    pub struct TestDriver {}
    impl RatDriver for TestDriver {
        fn execute(&self, tx: Sender<RatMessage>, _rx: Receiver<RatMessage>, _peer_cert: X509) {
            if tx.send(RatMessage::ControlMessage(RatIcm::OK)).is_err() {
                log::warn!("Prover was terminated from fsm");
            }
        }

        fn get_id(&self) -> &'static str {
            TEST_DRIVER_ID
        }
    }

    fn get_test_cert() -> X509 {
        let local_client_cert = fs::read(PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.crt"
        )))
        .unwrap();
        X509::from_pem(&local_client_cert).unwrap()
    }

    #[test]
    fn test_rat_registries() {
        let mut registry = RatRegistry::new();

        let driver = registry.get_driver(TEST_DRIVER_ID);
        assert!(driver.is_none());

        let test_driver = TestDriver {};
        let test_cert = get_test_cert();
        registry.register_driver(Arc::new(test_driver));
        let driver = registry.get_driver("some.invalid.driver");
        assert!(driver.is_none());

        let driver = registry.get_driver(TEST_DRIVER_ID);
        assert!(driver.is_some());

        let driver_clone = Arc::clone(driver.unwrap());

        registry.unregister_driver(TEST_DRIVER_ID);

        let driver = registry.get_driver(TEST_DRIVER_ID);
        assert!(driver.is_none());

        //create channel
        let (tx_, rx) = mpsc::channel();
        let (tx, rx_) = mpsc::channel();

        //spawn thread and execute verifier driver
        thread::spawn(move || {
            driver_clone.execute(tx, rx, test_cert);
        });

        drop(tx_);
        drop(rx_);
    }
}
