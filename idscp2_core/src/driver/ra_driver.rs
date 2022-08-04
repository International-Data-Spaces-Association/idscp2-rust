use openssl::x509::X509;
use std::collections::hash_map::Entry;
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

pub trait RaDriver {
    fn execute(&self, tx: Sender<RatMessage>, rx: Receiver<RatMessage>, cert: X509);
    fn get_id(&self) -> &'static str;
}

/*
TODO: Are drivers considered equal in the attestation quality?

If the order is relevant, it would be useful to adopt some kind of ordering mechanism to give
certain drivers priority over others. On the other hand, some registered drivers may be disqualified
for some connection and thus unavailable.

The registry itself should provide this information to the `IdscpConnection` as a single source of
truth and prevent the registry and supported-lists to become de-synced. This is important, since the
registry is only referenced and could be dynamically changed, while the list has been dependent on
the
 */

/// The RaRegistry provides a set of available attestation drivers.
/// Each supported driver needs to be registered in the registry
#[derive(Clone)]
pub struct RaRegistry {
    drivers: HashMap<&'static str, Arc<dyn RaDriver + Send + Sync>>,
}

impl RaRegistry {
    pub fn new() -> Self {
        RaRegistry {
            drivers: HashMap::new(),
        }
    }

    /// Registers a new driver.
    /// Does not replace any already registered driver with the same id.
    pub fn register_driver(
        &mut self,
        driver: Arc<dyn RaDriver + Send + Sync>,
    ) -> Result<&mut Arc<dyn RaDriver + Send + Sync>, Arc<dyn RaDriver + Send + Sync>> {
        let id = driver.get_id();
        match self.drivers.entry(id) {
            Entry::Occupied(entry) => Err(driver),
            Entry::Vacant(entry) => Ok(entry.insert(driver)),
        }
    }

    pub fn unregister_driver(&mut self, id: &'static str) {
        self.drivers.remove(id);
    }

    pub fn get_driver(&self, id: &str) -> Option<&Arc<dyn RaDriver + Send + Sync>> {
        self.drivers.get(id)
    }

    // TODO introduce order
    pub fn get_all_driver_ids(&self) -> Vec<&&str> {
        self.drivers.keys().collect()
    }

    pub(crate) fn get_ordered_ids(&self) -> Vec<String> {
        self.drivers.keys().map(|&id| String::from(id)).collect()
    }
}

impl Default for RaRegistry {
    fn default() -> Self {
        RaRegistry::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::driver::ra_driver::{RaDriver, RaRegistry, RatIcm, RatMessage};
    use openssl::x509::X509;
    use std::path::PathBuf;
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{mpsc, Arc};
    use std::{fs, thread};

    const TEST_DRIVER_ID: &'static str = "test.driver.id";

    pub struct TestDriver {}
    impl RaDriver for TestDriver {
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
        let mut registry = RaRegistry::new();

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
