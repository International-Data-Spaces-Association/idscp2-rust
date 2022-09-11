use crate::api::idscp2_config::Certificate;
use crate::RaMessage;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;

/// A `RaDriverInstance` represents the exclusive interface of an `IdscpConnection` to a driver. It
/// is owned by a connection and only exists for the lifetime of the connection. Therefore, it
/// should support multiple re-attestations.
///
/// The `RaDriverInstance` trait combines all necessary functionalities required to interact with
/// the driver. It provides a synchronous common interface to which message bytes can be passed and
/// from which message bytes can be returned. These message bytes originate/are sent to another
/// compatible driver.
#[async_trait]
pub trait RaDriverInstance<RaType> {
    // TODO is this needed?
    /// Returns the identifier of this driver
    fn get_id(&self) -> DriverId;

    // TODO more async funcions?

    /// Signal to the `RaDriverInstance` that the start of a (re-)attestation is requested.
    /// Trigger-function that is called whenever the connection requires attestation.
    fn begin_attestation(&mut self);

    /// Synchronously triggers the processing of `msg`. Does not necessarily block until the message
    /// has been processed.
    fn send_msg(&mut self, msg: Bytes);

    /// Synchronously returns any output message if available. This message may be some `RawData`
    /// bytes destined for the driver at the other end of the connection or a `ControlMessage`
    /// indicating to the connection that some process has been completed.
    async fn recv_msg(&mut self) -> RaMessage<RaType>;
}

/// Executable drivers capable of being started synchronously once and to process (re-)attestation
/// either as a Prover or Verifier. An `RaDriver` should hold all resources required for
/// (re-)attestation that are shared between multiple connections.
///
/// Structs implementing this trait should provide their own interface for managing asynchronous
/// Prover or Verifier executables. This should include scheduling and communication channels.
///
/// A RaDriver creates a launched instance with the `execute` function.
pub trait RaDriver<RaType> {
    /// Synchronously creates a new `RaDriverInstance` which holds all resources (such as
    /// communication channels, nonces, or locks to shared resources) exclusive to one connection
    /// and required to process multiple (re-)attestations.
    fn new_instance(&self, cert: &Certificate) -> Box<dyn RaDriverInstance<RaType>>;

    /// Returns the identifier of this driver
    fn get_id(&self) -> DriverId;
}

pub type DriverId = &'static str;

/// The `RaRegistry` provides a set of available attestation drivers.
/// Each supported driver needs to be registered in the registry
#[derive(Clone)]
pub struct RaRegistry<RaType> {
    drivers: HashMap<DriverId, Arc<dyn RaDriver<RaType> + Send + Sync>>,
}

impl<RaType> RaRegistry<RaType> {
    pub fn new() -> Self {
        RaRegistry {
            drivers: HashMap::new(),
        }
    }

    /// Registers a new driver.
    /// Does not replace any already registered driver with the same id.
    pub fn register_driver(
        &mut self,
        driver: Arc<dyn RaDriver<RaType> + Send + Sync>,
    ) -> Result<&mut Arc<dyn RaDriver<RaType> + Send + Sync>, Arc<dyn RaDriver<RaType> + Send + Sync>>
    {
        let id = driver.get_id();
        match self.drivers.entry(id) {
            Entry::Occupied(ref _entry) => Err(driver),
            Entry::Vacant(entry) => Ok(entry.insert(driver)),
        }
    }

    pub fn unregister_driver(&mut self, id: &DriverId) {
        self.drivers.remove(id);
    }

    pub fn get_driver(&self, id: &DriverId) -> Option<&Arc<dyn RaDriver<RaType> + Send + Sync>> {
        self.drivers.get(id)
    }

    pub fn get_all_driver_ids(&self) -> Vec<&DriverId> {
        self.drivers.keys().collect()
    }
}

/// Provides the connection with an interface to synchronously launch and interact with a type of
/// `RaDriver` (e.g., a Prover)
pub(crate) struct RaManager<'reg, RaType> {
    registry: &'reg RaRegistry<RaType>,
    cert: &'reg Certificate, // ref?
    // state
    active_driver: Option<Arc<dyn RaDriver<RaType>>>,
    active_instance: Option<Box<dyn RaDriverInstance<RaType>>>,
    id: Option<DriverId>, // TODO redundant
}

// TODO naming
pub enum RaManagerEvent<RaType> {
    SelectDriver(DriverId),
    RunDriver,
    RawData(Bytes, PhantomData<RaType>),
}

///
#[derive(Debug, Error)]
pub(crate) enum RaManagerError {
    #[error("The input could not be processed")]
    DriverUnregistered,
    // #[error("The input could not be processed")]
    // DriverNotStarted,
}

impl<'reg, RaType> RaManager<'reg, RaType> {
    pub fn new(registry: &'reg RaRegistry<RaType>, cert: &'reg Certificate) -> Self {
        Self {
            registry,
            cert,
            active_driver: None,
            active_instance: None,
            id: None,
        }
    }

    pub fn process_event(&mut self, event: RaManagerEvent<RaType>) -> Result<(), RaManagerError> {
        match event {
            RaManagerEvent::SelectDriver(id) => self.select_driver(id),
            RaManagerEvent::RunDriver => self.run_driver(),
            RaManagerEvent::RawData(msg, _) => {
                self.send_msg(msg);
                Ok(())
            },
        }
    }

    /// Internally selects the driver with identifier `id` for running.
    /// Returns an error, if `id` is not present in the registry.
    pub fn select_driver(&mut self, id: DriverId) -> Result<(), RaManagerError> {
        self.id = Some(id);
        let driver = self
            .registry
            .get_driver(&id)
            .ok_or(RaManagerError::DriverUnregistered)?
            .clone();
        self.active_driver = Some(driver);
        Ok(())
    }

    pub fn run_driver(&mut self) -> Result<(), RaManagerError> {
        if self.active_instance.is_none() {
            let driver = self
                .active_driver
                .as_ref()
                .ok_or(RaManagerError::DriverUnregistered)?;
            let instance = driver.new_instance(self.cert);

            self.active_instance = Some(instance);
        }
        self.active_instance.as_mut().unwrap().begin_attestation();
        Ok(())
    }

    pub fn recv_msg(
        &mut self,
    ) -> Option<
        std::pin::Pin<
            std::boxed::Box<
                dyn futures::Future<Output = RaMessage<RaType>> + std::marker::Send + '_,
            >,
        >,
    > {
        self.active_instance
            .as_mut().map(|instance| instance.recv_msg())
    }

    pub fn send_msg(&mut self, msg: Bytes) {
        if let Some(instance) = &mut self.active_instance {
            instance.send_msg(msg)
        }
    }
}

impl<RaType> Default for RaRegistry<RaType> {
    fn default() -> Self {
        RaRegistry::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::api::idscp2_config::Certificate;
    use crate::driver::ra_driver::{DriverId, RaDriver, RaDriverInstance, RaMessage};
    use crate::{RaProverType, RaVerifierType};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::fs;
    use std::marker::PhantomData;
    use std::path::PathBuf;
    use tokio::select;

    pub(crate) const TEST_PROVER_ID: DriverId = "test.prover";
    pub(crate) const TEST_VERIFIER_ID: DriverId = "test.prover";

    pub(crate) struct TestVerifier {}

    impl RaDriver<RaVerifierType> for TestVerifier {
        fn new_instance(
            &self,
            _cert: &Certificate,
        ) -> Box<(dyn RaDriverInstance<RaVerifierType> + 'static)> {
            Box::new(TestVerifierInstance {
                state: TestVerifierState::Idle,
            })
        }

        fn get_id(&self) -> DriverId {
            TEST_PROVER_ID
        }
    }

    pub(crate) struct TestVerifierInstance {
        state: TestVerifierState,
    }

    pub(crate) enum TestVerifierState {
        Idle,
        Begin(Bytes),
        WaitingForReply,
        Ok(Bytes),
        Failed,
    }

    #[async_trait]
    impl RaDriverInstance<RaVerifierType> for TestVerifierInstance {
        fn get_id(&self) -> DriverId {
            TEST_PROVER_ID
        }

        fn begin_attestation(&mut self) {
            let msg = Bytes::from("test_begin_attest");
            self.state = TestVerifierState::Begin(msg);
        }

        fn send_msg(&mut self, msg: Bytes) {
            if let TestVerifierState::WaitingForReply = &self.state {
                self.state = if msg == *"test_report" {
                    TestVerifierState::Ok(Bytes::from("test_ok"))
                } else {
                    TestVerifierState::Failed
                };
            }
        }

        async fn recv_msg(&mut self) -> RaMessage<RaVerifierType> {
            loop {
                match &self.state {
                    TestVerifierState::Begin(msg) => {
                        let msg = msg.clone();
                        self.state = TestVerifierState::WaitingForReply;
                        return RaMessage::RawData(msg, PhantomData);
                    }
                    TestVerifierState::Ok(msg) => {
                        let msg = msg.clone();
                        self.state = TestVerifierState::Idle;
                        return RaMessage::Ok(msg);
                    }
                    TestVerifierState::Failed => {
                        self.state = TestVerifierState::Idle;
                        return RaMessage::Failed();
                    }
                    _ => {
                        // println!("a");
                        tokio::task::yield_now().await;
                    }
                }
            }
            /*
            loop {
                let mut state = self.state.lock().await;
                match state.deref() {
                    TestVerifierState::Begin(msg) => {
                        let msg = msg.clone();
                        *state = TestVerifierState::WaitingForReply;
                        return RaMessage::RawData(msg, PhantomData);
                    }
                    TestVerifierState::Ok(msg) => {
                        let msg = msg.clone();
                        *state = TestVerifierState::Idle;
                        return RaMessage::Ok(msg);
                    }
                    TestVerifierState::Failed => {
                        *state = TestVerifierState::Idle;
                        return RaMessage::Failed();
                    }
                    _ => {
                        println!("a");
                    },
                }
            }
             */
        }
    }

    pub(crate) struct TestProver {}

    impl RaDriver<RaProverType> for TestProver {
        fn new_instance(
            &self,
            _cert: &Certificate,
        ) -> Box<(dyn RaDriverInstance<RaProverType> + 'static)> {
            Box::new(TestProverInstance {
                state: TestProverState::Idle,
            })
        }

        fn get_id(&self) -> DriverId {
            TEST_VERIFIER_ID
        }
    }

    pub(crate) struct TestProverInstance {
        state: TestProverState,
    }

    pub(crate) enum TestProverState {
        Idle,
        WaitingForBegin,
        Reply(Bytes),
        WaitingForResponse,
        Ok,
        Failed,
    }

    #[async_trait]
    impl RaDriverInstance<RaProverType> for TestProverInstance {
        fn get_id(&self) -> DriverId {
            TEST_VERIFIER_ID
        }

        fn begin_attestation(&mut self) {
            self.state = TestProverState::WaitingForBegin;
        }

        fn send_msg(&mut self, msg: Bytes) {
            match &self.state {
                TestProverState::WaitingForBegin => {
                    self.state =
                        TestProverState::Reply(Bytes::from(if msg == *"test_begin_attest" {
                            "test_report"
                        } else {
                            "test_failure"
                        }));
                }
                TestProverState::WaitingForResponse => {
                    self.state = if msg == *"test_ok" {
                        TestProverState::Ok
                    } else {
                        TestProverState::Failed
                    };
                }
                _ => {}
            }
        }

        async fn recv_msg(&mut self) -> RaMessage<RaProverType> {
            loop {
                match &self.state {
                    TestProverState::Reply(msg) => {
                        let msg = msg.clone();
                        self.state = TestProverState::WaitingForResponse;
                        return RaMessage::RawData(msg, PhantomData);
                    }
                    TestProverState::Ok => {
                        self.state = TestProverState::Idle;
                        return RaMessage::Ok(Bytes::from("test_ok"));
                    }
                    TestProverState::Failed => {
                        self.state = TestProverState::Idle;
                        return RaMessage::Failed();
                    }
                    _ => {
                        // println!("b");
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }

    pub(crate) fn get_test_cert() -> Certificate {
        let local_client_cert = fs::read(PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.crt"
        )))
        .unwrap();
        Certificate::from_pem(&local_client_cert).unwrap()
    }

    #[test]
    fn async_ra_test_driver_communication() {
        let verifier_driver = TestVerifier {};
        let prover_driver = TestProver {};

        let cert = get_test_cert();
        let mut verifier_instance = verifier_driver.new_instance(&cert);
        let mut prover_instance = prover_driver.new_instance(&cert);

        verifier_instance.begin_attestation();
        prover_instance.begin_attestation();

        let mut verifier_ok = false;
        let mut prover_ok = false;

        println!("Starting test");

        tokio_test::block_on(async {
            while !prover_ok || !verifier_ok {
                let loop_idle;

                select! {
                    msg = verifier_instance.recv_msg() => {
                        match msg {
                            RaMessage::RawData(msg, ..) => {
                                loop_idle = false;
                                println!("Passing msg V->P {:?}", msg);
                                prover_instance.send_msg(msg);
                            }
                            RaMessage::Ok(msg) => {
                                loop_idle = false;
                                println!("Verifier Ok. Passing msg V->P {:?}", msg);
                                prover_instance.send_msg(msg);
                                verifier_ok = true;
                            }
                            RaMessage::Failed() => {
                                panic!("Test Verifier Failed");
                            }
                        }
                    }
                    msg = prover_instance.recv_msg() => {
                        match msg {
                            RaMessage::RawData(msg, ..) => {
                                loop_idle = false;
                                println!("Passing msg P->V {:?}", msg);
                                verifier_instance.send_msg(msg);
                            }
                            RaMessage::Ok(_) => {
                                loop_idle = false;
                                println!("Prover Ok");
                                prover_ok = true;
                            }
                            RaMessage::Failed() => {
                                panic!("Test Prover Failed");
                            }
                        }
                    }
                }
                if loop_idle {
                    panic!("Prover and Verifier deadlocked.");
                }
            }
        });
    }
}
