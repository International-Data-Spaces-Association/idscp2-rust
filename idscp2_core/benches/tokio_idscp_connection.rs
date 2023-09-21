use bytes::{Bytes, BytesMut};
use idscp2_core::tokio_idscp_connection::{AsyncIdscpConnection, AsyncIdscpListener};
use rand::{thread_rng, Fill};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use idscp2_core::api::idscp2_config::{AttestationConfig, IdscpConfig};
use idscp2_core::driver::daps_driver::DapsDriver;
use idscp2_core::driver::ra_driver::{
    DriverId, RaDriver, RaDriverInstance, RaMessage, RaProverType, RaRegistry, RaVerifierType,
};
use idscp2_core::Certificate;
use lazy_static::lazy_static;
use tokio_test::assert_ok;

pub(crate) const DUMMY_ID: DriverId = "dummy";

pub(crate) struct DummyVerifier {}

impl RaDriver<RaVerifierType> for DummyVerifier {
    fn new_instance(
        &self,
        _cert: &Certificate,
    ) -> Box<(dyn RaDriverInstance<RaVerifierType> + 'static)> {
        Box::new(DummyVerifierInstance {
            state: DummyState::Idle,
        })
    }

    fn get_id(&self) -> DriverId {
        DUMMY_ID
    }
}

pub(crate) struct DummyVerifierInstance {
    state: DummyState,
}

pub(crate) enum DummyState {
    Idle,
    Ok,
}

#[async_trait]
impl RaDriverInstance<RaVerifierType> for DummyVerifierInstance {
    fn get_id(&self) -> DriverId {
        DUMMY_ID
    }

    fn begin_attestation(&mut self) {
        self.state = DummyState::Idle;
    }

    fn send_msg(&mut self, _msg: Bytes) {}

    async fn recv_msg(&mut self) -> RaMessage<RaVerifierType> {
        loop {
            match &self.state {
                DummyState::Ok => {
                    self.state = DummyState::Idle;
                    return RaMessage::Ok(Bytes::new());
                }
                _ => {
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

pub(crate) struct DummyProver {}

impl RaDriver<RaProverType> for DummyProver {
    fn new_instance(
        &self,
        _cert: &Certificate,
    ) -> Box<(dyn RaDriverInstance<RaProverType> + 'static)> {
        Box::new(DummyProverInstance {
            state: DummyState::Idle,
        })
    }

    fn get_id(&self) -> DriverId {
        DUMMY_ID
    }
}

pub(crate) struct DummyProverInstance {
    state: DummyState,
}

#[async_trait]
impl RaDriverInstance<RaProverType> for DummyProverInstance {
    fn get_id(&self) -> DriverId {
        DUMMY_ID
    }

    fn begin_attestation(&mut self) {
        self.state = DummyState::Ok;
    }

    fn send_msg(&mut self, _msg: Bytes) {}

    async fn recv_msg(&mut self) -> RaMessage<RaProverType> {
        loop {
            match &self.state {
                DummyState::Ok => {
                    self.state = DummyState::Idle;
                    return RaMessage::Ok(Bytes::new());
                }
                _ => {
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

lazy_static! {
    pub(crate) static ref TEST_RA_VERIFIER_REGISTRY: RaRegistry<RaVerifierType> = {
        let mut registry = RaRegistry::new();
        let _ = registry.register_driver(Arc::new(DummyVerifier {}));
        registry
    };
    pub(crate) static ref TEST_RA_PROVER_REGISTRY: RaRegistry<RaProverType> = {
        let mut registry = RaRegistry::new();
        let _ = registry.register_driver(Arc::new(DummyProver {}));
        registry
    };
    pub(crate) static ref TEST_RA_CONFIG: AttestationConfig<'static> = AttestationConfig {
        supported_provers: vec![DUMMY_ID],
        expected_verifiers: vec![DUMMY_ID],
        prover_registry: &TEST_RA_PROVER_REGISTRY,
        ra_timeout: Duration::from_secs(20),
        verifier_registry: &TEST_RA_VERIFIER_REGISTRY,
        peer_cert: get_test_cert(),
    };
    pub(crate) static ref TEST_CONFIG_ALICE: IdscpConfig<'static> = IdscpConfig {
        id: "alice",
        resend_timeout: Duration::from_secs(1),
        ra_config: &TEST_RA_CONFIG,
    };
    pub(crate) static ref TEST_CONFIG_BOB: IdscpConfig<'static> = IdscpConfig {
        id: "bob",
        resend_timeout: Duration::from_secs(1),
        ra_config: &TEST_RA_CONFIG,
    };
}

pub(crate) struct DummyDaps {
    is_valid: bool,
    timeout: Duration,
}

impl Default for DummyDaps {
    fn default() -> Self {
        Self::with_timeout(Duration::from_secs(100000)) // practically forever
    }
}

impl DummyDaps {
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            is_valid: false,
            timeout,
        }
    }
}

impl DapsDriver for DummyDaps {
    fn is_valid(&self) -> bool {
        self.is_valid
    }

    fn get_token(&self) -> String {
        "valid".to_string()
    }

    fn verify_token(&mut self, token_bytes: &[u8]) -> Option<Duration> {
        let token = String::from_utf8_lossy(token_bytes);
        if token.eq("valid") {
            self.is_valid = true;
            Some(self.timeout)
        } else {
            None
        }
    }

    fn invalidate(&mut self) {
        self.is_valid = false;
    }
}

fn random_data(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();

    let mut data = vec![0u8; size];
    data.try_fill(&mut rng).unwrap();
    data
}

async fn spawn_connection<'a>(
    daps_driver_1: &'a mut dyn DapsDriver,
    daps_driver_2: &'a mut dyn DapsDriver,
    config_1: &'a IdscpConfig<'a>,
    config_2: &'a IdscpConfig<'a>,
) -> (AsyncIdscpConnection<'a>, AsyncIdscpConnection<'a>) {
    const ADDRESS: &str = "127.0.0.1:8080";
    let listener = AsyncIdscpListener::bind(ADDRESS).await.unwrap();
    let (connect_result, accept_result) = tokio::join!(
        AsyncIdscpConnection::connect(ADDRESS, daps_driver_1, config_1),
        listener.accept(daps_driver_2, config_2),
    );

    assert_ok!(&connect_result);
    assert_ok!(&accept_result);

    (connect_result.unwrap(), accept_result.unwrap())
}

async fn transfer(
    peer1: &mut AsyncIdscpConnection<'_>,
    peer2: &mut AsyncIdscpConnection<'_>,
    mut data: BytesMut,
    chunk_size: usize,
) -> Result<bool, std::io::Error> {
    let mut cmp_data = data.clone();

    tokio::try_join!(
        async {
            while !cmp_data.is_empty() {
                let msg = peer2.recv(None).await.unwrap();
                assert_eq!(msg.len(), chunk_size);
                let cmp_msg = cmp_data.split_to(chunk_size);
                assert_eq!(std::convert::AsRef::as_ref(&msg), cmp_msg.as_ref());
            }
            Ok::<(), std::io::Error>(())
        },
        async {
            while !data.is_empty() {
                let msg = data.split_to(chunk_size);
                let n = peer1.send(msg.freeze(), None).await?;
                assert!(n == chunk_size);
            }
            Ok::<(), std::io::Error>(())
        },
    )?;

    Ok(data.is_empty() && cmp_data.is_empty())
}

fn bench_transfer_size_1000(c: &mut Criterion) {
    const TRANSMISSION_SIZE: usize = 200_000;
    const FIXED_CHUNK_SIZE: usize = 1000;

    let data = BytesMut::from(random_data(TRANSMISSION_SIZE).as_slice());

    c.bench_function("transfer_size_1000", |b| {
        b.iter(|| {
            tokio_test::block_on(async {
                let mut daps_driver_1 = DummyDaps::default();
                let mut daps_driver_2 = DummyDaps::default();
                let (mut peer1, mut peer2) = spawn_connection(
                    &mut daps_driver_1,
                    &mut daps_driver_2,
                    &TEST_CONFIG_ALICE,
                    &TEST_CONFIG_BOB,
                )
                .await;
                transfer(
                    &mut peer1,
                    &mut peer2,
                    black_box(data.clone()),
                    FIXED_CHUNK_SIZE,
                )
                .await
                .unwrap()
            })
        })
    });
}

criterion_group!(benches, bench_transfer_size_1000);
criterion_main!(benches);
