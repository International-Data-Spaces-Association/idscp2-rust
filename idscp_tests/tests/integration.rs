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

use idscp_core::api::idscp_configuration::AttestationConfig;
use idscp_core::api::idscp_configuration::Idscp2Configuration;
use idscp_core::api::idscp_connection::{Idscp2Connection, IdscpEvent};

use idscp_core::drivers::ra_driver::RaRegistry;
use idscp_default_drivers::daps_drivers::null_daps::NullDaps;
use idscp_default_drivers::ra_drivers::null_ra::{NullRaProver, NullRaVerifier};
use idscp_default_drivers::secure_channels::openssl::client::OpensslClient;
use idscp_default_drivers::secure_channels::openssl::server::OpensslServer;
use idscp_default_drivers::secure_channels::openssl::OpensslAddr;

use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use idscp_core::api::idscp_server::Idscp2Server;

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::thread;

mod common;

#[test]
fn server_to_client_1_to_1() {
    common::setup_logging();

    let addr = OpensslAddr {
        port: 1234,
        hostname: "127.0.0.1".to_string(),
        domain: "idscp-test.de".to_string(),
    };
    println!("setting up IDSCP listener");
    let (secure_channel_server, config_server) = setup_idscp_listener();
    println!("Start listening at {}:{}", addr.hostname, addr.port);
    let server_addr = addr.clone();
    thread::spawn(move || {
        start_listener(secure_channel_server, server_addr, config_server);
    });

    println!("setting up idscp connection");
    let (secure_channel_client, client_config) = setup_idscp_connection();
    println!("connecting to {}:{}", addr.hostname, addr.port);
    sleep(Duration::from_millis(100));

    let (done_tx, done_rx) = channel();
    let terminate_signal = Arc::new(Mutex::new(done_tx));
    thread::spawn(move || {
        connect(secure_channel_client, addr, client_config, terminate_signal);
    });

    let result = done_rx.recv().unwrap();
    match result {
        Ok(()) => {
            log::info!("test successful");
        }

        Err(e) => {
            log::error!("test failed: {}", e);
            assert!(false);
        }
    }
}

#[test]
fn server_to_client_1_to_2() {
    common::setup_logging();

    let addr = OpensslAddr {
        port: 2345,
        hostname: "127.0.0.1".to_string(),
        domain: "idscp-test.de".to_string(),
    };
    println!("setting up IDSCP listener");
    let (secure_channel_server, config_server) = setup_idscp_listener();
    println!("Start listening at {}:{}", addr.hostname, addr.port);
    let server_addr = addr.clone();
    thread::spawn(move || {
        start_listener(secure_channel_server, server_addr, config_server);
    });

    println!("setting up idscp connection");
    let (secure_channel_client1, client1_config) = setup_idscp_connection();
    let (secure_channel_client2, client2_config) = setup_idscp_connection();
    println!("connecting to {}:{}", addr.hostname, addr.port);
    sleep(Duration::from_millis(1000));
    let (done_tx1, done_rx1) = channel();
    let terminate_signal1 = Arc::new(Mutex::new(done_tx1));
    let (done_tx2, done_rx2) = channel();
    let terminate_signal2 = Arc::new(Mutex::new(done_tx2));
    let addr1 = addr.clone();
    let addr2 = addr.clone();
    thread::spawn(move || {
        connect(
            secure_channel_client1,
            addr1,
            client1_config,
            terminate_signal1,
        );
    });

    thread::spawn(move || {
        connect(
            secure_channel_client2,
            addr2,
            client2_config,
            terminate_signal2,
        );
    });

    done_rx1.recv().unwrap().unwrap();
    done_rx2.recv().unwrap().unwrap();
    log::info!("test successful");
}

#[test]
fn server_to_client_repeat_ra() {
    common::setup_logging();

    let addr = OpensslAddr {
        port: 3456,
        hostname: "127.0.0.1".to_string(),
        domain: "idscp-test.de".to_string(),
    };
    println!("setting up IDSCP listener");
    let (secure_channel_server, config_server) = setup_idscp_listener();
    println!("Start listening at {}:{}", addr.hostname, addr.port);
    let server_addr = addr.clone();
    thread::spawn(move || {
        start_listener_with_rera(secure_channel_server, server_addr, config_server);
    });

    println!("setting up idscp connection");
    let (secure_channel_client, client_config) = setup_idscp_connection();
    println!("connecting to {}:{}", addr.hostname, addr.port);
    sleep(Duration::from_millis(1000));

    let (done_tx, done_rx) = channel();
    let terminate_signal = Arc::new(Mutex::new(done_tx));
    thread::spawn(move || {
        connect(secure_channel_client, addr, client_config, terminate_signal);
    });

    let result = done_rx.recv().unwrap();
    match result {
        Ok(()) => {
            log::info!("test successful");
        }

        Err(e) => {
            log::error!("test failed: {}", e);
            assert!(false);
        }
    }
}

fn start_listener(
    secure_channel_server: OpensslServer,
    addr: OpensslAddr,
    config: Idscp2Configuration,
) {
    let idscp_listener = Idscp2Server::listen(secure_channel_server, addr, &config).unwrap();

    for connection in idscp_listener.incoming_connections() {
        thread::spawn(move || {
            log::info!("New connection on client side config");
            assert!(connection.is_connected());

            thread::sleep(Duration::from_millis(1000));
            for i in 0..10u32 {
                log::info!("sending Ping {}", i + 1);
                connection
                    .blocking_send(
                        format!("Ping {}", i + 1).into_bytes(),
                        Duration::from_millis(3000),
                        Some(Duration::from_millis(100)),
                    )
                    .unwrap();
            }

            // block until peer acknowledges 10 messages
            match connection.incoming_messages().next().unwrap() {
                IdscpEvent::ConnectionClosed => {
                    log::error!("expect acknowledgment message");
                    assert!(false);
                }

                IdscpEvent::Message(msg) => log::info!(
                    "received acknoledgment message from peer: {}",
                    String::from_utf8_lossy(&msg)
                ),
            }
        });
    }
}

fn wait_for_reconnection(idscp_connection: &Idscp2Connection) {
    log::debug!("wait for reconnection");
    loop {
        thread::sleep(Duration::from_millis(100));
        if idscp_connection.is_connected() {
            log::debug!("reconnected");
            break;
        } else {
            log::debug!("not yet reconnected");
        }
    }
}

fn start_listener_with_rera(
    secure_channel_server: OpensslServer,
    addr: OpensslAddr,
    config: Idscp2Configuration,
) {
    let idscp_listener = Idscp2Server::listen(secure_channel_server, addr, &config).unwrap();

    for connection in idscp_listener.incoming_connections() {
        thread::spawn(move || {
            log::info!("New connection on client side config");
            assert!(connection.is_connected());

            thread::sleep(Duration::from_millis(1000));
            for i in 0..10u32 {
                if i % 2 == 0 {
                    connection.repeat_ra().unwrap();
                    wait_for_reconnection(&connection);
                }
                assert_eq!(connection.is_connected(), true);
                connection
                    .blocking_send(
                        format!("Ping {}", i + 1).into_bytes(),
                        Duration::from_millis(3000),
                        Some(Duration::from_millis(100)),
                    )
                    .unwrap();
            }

            // block until peer acknowledges 10 messages
            match connection.incoming_messages().next().unwrap() {
                IdscpEvent::ConnectionClosed => {
                    log::error!("expect acknowledgment message");
                    assert!(false);
                }

                IdscpEvent::Message(msg) => log::info!(
                    "received acknoledgment message from peer: {}",
                    String::from_utf8_lossy(&msg)
                ),
            }
        });
    }
}

fn connect(
    secure_channel_client: OpensslClient,
    addr: OpensslAddr,
    config: Idscp2Configuration,
    terminate_signal: Arc<Mutex<Sender<Result<(), &'static str>>>>,
) {
    let mut counter = 0u32;
    let connection = idscp_core::connect(secure_channel_client, &addr, &config).unwrap();
    assert!(connection.is_connected());
    log::info!("connected.");

    for event in connection.incoming_messages() {
        match event {
            IdscpEvent::ConnectionClosed => {
                log::info!("Connection has been closed");
                break;
            }

            IdscpEvent::Message(msg) => {
                counter += 1;
                log::info!("client received {}th message: {:?}", counter, msg);
                if counter == 10 {
                    break;
                }
            }
        }
    }

    let result = if counter == 10 {
        connection
            .blocking_send(
                b"all 10 messages received".to_vec(),
                Duration::from_millis(3000),
                Some(Duration::from_millis(100)),
            )
            .unwrap();
        Ok(())
    } else {
        Err("Connection has been closed early")
    };

    let guard = terminate_signal.lock().unwrap();
    let tx = guard.deref();
    tx.send(result).unwrap();
}

fn setup_idscp_connection() -> (OpensslClient, Idscp2Configuration) {
    log::info!("Initialize Client");

    let mut prover_registry = RaRegistry::new();
    let mut verifier_registry = RaRegistry::new();

    let daps_client = NullDaps {};
    let prover = Arc::new(NullRaProver {});
    let verifier = Arc::new(NullRaVerifier {});
    prover_registry.register_driver(prover);
    verifier_registry.register_driver(verifier);

    let ra_config = AttestationConfig {
        supported_attestation_suite: prover_registry
            .get_all_driver_ids()
            .iter()
            .map(|p| p.to_string())
            .collect(),
        expected_attestation_suite: verifier_registry
            .get_all_driver_ids()
            .iter()
            .map(|v| v.to_string())
            .collect(),
        ra_timeout: Duration::from_secs(24 * 60 * 60),
    };

    let config = Idscp2Configuration {
        ra_config,
        daps: Arc::new(daps_client),
        prover_registry,
        verifier_registry,
        handshake_timeout: Duration::from_secs(5),
        ack_timeout: Duration::from_millis(1000),
    };

    let key = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "test_client.key"
    ));
    let cert = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "test_client.chain"
    ));
    let ca_cert = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "rootCA.crt"
    ));

    let secure_channel_client = OpensslClient {
        key_file_path: key,
        cert_file_path: cert,
        trusted_ca_file_path: ca_cert,
    };

    (secure_channel_client, config)
}

fn setup_idscp_listener() -> (OpensslServer, Idscp2Configuration) {
    let mut prover_registry = RaRegistry::new();
    let mut verifier_registry = RaRegistry::new();

    let daps_client = NullDaps {};

    let prover = Arc::new(NullRaProver {});
    let verifier = Arc::new(NullRaVerifier {});
    prover_registry.register_driver(prover);
    verifier_registry.register_driver(verifier);

    let ra_config = AttestationConfig {
        supported_attestation_suite: prover_registry
            .get_all_driver_ids()
            .iter()
            .map(|p| p.to_string())
            .collect(),
        expected_attestation_suite: verifier_registry
            .get_all_driver_ids()
            .iter()
            .map(|v| v.to_string())
            .collect(),
        ra_timeout: Duration::from_secs(24 * 60 * 60),
    };

    let config = Idscp2Configuration {
        ra_config,
        daps: Arc::new(daps_client),
        prover_registry,
        verifier_registry,
        handshake_timeout: Duration::from_secs(5),
        ack_timeout: Duration::from_millis(1000),
    };

    let key = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "test_server.key"
    ));
    let cert = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "test_server.chain"
    ));
    let ca_cert = PathBuf::from(format!(
        "{}/../test_pki/resources/openssl/out/{}",
        env!("CARGO_MANIFEST_DIR"),
        "rootCA.crt"
    ));

    let secure_server = OpensslServer::new(key, cert, ca_cert);

    (secure_server, config)
}
