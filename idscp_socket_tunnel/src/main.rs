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

use idscp_core::api::idscp_configuration::Idscp2Configuration;

use idscp_core::api::idscp_configuration::AttestationConfig;
use idscp_core::drivers::rat_driver::RatRegistry;

use idscp_default_drivers::daps_drivers::null_daps::NullDaps;
use idscp_default_drivers::rat_drivers::null_rat::{NullRatProver, NullRatVerifier};

use idscp_default_drivers::secure_channels::openssl::client::OpensslClient;
use idscp_default_drivers::secure_channels::openssl::OpensslAddr;

use std::path::PathBuf;

use std::sync::Arc;

use std::time::Duration;

use std::os::unix::net::UnixListener;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use clap::{App, Arg};
use idscp_core::api::idscp_connection::{Idscp2Connection, IdscpEvent};
use idscp_core::api::idscp_server::Idscp2Server;
use idscp_default_drivers::secure_channels::openssl::server::OpensslServer;

use std::io::Read;
use std::io::Write;

const ASYNC_TIMOUT: Duration = Duration::from_millis(10);

fn default_config() -> Idscp2Configuration {
    let mut prover_registry = RatRegistry::new();
    let mut verifier_registry = RatRegistry::new();

    let daps = NullDaps {};

    let (prover, verifier) = (Arc::new(NullRatProver {}), Arc::new(NullRatVerifier {}));

    prover_registry.register_driver(prover);
    verifier_registry.register_driver(verifier);

    let rat_config = AttestationConfig {
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
        rat_timeout: Duration::from_secs(24 * 60 * 60),
    };

    Idscp2Configuration {
        rat_config,
        daps: Arc::new(daps),
        prover_registry,
        verifier_registry,
        handshake_timeout: Duration::from_secs(5),
        ack_timeout: Duration::from_millis(1000),
    }
}

fn create_socket(
    path: &str,
    send_tx: Sender<Vec<u8>>,
    receive_rx: Receiver<Vec<u8>>,
) -> std::io::Result<()> {
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::AddrInUse => {
                    println!("removing existing unix socket at path {}", path);
                    std::fs::remove_file(path)?;

                    //try to bind again
                    UnixListener::bind(path)?
                }

                _ => panic!("unexpected error {:?}", e),
            }
        }
    };
    println!("socket created at {}", path);
    println!("For writing to socket use, e.g., nc -U {0}", path);

    let (mut stream, addr) = listener.accept().unwrap();
    println!("new connection to socket from {:?}", addr);
    stream.set_read_timeout(Some(ASYNC_TIMOUT)).unwrap();
    thread::spawn(move || loop {
        let mut buffer = [0u8; 1024];
        //println!("trying to read from socket");
        match stream.read(&mut buffer) {
            Ok(nbytes) => {
                if nbytes > 0 {
                    println!("sending data");
                    send_tx.send(buffer[0..nbytes].to_vec()).unwrap();
                } else {
                    println!("did not read anything");
                }
            }

            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {
                    //println!("would block");
                }

                _ => {
                    println!("socket closed. exiting");
                    break;
                }
            },
        }

        if let Ok(data) = receive_rx.recv_timeout(ASYNC_TIMOUT) {
            stream.write_all(&data).unwrap();
            stream.flush().unwrap();
        }
    });

    Ok(())
}

fn handle_connection(connection: Idscp2Connection, connnection_id: usize) {
    let (receive_tx, receive_rx) = channel();
    let (send_tx, send_rx) = channel();
    let path = format!("/tmp/idscp_socket{}", connnection_id);
    create_socket(&path, send_tx, receive_rx).unwrap();

    loop {
        if let Ok(event) = connection.recv_incoming_msg_with_timeout(ASYNC_TIMOUT) {
            match event {
                IdscpEvent::ConnectionClosed => break,
                IdscpEvent::Message(data) => receive_tx.send(data).unwrap(),
            }
        }

        if let Ok(data) = send_rx.recv_timeout(ASYNC_TIMOUT) {
            connection
                .blocking_send(data, Duration::from_millis(500), None)
                .unwrap();
        }
    }
}

enum Mode {
    Connector,
    Listener,
}

const CERT_ARG: &str = "cert";
const KEY_ARG: &str = "key";
const TRUSTED_CA_ARG: &str = "trusted-ca";
const HOST_ARG: &str = "host";
const PORT_ARG: &str = "port";
const DOMAIN_ARG: &str = "domain";

fn main() {
    env_logger::init();

    let clap = App::new("IDSCP Socket Tunnel")
        .version("v0.1.0")
        .author("Oliver Braunsdorf <oliver.braunsdorf@aisec.fraunhofer.de>")
        .about("Creates a unix socket that tunnels data through IDSCPv2")
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .takes_value(true)
                .possible_values(&["Listener", "Connector"])
                .help("Start IDSCP as listening or connecting peer")
                .required(true),
        )
        .arg(
            Arg::with_name(KEY_ARG)
                .long("key")
                .takes_value(true)
                .help("TLS private key file")
                .required(true),
        )
        .arg(
            Arg::with_name(CERT_ARG)
                .long("cert")
                .takes_value(true)
                .help("TLS certificate file")
                .required(true),
        )
        .arg(
            Arg::with_name(TRUSTED_CA_ARG)
                .long("trusted-ca")
                .takes_value(true)
                .help("Certificate of trusted Root-CA")
                .required(true),
        )
        .arg(
            Arg::with_name(HOST_ARG)
                .long("host")
                .takes_value(true)
                .help("address to conncet/bind to")
                .required(true),
        )
        .arg(
            Arg::with_name(PORT_ARG)
                .long("port")
                .takes_value(true)
                .help("port to conncet/bind to")
                .required(true),
        )
        .arg(
            Arg::with_name(DOMAIN_ARG)
                .long("domain")
                .takes_value(true)
                .help("domain name of peer/self")
                .required(true),
        );
    let matches = clap.get_matches();

    let mode = match matches.value_of("mode").unwrap() {
        "Listener" => Mode::Listener,
        "Connector" => Mode::Connector,
        _ => {
            let err = clap::Error::with_description("invalid mode", clap::ErrorKind::InvalidValue);
            err.exit();
        }
    };

    let key = matches.value_of(KEY_ARG).unwrap();
    let cert = matches.value_of(CERT_ARG).unwrap();
    let trusted_ca = matches.value_of(TRUSTED_CA_ARG).unwrap();
    let host = matches.value_of(HOST_ARG).unwrap();
    let port: u16 = matches.value_of(PORT_ARG).unwrap().parse().unwrap();
    let domain = matches.value_of(DOMAIN_ARG).unwrap();

    let addr = OpensslAddr {
        port,
        hostname: host.to_string(),
        domain: domain.to_string(),
    };

    let config = default_config();

    match mode {
        Mode::Connector => {
            println!("setting up idscp connection");
            let secure_channel_client = OpensslClient {
                key_file_path: PathBuf::from(key),
                cert_file_path: PathBuf::from(cert),
                trusted_ca_file_path: PathBuf::from(trusted_ca),
            };

            println!("connecting to {}:{}", addr.hostname, addr.port);
            let connection = idscp_core::connect(secure_channel_client, &addr, &config).unwrap();
            assert!(connection.is_connected());
            println!("connected.");
            handle_connection(connection, 0);
        }

        Mode::Listener => {
            println!("setting up IDSCP listener");
            let secure_channel_server = OpensslServer::new(
                PathBuf::from(key),
                PathBuf::from(cert),
                PathBuf::from(trusted_ca),
            );

            println!("Start listening at {}:{}", addr.hostname, addr.port);
            let server = Idscp2Server::listen(secure_channel_server, addr, &config).unwrap();

            for (counter, connection) in server.incoming_connections().enumerate() {
                thread::spawn(move || handle_connection(connection, counter));
            }
        }
    }
}
