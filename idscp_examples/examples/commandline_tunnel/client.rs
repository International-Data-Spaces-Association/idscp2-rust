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

#[cfg(not(feature = "tpm_rat"))]
use idscp_default_drivers::rat_drivers::null_rat::{NullRatProver, NullRatVerifier};

use idscp_default_drivers::secure_channels::openssl::client::OpensslClient;
use idscp_default_drivers::secure_channels::openssl::OpensslAddr;

use std::path::PathBuf;

use std::sync::Arc;

use std::time::Duration;

mod common;

fn setup_idscp_connection() -> (OpensslClient, OpensslAddr, Idscp2Configuration) {
    println!("Initialize Client");

    let mut prover_registry = RatRegistry::new();
    let mut verifier_registry = RatRegistry::new();

    let daps_client = NullDaps {};

    #[cfg(feature = "tpm_rat")]
    let (prover, verifier) = (
        common::tpm_rat::setup_tpm_prover(),
        common::tpm_rat::setup_tpm_verifier(),
    );

    #[cfg(not(feature = "tpm_rat"))]
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

    let config = Idscp2Configuration {
        rat_config,
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
    let addr = OpensslAddr {
        port: 1234,
        hostname: "127.0.0.1".to_string(),
        domain: "idscp-test.de".to_string(),
    };

    (secure_channel_client, addr, config)
}

fn main() {
    env_logger::init();
    println!("setting up idscp connection");
    let (secure_channel_client, addr, config) = setup_idscp_connection();

    println!("connecting to {}:{}", addr.hostname, addr.port);
    let connection = idscp_core::connect(secure_channel_client, &addr, &config).unwrap();
    assert!(connection.is_connected());
    println!("connected.");
    common::connection_handler(connection);
}
