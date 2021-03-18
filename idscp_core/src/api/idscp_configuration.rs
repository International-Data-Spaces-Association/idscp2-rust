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

use crate::drivers::daps_driver::DapsDriver;
use crate::drivers::rat_driver::RatRegistry;

use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct AttestationConfig {
    // TODO integrate this with IDSCP2Configuration?
    // TODO: rename to "supported_provers" and "supported verifiers"
    pub supported_attestation_suite: Vec<String>,
    pub expected_attestation_suite: Vec<String>,
    pub rat_timeout: Duration,
}

#[derive(Clone)] //TODO check if the derived clone functionality is exactly what we want
pub struct Idscp2Configuration {
    pub rat_config: AttestationConfig,
    pub daps: Arc<dyn DapsDriver + Send + Sync>,
    pub prover_registry: RatRegistry,
    pub verifier_registry: RatRegistry,
    pub handshake_timeout: Duration,
    pub ack_timeout: Duration,
}
