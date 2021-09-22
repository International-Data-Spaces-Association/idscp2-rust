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

pub mod idscp_configuration;
pub mod idscp_connection;
pub mod idscp_server;

use crate::fsm::FsmError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdscpError {
    #[error("Cannot access Fsm")]
    ConnectionNotAccessible,
    #[error("Connection is temporarily not established")]
    ConnectionTemporaryNotAvailable,
    #[error("Connection aborted")]
    ConnectionAborted(#[from] FsmError),
    #[error("Connection was never started")]
    ConnectionNotStarted,
    #[error("RA error occurred")]
    RaError,
    #[error("Unknown error occurred")]
    Other(#[from] anyhow::Error),
}
