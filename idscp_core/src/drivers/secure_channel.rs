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
use std::sync::{Arc, Mutex};

pub trait SecureChannel: Send + 'static {
    fn send_msg(&self, data: Vec<u8>) -> Result<(), std::io::Error>;
    fn recv_msg(&self) -> Result<Vec<u8>, std::io::Error>;
    fn terminate(&self);
    fn get_peer_certificate(&self) -> X509;
}

pub trait SecureChannelClient {
    type SC: SecureChannel + Send + 'static;
    type AddrType;
    fn connect(&self, server_addr: &Self::AddrType) -> anyhow::Result<Self::SC>;
}

pub type SecureChannelIncomingConnectionCallback =
    Arc<Mutex<Box<dyn Fn(Arc<dyn SecureChannel + Send + Sync + 'static>) + Send>>>;
pub trait SecureChannelServer {
    type SC: SecureChannel + Send + 'static;
    type AddrType;
    fn listen(
        &mut self,
        addr: Self::AddrType,
        callback: SecureChannelIncomingConnectionCallback,
    ) -> Result<(), &'static str>;
    fn stop(&mut self);
}
