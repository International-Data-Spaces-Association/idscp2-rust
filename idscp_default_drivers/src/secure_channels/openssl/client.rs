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

use crate::secure_channels::openssl::{OpensslAddr, OpensslChannel};
use anyhow::Error;
use idscp_core::drivers::secure_channel::SecureChannelClient;
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

pub struct OpensslClient {
    pub key_file_path: PathBuf,
    pub cert_file_path: PathBuf,
    pub trusted_ca_file_path: PathBuf,
}

impl SecureChannelClient for OpensslClient {
    type SC = OpensslChannel;
    type AddrType = OpensslAddr;

    fn connect(&self, server_addr: &Self::AddrType) -> Result<Self::SC, Error> {
        log::debug!("Start client");
        let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        connector_builder.set_ca_file(self.trusted_ca_file_path.as_path())?; // trusting this CA
        connector_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT); //always expect server
                                                                                                 // certificate
        connector_builder.set_private_key_file(self.key_file_path.as_path(), SslFiletype::PEM)?;
        connector_builder.set_certificate_chain_file(self.cert_file_path.as_path())?;
        connector_builder.clear_options(SslOptions::NO_TLSV1_3); //activate TLSv1.3
        connector_builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap(); //set min TLSv1.3
        let connector = connector_builder.build();

        log::debug!("Connect Tcp");
        let addr = format!("{}:{}", server_addr.hostname, server_addr.port);
        let mut retry: u32 = 10;
        let stream_and_fd = loop {
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    log::debug!("tcp connection successful");
                    let raw_fd = stream.as_raw_fd();
                    let tls_stream = connector
                        .connect(server_addr.domain.as_ref(), stream)
                        .unwrap();
                    break Ok((tls_stream, raw_fd));
                }
                Err(e) => {
                    if retry > 0 {
                        log::warn!(
                            "could not connect to server. Retrying for {} more time(s)",
                            retry
                        );
                        retry -= 1;
                        continue;
                    } else {
                        break Err(e);
                    }
                }
            }
        };

        //println!("Connect tls");
        match stream_and_fd {
            Ok((tls_stream, raw_fd)) => Ok(OpensslChannel::new(tls_stream, raw_fd)),
            Err(e) => Err(Error::new(e)),
        }
    }
}
