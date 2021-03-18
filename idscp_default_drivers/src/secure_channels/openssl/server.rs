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
use idscp_core::drivers::secure_channel::{
    SecureChannel, SecureChannelIncomingConnectionCallback, SecureChannelServer,
};
use std::sync::Arc;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion};
use std::net::TcpListener;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::thread::{self};

pub struct OpensslServer {
    kill_signal: Option<calloop::ping::Ping>,
    key_file_path: PathBuf,
    cert_file_path: PathBuf,
    trusted_ca_cert_file_path: PathBuf,
}

impl OpensslServer {
    pub fn new(
        key_file_path: PathBuf,
        cert_file_path: PathBuf,
        trusted_ca_cert_file_path: PathBuf,
    ) -> OpensslServer {
        OpensslServer {
            kill_signal: None,
            key_file_path,
            cert_file_path,
            trusted_ca_cert_file_path,
        }
    }
}

impl SecureChannelServer for OpensslServer {
    type SC = OpensslChannel;
    type AddrType = OpensslAddr;

    fn listen(
        &mut self,
        addr: Self::AddrType,
        callback: SecureChannelIncomingConnectionCallback,
    ) -> Result<(), &'static str> {
        // create ping for terminating server
        let (ping, ping_src) = calloop::ping::make_ping().unwrap();

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor_builder
            .set_ca_file(self.trusted_ca_cert_file_path.as_path())
            .unwrap(); // trusting this CA
        acceptor_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT); //always expect client certificate

        acceptor_builder
            .set_private_key_file(self.key_file_path.as_path(), SslFiletype::PEM)
            .unwrap();
        acceptor_builder
            .set_certificate_chain_file(self.cert_file_path.as_path())
            .unwrap();
        acceptor_builder.check_private_key().unwrap();
        acceptor_builder.clear_options(SslOptions::NO_TLSV1_3); //activate TLSv1.3
        acceptor_builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap(); //set min TLSv1.3
        let acceptor = Arc::new(acceptor_builder.build());
        // spawn listener thread
        let addr_s = format!("{}:{}", addr.hostname, addr.port);
        let listener = match TcpListener::bind(&addr_s) {
            Err(e) => {
                log::error!("Cannot bind listener: {}", e);
                return Err("cannot bind to given address");
            }
            Ok(l) => l,
        };
        log::debug!("OpenSSL server starts listening on {}", addr_s);
        let _ = thread::spawn(move || {
            // create event loop
            let mut event_loop = calloop::EventLoop::try_new().unwrap();
            let loop_handle = event_loop.handle();

            // insert sig event
            let _ = loop_handle.insert_source(
                ping_src,
                move |_, _, data: &mut (bool, Vec<Arc<OpensslChannel>>)| {
                    let (kill_sig, connections) = data;
                    for c in connections {
                        c.terminate();
                    }
                    *kill_sig = true;
                },
            );

            // insert listener event
            let listener_src = calloop::generic::Generic::from_fd(
                listener.as_raw_fd(),
                calloop::Interest::READ,
                calloop::Mode::Level,
            );
            loop_handle
                .insert_source(listener_src, move |_, _, (_, connections)| {
                    log::debug!("accept incoming tcp connection. there should be one because we were notified by epoll");
                    if let Some(Ok(tcp_stream)) = listener.incoming().next() {
                        log::debug!("new tcp connection from {:?}", tcp_stream.peer_addr());
                        let stream_raw_fd = tcp_stream.as_raw_fd();
                        let tls_stream = acceptor.accept(tcp_stream).unwrap();
                        log::debug!("TLS handshake successful");
                        let sc = Arc::new(OpensslChannel::new(tls_stream, stream_raw_fd));
                        connections.push(Arc::clone(&sc));
                        let callback_clone = Arc::clone(&callback);
                        let _ = thread::spawn(move || {
                            let callback_guard = callback_clone.lock().unwrap();
                            let cb = callback_guard.deref();
                            log::debug!("notifying IDSCP listener about new connection");
                            cb(sc);
                            log::debug!("callback returned");
                        });
                    }
                    Ok(())
                })
                .unwrap();

            let mut data: (bool, Vec<Arc<OpensslChannel>>) = (false, vec![]);
            loop {
                let _ = event_loop.dispatch(None, &mut data);
                if data.0 {
                    log::debug!("Stopping Secure server");
                    break;
                }
            }
        });

        self.kill_signal = Some(ping);
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(ping) = self.kill_signal.take() {
            ping.ping();
        }
    }
}
