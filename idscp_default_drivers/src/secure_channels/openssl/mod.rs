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

use idscp_core::drivers::secure_channel::SecureChannel;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::thread;

use byteorder::{BigEndian, ByteOrder};
use calloop::channel::{Event, Sender};
use calloop::EventLoop;
use openssl::ssl::SslStream;
use openssl::x509::X509;
use std::os::unix::io::RawFd;
use std::sync::mpsc;

pub mod client;
pub mod server;

const LENGTH_PREFIX_SIZE: usize = 4; // byte

pub struct OpensslChannel {
    // must be mutex to share safely between threads
    to_remote: Mutex<Sender<ScMessage>>,
    from_remote: Mutex<mpsc::Receiver<ScMessage>>,
    peer_certificate: X509,
}

pub struct OpensslAddr {
    pub port: u16,
    pub hostname: String,
    pub domain: String,
}

impl Clone for OpensslAddr {
    fn clone(&self) -> Self {
        OpensslAddr {
            port: self.port,
            hostname: String::from(&self.hostname),
            domain: String::from(&self.domain),
        }
    }
}

enum ScMessage {
    Close,
    Data(Vec<u8>),
}

impl OpensslChannel {
    pub fn new(stream: SslStream<TcpStream>, raw_fd: RawFd) -> OpensslChannel {
        // create channels
        let (to_remote, from_upper) = calloop::channel::channel();
        let (to_upper, from_remote) = mpsc::channel::<ScMessage>();
        let peer_cert = stream.ssl().peer_certificate().unwrap();

        let _ = thread::spawn(move || {
            let mut event_loop = EventLoop::try_new().unwrap();
            let loop_handle = event_loop.handle();

            // stream
            let remote_src = calloop::generic::Generic::from_fd(
                raw_fd,
                calloop::Interest::READ,
                calloop::Mode::Level,
            );
            loop_handle
                .insert_source(
                    remote_src,
                    move |event, _fd, (closed, stream): &mut (bool, SslStream<TcpStream>)| {
                        if event.error {
                            log::warn!("Secure connection received an error");
                            *closed = true;
                        } else if event.readable {
                            let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];

                            //should be u32 but java requires i32
                            let size = match stream.read_exact(&mut size_buf) {
                                Err(e) => {
                                    if BigEndian::read_i32(&size_buf) <= 0 {
                                        log::debug!("Secure Channel received EOF");
                                    } else {
                                        log::warn!("Cannot read size of data: {}", e);
                                    }
                                    *closed = true;
                                    return Ok(());
                                }

                                Ok(_) => BigEndian::read_i32(&size_buf),
                            };

                            let mut buf = vec![0u8; size as usize];

                            match stream.read_exact(&mut buf) {
                                Ok(_) => {
                                    if to_upper.send(ScMessage::Data(buf)).is_err() {
                                        // upper layer not available anymore, terminate this
                                        *closed = true;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Cannot read data from stream: {}", e);
                                    *closed = true;
                                }
                            }
                        }

                        Ok(())
                    },
                )
                .unwrap();

            // upper channel
            let _ = loop_handle.insert_source(from_upper, move |e, _, (closed, stream)| {
                log::debug!("calloop: send event was triggered");
                match e {
                    Event::Closed => {
                        *closed = true;
                    }
                    Event::Msg(msg) => match msg {
                        ScMessage::Close => {
                            *closed = true;
                        }
                        ScMessage::Data(data) => {
                            let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];
                            //should be u32, but java implementation requires i32
                            BigEndian::write_i32(&mut size_buf, data.len() as i32);
                            log::debug!("writing {} bytes of data: {:?}", data.len(), &data);
                            if stream.write_all(&size_buf).is_err()
                                || stream.write_all(&data).is_err()
                                || stream.flush().is_err()
                            {
                                log::warn!("Cannot write to secure stream");
                                *closed = true;
                            }
                        }
                    },
                }
                log::debug!("calloop: send event is done");
            });

            // listen
            let mut data: (bool, SslStream<TcpStream>) = (false, stream);
            loop {
                event_loop.dispatch(None, &mut data).unwrap();
                if data.0 {
                    log::debug!("Terminating SC while dispatching events");
                    return;
                }
            }
        });

        // return openssl channel
        OpensslChannel {
            to_remote: Mutex::new(to_remote),
            from_remote: Mutex::new(from_remote),
            peer_certificate: peer_cert,
        }
    }
}

impl SecureChannel for OpensslChannel {
    fn send_msg(&self, data: Vec<u8>) -> Result<(), Error> {
        log::debug!("try to get lock to OpenSSL sending half");
        let lock_result = self.to_remote.lock();
        log::debug!("got lock on OpenSSL sending half");
        match lock_result {
            Err(e) => {
                log::error!("Cannot send data via channel: {}", e);
                Err(Error::new(ErrorKind::Other, "Cannot access secure channel"))
            }

            Ok(sender) => match sender.send(ScMessage::Data(data)) {
                Err(_) => {
                    log::error!("could not send data via calloop channel");
                    Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "Connection aborted",
                    ))
                }
                Ok(_) => {
                    log::debug!("sent data via calloop event");
                    Ok(())
                }
            },
        }
    }

    fn recv_msg(&self) -> Result<Vec<u8>, Error> {
        match self.from_remote.lock() {
            Err(_) => Err(Error::new(ErrorKind::Other, "Cannot access secure channel")),

            Ok(rx) => match rx.recv() {
                Err(_) => Err(Error::new(ErrorKind::Other, "Cannot access receiver")),
                Ok(data) => match data {
                    ScMessage::Close => {
                        Err(Error::new(ErrorKind::ConnectionAborted, "Channel closed"))
                    }
                    ScMessage::Data(data) => Ok(data),
                },
            },
        }
    }

    fn terminate(&self) {
        match self.to_remote.lock() {
            Err(e) => {
                log::warn!("Cannot close channel: {}", e);
            }

            Ok(sender) => {
                let _ = sender.send(ScMessage::Close);
            }
        }
    }

    fn get_peer_certificate(&self) -> X509 {
        self.peer_certificate.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::client::OpensslClient;
    use super::server::OpensslServer;
    use super::*;
    use idscp_core::drivers::secure_channel::{SecureChannelClient, SecureChannelServer};
    use log::LevelFilter;
    use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
    use std::net::TcpListener;
    use std::path::PathBuf;

    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    #[ignore]
    #[test]
    fn test_calloop_deadlock() {
        enum TestMsg {
            Number(u32),
            Control(u32),
        }

        let (to_remote, from_upper) = calloop::channel::channel();
        let join_handle = thread::spawn(move || {
            let mut event_loop = EventLoop::try_new().unwrap();
            let loop_handle = event_loop.handle();

            loop_handle
                .insert_source(from_upper, move |e, _, global_close| {
                    println!("calloop: event was triggered");
                    match e {
                        Event::Closed => {
                            println!("calloop close event: calloop channel was closed");
                            *global_close = true;
                        }
                        Event::Msg(msg) => match msg {
                            TestMsg::Number(n) => println!("Number: {}", n),
                            TestMsg::Control(n) => println!("Control: {}", n),
                        },
                    }
                    println!("calloop event is done");
                })
                .unwrap();

            // listen
            let mut global_close = false;
            loop {
                println!("starting dispatch");
                event_loop.dispatch(None, &mut global_close).unwrap();
                if global_close {
                    break;
                }
                println!("dispatch done");
            }
        });

        for i in 1..10 {
            to_remote.send(TestMsg::Number(i)).unwrap();
            to_remote.send(TestMsg::Control(i)).unwrap();
            sleep(Duration::from_millis(1000));
        }
        drop(to_remote);
        join_handle.join().unwrap();
    }

    #[test]
    fn test_tcp_stream() {
        let (server_started_signal_tx, server_started_signal_rx) = mpsc::channel();
        thread::spawn(move || {
            let l = TcpListener::bind("127.0.0.1:8080").unwrap();
            server_started_signal_tx.send(()).unwrap();
            if let Some(Ok(mut stream)) = l.incoming().next() {
                let data = "Hello".as_bytes().to_vec();
                let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];
                //should be u32, but java implementation requires i32
                BigEndian::write_i32(&mut size_buf, data.len() as i32);
                log::debug!("writing {} bytes of data: {:?}", data.len(), &data);
                if stream.write_all(&size_buf).is_err() || stream.write_all(&data).is_err() {
                    log::warn!("Cannot write to secure stream");
                }
            }
        });

        server_started_signal_rx.recv().expect("server terminated?");
        let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];

        //should be u32 but java requires i32
        let size = match stream.read_exact(&mut size_buf) {
            Err(e) => {
                log::warn!("Cannot read size of data: {}", e);
                return;
            }

            Ok(_) => BigEndian::read_i32(&size_buf),
        };

        let mut buf = vec![0u8; size as usize];
        stream.read_exact(&mut buf).unwrap();

        println!("{}, {:?}", size, buf);
    }

    #[test]
    fn test_tls_stream() {
        simple_logging::log_to_stderr(LevelFilter::Debug);
        let (server_started_signal_tx, server_started_signal_rx) = mpsc::channel::<()>();
        let addr = "127.0.0.1:8443";
        let server_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.key"
        ));
        log::debug!("{}", server_key.display());
        let client_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "/test_client.key"
        ));
        log::debug!("{}", client_key.display());
        let server_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.chain"
        ));
        let client_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.chain"
        ));
        let ca_cert = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/{}",
            env!("CARGO_MANIFEST_DIR"),
            "root-ca/certs/rootCA.crt"
        ));
        log::debug!("{}", ca_cert.display());
        let ca_cert_clone = ca_cert.clone();

        let _join_handle = thread::spawn(move || {
            let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor_builder.set_ca_file(ca_cert_clone).unwrap();
            acceptor_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            acceptor_builder
                .set_private_key_file(server_key.as_path(), SslFiletype::PEM)
                .unwrap();
            acceptor_builder
                .set_certificate_chain_file(server_chain.as_path())
                .unwrap();
            acceptor_builder.check_private_key().unwrap();
            let acceptor = Arc::new(acceptor_builder.build());
            let l = TcpListener::bind(addr).unwrap();
            server_started_signal_tx.send(()).unwrap();
            if let Some(Ok(tcp_stream)) = l.incoming().next() {
                let mut tls_stream = acceptor.accept(tcp_stream).unwrap();
                let data = "Hello".as_bytes().to_vec();
                let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];
                //should be u32, but java implementation requires i32
                BigEndian::write_i32(&mut size_buf, data.len() as i32);
                log::debug!("writing {} bytes of data: {:?}", data.len(), &data);
                if tls_stream.write_all(&size_buf).is_err() || tls_stream.write_all(&data).is_err()
                {
                    log::warn!("Cannot write to secure stream");
                }
            }
        });

        let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        connector_builder.set_ca_file(ca_cert).unwrap();
        connector_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        connector_builder
            .set_private_key_file(client_key.as_path(), SslFiletype::PEM)
            .unwrap();
        connector_builder
            .set_certificate_chain_file(client_chain.as_path())
            .unwrap();
        let connector = connector_builder.build();
        server_started_signal_rx.recv().expect("server terminated?");
        let tcp_stream = TcpStream::connect(addr).unwrap();
        let mut tls_stream = connector.connect("idscp-test.de", tcp_stream).unwrap();
        let mut size_buf = [0u8; LENGTH_PREFIX_SIZE];

        //should be u32 but java requires i32
        let size = match tls_stream.read_exact(&mut size_buf) {
            Err(e) => {
                log::warn!("Cannot read size of data: {}", e);
                return;
            }

            Ok(_) => BigEndian::read_i32(&size_buf),
        };

        let mut buf = vec![0u8; size as usize];
        tls_stream.read_exact(&mut buf).unwrap();

        println!("{}, {:?}", size, buf);
    }

    // Use malicious credentials for client which should lead to a panic at acceptor.accept
    #[test]
    fn test_malicious_ca() {
        simple_logging::log_to_stderr(LevelFilter::Debug);
        let (server_started_signal_tx, server_started_signal_rx) = mpsc::channel::<()>();
        let addr = "127.0.0.1:8444";
        let server_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.key"
        ));
        log::debug!("{}", server_key.display());
        let client_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/malicious_ca/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.key"
        ));
        log::debug!("{}", client_key.display());
        let server_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.chain"
        ));
        let client_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/malicious_ca/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.chain"
        ));
        let malicious_ca_cert = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/malicious_ca/{}",
            env!("CARGO_MANIFEST_DIR"),
            "rootCA.crt"
        ));
        let ca_cert = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/{}",
            env!("CARGO_MANIFEST_DIR"),
            "root-ca/certs/rootCA.crt"
        ));
        log::debug!("{}", ca_cert.display());

        let _join_handle = thread::spawn(move || {
            let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor_builder.set_ca_file(ca_cert).unwrap();
            acceptor_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            acceptor_builder
                .set_private_key_file(server_key.as_path(), SslFiletype::PEM)
                .unwrap();
            acceptor_builder
                .set_certificate_chain_file(server_chain.as_path())
                .unwrap();
            acceptor_builder.check_private_key().unwrap();
            let acceptor = Arc::new(acceptor_builder.build());
            let l = TcpListener::bind(addr).unwrap();
            server_started_signal_tx.send(()).unwrap();
            if let Some(Ok(tcp_stream)) = l.incoming().next() {
                match acceptor.accept(tcp_stream) {
                    Ok(_) => panic!("No Error when connecting with malicious certificate chain"),
                    Err(e) => log::debug!("Error {}", e),
                }
            }
        });

        let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        connector_builder.set_ca_file(malicious_ca_cert).unwrap();
        connector_builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        connector_builder
            .set_private_key_file(client_key.as_path(), SslFiletype::PEM)
            .unwrap();
        connector_builder
            .set_certificate_chain_file(client_chain.as_path())
            .unwrap();
        let connector = connector_builder.build();
        server_started_signal_rx.recv().expect("server terminated?");
        let tcp_stream = TcpStream::connect(addr).unwrap();
        match connector.connect("idscp-test.de", tcp_stream) {
            Ok(_) => panic!("No Error when connecting with malicious certificate chain"),
            Err(e) => log::debug!("Error {}", e),
        }
    }

    #[test]
    fn test_secure_channel() {
        simple_logging::log_to_stderr(LevelFilter::Debug);
        let server_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.key"
        ));
        log::debug!("{}", server_key.display());
        let client_key = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "/test_client.key"
        ));
        log::debug!("{}", client_key.display());
        let server_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_server.chain"
        ));
        let client_chain = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/out/{}",
            env!("CARGO_MANIFEST_DIR"),
            "test_client.chain"
        ));
        let ca_cert = PathBuf::from(format!(
            "{}/../test_pki/resources/openssl/{}",
            env!("CARGO_MANIFEST_DIR"),
            "root-ca/certs/rootCA.crt"
        ));

        let addr = OpensslAddr {
            port: 1234,
            hostname: "127.0.0.1".to_string(),
            domain: "idscp-test.de".to_string(),
        };
        let mut server = OpensslServer::new(server_key, server_chain, ca_cert.clone());
        server
            .listen(
                addr.clone(),
                Arc::new(Mutex::new(Box::new(move |sc| {
                    println!("server received new connection");
                    (*sc).send_msg(b"hello".to_vec()).unwrap();
                    let msg = (*sc).recv_msg().unwrap();
                    println!("server received message: {:?}", msg);
                }))),
            )
            .unwrap();

        let client = OpensslClient {
            key_file_path: client_key,
            cert_file_path: client_chain,
            trusted_ca_file_path: ca_cert,
        };

        let mut retry = 3;
        let secure_channel = loop {
            sleep(Duration::from_millis(20));
            match client.connect(&addr) {
                Err(e) => {
                    println!("error while connceting {:?}", e);
                    if retry > 0 {
                        println!("retrying {} more times", retry);
                        retry = -1;
                        continue;
                    } else {
                        panic!("error connecting, no more retrying")
                    }
                }

                Ok(channel) => break channel,
            };
        };
        println!("client connected");
        let msg = secure_channel.recv_msg().unwrap();
        println!("client received msg: {:?}", msg);
        secure_channel.send_msg(b"world".to_vec()).unwrap();
        secure_channel.terminate();
        server.stop();
    }
}
