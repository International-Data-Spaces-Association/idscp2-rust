use rustls::NoClientAuth;
use rustls::ServerConfig;
use rustls::ServerSession;
use std::sync::Arc;

struct RustlsSecureChannelServer {
    session: ServerSession,
}

impl RustlsSecureChannelServer {
    pub fn new() -> RustlsSecureChannelServer {
        let config = ServerConfig::new(NoClientAuth::new()); // TODO: DANGER: No client auth!
        let session = ServerSession::new(&Arc::new(config));
        RustlsSecureChannelServer { session }
    }
}

mod tests {
    use super::*;
    use rustls::Session;

    #[test]
    fn client_connect() {
        let config = ServerConfig::new(NoClientAuth::new()); // TODO: DANGER: No client auth!
        let mut server_session = ServerSession::new(&Arc::new(config));

        let mut config = rustls::ClientConfig::default();
        let _dangerous_config = config.dangerous();
        let dns_name = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
        let mut client_session = rustls::ClientSession::new(&Arc::new(config), dns_name);
        let mut buf: Vec<u8> = vec![];
        while client_session.wants_write() {
            let bytes_written = client_session.write_tls(&mut buf).unwrap();
            println!("{} bytes written", bytes_written)
        }
        println!("{:?}", String::from_utf8_lossy(&buf));
        let bytes_read = server_session.read_tls(&mut &buf[..]).unwrap();
        println!("{} bytes read", bytes_read);
    }
}
