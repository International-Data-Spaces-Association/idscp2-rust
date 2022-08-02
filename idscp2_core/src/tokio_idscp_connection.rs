use super::IdscpConnection;
use crate::{DapsDriver, IdscpConfig, IdscpConnectionError, MAX_FRAME_SIZE};
use bytes::{Bytes, BytesMut};
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct AsyncIdscpListener {
    tcp_listener: TcpListener,
}
impl AsyncIdscpListener {
    pub async fn bind(addr: &'static str) -> std::io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(AsyncIdscpListener { tcp_listener })
    }

    pub async fn accept<'a>(
        &self,
        daps_driver: &'a mut dyn DapsDriver,
        config: &'a IdscpConfig<'a>,
    ) -> std::io::Result<AsyncIdscpConnection<'a>> {
        let (mut tcp_stream, _) = self.tcp_listener.accept().await.unwrap();
        let mut connection = IdscpConnection::connect(daps_driver, config);
        AsyncIdscpConnection::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }
}

pub struct AsyncIdscpConnection<'fsm> {
    tcp_stream: TcpStream,
    connection: IdscpConnection<'fsm>,
}

macro_rules! timed_out {
    ($opt_timeout:expr, $future:expr) => {
        if let Some(duration) = $opt_timeout {
            tokio::time::timeout(duration, $future)
                .await
                .unwrap_or_else(|_| {
                    Err(std::io::Error::new(
                        ErrorKind::Interrupted,
                        "action timed out",
                    ))
                })
        } else {
            $future.await
        }
    };
}

impl<'fsm> AsyncIdscpConnection<'fsm> {
    pub async fn connect(
        addr: &'static str,
        daps_driver: &'fsm mut dyn DapsDriver,
        config: &'fsm IdscpConfig<'fsm>,
    ) -> std::io::Result<AsyncIdscpConnection<'fsm>> {
        let mut tcp_stream = TcpStream::connect(addr).await?;
        let mut connection = IdscpConnection::connect(daps_driver, config);

        Self::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }

    async fn start_handshake<'a>(
        connection: &mut IdscpConnection<'a>,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        let (mut reader, mut writer) = stream.split();
        while !connection.is_connected() {
            while connection.wants_write() {
                Self::write(connection, &mut writer).await?;
            }

            // ignore invalid frames here
            // TODO differentiate between unknown frames and undefined traffic
            let _ = Self::read(connection, &mut reader).await?;

            while connection.wants_write() {
                Self::write(connection, &mut writer).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    }

    async fn read<'a, R: AsyncReadExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        reader: &mut R,
    ) -> std::io::Result<Result<usize, IdscpConnectionError>> {
        // TODO no nontransparent allocation during read function, maybe replace with arena?
        let mut buf: BytesMut = BytesMut::with_capacity(MAX_FRAME_SIZE);
        reader.read_buf(&mut buf).await?; // initial read "Copy"
                                          // TODO error type
        Ok(connection.read(buf))
    }

    pub async fn write<'a, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        writer: &mut W,
    ) -> std::io::Result<()> {
        /* FIXME this is triple-buffered: messages buffered in the connection are written via an
           internal buffer to buf which implements std::io::Write and from there to the actual
           async writer
        */
        let mut buf = Vec::new(); // TODO: use a statically sized array here?
        let _n = connection.write(&mut buf)?;
        writer.write_all(&buf).await
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    async fn recover<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // TODO temporary implementation
        while !connection.is_ready_to_send() {
            while connection.wants_write() {
                Self::write(connection, writer).await?;
            }
            match Self::read(connection, reader).await? {
                Ok(_) => {}
                Err(IdscpConnectionError::MalformedInput) => {
                    // TODO differentiate between unknown frame and undefined traffic
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "received invalid messages",
                    ));
                }
                Err(IdscpConnectionError::NotReady) => {
                    // received message frame that should be discarded
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    async fn idle(&mut self) -> std::io::Result<()> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        Self::recover(&mut self.connection, &mut reader, &mut writer).await
    }

    #[inline]
    async fn do_send_to<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        loop {
            match connection.send(data.clone()) {
                Ok(n) => {
                    Self::write(connection, writer).await?;
                    break Ok(n);
                }
                Err(IdscpConnectionError::MalformedInput) => {
                    break Err(std::io::Error::new(
                        ErrorKind::OutOfMemory,
                        "data too large",
                    ));
                }
                Err(IdscpConnectionError::NotReady) => {
                    Self::recover(connection, reader, writer).await?;
                }
            }
        }
    }

    pub async fn send(&mut self, data: Bytes, timeout: Option<Duration>) -> std::io::Result<usize> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        timed_out!(
            timeout,
            Self::do_send_to(&mut self.connection, &mut reader, &mut writer, data)
        )
    }

    pub async fn send_to<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
        timeout: Option<Duration>,
    ) -> std::io::Result<usize> {
        timed_out!(
            timeout,
            Self::do_send_to(&mut self.connection, reader, writer, data)
        )
    }

    #[inline]
    async fn do_try_send_to<'a, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        // TODO error-type
        let n = connection
            .send(data)
            .map_err(|_e| std::io::Error::new(ErrorKind::Other, ""))?;
        Self::write(connection, writer).await?;
        Ok(n)
    }

    pub async fn try_send(&mut self, data: Bytes) -> std::io::Result<usize> {
        Self::do_try_send_to(&mut self.connection, &mut self.tcp_stream, data).await
    }

    pub async fn try_send_to<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        Self::do_try_send_to(&mut self.connection, writer, data).await
    }

    async fn do_recv_from<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<Option<Bytes>> {
        match connection.recv() {
            Some(msg) => Ok(Some(msg)),
            None => {
                loop {
                    // check write first to prevent a deadlock
                    while connection.wants_write() {
                        Self::write(connection, writer).await?;
                    }
                    match Self::read(connection, reader).await? {
                        Ok(_) => {
                            break Ok(connection.recv());
                        }
                        Err(IdscpConnectionError::MalformedInput) => {
                            break Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "received invalid messages",
                            ));
                        }
                        Err(IdscpConnectionError::NotReady) => {}
                    }
                }
            }
        }
    }

    pub async fn recv(&mut self, timeout: Option<Duration>) -> std::io::Result<Option<Bytes>> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        timed_out!(
            timeout,
            Self::do_recv_from(&mut self.connection, &mut reader, &mut writer)
        )
    }

    pub async fn recv_from<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        timeout: Option<Duration>,
    ) -> std::io::Result<Option<Bytes>> {
        timed_out!(
            timeout,
            Self::do_recv_from(&mut self.connection, reader, writer)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::idscp2_config::AttestationConfig;
    use crate::fsm_spec::fsm_tests::TestDaps;
    use crate::util::test::spawn_listener;
    use bytes::BytesMut;
    use futures::lock::MutexGuard;
    use rand::{thread_rng, Fill};
    use std::ops::Deref;
    use std::thread::sleep;
    use std::time::Duration;
    use tokio_test::{assert_err, assert_ok};

    const TEST_RA_CONFIG: AttestationConfig = AttestationConfig {
        supported_provers: vec![],
        supported_verifiers: vec![],
        ra_timeout: Duration::from_secs(20),
    };

    const TEST_CONFIG: IdscpConfig = IdscpConfig {
        resend_timeout: Duration::from_secs(20),
        ra_config: &TEST_RA_CONFIG,
    };

    #[test]
    fn async_establish_connection() {
        let _ = env_logger::builder().is_test(true).try_init();
        tokio_test::block_on(async {
            let (listener, _guard, address) = spawn_listener().await;
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection =
                        AsyncIdscpConnection::connect(address, &mut daps_driver, &TEST_CONFIG)
                            .await?;
                    let data = Bytes::from([1u8, 2, 3, 4].as_slice());
                    let n = connection.send(data, None).await?;
                    assert!(n == 4);
                    Ok::<(), std::io::Error>(())
                },
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection = listener.accept(&mut daps_driver, &TEST_CONFIG).await?;
                    connection.idle().await?;
                    Ok::<(), std::io::Error>(())
                }
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());

            //tokio::spawn(task)tokio::spawn(TcpStream::connect("127.0.0.1:8080"));
            println!("test done");
        });
    }

    #[test]
    fn async_transmit_data() {
        const MSG: &[u8; 4] = &[1, 2, 3, 4];

        let _ = env_logger::builder().is_test(true).try_init();
        tokio_test::block_on(async {
            let (listener, _guard, address) = spawn_listener().await;
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection =
                        AsyncIdscpConnection::connect(address, &mut daps_driver, &TEST_CONFIG)
                            .await?;
                    let n = connection.send(Bytes::from(MSG.as_slice()), None).await?;
                    assert!(n == 4);
                    Ok::<(), std::io::Error>(())
                },
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection = listener
                        .accept(&mut daps_driver, &TEST_CONFIG)
                        .await
                        .unwrap();
                    // sleep(Duration::from_secs(1));
                    let msg = connection.recv(None).await.unwrap().unwrap();
                    assert_eq!(msg.deref(), MSG);
                    Ok::<(), std::io::Error>(())
                }
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());

            println!("test done");
        });
    }

    fn random_data(size: usize) -> Vec<u8> {
        let mut rng = thread_rng();

        let mut data = vec![0u8; size];
        data.try_fill(&mut rng).unwrap();
        data
    }

    async fn spawn_connection<'a>(
        daps_driver_1: &'a mut dyn DapsDriver,
        daps_driver_2: &'a mut dyn DapsDriver,
        config: &'a IdscpConfig<'a>,
    ) -> (
        AsyncIdscpConnection<'a>,
        AsyncIdscpConnection<'a>,
        MutexGuard<'static, ()>,
    ) {
        let (listener, guard, address) = spawn_listener().await;
        let (connect_result, accept_result) = tokio::join!(
            AsyncIdscpConnection::connect(address, daps_driver_1, config),
            listener.accept(daps_driver_2, config),
        );

        assert_ok!(&connect_result);
        assert_ok!(&accept_result);

        (connect_result.unwrap(), accept_result.unwrap(), guard)
    }

    async fn transfer(
        peer1: &mut AsyncIdscpConnection<'_>,
        peer2: &mut AsyncIdscpConnection<'_>,
        transmission_size: usize,
        chunk_size: usize,
        send_delay: Option<Duration>,
    ) -> Result<bool, std::io::Error> {
        let mut data = BytesMut::from(random_data(transmission_size).as_slice());
        let mut cmp_data = data.clone();

        tokio::try_join!(
            async {
                while !cmp_data.is_empty() {
                    let msg = peer2.recv(None).await.unwrap();
                    if let Some(msg) = msg {
                        assert_eq!(msg.len(), chunk_size);
                        let cmp_msg = cmp_data.split_to(chunk_size);
                        assert_eq!(std::convert::AsRef::as_ref(&msg), cmp_msg.as_ref());
                    }
                }
                Ok::<(), std::io::Error>(())
            },
            async {
                while !data.is_empty() {
                    let msg = data.split_to(chunk_size);
                    let n = peer1.send(msg.freeze(), None).await?;
                    if let Some(delay) = send_delay {
                        sleep(delay);
                    }
                    assert!(n == chunk_size);
                }
                Ok::<(), std::io::Error>(())
            },
        )?;

        println!("test done");

        Ok(data.is_empty() && cmp_data.is_empty())
    }

    #[test]
    fn test_transfer_size_1000() {
        const TRANSMISSION_SIZE: usize = 10000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::default();
            let (mut peer1, mut peer2, _guard) =
                spawn_connection(&mut daps_driver_1, &mut daps_driver_2, &TEST_CONFIG).await;
            transfer(
                &mut peer1,
                &mut peer2,
                TRANSMISSION_SIZE,
                FIXED_CHUNK_SIZE,
                None,
            )
            .await
        });

        assert_ok!(res);
        println!("test done");
    }

    #[test]
    fn test_transfer_dat_expired() {
        const TRANSMISSION_SIZE: usize = 20_000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::with_timeout(Duration::from_secs(4));
            let (mut peer1, mut peer2, _guard) =
                spawn_connection(&mut daps_driver_1, &mut daps_driver_2, &TEST_CONFIG).await;
            transfer(
                &mut peer1,
                &mut peer2,
                TRANSMISSION_SIZE,
                FIXED_CHUNK_SIZE,
                Some(Duration::from_millis(100)),
            )
            .await
        });

        assert_ok!(res);
        println!("test done");
    }

    async fn send(
        peer1: &mut AsyncIdscpConnection<'_>,
        transmission_size: usize,
        chunk_size: usize,
    ) -> Result<bool, std::io::Error> {
        let mut data = BytesMut::from(random_data(transmission_size).as_slice());
        let mut sink = tokio::io::sink();

        while !data.is_empty() {
            let msg = data.split_to(chunk_size);
            let n = peer1.try_send_to(&mut sink, msg.freeze()).await?;
            assert_eq!(n, chunk_size);
        }

        Ok(data.is_empty())
    }

    #[test]
    fn test_send_size_1000() {
        const TRANSMISSION_SIZE: usize = 200_000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::default();
            let (mut peer1, mut _peer2, _guard) =
                spawn_connection(&mut daps_driver_1, &mut daps_driver_2, &TEST_CONFIG).await;
            send(&mut peer1, TRANSMISSION_SIZE, FIXED_CHUNK_SIZE).await
        });

        // This test fails now, since no acknowledgements are received
        assert_err!(res);
        println!("test done");
    }
}
