use super::IdscpConnection;
use crate::{
    DapsDriver, IdscpConfig, IdscpConnectionError, RaManager, RaProverType, RaVerifierType,
    MAX_FRAME_SIZE,
};
use bytes::{Bytes, BytesMut};
use log::Level::Warn;
use log::{info, log_enabled, trace, warn};
use std::io;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

impl From<IdscpConnectionError> for std::io::Error {
    fn from(e: IdscpConnectionError) -> Self {
        match e {
            IdscpConnectionError::MalformedInput => {
                io::Error::new(ErrorKind::InvalidData, "Malformed input from out_conn")
            }
            IdscpConnectionError::NotReady => {
                io::Error::new(ErrorKind::WouldBlock, "IdscpConnection not ready")
            }
        }
    }
}

pub struct AsyncIdscpListener {
    tcp_listener: TcpListener,
}

impl AsyncIdscpListener {
    pub async fn bind(addr: &'static str) -> std::io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        info!("Binding Listener to {}", addr);
        Ok(AsyncIdscpListener { tcp_listener })
    }

    pub async fn accept<'a>(
        &self,
        daps_driver: &'a mut dyn DapsDriver,
        config: &'a IdscpConfig<'a>,
    ) -> std::io::Result<AsyncIdscpConnection<'a>> {
        let (mut tcp_stream, _) = self.tcp_listener.accept().await.unwrap();
        info!("Accepted incoming TCP connection, initializing connection");
        let mut ra_prover_manager = RaManager::new(
            config.ra_config.prover_registry,
            &config.ra_config.peer_cert,
        );
        let mut ra_verifier_manager = RaManager::new(
            config.ra_config.verifier_registry,
            &config.ra_config.peer_cert,
        );

        let mut connection = IdscpConnection::connect(daps_driver, config);
        info!("{}: Starting handshake", connection.id);
        AsyncIdscpConnection::start_handshake(
            &mut connection,
            &mut ra_verifier_manager,
            &mut ra_prover_manager,
            &mut tcp_stream,
        )
        .await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
            ra_verifier_manager,
            ra_prover_manager,
        })
    }
}

pub struct AsyncIdscpConnection<'fsm> {
    tcp_stream: TcpStream,
    connection: IdscpConnection<'fsm>,
    /// attestation manager launching and communicating with the ra_verifier
    ra_verifier_manager: RaManager<'fsm, RaVerifierType>,
    /// attestation manager launching and communicating with the ra_prover
    ra_prover_manager: RaManager<'fsm, RaProverType>,
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

        let mut ra_prover_manager = RaManager::new(
            config.ra_config.prover_registry,
            &config.ra_config.peer_cert,
        );
        let mut ra_verifier_manager = RaManager::new(
            config.ra_config.verifier_registry,
            &config.ra_config.peer_cert,
        );

        Self::start_handshake(
            &mut connection,
            &mut ra_verifier_manager,
            &mut ra_prover_manager,
            &mut tcp_stream,
        )
        .await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
            ra_prover_manager,
            ra_verifier_manager,
        })
    }

    // TODO unify with recover
    async fn start_handshake<'a>(
        connection: &mut IdscpConnection<'a>,
        ra_verifier_manager: &mut RaManager<'a, RaVerifierType>,
        ra_prover_manager: &mut RaManager<'a, RaProverType>,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        let (mut reader, mut writer) = stream.split();
        let res = Self::recover(
            connection,
            ra_verifier_manager,
            ra_prover_manager,
            &mut reader,
            &mut writer,
        )
        .await;
        if log_enabled!(Warn) {
            if connection.is_ready_to_send() {
                info!(
                    "{}: Connection established, ready to send data.",
                    connection.id
                )
            } else {
                warn!(
                    "{}: Connection established, not ready to send data!",
                    connection.id
                );
            }
        }
        res
    }

    async fn read<'a, R: AsyncReadExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        reader: &mut R,
    ) -> std::io::Result<Result<usize, IdscpConnectionError>> {
        // TODO no nontransparent allocation during read function, maybe replace with arena?
        let mut buf: BytesMut = BytesMut::with_capacity(MAX_FRAME_SIZE);
        reader.read_buf(&mut buf).await?; // initial read "Copy"
                                          // TODO error type
        if buf.is_empty() {
            trace!(
                "{}: read: Read {} bytes from io::Reader, skipping connection",
                connection.id,
                buf.len()
            );
            Ok(Ok(0))
        } else {
            trace!(
                "{}: read: Read {} bytes from io::Reader, passing to connection",
                connection.id,
                buf.len()
            );
            Ok(connection.read_out_conn(buf))
        }
    }

    async fn write<'a, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        writer: &mut W,
    ) -> std::io::Result<()> {
        /* FIXME this is triple-buffered: messages buffered in the connection are written via an
           internal buffer to buf which implements std::io::Write and from there to the actual
           async writer
        */
        let mut buf = Vec::new(); // TODO: use a statically sized array here?
        let _n = connection.write_out_conn(&mut buf)?;
        writer.write_all(&buf).await
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_open()
    }

    async fn recover<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        ra_verifier_manager: &mut RaManager<'a, RaVerifierType>,
        ra_prover_manager: &mut RaManager<'a, RaProverType>,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        loop {
            // check outgoing channels
            while connection.wants_write_out_conn() {
                Self::write(connection, writer).await?;
            }
            while let Some(event) = connection.write_ra_verifier_manager() {
                ra_verifier_manager.process_event(event).unwrap();
            }
            while let Some(event) = connection.write_ra_prover_manager() {
                ra_prover_manager.process_event(event).unwrap();
            }

            // break if ready
            if connection.is_ready_to_send() {
                break;
            }

            // check incoming channels
            /*
            let msg_from_ra_verifier = ra_verifier_manager.recv_msg();
            let msg_from_ra_prover = ra_prover_manager.recv_msg();
            select! {
                _ = Self::read(connection, reader) => {
                    // read completed
                }
                msg = msg_from_ra_verifier.unwrap(), if msg_from_ra_verifier.is_some() =>  {
                    connection.read_ra_verifier_manager(msg).unwrap();
                }
                msg = msg_from_ra_prover.unwrap(), if msg_from_ra_prover.is_some() =>  {
                    connection.read_ra_prover_manager(msg).unwrap();
                }
            };
            */

            // since guards don't seem to allow lazy execution, use this workaround:
            // TODO process result
            match (ra_verifier_manager.recv_msg(), ra_prover_manager.recv_msg()) {
                (Some(msg_from_ra_verifier), Some(msg_from_ra_prover)) => {
                    select! {
                        _ = Self::read(connection, reader) => {
                            // read completed
                        }
                        msg = msg_from_ra_verifier =>  {
                            connection.read_ra_verifier_manager(msg).unwrap();
                        }
                        msg = msg_from_ra_prover =>  {
                            connection.read_ra_prover_manager(msg).unwrap();
                        }
                    };
                }
                (Some(msg_from_ra_verifier), None) => {
                    select! {
                        _ = Self::read(connection, reader) => {
                            // read completed
                        }
                        msg = msg_from_ra_verifier =>  {
                            connection.read_ra_verifier_manager(msg).unwrap();
                        }
                    };
                }
                (None, Some(msg_from_ra_prover)) => {
                    select! {
                        _ = Self::read(connection, reader) => {
                            // read completed
                        }
                        msg = msg_from_ra_prover =>  {
                            connection.read_ra_prover_manager(msg).unwrap();
                        }
                    };
                }
                (None, None) => {
                    Self::read(connection, reader).await?.unwrap(); // TODO
                }
            }
        }
        Ok(())
    }

    #[inline]
    async fn do_send_to<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        ra_verifier_manager: &mut RaManager<'a, RaVerifierType>,
        ra_prover_manager: &mut RaManager<'a, RaProverType>,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        let res = Self::do_try_send_to(
            connection,
            ra_verifier_manager,
            ra_prover_manager,
            reader,
            writer,
            data,
        )
        .await?;
        trace!("{}: send: Recovering", connection.id,);
        Self::recover(
            connection,
            ra_verifier_manager,
            ra_prover_manager,
            reader,
            writer,
        )
        .await?;
        Ok(res)
    }

    /// Sends `data` to the connected peer and awaits acknowledgement.
    /// If `timeout` is supplied, the operation may terminate during operation if the timeout elapses.
    /// In this case, there is no guarantee that the data has been delivered, but the connection
    /// should be able to recover.
    pub async fn send(&mut self, data: Bytes, timeout: Option<Duration>) -> std::io::Result<usize> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        timed_out!(
            timeout,
            Self::do_send_to(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                &mut reader,
                &mut writer,
                data
            )
        )
    }

    #[allow(dead_code)]
    pub(crate) async fn send_to<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
        timeout: Option<Duration>,
    ) -> std::io::Result<usize> {
        timed_out!(
            timeout,
            Self::do_send_to(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                reader,
                writer,
                data
            )
        )
    }

    #[inline]
    async fn do_try_send_to<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        ra_verifier_manager: &mut RaManager<'a, RaVerifierType>,
        ra_prover_manager: &mut RaManager<'a, RaProverType>,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        trace!(
            "{}: send: Sending {} byte of payload.",
            connection.id,
            data.len()
        );
        loop {
            trace!("{}: send: Looping read_in_user", connection.id);
            match connection.read_in_user(data.clone()) {
                Ok(n) => {
                    // anticipative write
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
                    Self::recover(
                        connection,
                        ra_verifier_manager,
                        ra_prover_manager,
                        reader,
                        writer,
                    )
                    .await?;
                }
            }
        }
    }

    /// Sends `data` to the connected peer without awaiting acknowledgement.
    /// If `timeout` is supplied, the operation may terminate during operation if the timeout elapses.
    /// In this case, there is no guarantee that the data has been delivered, but the connection
    /// should be able to recover.
    pub async fn try_send(
        &mut self,
        data: Bytes,
        timeout: Option<Duration>,
    ) -> std::io::Result<usize> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        timed_out!(
            timeout,
            Self::do_try_send_to(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                &mut reader,
                &mut writer,
                data
            )
        )
    }

    #[allow(dead_code)]
    pub(crate) async fn try_send_to<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        data: Bytes,
        timeout: Option<Duration>,
    ) -> std::io::Result<usize> {
        timed_out!(
            timeout,
            Self::do_try_send_to(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                reader,
                writer,
                data
            )
        )
    }

    /*
    #[inline]
    async fn do_try_send_to<'a, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        trace!(
            "{}: try_send: Sending {} byte of payload.",
            connection.id,
            data.len()
        );
        // TODO error-type
        let n = connection
            .read_in_user(data)
            .map_err(|_e| std::io::Error::new(ErrorKind::Other, ""))?;
        Self::write(connection, writer).await?;
        Ok(n)
    }

    pub async fn try_send(&mut self, data: Bytes) -> std::io::Result<usize> {
        Self::do_try_send_to(&mut self.connection, &mut self.tcp_stream, data).await
    }

    pub(crate) async fn try_send_to<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
        data: Bytes,
    ) -> std::io::Result<usize> {
        Self::do_try_send_to(&mut self.connection, writer, data).await
    }
     */

    async fn do_recv_from<'a, R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        connection: &mut IdscpConnection<'a>,
        ra_verifier_manager: &mut RaManager<'a, RaVerifierType>,
        ra_prover_manager: &mut RaManager<'a, RaProverType>,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<Bytes> {
        trace!("{}: recv: Requesting data from connection.", connection.id);
        match connection.write_in_user() {
            Some(msg) => {
                // fast path
                Ok(msg)
            }
            None => {
                // slow path
                trace!(
                    "{}: recv: No cached messages, entering slow path.",
                    connection.id
                );
                let mut res: Option<Bytes> = None;

                /*
                The loop is structured that it first checks all outgoing channels of the
                IdscpConnection for any pending messages that need to be delivered, then reading on
                the underlying socket using Self::read.
                Any read messages are cached in the `res` variable.
                The loop will wrap at least once, such that the outgoing channels can again be
                checked for any acknowledgements resulting of the read operation before attempting
                to return some cached message.
                 */
                loop {
                    // check outgoing channels
                    while connection.wants_write_out_conn() {
                        Self::write(connection, writer).await?;
                    }
                    while let Some(event) = connection.write_ra_verifier_manager() {
                        ra_verifier_manager.process_event(event).unwrap();
                    }
                    while let Some(event) = connection.write_ra_prover_manager() {
                        ra_prover_manager.process_event(event).unwrap();
                    }

                    // loop exit condition only triggered after second loop iteration
                    if let Some(msg) = res {
                        return Ok(msg);
                    }

                    // check incoming channels
                    // since guards don't seem to allow lazy execution, use this workaround:
                    match (ra_verifier_manager.recv_msg(), ra_prover_manager.recv_msg()) {
                        (Some(msg_from_ra_verifier), Some(msg_from_ra_prover)) => {
                            select! {
                                msg = msg_from_ra_verifier =>  {
                                    connection.read_ra_verifier_manager(msg).unwrap();
                                }
                                msg = msg_from_ra_prover =>  {
                                    connection.read_ra_prover_manager(msg).unwrap();
                                }
                                read_res = Self::read(connection, reader) => {
                                    if read_res?? == 0 { // TODO evaluate if fix is correct
                                        res = Some(Bytes::new());
                                    }
                                    if let Some(msg) = connection.write_in_user() {
                                        res = Some(msg);
                                    }
                                }
                            };
                        }
                        (Some(msg_from_ra_verifier), None) => {
                            select! {
                                msg = msg_from_ra_verifier =>  {
                                    connection.read_ra_verifier_manager(msg).unwrap();
                                }
                                read_res = Self::read(connection, reader) => {
                                    if read_res?? == 0 { // TODO evaluate if fix is correct
                                        res = Some(Bytes::new());
                                    }
                                    if let Some(msg) = connection.write_in_user() {
                                        res = Some(msg);
                                    }
                                }
                            };
                        }
                        (None, Some(msg_from_ra_prover)) => {
                            select! {
                                msg = msg_from_ra_prover =>  {
                                    connection.read_ra_prover_manager(msg).unwrap();
                                }
                                read_res = Self::read(connection, reader) => {
                                    if read_res?? == 0 { // TODO evaluate if fix is correct
                                        res = Some(Bytes::new());
                                    }
                                    if let Some(msg) = connection.write_in_user() {
                                        res = Some(msg);
                                    }
                                }
                            };
                        }
                        (None, None) => {
                            let read_res = Self::read(connection, reader).await;
                            if read_res?? == 0 {
                                // TODO evaluate if fix is correct
                                res = Some(Bytes::new());
                            }
                            if let Some(msg) = connection.write_in_user() {
                                res = Some(msg);
                            }
                        }
                    }
                    // end of loop
                }
            }
        }
    }

    /// Receives data from the connected peer and replies with an acknowledgement.
    /// If `timeout` is supplied, the operation may terminate during operation if the timeout elapses.
    /// In this case, there is no guarantee that the data has been delivered, but the connection
    /// should be able to recover.
    pub async fn recv(&mut self, timeout: Option<Duration>) -> std::io::Result<Bytes> {
        let (mut reader, mut writer) = self.tcp_stream.split();
        timed_out!(
            timeout,
            Self::do_recv_from(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                &mut reader,
                &mut writer
            )
        )
    }

    pub async fn recv_from<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        timeout: Option<Duration>,
    ) -> std::io::Result<Bytes> {
        timed_out!(
            timeout,
            Self::do_recv_from(
                &mut self.connection,
                &mut self.ra_verifier_manager,
                &mut self.ra_prover_manager,
                reader,
                writer
            )
        )
    }

    /// Gracefully waits for acknowledgement of all transferred data and issues close message to the
    /// connected peer if one of the following conditions is met:
    /// - all messages have been acknowledged and a close message is sent
    /// - the attestation or dynamic attribute tokens time out
    /// - the channel is externally closed, either by a close message or by protocol violation
    /// - an io::Error occurred
    pub async fn close(self) -> std::io::Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm_spec::fsm_tests::TestDaps;
    use crate::tests::{TEST_CONFIG_ALICE, TEST_CONFIG_BOB};
    use crate::util::test::spawn_listener;
    use crate::{test_begin, test_finalize};
    use bytes::BytesMut;
    use futures::lock::MutexGuard;
    use rand::{thread_rng, Fill};
    use std::ops::Deref;
    use std::thread::sleep;
    use std::time::Duration;
    use tokio_test::assert_ok;

    #[test]
    fn async_establish_connection() {
        test_begin!();
        tokio_test::block_on(async {
            let (listener, _guard, address) = spawn_listener().await;
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut daps_driver = TestDaps::default();
                    let _connection = AsyncIdscpConnection::connect(
                        address,
                        &mut daps_driver,
                        &TEST_CONFIG_ALICE,
                    )
                    .await?;
                    Ok::<(), std::io::Error>(())
                },
                async {
                    let mut daps_driver = TestDaps::default();
                    let _connection = listener.accept(&mut daps_driver, &TEST_CONFIG_BOB).await?;
                    Ok::<(), std::io::Error>(())
                }
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());

            //tokio::spawn(task)tokio::spawn(TcpStream::connect("127.0.0.1:8080"));
        });
        test_finalize!();
    }

    #[test]
    fn async_transmit_data() {
        test_begin!();
        const MSG: &[u8; 4] = &[1, 2, 3, 4];

        tokio_test::block_on(async {
            let (listener, _guard, address) = spawn_listener().await;
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection = AsyncIdscpConnection::connect(
                        address,
                        &mut daps_driver,
                        &TEST_CONFIG_ALICE,
                    )
                    .await?;
                    let n = connection.send(Bytes::from(MSG.as_slice()), None).await?;
                    assert!(n == 4);
                    Ok::<(), std::io::Error>(())
                },
                async {
                    let mut daps_driver = TestDaps::default();
                    let mut connection =
                        listener.accept(&mut daps_driver, &TEST_CONFIG_BOB).await?;
                    let msg = connection.recv(None).await?;
                    assert_eq!(msg.deref(), MSG);
                    Ok::<(), std::io::Error>(())
                }
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());
        });
        test_finalize!();
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
        config_1: &'a IdscpConfig<'a>,
        config_2: &'a IdscpConfig<'a>,
    ) -> (
        AsyncIdscpConnection<'a>,
        AsyncIdscpConnection<'a>,
        MutexGuard<'static, ()>,
    ) {
        let (listener, guard, address) = spawn_listener().await;
        let (connect_result, accept_result) = tokio::join!(
            AsyncIdscpConnection::connect(address, daps_driver_1, config_1),
            listener.accept(daps_driver_2, config_2),
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
                    let msg = peer2.recv(None).await.unwrap(); // TODO right place to unwrap?
                    assert_eq!(msg.len(), chunk_size);
                    let cmp_msg = cmp_data.split_to(chunk_size);
                    assert_eq!(std::convert::AsRef::as_ref(&msg), cmp_msg.as_ref());
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

        Ok(data.is_empty() && cmp_data.is_empty())
    }

    #[test]
    fn test_transfer_size_1000() {
        test_begin!();
        const TRANSMISSION_SIZE: usize = 10000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::default();
            let (mut peer1, mut peer2, _guard) = spawn_connection(
                &mut daps_driver_1,
                &mut daps_driver_2,
                &TEST_CONFIG_ALICE,
                &TEST_CONFIG_BOB,
            )
            .await;
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
        test_finalize!();
    }

    #[test]
    fn test_transfer_dat_expired() {
        test_begin!();
        const TRANSMISSION_SIZE: usize = 20_000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::with_timeout(Duration::from_secs(4));
            let (mut peer1, mut peer2, _guard) = spawn_connection(
                &mut daps_driver_1,
                &mut daps_driver_2,
                &TEST_CONFIG_ALICE,
                &TEST_CONFIG_BOB,
            )
            .await;
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
        test_finalize!();
    }

    /*
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
        test_begin!();
        const TRANSMISSION_SIZE: usize = 200_000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let mut daps_driver_1 = TestDaps::default();
            let mut daps_driver_2 = TestDaps::default();
            let (mut peer1, mut _peer2, _guard) = spawn_connection(
                &mut daps_driver_1,
                &mut daps_driver_2,
                &TEST_CONFIG_ALICE,
                &TEST_CONFIG_BOB,
            )
            .await;
            send(&mut peer1, TRANSMISSION_SIZE, FIXED_CHUNK_SIZE).await
        });

        // This test fails now, since no acknowledgements are received
        assert_err!(res);
        test_finalize!();
    }
     */
}
