extern crate core;

use std::collections::VecDeque;
use std::convert::TryFrom;
use std::io::Write;
use std::marker::PhantomData;
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use log::{error, info, trace, warn};
use protobuf::{CodedOutputStream, Message};

use crate::api::idscp2_config::IdscpConfig;
use crate::driver::daps_driver::DapsDriver;
use crate::driver::ra_driver::{
    RaManager, RaManagerEvent, RaMessage, RaProverType, RaVerifierType,
};
use crate::messages::idscpv2_messages::IdscpMessage_oneof_message;
use crate::UserEvent::RequestReattestation;
use chunkvec::ChunkVecBuffer;
use fsm_spec::fsm::*;
use messages::{idscp_message_factory as msg_factory, idscpv2_messages::IdscpMessage};
use openssl::x509::X509;
use thiserror::Error;

pub mod api;
mod chunkvec;
pub mod driver;
mod fsm_spec;
mod messages;
pub mod tokio_idscp_connection;
mod util;

type LengthPrefix = u32;

const LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<LengthPrefix>();

/// The maximum frame size (including length prefix) supported by this implementation
///
/// This number impacts internal buffer sizes and restricts the maximum data message size.
const MAX_FRAME_SIZE: usize = 4096;

/// A certificate TODO
pub type Certificate = X509;

#[derive(Error, Debug)]
pub enum IdscpConnectionError {
    // TODO name
    #[error("The input could not be processed")]
    MalformedInput,
    #[error("Action cannot be performed currently, since the connection is in an invalid state")]
    NotReady,
}

pub struct IdscpConnection<'fsm> {
    /// debug identifier
    id: &'fsm str,
    /// state machine
    fsm: Fsm<'fsm, 'fsm>,

    // Buffers
    /// buffer of partial bytes received from out_conn
    read_out_conn_queue: ChunkVecBuffer<BytesMut>,
    /// length of the next expected, but partially received frame from out_conn
    read_out_conn_partial_len: Option<LengthPrefix>,
    /// buffer for messages to be sent to out_conn
    write_out_conn_queue: Vec<IdscpMessage>,
    /// buffer of payload parsed from the connected peer destined for the user
    write_in_user_queue: ChunkVecBuffer<Bytes>,
    /// buffer of messages destined for the verifier manager
    write_ra_verifier_queue: VecDeque<RaManagerEvent<RaVerifierType>>, // TODO ArrayDeque?
    /// buffer of messages destined for the prover manager
    write_ra_prover_queue: VecDeque<RaManagerEvent<RaProverType>>,

    // Timeouts
    dat_timeout: Option<Instant>,
    ra_timeout: Option<Instant>,
    reset_data_timeout: Option<Instant>,
}

impl<'fsm> IdscpConnection<'fsm> {
    /// Returns a new initialized `IdscpConnection` ready to communicate with another peer
    pub fn connect(daps_driver: &'fsm mut dyn DapsDriver, config: &'fsm IdscpConfig<'fsm>) -> Self {
        let fsm = Fsm::new(daps_driver, config);
        let mut conn = Self {
            id: config.id,
            fsm,
            read_out_conn_queue: Default::default(),
            read_out_conn_partial_len: None,
            write_out_conn_queue: vec![],
            write_in_user_queue: Default::default(),
            write_ra_verifier_queue: Default::default(),
            write_ra_prover_queue: Default::default(),
            dat_timeout: None,
            ra_timeout: None,
            reset_data_timeout: None,
        };
        conn.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
        info!("{}: Created connection", conn.id);

        conn
    }

    /*
    pub fn check_drivers(&mut self) {
        while let Some(msg) = self.ra_verifier_manager.recv_msg() {
            self.process_event(FsmEvent::FromRaVerifier(msg));
        }
        while let Some(msg) = self.ra_prover_manager.recv_msg() {
            self.process_event(FsmEvent::FromRaProver(msg));
        }
    }
    */

    /// Returns `true`, if the connection is in an active communication with another peer, i.e.,
    /// initialized and not closed.
    pub fn is_open(&self) -> bool {
        self.fsm.is_open()
    }

    // TODO naming partially <> fully

    /// Returns `true`, if the connection is connected and attestation of the connected peer has
    /// been completed and not timed out.
    ///
    /// If true, incoming data from the connected peer can be trusted, but no data can be sent due
    /// to the missing attestation of this peer to the connected peer.
    pub fn is_partially_attested(&self) -> bool {
        self.fsm.is_partially_attested()
    }

    /// Returns `true`, if the connection is connected and attestation of both peers to each other
    /// has been completed and not timed out.
    ///
    /// If true, data can be both received and queued for sending. Sending may not succeed due to
    /// the connection being blocked. See [IdscpConnection::is_ready_to_send](IdscpConnection::is_ready_to_send).
    pub fn is_fully_attested(&self) -> bool {
        self.fsm.is_fully_attested()
    }

    /// Returns `true`, if the connection is connected, attested, and available for sending data.
    /// This may not be the case, if previously sent data has not been acknowledged by the connected
    /// peer.
    pub fn is_ready_to_send(&self) -> bool {
        self.fsm.is_ready_to_send()
    }

    /// Checks internal attestation timeouts and issues all actions required to return the internal
    /// state machine to a state where data can be transferred again.
    fn check_attestation_timeouts(&mut self, now: &Instant) {
        // Note: the order is important, since some timeouts may be cancelled out by other timeouts.
        // unwrap() is called since we expect the fsm to never fail expired timouts, though this may
        // be changed.
        if let Some(timeout) = &self.dat_timeout {
            if timeout < now {
                trace!("{}: check_attestation_timeouts: DAT timed out.", self.id);
                self.process_event(FsmEvent::DatExpired);
            }
        }
        if let Some(timeout) = &self.ra_timeout {
            if timeout < now {
                trace!("{}: check_attestation_timeouts: DAT timed out.", self.id);
                self.process_event(FsmEvent::FromUpper(RequestReattestation("timeout")));
            }
        }
    }

    /// Checks internal resend timeout and issues all actions required to return the internal
    /// state machine to a state where data can be transferred again.
    fn check_resend_timeout(&mut self, now: &Instant) {
        if let Some(timeout) = &self.reset_data_timeout {
            if timeout < now {
                self.process_event(FsmEvent::ResendTimout);
            }
        }
    }

    /// Passes an event to the internal state machine and executes all actions commanded by the
    /// state machine.
    fn process_event(&mut self, event: FsmEvent) {
        let actions = self.fsm.process_event(event);

        for action in actions {
            match action {
                // Outgoing messages
                FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => {
                    trace!(
                        "{}: FsmAction SecureChannel: Pushing message to send queue",
                        self.id
                    );
                    self.write_out_conn_queue.push(msg);
                }
                FsmAction::NotifyUserData(data) => {
                    trace!(
                        "{}: FsmAction NotifyUserData: Pushing message to receive queue",
                        self.id
                    );
                    self.write_in_user_queue.append(data);
                }

                // Timeouts
                FsmAction::SetDatTimeout(timeout) => {
                    trace!(
                        "{}: FsmAction SetDatTimeout: Set timeout to {}s",
                        self.id,
                        timeout.as_secs()
                    );
                    self.dat_timeout = Some(Instant::now() + timeout);
                }
                FsmAction::StopDatTimeout => {
                    self.dat_timeout = None;
                }
                FsmAction::SetRaTimeout(timeout) => {
                    trace!(
                        "{}: FsmAction SetRaTimeout: Set timeout to {}s",
                        self.id,
                        timeout.as_secs()
                    );
                    self.ra_timeout = Some(Instant::now() + timeout);
                }
                FsmAction::StopRaTimeout => {
                    self.ra_timeout = None;
                }
                FsmAction::SetResendDataTimeout(timeout) => {
                    self.reset_data_timeout = Some(Instant::now() + timeout);
                }
                FsmAction::StopResendDataTimeout => {
                    self.reset_data_timeout = None;
                }

                // Prover/Verifier communication
                // TODO error management
                FsmAction::StartVerifier(id) => {
                    trace!(
                        "{}: FsmAction StartVerifier: Starting selected Verifier {}",
                        self.id,
                        id
                    );
                    self.write_ra_verifier_queue
                        .push_back(RaManagerEvent::SelectDriver(id));
                    self.write_ra_verifier_queue
                        .push_back(RaManagerEvent::RunDriver);
                }
                FsmAction::StartProver(id) => {
                    trace!(
                        "{}: FsmAction StartProver: Starting selected Prover {}",
                        self.id,
                        id
                    );
                    self.write_ra_prover_queue
                        .push_back(RaManagerEvent::SelectDriver(id));
                    self.write_ra_prover_queue
                        .push_back(RaManagerEvent::RunDriver);
                }
                FsmAction::RestartVerifier => {
                    trace!("{}: FsmAction RestartVerifier", self.id);
                    self.write_ra_verifier_queue
                        .push_back(RaManagerEvent::RunDriver);
                }
                FsmAction::RestartProver => {
                    trace!("{}: FsmAction RestartProver", self.id);
                    self.write_ra_prover_queue
                        .push_back(RaManagerEvent::RunDriver);
                }
                FsmAction::ToVerifier(msg) => {
                    trace!("{}: FsmAction ToVerifier", self.id);
                    self.write_ra_verifier_queue
                        .push_back(RaManagerEvent::RawData(msg, PhantomData));
                }
                FsmAction::ToProver(msg) => {
                    trace!("{}: FsmAction ToProver", self.id);
                    self.write_ra_prover_queue
                        .push_back(RaManagerEvent::RawData(msg, PhantomData));
                }

                FsmAction::None => {
                    #[cfg(debug_assertions)]
                    unimplemented!("Tasked to perform FsmAction::None");
                }
            }
        }
    }

    /// Consumes `buf` and attempts to parse at least one message frame from out_conn.
    /// Remaining bytes belonging to partial message frames are cached and parsed in a future call to `read`.
    /// This function checks potential channel timeouts during processing.
    ///
    /// # Return
    ///
    /// The number of bytes parsed in total.
    /// This may include bytes parsed from previous calls to `read`.
    ///
    /// # Errors
    ///
    /// If this function encounters an error during parsing, an [`IdscpConnectionError::MalformedInput`] error is returned.
    /// If the state of the secure channel can no longer be trusted and messages received,
    ///
    pub fn read_out_conn(&mut self, buf: BytesMut) -> Result<usize, IdscpConnectionError> {
        trace!(
            "{}: read_out_conn: Appending {} byte to read_out_queue",
            self.id,
            buf.len()
        );
        self.read_out_conn_queue.append(buf);
        self.parse_read_out_queue(0)
    }

    /// Recursively parses and processes messages from the internal read buffer
    fn parse_read_out_queue(&mut self, parsed_bytes: usize) -> Result<usize, IdscpConnectionError> {
        let msg_length: LengthPrefix = match self.read_out_conn_partial_len.take() {
            Some(len) => len,
            None => {
                if self.read_out_conn_queue.len() >= LENGTH_PREFIX_SIZE {
                    self.read_out_conn_queue.get_u32()
                } else {
                    return Ok(parsed_bytes);
                }
            }
        };

        if self.read_out_conn_queue.remaining() < msg_length as usize {
            // not enough bytes available to parse message
            self.read_out_conn_partial_len = Some(msg_length);
            return Ok(parsed_bytes);
        }

        let mut frame = self.read_out_conn_queue.pop().unwrap();

        // extend frame, can be zero-copy if the original buffer was contiguous
        while frame.len() < msg_length as usize {
            let b = self.read_out_conn_queue.pop().unwrap();
            frame.unsplit(b);
        }

        // reinsert the remainder to the read queue
        if frame.len() > msg_length as usize {
            let rem = frame.split_off(msg_length as usize);
            self.read_out_conn_queue.insert_front(rem);
        }

        if let Ok(msg) = IdscpMessage::parse_from_carllerche_bytes(&frame.freeze()) {
            let m = msg.compute_size();
            assert_eq!(m, msg_length);
            let msg_len = usize::try_from(m).unwrap();

            // match if data?
            let msg = match msg.message.unwrap() {
                IdscpMessage_oneof_message::idscpData(data_msg) => {
                    trace!(
                        "{}: read_out_conn: Parsed {} byte data message with {} byte payload",
                        self.id,
                        msg_len,
                        data_msg.data.len()
                    );
                    // check timeouts and continue only when ready
                    let now = Instant::now();
                    self.check_attestation_timeouts(&now);
                    if !self.is_partially_attested() {
                        warn!(
                            "{}: read_out_conn: Connection not partially attested, discarding data",
                            self.id
                        );
                        return Err(IdscpConnectionError::NotReady);
                    }
                    IdscpMessage_oneof_message::idscpData(data_msg)
                }
                msg => {
                    trace!(
                        "{}: read_out_conn: Parsed {} byte non-data message",
                        self.id,
                        msg_len
                    );
                    msg
                }
            };

            let event = FsmEvent::FromSecureChannel(SecureChannelEvent::Message(msg));

            self.process_event(event);
            self.parse_read_out_queue(LENGTH_PREFIX_SIZE + msg_len)
        } else {
            Err(IdscpConnectionError::MalformedInput)
        }
    }

    /// Synchronously returns whether the connection has buffered message frames to be sent to
    /// the connected peer.
    pub fn wants_write_out_conn(&self) -> bool {
        !self.write_out_conn_queue.is_empty()
    }

    /// Writes the buffered message frames destined to the connected peer to `out`.
    pub fn write_out_conn(&mut self, out: &mut dyn Write) -> std::io::Result<usize> {
        let mut written = 0usize;

        if self.wants_write_out_conn() {
            // Workaround: serialize without the wrapper method of IdscpMessage to initialize and
            // use only a single buffer for length delimiters and messages
            let mut os = CodedOutputStream::new(out);

            for msg in self.write_out_conn_queue.drain(..) {
                let msg_length: u32 = msg.compute_size();
                os.write_raw_bytes(msg_length.to_be_bytes().as_slice())?;
                written += 4;
                msg.check_initialized()?;
                msg.write_to_with_cached_sizes(&mut os)?;
                written += msg_length as usize;
            }
            os.flush()?;
        }
        trace!(
            "{}: write_out_conn: Write {} byte to out_conn",
            self.id,
            written
        );
        Ok(written)
    }

    /// Reads data from in_user destined to out_conn.
    /// This function checks potential channel timeouts during processing.
    ///
    /// # Return
    ///
    /// The number of bytes to be sent in total.
    /// This includes message frame headers.
    ///
    /// # Errors
    ///
    /// If `data` is too large to be sent, an [`IdscpConnectionError::MalformedInput`] error is returned.
    /// Returns [`IdscpConnectionError::NotReady`], if the state of the secure channel can no longer be trusted and messages not sent.
    ///
    pub fn read_in_user(&mut self, data: Bytes) -> Result<usize, IdscpConnectionError> {
        // the empty vector would not have worked, since the protobuf-encoded len of data also has
        // variable length that needs to be accounted for
        // no copy here, since data is ref-counted and dropped
        let msg: IdscpMessage = msg_factory::create_idscp_data(data.clone(), true); // create empty package to determine size overhead of protobuf encapsulation
        let frame_size = usize::try_from(msg.compute_size()).unwrap();
        let buffer_space: usize = MAX_FRAME_SIZE;

        // TODO maybe split data here to MAX_FRAME_SIZE
        if frame_size > buffer_space {
            error!("{}: read_in_user: Malformed input by in_user", self.id);
            return Err(IdscpConnectionError::MalformedInput);
        }

        let n = data.len();

        // check timeouts and continue only when ready
        let now = Instant::now();
        warn!("{}: attested {}", self.id, self.is_fully_attested());
        self.check_attestation_timeouts(&now);
        if !self.is_fully_attested() {
            warn!(
                "{}: read_in_user: Connection not attested, discarding data",
                self.id
            );
            return Err(IdscpConnectionError::NotReady);
        }
        self.check_resend_timeout(&now);
        if !self.is_ready_to_send() {
            warn!(
                "{}: read_in_user: Connection attested, but not ready to send, discarding data",
                self.id
            );
            return Err(IdscpConnectionError::NotReady);
        }

        trace!("{}: read_in_user: Parsing {} byte data", self.id, n);
        self.process_event(FsmEvent::FromUpper(UserEvent::Data(data)));
        Ok(n)
    }

    /// Returns optional data received from the out_conn
    pub fn write_in_user(&mut self) -> Option<Bytes> {
        trace!(
            "{}: write_in_user: Returning message: {}",
            self.id,
            !self.write_in_user_queue.is_empty()
        );
        self.write_in_user_queue.pop()
    }

    /// Reads a message from the verifier
    pub fn read_ra_verifier_manager(
        &mut self,
        msg: RaMessage<RaVerifierType>,
    ) -> Result<(), IdscpConnectionError> {
        trace!("{}: read_ra_verifier_manager: Reading message", self.id);
        self.process_event(FsmEvent::FromRaVerifier(msg));
        Ok(())
    }

    pub fn wants_write_ra_verifier_manager(&self) -> bool {
        !self.write_ra_verifier_queue.is_empty()
    }

    /// Returns instructions for the verifier manager
    pub fn write_ra_verifier_manager(&mut self) -> Option<RaManagerEvent<RaVerifierType>> {
        trace!(
            "{}: write_ra_verifier_manager: Returning event: {}",
            self.id,
            !self.write_ra_verifier_queue.is_empty()
        );
        self.write_ra_verifier_queue.pop_front()
    }

    /// Reads a message from the prover
    pub fn read_ra_prover_manager(
        &mut self,
        msg: RaMessage<RaProverType>,
    ) -> Result<(), IdscpConnectionError> {
        trace!("{}: read_ra_prover_manager: Reading message", self.id);
        self.process_event(FsmEvent::FromRaProver(msg));
        Ok(())
    }

    pub fn wants_write_ra_prover_manager(&self) -> bool {
        !self.write_ra_prover_queue.is_empty()
    }

    /// Returns instructions for the prover manager
    pub fn write_ra_prover_manager(&mut self) -> Option<RaManagerEvent<RaProverType>> {
        trace!(
            "{}: write_ra_prover_manager: Returning event: {}",
            self.id,
            !self.write_ra_prover_queue.is_empty()
        );
        self.write_ra_prover_queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::api::idscp2_config::AttestationConfig;
    use crate::driver::ra_driver::tests::{
        get_test_cert, TestProver, TestProverNeverDone, TestVerifier, TEST_PROVER_ID,
        TEST_VERIFIER_ID,
    };
    use crate::driver::ra_driver::{RaProverType, RaRegistry, RaVerifierType};
    use bytes::{BufMut, BytesMut};
    use fsm_spec::fsm_tests::TestDaps;
    use lazy_static::lazy_static;

    #[macro_export]
    macro_rules! test_begin {
        () => {
            let _ = env_logger::builder().is_test(true).try_init();
            println!("Test started.");
        };
    }

    #[macro_export]
    macro_rules! test_finalize {
        () => {
            println!("Test done.")
        };
    }

    use super::*;

    lazy_static! {
        pub(crate) static ref TEST_RA_VERIFIER_REGISTRY: RaRegistry<RaVerifierType> = {
            let mut registry = RaRegistry::new();
            let _ = registry.register_driver(Arc::new(TestVerifier {}));
            registry
        };
        pub(crate) static ref TEST_RA_PROVER_REGISTRY: RaRegistry<RaProverType> = {
            let mut registry = RaRegistry::new();
            let _ = registry.register_driver(Arc::new(TestProver {}));
            registry
        };
        pub(crate) static ref TEST_RA_PROVER_NEVER_DONE_REGISTRY: RaRegistry<RaProverType> = {
            let mut registry = RaRegistry::new();
            let _ = registry.register_driver(Arc::new(TestProverNeverDone {}));
            registry
        };
        pub(crate) static ref TEST_RA_CONFIG: AttestationConfig<'static> = AttestationConfig {
            supported_provers: vec![TEST_PROVER_ID],
            expected_verifiers: vec![TEST_VERIFIER_ID],
            prover_registry: &TEST_RA_PROVER_REGISTRY,
            ra_timeout: Duration::from_secs(20),
            verifier_registry: &TEST_RA_VERIFIER_REGISTRY,
            peer_cert: get_test_cert(),
        };
        pub(crate) static ref TEST_RA_PROVER_NEVER_DONE_CONFIG: AttestationConfig<'static> =
            AttestationConfig {
                supported_provers: vec![TEST_PROVER_ID],
                expected_verifiers: vec![TEST_VERIFIER_ID],
                prover_registry: &TEST_RA_PROVER_NEVER_DONE_REGISTRY,
                ra_timeout: Duration::from_secs(20),
                verifier_registry: &TEST_RA_VERIFIER_REGISTRY,
                peer_cert: get_test_cert(),
            };
        pub(crate) static ref TEST_CONFIG_ALICE: IdscpConfig<'static> = IdscpConfig {
            id: "alice",
            resend_timeout: Duration::from_secs(1),
            ra_config: &TEST_RA_CONFIG,
        };
        pub(crate) static ref TEST_CONFIG_BOB: IdscpConfig<'static> = IdscpConfig {
            id: "bob",
            resend_timeout: Duration::from_secs(1),
            ra_config: &TEST_RA_CONFIG,
        };
        pub(crate) static ref TEST_PROVER_NEVER_DONE_CONFIG_BOB: IdscpConfig<'static> =
            IdscpConfig {
                id: "bob",
                resend_timeout: Duration::from_secs(1),
                ra_config: &TEST_RA_PROVER_NEVER_DONE_CONFIG,
            };
    }

    pub(crate) struct IdscpConnectionHandle<'a> {
        connection: IdscpConnection<'a>,
        out_conn_channel: BytesMut,
    }

    fn read_channel(peer2: &mut IdscpConnection, in_channel: &mut BytesMut) {
        let mut chunk_start = 0;
        while chunk_start < in_channel.len() {
            match peer2.read_out_conn(in_channel.split_to(in_channel.len())) {
                Ok(n) => chunk_start += n,
                Err(e) => {
                    panic!("{:?}", e)
                }
            }
        }
    }

    fn emulate_ra_manager<T>(event: RaManagerEvent<T>) -> Option<RaMessage<T>> {
        match event {
            RaManagerEvent::RunDriver => Some(RaMessage::Ok(Bytes::from(""))),
            _ => None,
        }
    }

    fn spawn_peers<'a>(
        daps_driver_1: &'a mut dyn DapsDriver,
        daps_driver_2: &'a mut dyn DapsDriver,
    ) -> std::io::Result<(IdscpConnectionHandle<'a>, IdscpConnectionHandle<'a>)> {
        let mut connection_1 = IdscpConnection::connect(daps_driver_1, &TEST_CONFIG_ALICE);
        let mut connection_2 = IdscpConnection::connect(daps_driver_2, &TEST_CONFIG_BOB);

        const MTU: usize = 1500; // Maximum Transmission Unit
        let mut channel_1_2 = BytesMut::with_capacity(MTU);
        let mut channel_2_1 = BytesMut::with_capacity(MTU);

        while !connection_1.is_ready_to_send() || !connection_2.is_ready_to_send() {
            while connection_1.wants_write_out_conn() {
                let mut writer = channel_1_2.writer();
                connection_1.write_out_conn(&mut writer).unwrap();
                channel_1_2 = writer.into_inner();
            }
            while let Some(event) = connection_1.write_ra_verifier_manager() {
                if let Some(msg) = emulate_ra_manager(event) {
                    connection_1.read_ra_verifier_manager(msg).unwrap();
                }
            }
            while let Some(event) = connection_1.write_ra_prover_manager() {
                if let Some(msg) = emulate_ra_manager(event) {
                    connection_1.read_ra_prover_manager(msg).unwrap();
                }
            }

            read_channel(&mut connection_2, &mut channel_1_2);
            channel_2_1.reserve(MTU);

            while connection_2.wants_write_out_conn() {
                let mut writer = channel_2_1.writer();
                connection_2.write_out_conn(&mut writer).unwrap();
                channel_2_1 = writer.into_inner();
            }
            while let Some(event) = connection_2.write_ra_verifier_manager() {
                if let Some(msg) = emulate_ra_manager(event) {
                    connection_2.read_ra_verifier_manager(msg).unwrap();
                }
            }
            while let Some(event) = connection_2.write_ra_prover_manager() {
                if let Some(msg) = emulate_ra_manager(event) {
                    connection_2.read_ra_prover_manager(msg).unwrap();
                }
            }

            read_channel(&mut connection_1, &mut channel_2_1);
            channel_2_1.reserve(MTU);
        }

        Ok((
            IdscpConnectionHandle {
                connection: connection_1,
                out_conn_channel: channel_1_2,
            },
            IdscpConnectionHandle {
                connection: connection_2,
                out_conn_channel: channel_2_1,
            },
        ))
    }

    #[test]
    fn establish_connection() {
        test_begin!();
        let mut daps_driver_1 = TestDaps::default();
        let mut daps_driver_2 = TestDaps::default();
        let (peer1, peer2) = spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        assert!(peer1.connection.is_ready_to_send() && peer1.out_conn_channel.is_empty());
        assert!(peer2.connection.is_ready_to_send() && peer2.out_conn_channel.is_empty());
        test_finalize!();
    }

    #[test]
    fn transmit_data() {
        test_begin!();
        let mut daps_driver_1 = TestDaps::default();
        let mut daps_driver_2 = TestDaps::default();
        let (mut peer1, mut peer2) = spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        const MSG: &[u8; 11] = b"hello world";

        // send message from peer1 to peer2
        let n = peer1
            .connection
            .read_in_user(Bytes::from(MSG.as_slice()))
            .unwrap();
        assert!(n == 11 && peer1.connection.wants_write_out_conn());
        let mut n = 0;
        while peer1.connection.wants_write_out_conn() {
            let mut writer = peer1.out_conn_channel.writer();
            n += peer1.connection.write_out_conn(&mut writer).unwrap();
            peer1.out_conn_channel = writer.into_inner();
        }
        assert!(n > 0 && n == peer1.out_conn_channel.len());

        // peer2 reads from channel
        read_channel(&mut peer2.connection, &mut peer1.out_conn_channel);

        // receive msg and compare from peer2
        let recv_msg = peer2.connection.write_in_user().unwrap();
        assert_eq!(MSG, recv_msg.deref());

        // peer2 must reply with an ack
        let mut n = 0;
        while peer2.connection.wants_write_out_conn() {
            let mut writer = peer2.out_conn_channel.writer();
            n += peer2.connection.write_out_conn(&mut writer).unwrap();
            peer2.out_conn_channel = writer.into_inner();
        }
        assert!(n > 0 && n == peer2.out_conn_channel.len());

        // peer2 reads from channel
        read_channel(&mut peer1.connection, &mut peer2.out_conn_channel);

        test_finalize!();
    }
}
