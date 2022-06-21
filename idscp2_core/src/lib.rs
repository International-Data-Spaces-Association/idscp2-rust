extern crate core;

use std::convert::TryFrom;
use std::io::Write;
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use protobuf::{CodedOutputStream, Message};

use crate::api::idscp2_config::IdscpConfig;
use crate::driver::daps_driver::DapsDriver;
use crate::messages::idscpv2_messages::IdscpMessage_oneof_message;
use crate::UserEvent::RequestReattestation;
use chunkvec::ChunkVecBuffer;
use fsm_spec::fsm::*;
use messages::{idscp_message_factory as msg_factory, idscpv2_messages::IdscpMessage};
use thiserror::Error;

pub mod api;
mod chunkvec;
mod driver;
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

#[derive(Error, Debug)]
pub enum IdscpConnectionError {
    // TODO name
    #[error("The input could not be processed")]
    MalformedInput,
    #[error("Action cannot be performed currently, since the connection is in an invalid state")]
    NotReady,
}

pub struct IdscpConnection<'fsm> {
    /// state machine
    fsm: Fsm<'fsm, 'fsm>,
    /// internal buffer of messages to be sent to the connected peer
    send_queue: Vec<IdscpMessage>,
    /// internal buffer of partial bytes  received from the connected peer
    read_queue: ChunkVecBuffer<BytesMut>,
    /// length of the next expected, but partially received frame from the connected peer
    partial_read_len: Option<LengthPrefix>,
    /// internal buffer of payload parsed from the connected peer to be received
    recv_queue: ChunkVecBuffer<Bytes>,

    // Timeouts
    dat_timeout: Option<Instant>,
    ra_timeout: Option<Instant>,
    reset_data_timeout: Option<Instant>,
}

impl<'fsm> IdscpConnection<'fsm> {
    /// Returns a new initialized `IdscpConnection` ready to communicate with another peer
    pub fn connect(daps_driver: &'fsm mut dyn DapsDriver, config: &'fsm IdscpConfig<'fsm>) -> Self {
        let mut fsm = Fsm::new(daps_driver, config);
        let actions = fsm.process_event(FsmEvent::FromUpper(UserEvent::StartHandshake));
        let mut conn = Self {
            fsm,
            send_queue: vec![],
            read_queue: Default::default(),
            recv_queue: Default::default(),
            partial_read_len: None,
            dat_timeout: None,
            ra_timeout: None,
            reset_data_timeout: None,
        };
        conn.do_actions(actions);

        conn
    }

    pub fn is_connected(&self) -> bool {
        self.fsm.is_connected()
    }

    pub fn is_verified(&self) -> bool {
        self.fsm.is_verified()
    }

    pub fn is_ready_to_send(&self) -> bool {
        self.fsm.is_ready_to_send()
    }

    /// Checks internal timeouts and issues all actions required to return the internal state
    /// machine to a state where data can be transferred again.
    fn check_attestation_timeouts(&mut self, now: &Instant) {
        // Note: the order is important, since some timeouts may be cancelled out by other timeouts.
        // unwrap() is called since we expect the fsm to never fail expired timouts, though this may
        // be changed.
        if let Some(timeout) = &self.dat_timeout {
            if timeout < &now {
                self.process_event(FsmEvent::DatExpired);
            }
        }
        if let Some(timeout) = &self.ra_timeout {
            if timeout < &now {
                self.process_event(FsmEvent::FromUpper(RequestReattestation("timeout")));
            }
        }
    }

    fn check_resend_timeout(&mut self, now: &Instant) {
        if let Some(timeout) = &self.reset_data_timeout {
            if timeout < &now {
                self.process_event(FsmEvent::ResendTimout);
            }
        }
    }

    fn process_event(&mut self, event: FsmEvent) {
        let actions = self.fsm.process_event(event);
        self.do_actions(actions);
    }

    #[inline]
    fn do_actions<T: IntoIterator<Item = FsmAction>>(&mut self, action_vec: T) {
        for action in action_vec {
            match action {
                FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => {
                    // push outgoing message to send queue
                    self.send_queue.push(msg);
                }
                FsmAction::NotifyUserData(data) => {
                    self.recv_queue.append(data);
                }
                FsmAction::SetDatTimeout(timeout) => {
                    self.dat_timeout = Some(Instant::now() + timeout);

                    // TODO temporary implementation
                    self.process_event(FsmEvent::FromRaVerifier(RaMessage::Ok(vec![])));
                }
                FsmAction::StopDatTimeout => {
                    self.dat_timeout = None;
                }
                FsmAction::SetRaTimeout(timeout) => {
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
                FsmAction::ToProver(_msg) => {
                    // TODO temporary implementation
                    self.process_event(FsmEvent::FromRaProver(RaMessage::Ok(vec![])));
                }

                a => {
                    unimplemented!("Tasked to perform {:?}", a);
                }
            }
        }
    }

    /// Consumes `buf` and attempts to parse at least one message frame from another peer.
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
    pub fn read(&mut self, buf: BytesMut) -> Result<usize, IdscpConnectionError> {
        self.read_queue.append(buf);
        self.parse_read_queue(0)
    }

    /// Recursively parses and processes messages from the internal read buffer
    fn parse_read_queue(&mut self, parsed_bytes: usize) -> Result<usize, IdscpConnectionError> {
        let msg_length: LengthPrefix = match self.partial_read_len.take() {
            Some(len) => len,
            None => {
                if self.read_queue.len() >= LENGTH_PREFIX_SIZE {
                    self.read_queue.get_u32()
                } else {
                    return Ok(parsed_bytes);
                }
            }
        };

        if self.read_queue.remaining() < msg_length as usize {
            // not enough bytes available to parse message
            self.partial_read_len = Some(msg_length);
            return Ok(parsed_bytes);
        }

        let mut frame = self.read_queue.pop().unwrap();

        // extend frame, can be zero-copy if the original buffer was contiguous
        while frame.len() < msg_length as usize {
            let b = self.read_queue.pop().unwrap();
            frame.unsplit(b);
        }

        // reinsert the remainder to the read queue
        if frame.len() > msg_length as usize {
            let rem = frame.split_off(msg_length as usize);
            self.read_queue.insert_front(rem);
        }

        if let Ok(msg) = IdscpMessage::parse_from_carllerche_bytes(&frame.freeze()) {
            let m = msg.compute_size();
            assert_eq!(m, msg_length);
            let msg_length = usize::try_from(m).unwrap();

            // match if data?
            let msg = match msg.message.unwrap() {
                IdscpMessage_oneof_message::idscpData(data_msg) => {
                    // check timeouts and continue only when ready
                    let now = Instant::now();
                    self.check_attestation_timeouts(&now);
                    if !self.is_verified() {
                        return Err(IdscpConnectionError::NotReady);
                    }
                    IdscpMessage_oneof_message::idscpData(data_msg)
                }
                msg => msg,
            };

            let event = FsmEvent::FromSecureChannel(SecureChannelEvent::Message(msg));

            self.process_event(event);
            self.parse_read_queue(LENGTH_PREFIX_SIZE + msg_length)
        } else {
            Err(IdscpConnectionError::MalformedInput)
        }
    }

    /// Synchronously returns whether the connection has buffered message frames to be sent to
    /// the connected peer.
    pub fn wants_write(&self) -> bool {
        !self.send_queue.is_empty()
    }

    /// Writes the buffered message frames destined to the connected peer to `out`.
    pub fn write(&mut self, out: &mut dyn Write) -> std::io::Result<usize> {
        let mut written = 0usize;

        if self.wants_write() {
            // Workaround: serialize without the wrapper method of IdscpMessage to initialize and
            // use only a single buffer for length delimiters and messages
            let mut os = CodedOutputStream::new(out);

            for msg in self.send_queue.drain(..) {
                let msg_length: u32 = msg.compute_size();
                os.write_raw_bytes(msg_length.to_be_bytes().as_slice())?;
                written += 4;
                msg.check_initialized()?;
                msg.write_to_with_cached_sizes(&mut os)?;
                written += msg_length as usize;
            }
            os.flush()?;
        }
        Ok(written)
    }

    /// Sends `data` to the connected peer.
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
    pub fn send(&mut self, data: Bytes) -> Result<usize, IdscpConnectionError> {
        // the empty vector would not have worked, since the protobuf-encoded len of data also has
        // variable length that needs to be accounted for
        // no copy here, since data is ref-counted and dropped
        let msg: IdscpMessage = msg_factory::create_idscp_data(data.clone(), true); // create empty package to determine size overhead of protobuf encapsulation
        let frame_size = usize::try_from(msg.compute_size()).unwrap();
        let buffer_space: usize = MAX_FRAME_SIZE;

        // TODO maybe split data here to MAX_FRAME_SIZE
        if frame_size > buffer_space {
            return Err(IdscpConnectionError::MalformedInput);
        }

        let n = data.len();

        // check timeouts and continue only when ready
        let now = Instant::now();
        self.check_attestation_timeouts(&now);
        self.check_resend_timeout(&now);
        if !self.is_ready_to_send() {
            return Err(IdscpConnectionError::NotReady);
        }

        self.process_event(FsmEvent::FromUpper(UserEvent::Data(data)));
        Ok(n)
    }

    /// Returns optional data received from the connected peer
    pub fn recv(&mut self) -> Option<Bytes> {
        self.recv_queue.pop()
    }

    pub fn close(&mut self) {
        // TODO consume self?
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::time::Duration;

    use crate::api::idscp2_config::AttestationConfig;
    use bytes::{BufMut, BytesMut};
    use fsm_spec::fsm_tests::TestDaps;

    use super::*;

    const TEST_RA_CONFIG: AttestationConfig = AttestationConfig {
        supported_attestation_suite: vec![],
        expected_attestation_suite: vec![],
        ra_timeout: Duration::from_secs(20),
    };

    const TEST_CONFIG: IdscpConfig = IdscpConfig {
        resend_timeout: Duration::from_secs(20),
        ra_config: &TEST_RA_CONFIG,
    };

    fn spawn_peers<'a>(
        daps_driver_1: &'a mut dyn DapsDriver,
        daps_driver_2: &'a mut dyn DapsDriver,
    ) -> std::io::Result<(IdscpConnection<'a>, IdscpConnection<'a>, BytesMut, BytesMut)> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut peer1 = IdscpConnection::connect(daps_driver_1, &TEST_CONFIG);
        let mut peer2 = IdscpConnection::connect(daps_driver_2, &TEST_CONFIG);

        const MTU: usize = 1500; // Maximum Transmission Unit
        let mut channel1_2 = BytesMut::with_capacity(MTU);
        let mut channel2_1 = BytesMut::with_capacity(MTU);

        while peer1.wants_write() || peer2.wants_write() {
            while peer1.wants_write() {
                let mut writer = channel1_2.writer();
                peer1.write(&mut writer).unwrap();
                channel1_2 = writer.into_inner();
            }

            let mut chunk_start = 0;
            while chunk_start < channel1_2.len() {
                match peer2.read(channel1_2.split_to(channel1_2.len())) {
                    Ok(n) => chunk_start += n,
                    Err(e) => {
                        panic!("{:?}", e)
                    }
                }
            }
            channel1_2.reserve(MTU);

            while peer2.wants_write() {
                let mut writer = channel2_1.writer();
                peer2.write(&mut writer).unwrap();
                channel2_1 = writer.into_inner();
            }

            let mut chunk_start = 0;
            while chunk_start < channel2_1.len() {
                match peer1.read(channel2_1.split_to(channel2_1.len())) {
                    Ok(n) => chunk_start += n,
                    Err(e) => {
                        panic!("{:?}", e)
                    }
                }
            }
            channel2_1.reserve(MTU);
        }

        return Ok((peer1, peer2, channel1_2, channel2_1));
    }

    #[test]
    fn establish_connection() {
        let mut daps_driver_1 = TestDaps::default();
        let mut daps_driver_2 = TestDaps::default();
        let (peer1, peer2, channel1_2, _channel2_1) =
            spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        assert!(peer1.is_connected() && channel1_2.is_empty());
        assert!(peer2.is_connected() && channel1_2.is_empty());
    }

    #[test]
    fn transmit_data() {
        let mut daps_driver_1 = TestDaps::default();
        let mut daps_driver_2 = TestDaps::default();

        // spawn and connect peers
        let (mut peer1, mut peer2, mut channel1_2, mut channel2_1) =
            spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        const MSG: &[u8; 11] = b"hello world";

        // send message from peer1 to peer2
        let n = peer1.send(Bytes::from(MSG.as_slice())).unwrap();
        assert!(n == 11 && peer1.wants_write());
        let mut n = 0;
        while peer1.wants_write() {
            let mut writer = channel1_2.writer();
            n += peer1.write(&mut writer).unwrap();
            channel1_2 = writer.into_inner();
        }
        assert!(n > 0 && n == channel1_2.len());

        // peer2 reads from channel
        let mut chunk_start = 0;
        while chunk_start < channel1_2.len() {
            match peer2.read(channel1_2.split_to(channel1_2.len())) {
                Ok(n) => chunk_start += n,
                Err(e) => {
                    panic!("{:?}", e)
                }
            }
        }

        // receive msg and compare from peer2
        let recv_msg = peer2.recv().unwrap();
        assert_eq!(MSG, recv_msg.deref());

        // peer2 must reply with an ack
        let mut n = 0;
        while peer2.wants_write() {
            let mut writer = channel2_1.writer();
            n += peer2.write(&mut writer).unwrap();
            channel2_1 = writer.into_inner();
        }
        assert!(n > 0 && n == channel2_1.len());

        // peer2 reads from channel
        let mut chunk_start = 0;
        while chunk_start < channel2_1.len() {
            match peer1.read(channel2_1.split_to(channel2_1.len())) {
                Ok(n) => chunk_start += n,
                Err(e) => {
                    panic!("{:?}", e)
                }
            }
        }
    }
}
