extern crate core;

use std::convert::TryFrom;
use std::io::{Error, ErrorKind, Write};

use bytes::{Buf, Bytes, BytesMut};
use protobuf::{CodedOutputStream, Message};

use crate::api::idscp2_config::IdscpConfig;
use crate::driver::daps_driver::DapsDriver;
use chunkvec::ChunkVecBuffer;
use fsm_spec::fsm::*;
use messages::{idscp_message_factory as msg_factory, idscpv2_messages::IdscpMessage};

use crate::fsm::FsmError;

pub mod api;
mod chunkvec;
mod driver;
mod fsm;
mod fsm_spec;
mod messages;
pub mod tokio_idscp_connection;

type LengthPrefix = u32;

const LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<LengthPrefix>();

/// The maximum frame size (including length prefix) supported by this implementation
///
/// This number impacts internal buffer sizes and restricts the maximum data message size.
const MAX_FRAME_SIZE: usize = 4096;

pub struct IdscpConnection<'fsm> {
    fsm: Fsm<'fsm, 'fsm>,
    send_queue: Vec<IdscpMessage>,
    read_queue: ChunkVecBuffer<BytesMut>,
    partial_read_len: Option<LengthPrefix>,
    recv_buffer_queue: ChunkVecBuffer<Bytes>,
}

impl<'fsm> IdscpConnection<'fsm> {
    fn push_to_send_buffer(&mut self, msg: IdscpMessage) {
        self.send_queue.push(msg);
    }

    #[inline]
    fn do_action_vec(&mut self, action_vec: Vec<FsmAction>) {
        for action in action_vec {
            self.do_action(action);
        }
    }

    #[inline]
    fn do_action(&mut self, action: FsmAction) {
        match action {
            FsmAction::SecureChannelAction(SecureChannelAction::Message(msg)) => {
                self.push_to_send_buffer(msg);
            }
            FsmAction::NotifyUserData(data) => {
                self.recv_buffer_queue.append(data);
            }
            a => {
                unimplemented!("Tasked to perform {:?}", a);
            }
        }
    }

    pub fn wants_write(&self) -> bool {
        !self.send_queue.is_empty()
    }

    pub fn write(&mut self, out: &mut dyn Write) -> std::io::Result<usize> {
        let mut written = 0usize;

        if !self.send_queue.is_empty() {
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

    /// Consumes the buf and attempts to parse at least one message.
    /// Does not return an error if the message could only be partially parsed, but only if there
    /// is a critical error.
    pub fn read(&mut self, buf: BytesMut) -> std::io::Result<usize> {
        self.read_queue.append(buf);
        self.parse_read_queue(0)
    }

    fn parse_read_queue(&mut self, parsed_bytes: usize) -> std::io::Result<usize> {
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
            match self.process_new_msg(msg) {
                Err(FsmError::UnknownTransition)  //ignore unexpected messages
                | Ok(()) => self.parse_read_queue(LENGTH_PREFIX_SIZE + msg_length),
                Err(FsmError::NotConnected) => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block"))
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "could not decode idscp message",
            ))
        }
    }

    pub fn process_new_msg(&mut self, msg: IdscpMessage) -> Result<(), FsmError> {
        let event = FsmEvent::FromSecureChannel(SecureChannelEvent::Message(msg.message.unwrap()));
        let actions = self.fsm.process_event(event)?;
        self.do_action_vec(actions);
        Ok(())
    }

    pub fn connect(daps_driver: &'fsm mut dyn DapsDriver, config: &'fsm IdscpConfig<'fsm>) -> Self {
        let mut fsm = Fsm::new(daps_driver, config);
        let actions = fsm
            .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
            .unwrap();
        let mut conn = Self {
            fsm,
            send_queue: vec![],
            read_queue: Default::default(),
            recv_buffer_queue: Default::default(),
            partial_read_len: None,
        };
        conn.do_action_vec(actions);

        conn
    }

    pub fn accept(daps_driver: &'fsm mut dyn DapsDriver, config: &'fsm IdscpConfig<'fsm>) -> Self {
        let fsm = Fsm::new(daps_driver, config);
        Self {
            fsm,
            send_queue: vec![],
            read_queue: Default::default(),
            recv_buffer_queue: Default::default(),
            partial_read_len: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.fsm.is_connected()
    }

    pub fn send(&mut self, data: Bytes) -> std::io::Result<usize> {
        // the empty vector would not have worked, since the protobuf-encoded len of data also has
        // variable length that needs to be accounted for
        // no copy here, since data is ref-counted and dropped
        let msg: IdscpMessage = msg_factory::old_create_idscp_data(data.clone()); // create empty package to determine size overhead of protobuf encapsulation
        let frame_size = usize::try_from(msg.compute_size()).unwrap();
        let buffer_space: usize = MAX_FRAME_SIZE;

        // TODO maybe split data here to MAX_FRAME_SIZE
        if frame_size > buffer_space {
            return Err(Error::from(ErrorKind::OutOfMemory));
        }

        let n = data.len();

        match self
            .fsm
            .process_event(FsmEvent::FromUpper(UserEvent::Data(data)))
        {
            Ok(actions) => {
                self.do_action_vec(actions);
                Ok(n)
            }

            Err(FsmError::UnknownTransition) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unknown transition",
            )),

            Err(FsmError::NotConnected) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "would block",
            )),
        }
    }

    pub fn recv(&mut self) -> Option<Bytes> {
        self.recv_buffer_queue.pop()
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

    fn spawn_peers<'a>(daps_driver_1: &'a mut dyn DapsDriver, daps_driver_2: &'a mut dyn DapsDriver) -> std::io::Result<(IdscpConnection<'a>, IdscpConnection<'a>, BytesMut, BytesMut)> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut peer1 = IdscpConnection::connect(daps_driver_1, &TEST_CONFIG);
        let mut peer2 = IdscpConnection::accept(daps_driver_2, &TEST_CONFIG);

        const MTU: usize = 1500; // Maximum Transmission Unit
        let mut channel1_2 = BytesMut::with_capacity(MTU);
        let mut channel2_1 = BytesMut::with_capacity(MTU);

        while peer1.wants_write() || peer2.wants_write() {
            println!("peer1 write");
            while peer1.wants_write() {
                let mut writer = channel1_2.writer();
                peer1.write(&mut writer).unwrap();
                channel1_2 = writer.into_inner();
            }

            println!("peer2 read");
            let mut chunk_start = 0;
            while chunk_start < channel1_2.len() {
                match peer2.read(channel1_2.split_to(channel1_2.len())) {
                    Ok(n) => chunk_start += n,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                    }
                }
            }
            channel1_2.reserve(MTU);

            println!("peer2 write");
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
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                    }
                }
            }
            channel2_1.reserve(MTU);
        }

        return Ok((peer1, peer2, channel1_2, channel2_1));
    }

    #[test]
    fn establish_connection() {
        let mut daps_driver_1 = TestDaps { is_valid: false };
        let mut daps_driver_2 = TestDaps { is_valid: false };
        let (peer1, peer2, channel1_2, _channel2_1) = spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        assert!(peer1.is_connected() && channel1_2.is_empty());
        assert!(peer2.is_connected() && channel1_2.is_empty());
    }

    #[test]
    fn transmit_data() {
        let mut daps_driver_1 = TestDaps { is_valid: false };
        let mut daps_driver_2 = TestDaps { is_valid: false };
        let (mut peer1, mut peer2, mut channel1_2, _channel2_1) = spawn_peers(&mut daps_driver_1, &mut daps_driver_2).unwrap();

        const MSG: &[u8; 11] = b"hello world";

        let n = peer1.send(Bytes::from(MSG.as_slice())).unwrap();
        assert!(n == 11 && peer1.wants_write());
        while peer1.wants_write() {
            let mut writer = channel1_2.writer();
            peer1.write(&mut writer).unwrap();
            channel1_2 = writer.into_inner();
        }

        let data = Bytes::from(b"hello world".as_slice());
        let n = peer1.send(data).unwrap();
        assert!(n == 11 && peer1.wants_write());
        let mut chunk_start = 0;
        while chunk_start < channel1_2.len() {
            match peer2.read(channel1_2.split_to(channel1_2.len())) {
                Ok(n) => chunk_start += n,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                }
            }
        }

        let recv_msg = peer2.recv().unwrap();
        assert_eq!(MSG, recv_msg.deref());
    }
}
