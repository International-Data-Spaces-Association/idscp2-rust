mod chunkvec;
mod fsm;
mod messages;
mod tokio_idscp_connection;

use chunkvec::ChunkVecBuffer;
use fsm::*;
use futures::AsyncWrite;
use messages::{
    idscp_message_factory::{self as msg_factory, create_idscp_data},
    idscpv2_messages::IdscpMessage,
    idscpv2_messages::IdscpMessage_oneof_message,
};
use protobuf::Message;
use std::io::Write;
use std::{convert::TryFrom, task::Poll};

pub struct IDSCPConnection {
    fsm: FSM,
    send_buffer_queue: ChunkVecBuffer,
}

impl IDSCPConnection {
    fn push_to_send_buffer(&mut self, msg: IdscpMessage) {
        //TODO: optimize this to not create the "raw" buffer but to write directly to the end of the send_buffer

        let mut raw = Vec::new();
        msg.write_to_vec(&mut raw).unwrap();
        self.send_buffer_queue.append(raw);
    }

    fn do_action(&mut self, action: FsmAction) {
        match action {
            FsmAction::SecureChannelAction(SecureChannelEvent::Hello(name)) => {
                let msg = msg_factory::create_idscp_hello(
                    vec![],
                    &["hello".to_string()],
                    &["world".to_string()],
                );
                self.push_to_send_buffer(msg)
            }

            FsmAction::SecureChannelAction(SecureChannelEvent::Data(data)) => {
                let msg = msg_factory::create_idscp_data(data);
                self.push_to_send_buffer(msg)
            }

            _ => unimplemented!(),
        }
    }

    pub fn wants_write(&self) -> bool {
        !self.send_buffer_queue.is_empty()
    }

    pub fn write(&mut self, mut out: &mut [u8]) -> std::io::Result<usize> {
        self.send_buffer_queue.write_to(&mut out)
    }

    pub fn read(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(msg) = IdscpMessage::parse_from_bytes(buf) {
            let m = msg.compute_size();
            let n = usize::try_from(m).unwrap();
            match self.process_new_msg(msg) {
                Err(FsmError::UnknownTransition)  //ignore unexpected messages
                | Ok(()) => Ok(n),

                Err(FsmError::NotConnected)=> Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block"))
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "could not decode idscp message",
            ))
        }
    }

    pub fn process_new_msg(&mut self, msg: IdscpMessage) -> Result<(), FsmError> {
        let event = match msg.message {
            None => panic!(),

            Some(IdscpMessage_oneof_message::idscpHello(idscp_hello)) => {
                FsmEvent::FromSecureChannel(SecureChannelEvent::Hello("bla".to_string()))
            }

            _ => unimplemented!(),
        };
        if let Some(action) = self.fsm.process_event(event)? {
            self.do_action(action)
        }

        Ok(())
    }

    pub fn connect(config: String) -> IDSCPConnection {
        let mut fsm = FSM::new(config);
        let action = fsm
            .process_event(FsmEvent::FromUpper(UserEvent::StartHandshake))
            .unwrap()
            .expect("wrong fsm implementation?");
        let mut conn = IDSCPConnection {
            fsm: fsm,
            send_buffer_queue: ChunkVecBuffer::new(),
        };
        conn.do_action(action);

        conn
    }

    pub fn accept(config: String) -> IDSCPConnection {
        let mut fsm = FSM::new(config);
        IDSCPConnection {
            fsm: fsm,
            send_buffer_queue: ChunkVecBuffer::new(),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.fsm.is_connected()
    }

    pub fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let msg: IdscpMessage = create_idscp_data(vec![]); // create empty package to determine size overhead of protobuf encapsulation
        let header_size = msg.compute_size();
        let buffer_space: usize = 42; // this is a fictive number, because we currently have an unbounded buffer that has no limits
        let payload_space = buffer_space.saturating_sub(usize::try_from(header_size).unwrap());
        let n = std::cmp::min(payload_space, data.len());

        let copy = data[..n].to_vec(); //TODO: only copy the data if IDSCP_DATA message is constructed

        match self
            .fsm
            .process_event(FsmEvent::FromUpper(UserEvent::Data(copy)))
        {
            Ok(Some(action)) => {
                self.do_action(action);
                Ok(buffer_space)
            }

            Ok(None) => Ok(buffer_space),

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establish_connection() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut peer1 = IDSCPConnection::connect("peer1".into());
        let mut peer2 = IDSCPConnection::accept("peer2".into());

        const MTU: usize = 1500; // Maximum Transmission Unit
        let mut channel1_2 = Vec::with_capacity(MTU);
        let mut channel2_1 = Vec::with_capacity(MTU);

        while peer1.wants_write() || peer2.wants_write() {
            while peer1.wants_write() {
                peer1.write(&mut channel1_2).unwrap();
            }

            let mut chunk_start = 0;
            while chunk_start < channel1_2.len() {
                match peer2.read(&mut channel1_2[chunk_start..]) {
                    Ok(n) => chunk_start += n,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                    }
                }
            }
            channel1_2.clear();

            while peer2.wants_write() {
                peer2.write(&mut channel2_1).unwrap();
            }

            let mut chunk_start = 0;
            while chunk_start < channel2_1.len() {
                match peer1.read(&mut channel2_1[chunk_start..]) {
                    Ok(n) => chunk_start += n,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                    }
                }
            }
            channel2_1.clear();
        }

        assert!(peer1.is_connected() && channel1_2.is_empty());
        assert!(peer2.is_connected() && channel1_2.is_empty());

        let n = peer1.send(b"hello world").unwrap();
        assert!(n > 0 && peer1.wants_write())
    }
}
