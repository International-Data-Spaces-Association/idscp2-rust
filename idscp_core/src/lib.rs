mod fsm;
mod messages;

use std::{
    collections::VecDeque,
    io::{Read, Write},
};

use bytes::Buf;
use fsm::*;
use messages::{
    idscp_message_factory as msg_factory, idscpv2_messages::IdscpMessage,
    idscpv2_messages::IdscpMessage_oneof_message,
};
use protobuf::Message;

pub struct IDSCPConnection {
    fsm: FSM,
    send_buffer_queue: VecDeque<u8>, // TODO: maybe replace with bounded buffer?
    recv_buffer_queue: VecDeque<u8>, // TODO: maybe replace with bounded buffer?
}

impl IDSCPConnection {
    fn push_to_send_buffer(&mut self, msg: IdscpMessage) {
        //TODO: optimize this to not create the "raw" buffer but to write directly to the end of the send_buffer

        let mut raw = Vec::new();
        msg.write_to_vec(&mut raw).unwrap();
        self.send_buffer_queue.append(&mut raw.into());
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

    pub fn write(&mut self, out: &mut dyn Write) -> std::io::Result<usize> {
        let n = out.write(self.send_buffer_queue.make_contiguous())?;
        for _ in 1..=n {
            // TODO: this seems very inefficient. Find a good datastructure to write chunks
            self.send_buffer_queue.pop_front().unwrap(); //TODO this unwrap is unsafe
        }
        Ok(n)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n: usize = 0;
        for byte in buf {
            self.recv_buffer_queue.push_back(*byte);
            n += 1;
        }
        Ok(n)
    }

    pub fn process_new_msgs(&mut self) -> Result<(), FsmError> {
        if let Ok(msg) = IdscpMessage::parse_from_bytes(self.recv_buffer_queue.make_contiguous()) {
            let m = msg.compute_size();
            for _ in 1..=m {
                self.recv_buffer_queue.pop_front().unwrap();
            }
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
            send_buffer_queue: VecDeque::new(),
            recv_buffer_queue: VecDeque::new(),
        };
        conn.do_action(action);

        conn
    }

    pub fn accept(config: String) -> IDSCPConnection {
        let mut fsm = FSM::new(config);
        IDSCPConnection {
            fsm: fsm,
            send_buffer_queue: VecDeque::new(),
            recv_buffer_queue: VecDeque::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut peer1 = IDSCPConnection::connect("peer1".into());
        let mut peer2 = IDSCPConnection::accept("peer2".into());

        let mut channel1_2 = vec![];

        while peer1.wants_write() {
            peer1.write(&mut channel1_2);
        }

        peer2.read(&mut channel1_2[..]).unwrap();
        peer2.process_new_msgs();
    }
}
