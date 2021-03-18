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

use super::idscpv2_messages::{
    IdscpAck, IdscpClose, IdscpClose_CloseCause, IdscpDat, IdscpDatExpired, IdscpData, IdscpHello,
    IdscpMessage, IdscpRatProver, IdscpRatVerifier, IdscpReRat,
};
use crate::fsm::alternating_bit::AlternatingBit;
use bytes::Bytes;
use protobuf::SingularPtrField;

pub(crate) fn create_idscp_hello(
    dat: Vec<u8>,
    expected_rat_suite: &[String],
    supported_rat_suite: &[String],
) -> IdscpMessage {
    let mut idscp_dat = IdscpDat::new();
    idscp_dat.token = Bytes::from(dat);

    let mut hello = IdscpHello::new();
    hello.version = 2;
    hello.dynamicAttributeToken = SingularPtrField::some(idscp_dat);
    hello.expectedRatSuite = protobuf::RepeatedField::from_ref(expected_rat_suite);
    hello.supportedRatSuite = protobuf::RepeatedField::from_ref(supported_rat_suite);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpHello(hello);
    idscp
}

pub(crate) fn create_idscp_close(code: IdscpClose_CloseCause, msg: &'static str) -> IdscpMessage {
    let mut close = IdscpClose::new();
    close.cause_code = code;
    close.cause_msg = String::from(msg);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpClose(close);
    idscp
}

pub(crate) fn create_idscp_dat_exp() -> IdscpMessage {
    let mut idscp = IdscpMessage::new();
    idscp.set_idscpDatExpired(IdscpDatExpired::new());
    idscp
}

pub(crate) fn create_idscp_dat(dat: Vec<u8>) -> IdscpMessage {
    let mut idscp_dat = IdscpDat::new();
    idscp_dat.token = Bytes::from(dat);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpDat(idscp_dat);
    idscp
}

pub(crate) fn create_idscp_re_rat(cause: &'static str) -> IdscpMessage {
    let mut idscp_rerat = IdscpReRat::new();
    idscp_rerat.cause = String::from(cause);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpReRat(idscp_rerat);
    idscp
}

pub(crate) fn create_idscp_rat_prover(data: Vec<u8>) -> IdscpMessage {
    let mut idscp_p = IdscpRatProver::new();
    idscp_p.data = Bytes::from(data);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpRatProver(idscp_p);
    idscp
}

pub(crate) fn create_idscp_rat_verifier(data: Vec<u8>) -> IdscpMessage {
    let mut idscp_v = IdscpRatVerifier::new();
    idscp_v.data = Bytes::from(data);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpRatVerifier(idscp_v);
    idscp
}

pub(crate) fn create_idscp_data(data: Vec<u8>, alternating_bit: &AlternatingBit) -> IdscpMessage {
    let mut idscp_data = IdscpData::new();
    idscp_data.data = Bytes::from(data);
    idscp_data.set_alternating_bit(alternating_bit.as_bool());

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpData(idscp_data);
    idscp
}

pub(crate) fn create_idscp_ack(alternating_bit: AlternatingBit) -> IdscpMessage {
    let mut idscp = IdscpMessage::new();
    let mut ack = IdscpAck::new();
    ack.set_alternating_bit(alternating_bit.as_bool());
    idscp.set_idscpAck(ack);
    idscp
}
