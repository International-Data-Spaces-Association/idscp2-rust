use super::idscpv2_messages::{
    IdscpAck, IdscpClose, IdscpClose_CloseCause, IdscpDat, IdscpDatExpired, IdscpData, IdscpHello,
    IdscpMessage, IdscpRaProver, IdscpRaVerifier, IdscpReRa,
};
use crate::driver::ra_driver::DriverId;
use bytes::Bytes;
use protobuf::SingularPtrField;
use std::iter::FromIterator;

pub(crate) fn create_idscp_hello(
    dat: Bytes,
    expected_rat_suite: &[DriverId],
    supported_rat_suite: &[DriverId],
) -> IdscpMessage {
    let mut idscp_dat = IdscpDat::new();
    idscp_dat.token = dat;

    let mut hello = IdscpHello::new();
    hello.version = 2;
    hello.dynamicAttributeToken = SingularPtrField::some(idscp_dat);
    hello.expectedRaSuite =
        protobuf::RepeatedField::from_iter(expected_rat_suite.iter().map(|&id| String::from(id)));
    hello.supportedRaSuite =
        protobuf::RepeatedField::from_iter(supported_rat_suite.iter().map(|&id| String::from(id)));

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

pub(crate) fn create_idscp_ra_prover(data: Bytes) -> IdscpMessage {
    let mut idscp_p = IdscpRaProver::new();
    idscp_p.data = data;

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpRaProver(idscp_p);
    idscp
}

pub(crate) fn create_idscp_ra_verifier(data: Bytes) -> IdscpMessage {
    let mut idscp_v = IdscpRaVerifier::new();
    idscp_v.data = data;

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpRaVerifier(idscp_v);
    idscp
}

pub(crate) fn create_idscp_dat_exp() -> IdscpMessage {
    let mut idscp = IdscpMessage::new();
    idscp.set_idscpDatExpired(IdscpDatExpired::new());
    idscp
}

pub(crate) fn create_idscp_dat(dat: Bytes) -> IdscpMessage {
    let mut idscp_dat = IdscpDat::new();
    idscp_dat.token = dat;

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpDat(idscp_dat);
    idscp
}

pub(crate) fn create_idscp_re_rat(cause: &'static str) -> IdscpMessage {
    let mut idscp_rerat = IdscpReRa::new();
    idscp_rerat.cause = String::from(cause);

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpReRa(idscp_rerat);
    idscp
}

/* just commenting out because i dont need it right now
pub(crate) fn create_idscp_rat_prover(data: Bytes) -> IdscpMessage {
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
 */

pub(crate) fn create_idscp_data(data: Bytes, ack_bit: bool) -> IdscpMessage {
    let mut idscp_data = IdscpData::new();
    idscp_data.data = data;
    idscp_data.alternating_bit = ack_bit;

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpData(idscp_data);

    idscp
}

pub(crate) fn create_idscp_ack(ack_bit: bool) -> IdscpMessage {
    let mut idscp_ack = IdscpAck::new();
    idscp_ack.alternating_bit = ack_bit;

    let mut idscp = IdscpMessage::new();
    idscp.set_idscpAck(idscp_ack);

    idscp
}
