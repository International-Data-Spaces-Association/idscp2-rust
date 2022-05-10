#![cfg(rust_nightly)]
#![feature(test)]

extern crate core;
extern crate core;
extern crate test;

use bytes::BytesMut;
use core::slice::SlicePattern;
use idscp2_core::IdscpConnection;
use rand::{thread_rng, Fill};
use test::Bencher;

#[bench]
fn a(b: &mut Bencher) {
    const TRANSMISSION_SIZE: usize = 24000;
    const CHUNK_SIZE: usize = 24000;

    let mut rng = thread_rng();

    let mut data = BytesMut::with_capacity(TRANSMISSION_SIZE);
    data.try_fill(&mut rng);
    let cmp_data = data.clone();

    b.iter(|| {
        let mut peer1 = IdscpConnection::connect("peer1".into());
        let mut peer2 = IdscpConnection::accept("peer2".into());
    });
}
