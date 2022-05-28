use bytes::{Buf, BytesMut};
use idscp2_core::tokio_idscp_connection::{AsyncIdscpConnection, AsyncIdscpListener};
use rand::{thread_rng, Fill};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio_test::assert_ok;

fn random_data(size: usize) -> BytesMut {
    let mut rng = thread_rng();

    let mut data = BytesMut::with_capacity(size);
    data.try_fill(&mut rng).unwrap();
    data
}

fn spawn_connection() -> (AsyncIdscpConnection, AsyncIdscpConnection) {
    tokio_test::block_on(async {
        let listener = AsyncIdscpListener::bind("127.0.0.1:8080").await.unwrap();
        let (connect_result, accept_result) = tokio::join!(
            AsyncIdscpConnection::connect("127.0.0.1:8080"),
            listener.accept()
        );

        assert_ok!(&connect_result);
        assert_ok!(&accept_result);

        (connect_result.unwrap(), accept_result.unwrap())
    })
}

fn bench_transfer_size_1024(c: &mut Criterion) {
    const TRANSMISSION_SIZE: usize = 24000;
    const FIXED_CHUNK_SIZE: usize = 1024;

    let mut data = random_data(TRANSMISSION_SIZE);
    let mut cmp_data = data.clone();

    let (mut peer1, mut peer2) = spawn_connection();

    c.bench_function("transfer_size_1024", |b| {
        b.iter(|| {
            tokio_test::block_on(async {
                tokio::try_join!(
                    async {
                        while data.has_remaining() {
                            let msg = data.split_to(FIXED_CHUNK_SIZE);
                            let n = peer1.send(black_box(msg.as_ref())).await?;
                            assert!(n == FIXED_CHUNK_SIZE);
                        }
                        Ok::<(), std::io::Error>(())
                    },
                    async {
                        while cmp_data.has_remaining() {
                            // sleep(Duration::from_secs(1));
                            let msg = peer2.recv().await.unwrap();
                            if let Some(msg) = msg {
                                let cmp_msg = cmp_data.split_to(FIXED_CHUNK_SIZE);
                                assert_eq!(msg.as_slice(), cmp_msg.as_ref());
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    }
                )
                .unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_transfer_size_1024);
criterion_main!(benches);
