use bytes::{BytesMut};
use idscp2_core::tokio_idscp_connection::{AsyncIdscpConnection, AsyncIdscpListener};
use rand::{thread_rng, Fill};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio_test::assert_ok;

fn random_data(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();

    let mut data = vec![0u8; size];
    data.try_fill(&mut rng).unwrap();
    data
}

async fn spawn_connection() -> (AsyncIdscpConnection, AsyncIdscpConnection) {
    let listener = AsyncIdscpListener::bind("127.0.0.1:8080").await.unwrap();
    let (connect_result, accept_result) = tokio::join!(
        AsyncIdscpConnection::connect("127.0.0.1:8080"),
        listener.accept()
    );

    assert_ok!(&connect_result);
    assert_ok!(&accept_result);

    (connect_result.unwrap(), accept_result.unwrap())
}

async fn transfer(
    peer1: &mut AsyncIdscpConnection,
    peer2: &mut AsyncIdscpConnection,
    mut data: BytesMut,
    chunk_size: usize,
) -> Result<bool, std::io::Error> {
    let mut cmp_data = data.clone();

    tokio::try_join!(
            async {
                while !cmp_data.is_empty() {
                    let msg = peer2.recv().await.unwrap();
                    if let Some(msg) = msg {
                        assert_eq!(msg.len(), chunk_size);
                        let cmp_msg = cmp_data.split_to(chunk_size);
                        assert_eq!(std::convert::AsRef::as_ref(&msg), cmp_msg.as_ref());
                    }
                }
                Ok::<(), std::io::Error>(())
            },
            async {
                while !data.is_empty() {
                    let msg = data.split_to(chunk_size);
                    let n = peer1.send(black_box(msg.freeze())).await?;
                    assert!(n == chunk_size);
                }
                Ok::<(), std::io::Error>(())
            },
        )?;

    Ok(data.is_empty() && cmp_data.is_empty())
}

async fn send(
    peer1: &mut AsyncIdscpConnection,
    transmission_size: usize,
    chunk_size: usize,
) -> Result<bool, std::io::Error> {
    let mut data = BytesMut::from(random_data(transmission_size).as_slice());
    let mut sink = tokio::io::sink();

    while !data.is_empty() {
        let msg = data.split_to(chunk_size);
        let n = peer1.send_to(&mut sink, msg.freeze()).await?;
        assert_eq!(n, chunk_size);
    }

    Ok(data.is_empty())
}

fn bench_transfer_size_1000(c: &mut Criterion) {
    const TRANSMISSION_SIZE: usize = 200_000;
    const FIXED_CHUNK_SIZE: usize = 1000;

    let data = BytesMut::from(random_data(TRANSMISSION_SIZE).as_slice());

    c.bench_function("transfer_size_1000", |b| {
        b.iter(|| {
            tokio_test::block_on(async {
                let (mut peer1, mut peer2) = spawn_connection().await;
                transfer(&mut peer1, &mut peer2, black_box(data.clone()), FIXED_CHUNK_SIZE)
                    .await.unwrap()
            })
        })
    });
}

fn bench_send_size_1000(c: &mut Criterion) {
    const TRANSMISSION_SIZE: usize = 20_000_000;
    const FIXED_CHUNK_SIZE: usize = 1000;

    c.bench_function("send_size_1000", |b| {
        b.iter(|| {
            tokio_test::block_on(async {
                let (mut peer1, mut _peer2) = spawn_connection().await;
                send(&mut peer1, TRANSMISSION_SIZE, FIXED_CHUNK_SIZE)
                    .await
                    .unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_transfer_size_1000, bench_send_size_1000);
criterion_main!(benches);
