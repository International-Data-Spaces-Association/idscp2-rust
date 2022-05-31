use bytes::{Buf, BytesMut};
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
    transmission_size: usize,
    chunk_size: usize,
) -> Result<bool, std::io::Error> {
    let mut data = BytesMut::from(random_data(transmission_size).as_slice());
    let mut cmp_data = data.clone();
    let mut to_read = cmp_data.len();

    tokio::try_join!(
            async {
                while !data.is_empty() {
                    println!("snd");
                    let msg = data.split_to(chunk_size);
                    let n = peer1.send(msg.as_ref()).await?;
                    println!("sndd {}/{}", n, chunk_size);
                    assert!(n == chunk_size);
                }
                Ok::<(), std::io::Error>(())
            },
            async {
                while !cmp_data.is_empty() {
                    println!("recv");
                    // sleep(Duration::from_secs(1));
                    let msg = peer2.recv().await.unwrap();
                    if let Some(msg) = msg {
                        assert_eq!(msg.len(), chunk_size);
                        let cmp_msg = cmp_data.split_to(chunk_size);
                        assert_eq!(msg.as_slice(), cmp_msg.as_ref());
                    }
                }
                Ok::<(), std::io::Error>(())
            }
        )?;

    Ok(data.is_empty() && cmp_data.is_empty())
}

fn bench_transfer_size_1024(c: &mut Criterion) {
    const TRANSMISSION_SIZE: usize = 24000;
    const FIXED_CHUNK_SIZE: usize = 1024;

    c.bench_function("transfer_size_1024", |b| {
        b.iter(|| {
            tokio_test::block_on(async {
                let (mut peer1, mut peer2) = spawn_connection().await;
                transfer(&mut peer1, &mut peer2, TRANSMISSION_SIZE, FIXED_CHUNK_SIZE)
                    .await
                    .unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_transfer_size_1024);
criterion_main!(benches);
