use super::IdscpConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use crate::MAX_FRAME_SIZE;

pub struct AsyncIdscpListener {
    tcp_listener: TcpListener,
}
impl AsyncIdscpListener {
    pub async fn bind(addr: &'static str) -> std::io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(AsyncIdscpListener { tcp_listener })
    }

    pub async fn accept(&self) -> std::io::Result<AsyncIdscpConnection> {
        let (mut tcp_stream, _) = self.tcp_listener.accept().await.unwrap();
        let mut connection = IdscpConnection::accept(String::from("acceptor"));
        AsyncIdscpConnection::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }
}

pub struct AsyncIdscpConnection {
    tcp_stream: TcpStream,
    connection: IdscpConnection,
}
impl AsyncIdscpConnection {
    pub async fn connect(addr: &'static str) -> std::io::Result<Self> {
        let mut tcp_stream = TcpStream::connect(addr).await?;
        let mut connection = IdscpConnection::connect("connector".to_string());

        Self::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }

    async fn start_handshake(
        connection: &mut IdscpConnection,
        stream: &mut TcpStream,
    ) -> std::io::Result<()> {
        let (mut reader, mut writer) = stream.split();
        while !connection.is_connected() {
            while connection.wants_write() {
                Self::write(connection, &mut writer).await?;
            }

            Self::read(connection, &mut reader).await?;

            while connection.wants_write() {
                Self::write(connection, &mut writer).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    }

    async fn read(
        connection: &mut IdscpConnection,
        reader: &mut tokio::net::tcp::ReadHalf<'_>,
    ) -> std::io::Result<usize> {
        let mut buf = [0u8; MAX_FRAME_SIZE];
        let n = reader.read(&mut buf[..]).await?;
        connection.read(&mut buf[..n])
    }

    async fn write(
        connection: &mut IdscpConnection,
        writer: &mut tokio::net::tcp::WriteHalf<'_>,
    ) -> std::io::Result<()> {
        let mut buf = Vec::new(); // TODO: use a statically sized array here?
        let _n = connection.write(&mut buf)?;
        writer.write_all(&buf).await
    }

    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    pub async fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let n = self.connection.send(data)?;
        let (_, mut writer) = self.tcp_stream.split();
        Self::write(&mut self.connection, &mut writer).await?;
        Ok(n)
    }

    pub async fn recv(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let (mut reader, _) = self.tcp_stream.split();
        Self::read(&mut self.connection, &mut reader).await?;
        Ok(self.connection.recv())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use rand::{thread_rng, Fill};
    use tokio_test::assert_ok;

    #[test]
    fn async_establish_connection() {
        let _ = env_logger::builder().is_test(true).try_init();
        tokio_test::block_on(async {
            let listener = AsyncIdscpListener::bind("127.0.0.1:8080").await.unwrap();
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut connection = AsyncIdscpConnection::connect("127.0.0.1:8080").await?;
                    let n = connection.send(&[1, 2, 3, 4]).await?;
                    assert!(n == 4);
                    Ok::<(), std::io::Error>(())
                },
                listener.accept()
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());

            //tokio::spawn(task)tokio::spawn(TcpStream::connect("127.0.0.1:8080"));
            println!("test done");
        });
    }

    /// TODO: This test could potentially fail in real-network circumstances, if the data is not
    ///  transmitted before the call to `connection.recv()` reads on the socket.
    #[test]
    fn async_transmit_data() {
        const MSG: &[u8; 4] = &[1, 2, 3, 4];

        let _ = env_logger::builder().is_test(true).try_init();
        tokio_test::block_on(async {
            let listener = AsyncIdscpListener::bind("127.0.0.1:8081").await.unwrap();
            let (connect_result, accept_result) = tokio::join!(
                async {
                    let mut connection = AsyncIdscpConnection::connect("127.0.0.1:8081").await?;
                    let n = connection.send(MSG).await?;
                    assert!(n == 4);
                    Ok::<(), std::io::Error>(())
                },
                async {
                    let mut connection = listener.accept().await.unwrap();
                    // sleep(Duration::from_secs(1));
                    let msg = connection.recv().await.unwrap(); //.unwrap();
                    // assert_eq!(msg, MSG);
                    Ok::<(), std::io::Error>(())
                }
            );

            assert!(connect_result.is_ok());
            assert!(accept_result.is_ok());

            println!("test done");
        });
    }

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

    #[test]
    fn test_transfer_size_1024() {
        const TRANSMISSION_SIZE: usize = 10000;
        const FIXED_CHUNK_SIZE: usize = 1000;

        let res = tokio_test::block_on(async {
            let (mut peer1, mut peer2) = spawn_connection().await;
            transfer(&mut peer1, &mut peer2, TRANSMISSION_SIZE, FIXED_CHUNK_SIZE).await
        });

        assert_ok!(res);
        assert!(res.unwrap())
    }
}
