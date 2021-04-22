use super::IDSCPConnection;
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp,
};

struct AsyncIdscpListener {
    tcp_listener: TcpListener,
}
impl AsyncIdscpListener {
    async fn bind(addr: &'static str) -> std::io::Result<AsyncIdscpListener> {
        let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
        Ok(AsyncIdscpListener { tcp_listener })
    }

    async fn accept(&self) -> std::io::Result<AsyncIdscpConnection> {
        let (mut tcp_stream, _) = self.tcp_listener.accept().await.unwrap();
        let mut connection = IDSCPConnection::accept(String::from("acceptor"));
        AsyncIdscpConnection::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }
}

struct AsyncIdscpConnection {
    tcp_stream: TcpStream,
    connection: IDSCPConnection,
}
impl AsyncIdscpConnection {
    pub async fn connect(addr: &'static str) -> std::io::Result<AsyncIdscpConnection> {
        let mut tcp_stream = TcpStream::connect(addr).await?;
        let mut connection = IDSCPConnection::connect("connector".to_string());

        Self::start_handshake(&mut connection, &mut tcp_stream).await?;

        Ok(AsyncIdscpConnection {
            tcp_stream,
            connection,
        })
    }

    async fn start_handshake(
        connection: &mut IDSCPConnection,
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

    async fn read<'a>(
        connection: &mut IDSCPConnection,
        reader: &mut tokio::net::tcp::ReadHalf<'a>,
    ) -> std::io::Result<usize> {
        let mut buf = [0u8; 1024];
        let n = reader.read(&mut buf[..]).await?;
        connection.read(&mut buf[..n])
    }

    async fn write<'a>(
        connection: &mut IDSCPConnection,
        writer: &mut tokio::net::tcp::WriteHalf<'a>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

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
}
