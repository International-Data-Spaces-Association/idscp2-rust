use super::IDSCPConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct AsyncIdscpConnection {
    connection: IDSCPConnection,
}

struct AsyncIdscpListener {}
impl AsyncIdscpListener {
    fn accept() -> AsyncIdscpConnection {
        let connection = IDSCPConnection::accept(String::from("bla"));
        AsyncIdscpConnection { connection }
    }
    async fn listen(addr: &'static str) -> std::io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:8080").await?;
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut conn = Self::accept();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    while !conn.is_connected() {
                        while conn.wants_write() {
                            conn.write(&mut writer).await;
                        }

                        conn.read(&mut reader).await;
                    }
                    Ok::<(), std::io::Error>(())
                });
            }
        });
        Ok(())
    }
}

impl AsyncIdscpConnection {
    async fn connect(addr: &'static str) -> std::io::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        let mut connection = IDSCPConnection::connect("bla".to_string());
        let mut conn = AsyncIdscpConnection { connection };
        let (mut reader, mut writer) = stream.split();
        while !conn.is_connected() {
            while conn.wants_write() {
                conn.write(&mut writer).await;
            }

            conn.read(&mut reader).await;
        }

        Ok(())
    }

    async fn read<'a>(
        &mut self,
        reader: &mut tokio::net::tcp::ReadHalf<'a>,
    ) -> std::io::Result<usize> {
        let mut buf = [0u8; 1024];
        let n = reader.read(&mut buf[..]).await?;
        self.connection.read(&mut buf[..n])
    }

    async fn write<'a>(
        &mut self,
        writer: &mut tokio::net::tcp::WriteHalf<'a>,
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 1024];
        let n = self.connection.write(&mut buf[..])?;
        writer.write_all(&mut buf[..n]).await
    }

    fn wants_write(&self) -> bool {
        self.connection.wants_write()
    }

    fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn async_test() {
        let _ = env_logger::builder().is_test(true).try_init();
        tokio_test::block_on(async {
            AsyncIdscpListener::listen("127.0.0.1:8080").await.unwrap();
            let conn = AsyncIdscpConnection::connect("127.0.0.1:8080")
                .await
                .unwrap();

            //tokio::spawn(task)tokio::spawn(TcpStream::connect("127.0.0.1:8080"));
            println!("test done");
        });
    }
}
