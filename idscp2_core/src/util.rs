#[cfg(test)]
pub(crate) mod test {
    use crate::tokio_idscp_connection::AsyncIdscpListener;
    use futures::lock::{Mutex, MutexGuard};
    use lazy_static::lazy_static;
    use std::thread::sleep;
    use std::time::Duration;

    struct GuardedAddress<'a> {
        mutex: Mutex<()>,
        address: &'a str,
    }

    const TEST_ADDRESS_STRING: &str = "127.0.0.1:8080";

    lazy_static! {
        static ref TEST_ADDRESS: GuardedAddress<'static> = GuardedAddress {
            mutex: Mutex::new(()),
            address: TEST_ADDRESS_STRING,
        };
    }

    pub(crate) async fn spawn_listener(
    ) -> (AsyncIdscpListener, MutexGuard<'static, ()>, &'static str) {
        let guard = TEST_ADDRESS.mutex.lock().await;
        sleep(Duration::from_millis(100)); // give the OS some time to make the address available
        let listener = AsyncIdscpListener::bind("127.0.0.1:8080").await.unwrap();
        (listener, guard, TEST_ADDRESS.address)
    }
}
