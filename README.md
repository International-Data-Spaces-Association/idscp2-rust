The IDSCP2 Rust implementation
================================
The Rust implementation of the IDSCP2 transport layer.  

The IDSCP protocol establishes a secure peer-to-peer connection that provides **mutual remote attestation** and guarantees 
confidentiality, integrity, authenticity and perfect forward secrecy.
It is designed to be very modular and thus flexible regarding the underlying communication channels and mechanisms for
remote attestation.


## Disclaimer
The IDSCP2 transport layer protocol and its Rust implementation is still in early stages of development and **should
not be used in production**.

## Asynchronous Version vs Multithreaded version
This branch provides the asynchronous Rust implementation. It is more efficient in runtime and memory but **more experimental** than the multithreaded version.
See the respective branch for the multithreaded version.

## Building

Install the latest stable release of the rust toolchain (it is recommended to install it via https://rustup.rs/).

Install Linux dependencies
```
apt install libssl-dev protobuf-compiler 
```

In the root directory run
 - `cargo build` to download dependencies and build the library
 - `cargo test -- --nocapture` to run the tests
 - `RUST_LOG=debug cargo test -- --nocapture` to see log output of the idscp library (for more log configuration options see https://docs.rs/crate/env_logger)




## Remote Attestation
Fraunhofer AISEC is developing multiple "drivers" for different remote attestation mechanisms (based on TPM, 
Intel SGX, AMD SEV) which are currently not licensed as open source. If you want to use our implementations, please get
in touch.
