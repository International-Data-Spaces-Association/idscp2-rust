The IDSCP2 Rust implementation
================================

![CI pipeline status](https://github.com/International-Data-Spaces-Association/idscp2-rust/actions/workflows/ci.yml/badge.svg)

The Rust implementation of the IDSCP2 transport layer.  

The IDSCP protocol establishes a secure peer-to-peer connection that provides **mutual remote attestation** and guarantees 
confidentiality, integrity, authenticity and perfect forward secrecy.
It is designed to be very modular and thus flexible regarding the underlying communication channels and mechanisms for
remote attestation.

The Rust implementation **currently only runs on Linux** (tested on Ubuntu 18.04 and 20.04)

## Disclaimer
The IDSCP2 transport layer protocol and its Rust implementation is still in early stages of development and **should
not be used in production**.

## Building

Install the latest stable release of the rust toolchain (it is recommended to install it via https://rustup.rs/).

Install Linux dependencies
```
apt install libssl-dev protobuf-compiler 
```

In the root directory run
 - `cargo build` to download dependencies and build the library
 - `cargo test -- --nocapture` to run the tests
 - `RUST_LOG=debug cargo test -- --nocapture` to see log output of the idscp library (for more log configuration options see https://docs.rs/crate/env_logger/0.7.1)

To run the examples run
 - `cargo run --example commandline_tunnel_server` and
 - `cargo run --example commandline_tunnel_client`


## How to Use IDSCP
You can use IDSCP in two ways: 
1. Starting a socket tunnel (independent of programming languages)
2. Importing it as a library for your Rust project (requires Rust..at the moment)

### As Socket Tunnel
If you are not programming in Rust, the easiest way to use IDSCP is via the provided socket tunnel.
Install the idscp_socket_tunnel binary with
```
cargo install --path idscp_socket_tunnel
```
You can then start the tunnel as a listening or connecting IDSCP peer with 
```
idscp_socket_tunnel --mode [Listener|Connector]
```
You will additionally have to specify the address of the peer and path to TLS certificate chains
and keys.
For testing you can use TLS files from our [test PKI](test_pki):
```
idscp_socket_tunnel \
    --mode Connector \
    --cert test_pki/resources/openssl/out/test_client.chain \
    --key test_pki/resources/openssl/out/test_client.key \
    --trusted-ca test_pki/resources/openssl/root-ca/certs/rootCA.crt \
    --host localhost \
    --port=1234 \
    --domain="idscp-test.de"
```
For every connection, the idscp_socket_tunnel will create a unix socket at path `/tmp/idscp_socket{N}`.  
Use your favorite programming language to read from and write to this unix socket.
Every message written to the socket will be tunneled via IDSCP.

### As Library
Using IDSCP as library is more performant becaus it avoids the overhead of socket communication.
Example code for how to use IDSCP as library can be found in 
the [commandline tunnel example](idscp_examples/examples/commandline_tunnel).

We plan to provide C-language bindings in the near future that can be used from any other major programming languages.


## Remote Attestation
Fraunhofer AISEC is developing multiple "drivers" for different remote attestation mechanisms (based on TPM, 
Intel SGX, AMD SEV) which are currently not licensed as open source. If you want to use our implementations, please get
in touch.

The [NullRa driver](idscp_default_drivers/src/ra_drivers/null_ra) provided with this repository is
only a dummy driver that can be used to opt-out of remote attestation when using IDSCP.
**It should not be used in security critical applications that really rely on remote attestation.**  


## Contributing to the Development of IDSCP
Please see our [contributing guidelines](CONTRIBUTING.md)
