# Async-Idscp2

The asynchronous implementation of the IDSCP2 protocol in Rust.

#### Master Branch Status
![Pipeline](https://github.com/obraunsdorf/async-idscp2/actions/workflows/ci.yml/badge.svg?branch=master)

#### Develop Branch Status
![Pipeline](https://github.com/obraunsdorf/async-idscp2/actions/workflows/ci.yml/badge.svg?branch=develop)

# Notes
For returning a List of Actions from the FSM's `process_event()` method: encode them as bitflags: https://docs.rs/bitflags/1.2.1/bitflags/#methods-1
