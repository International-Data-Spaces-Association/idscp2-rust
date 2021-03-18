// Copyright (c) 2020, Fraunhofer AISEC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(test)]
extern crate log;

use std::io::Write;
use std::thread;

pub fn setup_logging() {
    let mut builder = env_logger::builder();

    builder.is_test(true).format(|buf, record| {
        let thread_id = {
            if let Some(name) = thread::current().name() {
                name.to_owned()
            } else {
                format!("{:?}", thread::current().id())
            }
        };
        writeln!(
            buf,
            "{}, {:?} {}::{}: {}",
            record.level(),
            thread_id,
            record.file().unwrap(),
            record.line().unwrap(),
            record.args()
        )
    });

    // if try_init fails, the logger has already been initialized for the test. Nothing to do then.
    let _ = builder.try_init();
}
