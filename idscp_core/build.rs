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

use protoc_rust::Customize;
use std::path::Path;

const PROTO_FILE_PATHS: &str = "src/messages/idscp2_messages.proto";
// const PROTO_INCLUDE_PATH: &Path = """;
const GEN_OUT_DIR: &str = "src/messages";

fn main() {
    println!("cargo:rerun-if-changed=src/messages/idscp2_messages.proto");
    std::fs::create_dir_all(GEN_OUT_DIR).expect(&format!(
        "could not create or find directory {}",
        GEN_OUT_DIR
    ));

    protoc_rust::Codegen::new()
        .out_dir(GEN_OUT_DIR)
        .input(Path::new(PROTO_FILE_PATHS))
        //.includes(PROTO_INCLUDE_PATH)
        .customize(Customize {
            carllerche_bytes_for_bytes: Some(true),
            carllerche_bytes_for_string: Some(false),
            ..Default::default()
        })
        .run()
        .expect("protoc");
}
