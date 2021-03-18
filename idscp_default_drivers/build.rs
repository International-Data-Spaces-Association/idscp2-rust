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

fn main() {
    println!("cargo:rerun-if-changed=../test_pki/resources/openssl/generate_test_pki.sh");
    let x = std::process::Command::new("sh")
        .arg("generate_test_pki.sh")
        .current_dir("../test_pki/resources/openssl")
        .output()
        .expect("could not generate test PKI");
    println!("{}", String::from_utf8_lossy(&x.stdout));
}
