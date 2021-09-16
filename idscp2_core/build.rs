use protoc_rust::Customize;
use std::path::Path;

const PROTO_FILE_PATHS: &str = "src/messages/idscpv2_messages.proto";
// const PROTO_INCLUDE_PATH: &Path = """;
const GEN_OUT_DIR: &str = "src/messages";

fn main() {
    println!("cargo:rerun-if-changed=src/messages/idscpv2_messages.proto");
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
