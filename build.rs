fn main() {
    prost_build::Config::new()
        .out_dir(std::env::var("OUT_DIR").expect("OUT_DIR not set"))
        .compile_protos(&["proto/packet.proto"], &["proto"])
        .expect("Failed to compile protobuf schemas");

    println!("cargo:rerun-if-changed=proto/packet.proto");
}
