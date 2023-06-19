// comment
fn main() {
    cc::Build::new()
        .file("src/zbalance_ipc_ffi.c")
        .compile("zbalance_ipc_ffi");
    println!("cargo:rerun-if-changed=src/zbalance_ipc_ffi.c");
}
