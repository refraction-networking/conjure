extern crate cc;

fn main() {
    cc::Build::new()
        .files(&[
            "libtapdance/tapdance.c",
            "libtapdance/ssl_api.c",
            "libtapdance/elligator2.c",
            "libtapdance/curve25519-donna-c64.c",
            "libtapdance/loadkey.c",
            "libtapdance/tapdance_rst_spoof.c",
            "libtapdance/tapdance_rust_util.c",
        ])
        .include("src")
        .compile("libtapdance.a");

    println!("cargo:rustc-link-lib=tapdance");
    println!("cargo:rustc-link-search=libtapdance");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=crypto");
}
