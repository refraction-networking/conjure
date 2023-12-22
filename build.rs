extern crate cc;

fn main() {
    println!("cargo:rustc-link-arg=-lgmp");

    cc::Build::new()
        .file("libtapdance/tapdance.c")
        .file("libtapdance/elligator2.c")
        .file("libtapdance/curve25519-donna-c64.c")
        .include("src")
        .compile("libtapdance.a");
}
