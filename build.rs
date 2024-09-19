extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=tapdance");
    println!("cargo:rustc-link-search=libtapdance");
    // cc::Build::new()
    //     .file("libtapdance/tapdance.c")
    //     .include("src")
    //     .compile("libtapdance.a");
}
