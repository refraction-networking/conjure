extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=tapdance");
    println!("cargo:rustc-link-search=libtapdance");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=crypto");
}
