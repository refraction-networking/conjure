extern crate cc;

fn main() {
    cc::Build::new()
        .file("libtapdance/tapdance.c")
        .include("src")
        .compile("libtapdance.a");
}
