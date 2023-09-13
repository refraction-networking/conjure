extern crate cc;

fn main() {
    cc::Build::new()
        .file("cmd/detector/libtapdance/tapdance.c")
        .include("src")
        .compile("libtapdance.a");
}
