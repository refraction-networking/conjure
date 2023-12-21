extern crate cc;

fn main() {
    cc::Build::new()
        .file("libtapdance/tapdance.c")
        .file("libtapdance/elligator2.c")
        .include("src")
        .compile("libtapdance.a");
}
