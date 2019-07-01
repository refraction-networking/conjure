extern crate gcc;

fn main() {
    gcc::Config::new()
                .file("libtapdance/tapdance.c")
                .include("src")
                .compile("libtapdance.a");
}
