
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use std::net::{IpAddr, SocketAddr};

fn format_str_dash(
    randomize_source: bool,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> String {
    let mut s = src.to_string();
    s.push_str("-");
    s.push_str(&src_port.to_string());

    let mut d = dst.to_string();
    d.push_str("-");
    d.push_str(&dst_port.to_string());

    if randomize_source {
        s.push_str("->");
        s.push_str(&d);
        return s
    }
    d.push_str("->");
    d.push_str(&s);
    d
}

fn format_str_sockaddr(
    randomize_source: bool,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> String {
    if randomize_source {

        let mut s = SocketAddr::new(src, src_port).to_string();
        s.push_str("->");
        s.push_str(&SocketAddr::new(dst, dst_port).to_string());
        return s
    }
    let mut d = SocketAddr::new(dst, dst_port).to_string();
    d.push_str("->");
    d.push_str(&SocketAddr::new(src, src_port).to_string());
    d
}

fn format_str(
    randomize_source: bool,
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
) -> String {
    if randomize_source {
        return format!(
            "{}->{}",
            SocketAddr::new(src, src_port),
            SocketAddr::new(dst, dst_port)
        );
    }
    format!(
        "{}->{}",
        SocketAddr::new(dst, dst_port),
        SocketAddr::new(src, src_port)
    )
}


pub fn criterion_benchmark(c: &mut Criterion) {
    let a_src = "8.8.8.8".parse::<IpAddr>().unwrap();
    let a_dst = "1.1.1.1".parse::<IpAddr>().unwrap();
    let a_src6 = "8.8.8.8".parse::<IpAddr>().unwrap();
    let a_dst6 = "1.1.1.1".parse::<IpAddr>().unwrap();

    let mut group = c.benchmark_group("format");
    for (s, d, t) in [(a_src, a_dst, "v4"), (a_src6, a_dst6, "v6")] {
        let addrs = (s, d);
        group.bench_with_input(BenchmarkId::new("format_string_dash", t), &addrs, |b, (src, dst)| b.iter(|| format_str_dash(black_box(true), black_box(*src), black_box(*dst),black_box(443), black_box(31234))));
        group.bench_with_input(BenchmarkId::new("format_string_addr", t), &addrs, |b, (src, dst)| b.iter(|| format_str_sockaddr(black_box(true), black_box(*src), black_box(*dst),black_box(443), black_box(31234))));
        group.bench_with_input(BenchmarkId::new("format_string", t), &addrs, |b, (src, dst)| b.iter(|| format_str(black_box(true), black_box(*src), black_box(*dst),black_box(443), black_box(31234))));
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);