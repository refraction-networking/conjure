#![feature(ip)]
#![feature(let_chains)]

extern crate maxminddb;

mod ip;
mod packet_handler;
use ip::get_mut_ip_packet;
use packet_handler::{PacketError, PacketHandler, SupplementalFields};

// use hex;
use clap::Parser;
use pcap::{Activated, Capture, Device};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::Packet;
use threadpool::ThreadPool;

use std::borrow::Cow;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ASNDB_PATH: &str = "test_mmdbs/GeoLite2-ASN.mmdb";
const CCDB_PATH: &str = "test_mmdbs/GeoLite2-Country.mmdb";

/// Program to capture from multiple interfaces and anonymize client address information.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to pcap file to read
    #[arg(short, long)]
    target_subnets: Option<String>,

    /// Path to pcap file to read
    #[arg(short, long)]
    read: Option<String>,

    /// Path to directory containing PCAPs files to read
    #[arg(short, long)]
    pcap_dir: Option<String>,

    /// Comma separated interfaces on which to listen (mutually exclusive with `--pcap_dir`, and `--read` options).
    #[arg(short, long, default_value_t = String::from("eno1"))]
    interfaces: String,

    /// Path to the Geolite CountryCode database (.mmdb) file
    #[arg(short, long, default_value_t = String::from("./out.pcapng"))]
    out: String,

    /// Path to the Geolite ASN database (.mmdb) file
    #[arg(short, long, default_value_t = String::from(ASNDB_PATH))]
    asn_db: String,

    /// Path to the Geolite CountryCode database (.mmdb) file
    #[arg(short, long, default_value_t = String::from(CCDB_PATH))]
    cc_db: String,
}

fn read_interfaces<W: Write + std::marker::Send + 'static>(
    interfaces: String,
    handler: Arc<Mutex<PacketHandler>>,
    arc_writer: Arc<Mutex<PcapNgWriter<W>>>,
) -> Result<(), Box<dyn Error>> {
    let pool = ThreadPool::new(interfaces.matches(',').count() + 1);
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    for (n, iface) in interfaces.split(',').enumerate() {
        match Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == iface)
        {
            Some(dev) => {
                let h = Arc::clone(&handler);
                let w = Arc::clone(&arc_writer);
                let t = Arc::clone(&term);
                pool.execute(move || {
                    let cap = Capture::from_device(dev)
                        .unwrap()
                        .immediate_mode(true) // enable immediate mode
                        .open()
                        .unwrap();
                    read_packets(n as u32, cap, h, w, t);
                });
            }
            None => println!("Couldn't find interface '{iface}'"),
        }
    }

    pool.join();

    Ok(())
}

fn read_pcap_dir<W: Write + std::marker::Send + 'static>(
    pcap_dir: String,
    handler: Arc<Mutex<PacketHandler>>,
    arc_writer: Arc<Mutex<PcapNgWriter<W>>>,
) -> Result<(), Box<dyn Error>> {
    let mut paths = fs::read_dir(pcap_dir.clone()).unwrap();
    let pool = ThreadPool::new(paths.count());
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

    // refresh the path list and launch jobs
    paths = fs::read_dir(pcap_dir).unwrap();
    for (n, path) in paths.enumerate() {
        match path {
            Ok(p) => {
                // println!("{}", p.path().display());
                let h = Arc::clone(&handler);
                let w = Arc::clone(&arc_writer);
                let t = Arc::clone(&term);
                pool.execute(move || {
                    let cap = Capture::from_file(p.path()).unwrap();
                    read_packets(n as u32, cap, h, w, t);
                });
            }
            Err(e) => println!("path error: {e}"),
        }
    }

    pool.join(); // all threads must complete or the process will hang

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let handler = Arc::new(Mutex::new(PacketHandler::create(
        &args.asn_db,
        &args.cc_db,
    )?));

    let file = File::create(args.out)?;
    let mut writer = PcapNgWriter::new(file).expect("failed to build writer");
    let interface = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![],
    };
    writer.write_pcapng_block(interface)?;
    let arc_writer = Arc::new(Mutex::new(writer));

    match args.pcap_dir {
        Some(pcap_dir) => read_pcap_dir(pcap_dir, handler, arc_writer),
        None => read_interfaces(args.interfaces, handler, arc_writer),
    }

    //Ok(())
}

// abstracts over live captures (Capture<Active>) and file captures
// (Capture<Offline>) using generics and the Activated trait,
fn read_packets<T: Activated, W: Write>(
    _id: u32,
    mut capture: Capture<T>,
    handler: Arc<Mutex<PacketHandler>>,
    writer: Arc<Mutex<PcapNgWriter<W>>>,
    terminate: Arc<AtomicBool>,
) {
    let seed = { handler.lock().unwrap().seed };

    while !terminate.load(Ordering::Relaxed) {
        let packet = match capture.next_packet() {
            Ok(p) => p,
            Err(_e) => continue,
        };
        // pcap::Packet doesn't implement DerefMut so we have to clone it as mutable -_-
        let data: &mut [u8] = &mut packet.data.to_owned();

        let mut eth = MutableEthernetPacket::new(data).unwrap();

        let mut ip_pkt = match get_mut_ip_packet(&mut eth) {
            Some(p) => p,
            None => continue,
        };

        let supplemental_fields: SupplementalFields = match {
            let h = handler.lock().unwrap();
            h.get_supplemental(ip_pkt.source(), ip_pkt.destination())
        } {
            Ok(s) => s,
            Err(e) => {
                match e {
                    PacketError::Skip => {}
                    _ => println!("skip packet: {e}"),
                }
                continue;
            }
        };

        match ip_pkt.anonymize(
            supplemental_fields.direction,
            seed,
            supplemental_fields.subnet,
        ) {
            Ok(_) => {}
            Err(_e) => continue,
        };

        let data = eth.packet();
        let eth_out = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_micros(packet.header.ts.tv_usec as u64),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: supplemental_fields.into(),
        };

        match { writer.lock().unwrap().write_pcapng_block(eth_out) } {
            Ok(_) => continue,
            Err(e) => println!("thread {_id} failed to write packet: {e}"),
        }
    }
}

// [X] read packets with pcap from interface / file and convert to usable type
//
// [X] anonymizing client address and port consistently
//
// [X] filtering based on geoip asn / cc / subnet / subnet len
//
// [X] adding asn and cc as comments while writing as pcapng
//
// [ ] reading from multiple __interfaces__ simultaneously

#[cfg(test)]
mod tests {
    mod threading;

    use super::*;
    use ipnet::IpNet;
    use maxminddb::geoip2;
    use std::net::IpAddr;

    #[test]
    fn test_cc_and_asn_lookup() -> Result<(), String> {
        let asn_reader = maxminddb::Reader::open_readfile(String::from(ASNDB_PATH)).unwrap();

        let cc_reader = maxminddb::Reader::open_readfile(String::from(CCDB_PATH)).unwrap();

        let ip: IpAddr = "192.122.190.123".parse().unwrap();

        let (asn_rec, prefix) = asn_reader.lookup_prefix::<geoip2::Asn>(ip).unwrap();
        let asn = asn_rec.autonomous_system_number.unwrap();

        let subnet = IpNet::new(ip, prefix.try_into().unwrap()).unwrap().trunc();
        assert_eq!(asn, 237);
        assert_eq!(Ok(subnet), "192.122.184.0/21".parse());

        let country_rec: geoip2::Country = cc_reader.lookup(ip).unwrap();
        let country = country_rec.country.unwrap().iso_code.unwrap();
        assert_eq!(country, "US");
        // println!("{country:#?}");

        Ok(())
    }
}
