#![feature(ip)]
#![feature(let_chains)]
#![feature(associated_type_bounds)]
#![feature(path_file_prefix)]

#[macro_use]
extern crate log;
extern crate maxminddb;

mod flows;
mod ip;
mod limit;
mod packet_handler;
use ip::MutableIpPacket;
use packet_handler::{PacketError, PacketHandler, SupplementalFields};

use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use humantime::parse_duration;
use ipnet::IpNet;
use pcap::{Activated, Capture, Device, Linktype};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use serde::Serialize;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag::register;
use threadpool::ThreadPool;

use std::borrow::Cow;
use std::error::Error;
use std::fs::{self, File};
#[cfg(debug_assertions)]
use std::io::stdin;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{self, Duration};

const ASNDB_PATH: &str = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";
const CCDB_PATH: &str = "/usr/share/GeoIP/GeoLite2-Country.mmdb";

const HELP: &str = "
Examples:

$ captool -t \"192.168.0.0/16\" -i \"en01\"

$ captool -t \"192.168.0.0/16,2001:abcd::/64\" -i \"ens15f0,ens15f1,en01\" -a \"$(cat ./asn_list.txt)\" -lpa 10000 -o \"$(date -u +\"%FT%H%MZ\").pcapng.gz\"
";

#[derive(Parser, Debug, Serialize)]
#[command(
    author,
    version,
    about = "
Program to capture from multiple interfaces and anonymize client address information.

Examples:

captool -t \"192.168.0.0/16,2001:abcd::/64\" -i \"ens15f0,ens15f1,en01\" -a \"$(cat ./asn_list.txt)\" -lpa 10000 -o \"$(date -u +\"%FT%H%MZ\").pcapng.gz\"
"
)]

struct Args {
    /// (Required) Target Subnets -- packets that include addresses in this subnet will be captured, the other (peer) address
    /// will be anonymized.
    #[arg(short, long)]
    t: String,

    /// Limits the total number of packets collected to N.
    #[arg(long)]
    lp: Option<u64>,

    /// Limits the total number of Flows collected to N. If no PPF or Packet Limit is specified this
    /// will read until Ctrl-C as flow termination is not tracked.
    #[arg(long)]
    lf: Option<u64>,

    /// Limit Duration (ld) takes a human parse-able time duration. If after that long the capture
    /// has not terminated due to a packet limit, the timer will terminate the capture.
    #[arg(long,value_parser=parse_duration)]
    timeout: Option<std::time::Duration>,

    /// This limits the number of packets captured in any given flow.
    #[arg(long)]
    ppf: Option<u64>,

    /// Comma separated list of ASNs from which to capture packets. Limits which packets are
    /// captured even if the other (peer) address is in a target subnet.
    #[arg(short, long)]
    asn_filter: Option<String>,

    /// Limit Packets per ASN (LPA) reads only N packets per ASN. If `asn_filter` argument is empty
    /// ASNs will be added and tracked dynamically.
    #[arg(long, conflicts_with_all=["lpc", "lfc"])]
    lpa: Option<u64>,

    /// Limit Flows per ASN (LFA) reads N Flows  per ASN. Requires. `asn_filter` argument. If no PPF
    /// or Packet Limit is specified this will read until Ctrl-C as flow termination is not tracked.
    #[arg(long, conflicts_with_all=["lpc", "lfc"])]
    lfa: Option<u64>,

    /// Comma separated list of CCs from which to capture packets. Limits which packets are
    /// captured even if the other (peer) address is in a target subnet.
    #[arg(short, long)]
    cc_filter: Option<String>,

    /// (WARNING - Disabled) Limit Packets per Country (LPC) reads only N packets per Country Code. Requires. `cc_filter` argument.
    #[arg(long, conflicts_with = "lpa")]
    lpc: Option<u64>,

    /// (WARNING - Disabled) Limit Flows per Country (LFC) reads N flows per Country Code. Requires. `cc_filter`
    /// argument. If no PPF or Packet Limit is specified this will read until Ctrl-C as flow
    /// termination is not tracked.
    #[arg(long, conflicts_with_all=["lpa", "lfa"])]
    lfc: Option<u64>,

    /// Comma separated interfaces on which to listen (mutually exclusive with `--pcap_dir`, and `--read` options).
    #[arg(short, long, default_value_t = String::from("eno1"), conflicts_with = "pcap_dir")]
    interfaces: String,

    /// Path to directory containing PCAPs files to read
    #[arg(short, long, conflicts_with = "interfaces")]
    pcap_dir: Option<String>,

    /// Enable capture for IPv4 Packets ONLY. Requires at least one IPv4 subnet in target-subnets or
    /// this will read nothing.
    #[arg(long, default_value_t = false, conflicts_with = "v6")]
    v4: bool,

    /// Enable capture for IPv6 Packets ONLY. Requires at least one IPv6 subnet in target-subnets or
    /// this will read nothing.
    #[arg(long, default_value_t = false, conflicts_with = "v4")]
    v6: bool,

    /// Path to the output PCAP_NG file.
    #[arg(short, long, default_value_t = String::from("./out.pcapng.gz"))]
    out: String,

    /// Path to the Geolite ASN database (.mmdb) file
    #[arg(long, default_value_t = String::from(ASNDB_PATH))]
    asn_db: String,

    /// Path to the Geolite CountryCode database (.mmdb) file
    #[arg(long, default_value_t = String::from(CCDB_PATH))]
    cc_db: String,
}

#[cfg(debug_assertions)]
fn debug_warn() {
    println!("WARNING - running in debug mode. Press enter to continue:");
    let mut input_text = String::new();
    stdin()
        .read_line(&mut input_text)
        .expect("failed to read from stdin");

    simple_logger::init_with_level(log::Level::Debug).unwrap();
    debug!("Debug enabled")
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let flag = Arc::new(AtomicBool::new(false));

    let toml_conf = toml::to_string(&args).unwrap();
    let out_path = Path::new(&args.out);
    let config_path = out_path.with_file_name(format!(
        "{}.cfg",
        out_path.file_prefix().unwrap().to_str().unwrap().replace("\"", "")
    ));
    let mut file = File::create(&config_path)?;
    file.write_all(&toml_conf.into_bytes())?;

    let asn_list = parse_asn_list(args.asn_filter);
    let cc_list = parse_cc_list(args.cc_filter);

    #[cfg(not(debug_assertions))]
    simple_logger::init_with_level(log::Level::Warn).unwrap();

    #[cfg(debug_assertions)]
    debug_warn();

    trace!(
        "{:?}\n{asn_list:#?} {:?}\n{cc_list:#?} {:?}",
        args.lp,
        args.lpa,
        args.lpc
    );

    let key_list: Vec<limit::Hashable> = if args.lpa.is_some() || args.lfa.is_some() {
        asn_list.iter().map(limit::Hashable::from).collect()
    } else if args.lpc.is_some() || args.lfc.is_some() {
        cc_list.iter().map(limit::Hashable::from).collect()
    } else {
        vec![]
    };

    // let limiter = limit::build(
    let limits = flows::Limits {
        lpk: args.lpa.unwrap_or(args.lpc.unwrap_or(0)),
        lfk: args.lfa.unwrap_or(args.lfc.unwrap_or(0)),
        lp: args.lp.unwrap_or(0),
        lf: args.lf.unwrap_or(0),
        lppf: args.ppf.unwrap_or(0),
    };
    let unlimited = limits.is_unlimited();
    let limit_state = limits.into_limiter(key_list, Arc::clone(&flag));

    let limiter = if unlimited { None } else { Some(limit_state) };
    let target_subnets = parse_targets(args.t);
    if target_subnets.is_empty() {
        error!("no valid target subnets provided{HELP}");
        Err("no valid target subnets provided")?;
    }

    let handler = Arc::new(Mutex::new(PacketHandler::create(
        &args.asn_db,
        &args.cc_db,
        target_subnets,
        limiter,
        cc_list,
        asn_list,
        args.v4,
        args.v6,
    )?));

    let file = File::create(args.out)?;
    let gzip_file = GzEncoder::new(file, Compression::default());
    let mut writer = PcapNgWriter::new(gzip_file).expect("failed to build writer");
    let ip4_iface = InterfaceDescriptionBlock {
        linktype: DataLink::IPV4,
        snaplen: 0xFFFF,
        options: vec![],
    };
    let ip6_iface = InterfaceDescriptionBlock {
        linktype: DataLink::IPV6,
        snaplen: 0xFFFF,
        options: vec![],
    };
    writer.write_pcapng_block(ip4_iface)?;
    writer.write_pcapng_block(ip6_iface)?;
    let arc_writer = Arc::new(Mutex::new(writer));

    match args.pcap_dir {
        Some(pcap_dir) => read_pcap_dir(
            pcap_dir,
            handler,
            arc_writer,
            Arc::clone(&flag),
            args.timeout,
        ),
        None => read_interfaces(
            args.interfaces,
            handler,
            arc_writer,
            Arc::clone(&flag),
            args.timeout,
        ),
    };

    if !flag.load(Ordering::Relaxed) {
        flag.store(true, Ordering::Relaxed);
    }

    Ok(())
}

fn read_interfaces<W>(
    interfaces: String,
    handler: Arc<Mutex<PacketHandler>>,
    arc_writer: Arc<Mutex<PcapNgWriter<W>>>,
    term: Arc<AtomicBool>,
    timeout: Option<Duration>,
) where
    W: Write + std::marker::Send + 'static,
{
    let n_interfaces = interfaces.matches(',').count();
    let pool = ThreadPool::new(n_interfaces + 2);

    let interfaces_complete = Arc::new(AtomicU32::new(0_u32));

    for sig in TERM_SIGNALS {
        register(*sig, Arc::clone(&term)).unwrap();
    }

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
                let ic = Arc::clone(&interfaces_complete);
                pool.execute(move || {
                    let cap = Capture::from_device(dev)
                        .unwrap()
                        .immediate_mode(true) // enable immediate mode
                        .open()
                        .unwrap();
                    read_packets(n as u32, cap, h, w, t);
                    ic.fetch_add(1, Ordering::Relaxed);

                });
            }
            None => println!("Couldn't find interface '{iface}'"),
        }
    }

    // if we were given a duration timeout sleep-wait until the flag is set or we hit the timeout.
    if let Some(duration_limit) = timeout {
        debug!("duration: {duration_limit:?}");
        let term_timeout = Arc::clone(&term);
        pool.execute(move || {
            let beginning_park = time::Instant::now();
            let mut timeout_remaining = duration_limit;
            let ic = Arc::clone(&interfaces_complete);
            loop {
                thread::park_timeout(timeout_remaining);
                let elapsed = beginning_park.elapsed();
                debug!("t: {elapsed:?}");
                if term_timeout.load(Ordering::Relaxed) {
                    break;
                }
                if elapsed >= duration_limit {
                    term_timeout.store(true, Ordering::Relaxed);
                    break;
                }
                if ic.load(Ordering::Relaxed) >= n_interfaces as u32 {
                    break;
                }

                timeout_remaining = duration_limit - elapsed;
            }
        })
    };

    pool.join();
}

fn read_pcap_dir<W>(
    pcap_dir: String,
    handler: Arc<Mutex<PacketHandler>>,
    arc_writer: Arc<Mutex<PcapNgWriter<W>>>,
    term: Arc<AtomicBool>,
    timeout: Option<Duration>,
) where
    W: Write + std::marker::Send + 'static,
{
    let mut paths = fs::read_dir(pcap_dir.clone()).unwrap();
    let total_files = paths.count();
    let pool = ThreadPool::new(total_files + 2);
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term)).unwrap();

    let files_complete = Arc::new(AtomicU32::new(0_u32));

    // refresh the path list and launch jobs
    paths = fs::read_dir(pcap_dir).unwrap();
    for (n, path) in paths.enumerate() {
        match path {
            Ok(p) => {
                // println!("{}", p.path().display());
                let h = Arc::clone(&handler);
                let w = Arc::clone(&arc_writer);
                let t = Arc::clone(&term);
                let fc = Arc::clone(&files_complete);
                pool.execute(move || {
                    let cap = Capture::from_file(p.path()).unwrap();
                    read_packets(n as u32, cap, h, w, t);
                    fc.fetch_add(1, Ordering::Relaxed);
                });
            }
            Err(e) => println!("path error: {e}"),
        }
    }

    // if we were given a duration timeout sleep-wait until the flag is set or we hit the timeout.
    if let Some(duration_limit) = timeout {
        debug!("duration: {duration_limit:?}");
        let term_timeout = Arc::clone(&term);
        let fc = Arc::clone(&files_complete);
        pool.execute(move || {
            let beginning_park = time::Instant::now();
            let mut timeout_remaining = duration_limit;
            loop {
                thread::park_timeout(timeout_remaining);
                let elapsed = beginning_park.elapsed();
                debug!("t: {elapsed:?}");
                if term_timeout.load(Ordering::Relaxed) {
                    break;
                }
                if elapsed >= duration_limit {
                    term_timeout.store(true, Ordering::Relaxed);
                    break;
                }
                if fc.load(Ordering::Relaxed) >= total_files as u32 {
                    break;
                }

                timeout_remaining = duration_limit - elapsed;
            }
        })
    };

    pool.join(); // all threads must complete or the process will hang
}

// abstracts over live captures (Capture<Active>) and file captures
// (Capture<Offline>) using generics and the Activated trait,
fn read_packets<T, W>(
    id: u32,
    mut capture: Capture<T>,
    handler: Arc<Mutex<PacketHandler>>,
    writer: Arc<Mutex<PcapNgWriter<W>>>,
    terminate: Arc<AtomicBool>,
) where
    T: Activated,
    W: Write,
{
    let seed = { handler.lock().unwrap().seed };

    let link_type = capture.get_datalink();

    if !vec![
        Linktype::ETHERNET,
        Linktype::IPV4,
        Linktype::IPV6,
        Linktype::RAW,
    ]
    .contains(&link_type)
        && !link_type.0 == 12
    {
        error!(
            "unsupported linktype: {:?} {}",
            link_type,
            link_type.get_name().unwrap_or(String::from("unknown"))
        );
        return;
    }

    while !terminate.load(Ordering::Relaxed) {
        let packet = match capture.next_packet() {
            Ok(p) => p,
            Err(e) => {
                match e {
                    pcap::Error::NoMorePackets => {}
                    pcap::Error::TimeoutExpired => {}
                    _ => {
                        println!("thread {id} err: {e}");
                    }
                }
                break;
            }
        };

        if packet.is_empty() {
            continue;
        }

        // pcap::Packet doesn't implement DerefMut so we have to clone it as mutable -_-
        let data: &mut [u8] = &mut packet.data.to_owned();
        let ts = Duration::from_micros(packet.header.ts.tv_usec as u64)
            + Duration::from_secs(packet.header.ts.tv_sec as u64);

        let data: (&mut [u8], Linktype) = (data, link_type);
        let mut ip_pkt = match MutableIpPacket::try_from(data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let supplemental_fields: SupplementalFields = match {
            let mut h = handler.lock().unwrap();
            h.get_supplemental(ip_pkt.source(), ip_pkt.destination())
        } {
            Ok(sf) => sf,
            Err(e) => {
                match e {
                    PacketError::Skip => {}
                    e_other => debug!("supplemental info error {e_other}"),
                }
                continue;
            }
        };

        let mut interface_id = 0;
        if matches!(ip_pkt, MutableIpPacket::V6(_)) {
            interface_id = 1;
        }

        let d_out = match {
            let mut h = handler.lock().unwrap();
            ip_pkt.anonymize(seed, supplemental_fields.clone(), &mut h.limiter)
        } {
            Ok(d) => d,
            Err(e) => {
                debug!("anonymization error {e}");
                continue;
            }
        };

        let out = EnhancedPacketBlock {
            interface_id,
            timestamp: ts,
            original_len: d_out.len() as u32,
            data: Cow::Borrowed(d_out),
            options: supplemental_fields.into(),
        };

        match { writer.lock().unwrap().write_pcapng_block(out) } {
            Ok(_) => continue,
            Err(e) => println!("thread {id} failed to write packet: {e}"),
        }
    }
    debug!("thread {id} shutting down")
}

fn parse_targets(input: String) -> Vec<IpNet> {
    // vec!["192.122.190.0/24".parse()?]
    if input.is_empty() {
        return vec![];
    }

    let mut out = vec![];
    for s in input.split(',') {
        if let Ok(subnet) = s.trim().parse() {
            out.push(subnet);
            debug!("adding target: {subnet}");
        } else {
            warn!("failed to parse subnet: \"{s}\" continuing");
        }
    }
    out
}

fn parse_asn_list(input: Option<String>) -> Vec<u32> {
    match input {
        None => vec![],
        Some(s) => {
            if s.is_empty() {
                vec![]
            } else {
                let mut out = vec![];
                for s in s.split(',') {
                    out.push(s.trim().parse().unwrap());
                }
                out
            }
        }
    }
}

fn parse_cc_list(input: Option<String>) -> Vec<String> {
    match input {
        None => vec![],
        Some(s) => {
            if s.is_empty() {
                vec![]
            } else {
                s.split(',').map(|s| s.trim().to_string()).collect()
            }
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
// [X] reading from multiple __interfaces__ simultaneously
//
// [X] conditional limitations on the number of packets captured
//
// [X] verbose / debug printing for runtime errors.

#[cfg(test)]
mod tests {
    mod threading;

    use super::*;
    use ipnet::IpNet;
    use maxminddb::geoip2;
    use std::net::IpAddr;

    #[test]
    fn test_parse() -> Result<(), Box<dyn Error>> {
        let ss_cc = parse_cc_list(None);
        assert_eq!(ss_cc.len(), 0);

        let empty_case = String::from("");
        let ss_cc = parse_cc_list(Some(empty_case));
        assert_eq!(ss_cc.len(), 0);

        let good_cases = String::from("aa,bb,cc , dd , ff");
        let ss_cc = parse_cc_list(Some(good_cases));
        assert_eq!(ss_cc.len(), 5);
        for a in ss_cc {
            assert!(!a.contains(' '));
        }

        let good_cases = Some(String::from("1,2,3, 4, 5 ,  6  "));
        let ss_asn = parse_asn_list(good_cases);
        assert_eq!(ss_asn.len(), 6);

        Ok(())
    }

    #[test]
    fn test_cc_and_asn_lookup() -> Result<(), String> {
        const ASNDB_PATH_TEST: &str = "./test_mmdbs/GeoLite2-ASN.mmdb";
        const CCDB_PATH_TEST: &str = "./test_mmdbs/GeoLite2-Country.mmdb";
        let asn_reader = maxminddb::Reader::open_readfile(String::from(ASNDB_PATH_TEST)).unwrap();

        let cc_reader = maxminddb::Reader::open_readfile(String::from(CCDB_PATH_TEST)).unwrap();

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
