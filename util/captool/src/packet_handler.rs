use crate::flows::LimiterState;
use crate::limit::LimitError;

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::cmp::{min, max};
use csv::Writer;

use crate::ip::IpPacket;
use ipnet::IpNet;
use maxminddb::{geoip2, MaxMindDBError, Reader};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct PacketHandler {
    pub asn_reader: Reader<Vec<u8>>,
    pub cc_reader: Reader<Vec<u8>>,
    pub limiter: Option<LimiterState>,

    // target_subnets is used to determine whether source or destination is the address we need
    // to anonymize.
    pub target_subnets: Vec<IpNet>,

    // cc_filter allows us to rule out packets we are not interested in capturing before processing them
    pub cc_filter: Vec<String>,
    // asn_filter allows us to rule out packets we are not interested in capturing before processing them
    pub asn_filter: Vec<u32>,

    // respect CLI options indicating capture of only one or the other IP version.
    pub v4_only: bool,
    pub v6_only: bool,

    // subnets from which to ignore incoming packets
    pub exclude_subnets: Vec<IpNet>,

    pub stats: HashMap<Flow, FlowStats>,
    pub stats_output_path: String,

    pub seed: [u8; 32],
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: IpNextHeaderProtocol,
}

impl Flow {
    pub fn new(ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> Flow {
        match ip_pkt {
            IpPacket::V4(pkt) => Flow {
                src_ip: IpAddr::V4(pkt.get_source()),
                dst_ip: IpAddr::V4(pkt.get_destination()),
                src_port: tcp_pkt.get_source(),
                dst_port: tcp_pkt.get_destination(),
                proto: IpNextHeaderProtocols::Tcp,
            },
            IpPacket::V6(pkt) => Flow {
                src_ip: IpAddr::V6(pkt.get_source()),
                dst_ip: IpAddr::V6(pkt.get_destination()),
                src_port: tcp_pkt.get_source(),
                dst_port: tcp_pkt.get_destination(),
                proto: IpNextHeaderProtocols::Tcp,
            },
        }
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{si}:{sp} -> {di}:{dp}", si = self.src_ip, sp = self.src_port, di = self.dst_ip, dp = self.dst_port)
    }
}

#[derive(Clone)]
/// Statistics for a given Flow
pub struct FlowStats{
    pub packet_count: u32,
    pub init_seq_num: u32,
    pub recent_comments: Vec<String>,

    // ipv4
    pub ipids: Option<IpidStats>,
    pub ttl_range: Option<TtlStats>,

    // ipv6
    pub flow_label: Option<u32>,
    pub hop_limit_range: Option<HopLimitStats>,

    pub cc: String,
    pub asn: u32,
}

impl FlowStats {
    pub fn new(ip_pkt: &IpPacket, _tcp_pkt: &TcpPacket, supplemental_fields: &SupplementalFields) -> FlowStats {
        match ip_pkt {
            IpPacket::V4(_pkt) => FlowStats {
                packet_count: 1,
                init_seq_num: _tcp_pkt.get_sequence(),
                recent_comments: vec![],
                ipids: None,
                ttl_range: None,
                flow_label: None,
                hop_limit_range: None,
                asn: supplemental_fields.asn,
                cc: supplemental_fields.cc.clone(),
            },
            IpPacket::V6(pkt) => FlowStats {
                packet_count: 1,
                init_seq_num: _tcp_pkt.get_sequence(),
                recent_comments: vec![],
                ipids: None,
                ttl_range: None,
                flow_label: Some(pkt.get_flow_label()),
                hop_limit_range: Some(HopLimitStats::new(pkt.get_hop_limit())),
                asn: supplemental_fields.asn,
                cc: supplemental_fields.cc.clone(),
            },
        }
    }

    /// append a packet to the given FlowStats object
    pub fn append(&mut self, ip_pkt: &IpPacket, _tcp_pkt: &TcpPacket) {
        match ip_pkt {
            IpPacket::V4(pkt) =>
            {
                self.packet_count += 1;
                if _tcp_pkt.get_sequence() >= self.init_seq_num +2 {
                match self.ttl_range.as_mut() {
                    Some(ttls) => {ttls.update(pkt.get_ttl(), &mut self.recent_comments); }
                    None => {self.ttl_range = Some(TtlStats::new(pkt.get_ttl()));}
                }
                match self.ipids.as_mut() {
                    Some(ipid) => {ipid.update(pkt.get_identification(), &mut self.recent_comments);}
                    None => {self.ipids = Some(IpidStats::new(pkt.get_identification()))}
                }
            }
            }
            IpPacket::V6(pkt) => {
                self.packet_count += 1;
                self.hop_limit_range.as_mut().expect("hop limit of ipv6 packet not initialized").update(pkt.get_hop_limit(), &mut self.recent_comments);
            },
        }
    }
}

impl From<FlowStats> for Vec<EnhancedPacketOption<'_>> {
    fn from(value: FlowStats) -> Self {
        let mut re: Vec<EnhancedPacketOption<'_>> = vec![];
        for i in value.recent_comments {
            re.push(EnhancedPacketOption::Comment(Cow::from(format!("{},", i))));
        }
        re
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct IpidStats {
    pub curr_ipid: u16,

    // currently tracks 5 most recent offsets
    pub recent_offsets: VecDeque<u16>,

    pub min_offset: Option<u16>,
    pub max_offset: Option<u16>,

    /* ANOMALOUS PACKET TYPES 
        0 - IPID = 0
        1 - IPID delta is 0
        2 - IPID delta changed
    */
    anomalous_pkts: Vec<u32>,
}

impl IpidStats{
    pub fn new(ipid: u16) -> IpidStats {
        IpidStats {
            curr_ipid: ipid,
            recent_offsets: VecDeque::new(),
            min_offset : None,
            max_offset : None,
            anomalous_pkts : vec![0,0,0],
        }
    }

    pub fn update(&mut self, new_ipid: u16, comments: &mut Vec<String>) {
        let new_off = (self.curr_ipid as i32 - new_ipid as i32).abs() as u16;

        // anomaly type 0
        if new_ipid == 0 {
            self.anomalous_pkts[0]+= 1;
            comments.push(format!("ipid0: IPID = 0"));
        }

        // anomaly type 1
        if new_off == 0 {
            self.anomalous_pkts[1]+= 1;
            comments.push(format!("ipid1: IPID delta = 0"));
        }

        if self.recent_offsets.len() < 5 {
            self.recent_offsets.push_back(new_off);
            self.curr_ipid = new_ipid;


            match self.min_offset
            {
                Some(mo) => { self.min_offset = Some(min(mo, new_off)); }
                None => { self.min_offset = Some(new_off);}
            }
            match self.max_offset
            {
                Some(mo) => { self.max_offset = Some(max(mo, new_off)); }
                None => { self.max_offset = Some(new_off);}
            }
        }
        else {


            // let avg = 0;
            // for offs in self.recent_offsets {
            //     avg += offs;
            // }
            // avg /= 5;

            // anomaly type 2
            if Some(&new_off) != self.recent_offsets.back()
            {
                self.anomalous_pkts[2] += 1;
                comments.push(format!("IPID delta changed"));
            }

            self.recent_offsets.pop_front();
            self.recent_offsets.push_back(new_off);
            self.curr_ipid = new_ipid;

            match self.min_offset
            {
                Some(mo) => { self.min_offset = Some(min(mo, new_off)); }
                None => { self.min_offset = Some(new_off);}
            }
            match self.max_offset
            {
                Some(mo) => { self.max_offset = Some(max(mo, new_off)); }
                None => { self.max_offset = Some(new_off);}
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct TtlStats {
    pub min_ttl: u8,
    pub max_ttl: u8,
    /* ANOMALOUS PACKET TYPES 
        0 - TTL falls outside min/max range
    */
    anomalous_pkts: Vec<u32>,
}

impl TtlStats{
    pub fn new(ttl: u8) -> TtlStats {
        TtlStats {
            min_ttl : ttl,
            max_ttl : ttl,
            anomalous_pkts : vec![0],
        }
    }

    pub fn update(&mut self, new_ttl: u8, comments: &mut Vec<String>) {
        if new_ttl < self.min_ttl {
            self.min_ttl = new_ttl;
            self.anomalous_pkts[0]+=1;
            comments.push(format!("ttl0: TTL falls out of min/max range"));
        }

        if new_ttl > self.max_ttl {
            self.max_ttl = new_ttl;
            self.anomalous_pkts[0]+=1;
            comments.push(format!("ttl0: TTL falls out of min/max range"));
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct HopLimitStats {
    pub min_hop: u8,
    pub max_hop: u8,
    /* ANOMALOUS PACKET TYPES 
        0 - Hop Limit falls outside min/max range
    */
    anomalous_pkts: Vec<u32>,
}

impl HopLimitStats{
    pub fn new(hop: u8) -> HopLimitStats {
        HopLimitStats {
            min_hop : hop,
            max_hop : hop,
            anomalous_pkts : vec![0],
        }
    }

    pub fn update(&mut self, new_hop: u8, comments: &mut Vec<String>) {
        if new_hop < self.min_hop {
            self.min_hop = new_hop;
            self.anomalous_pkts[0]+=1;
            comments.push(format!("hop0: HopCount falls out of min/max range"));


        }

        if new_hop > self.max_hop {
            self.max_hop = new_hop;
            self.anomalous_pkts[0]+=1;
            comments.push(format!("hop0: HopCount falls out of min/max range"));
        }
    }
}


#[derive(Clone)]
pub struct SupplementalFields {
    pub cc: String,
    pub asn: u32,
    pub subnet: IpNet,
    pub direction: bool,
}

#[derive(Debug)]
pub enum PacketError {
    Skip,
    SkipCC,
    SkipASN,
    SkipMissingGeoIP,
    SkipGeoip(MaxMindDBError),
    SkipLimit(LimitError),
    OtherError(Box<dyn Error>),
}

impl std::error::Error for PacketError {}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PacketError::Skip => write!(f, "irrelevant addr"),
            PacketError::SkipCC => write!(f, "irrelevant or missing cc"),
            PacketError::SkipASN => write!(f, "irrelevant or missing asn"),
            PacketError::SkipMissingGeoIP => write!(f, "no geoip entry for address"),
            PacketError::SkipGeoip(e) => write!(f, "encountered geoip lookup error {e}"),
            PacketError::SkipLimit(e) => write!(f, "skip limiter {e}"),
            PacketError::OtherError(e) => write!(f, "{e}"),
        }
    }
}

impl From<LimitError> for PacketError {
    fn from(value: LimitError) -> Self {
        PacketError::SkipLimit(value)
    }
}

impl From<MaxMindDBError> for PacketError {
    fn from(value: MaxMindDBError) -> Self {
        PacketError::SkipGeoip(value)
    }
}

impl From<Box<dyn Error>> for PacketError {
    fn from(value: Box<dyn Error>) -> Self {
        PacketError::OtherError(value)
    }
}

impl From<SupplementalFields> for Vec<EnhancedPacketOption<'_>> {
    fn from(value: SupplementalFields) -> Self {
        vec![
            EnhancedPacketOption::Comment(Cow::from(format!("cc:{:}", value.cc))),
            EnhancedPacketOption::Comment(Cow::from(format!("asn:{:}", value.asn))),
            EnhancedPacketOption::Comment(Cow::from(format!("subnet:{:}", value.subnet))),
            EnhancedPacketOption::Comment(Cow::from(format!(
                "sublen:{:}",
                value.subnet.prefix_len()
            ))),
        ]
    }
}

#[derive(PartialEq)]
enum AnonymizeTypes {
    // The source address and port need to be anonymized.
    Upload,
    // The destination address and port need to be anonymized.
    Download,
    // This is not a packet that should be included in our capture.
    None,
}

impl PacketHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        asn_path: &str,
        ccdb_path: &str,
        target_subnets: Vec<IpNet>,
        limiter: Option<LimiterState>,
        cc_filter: Vec<String>,
        asn_filter: Vec<u32>,
        v4_only: bool,
        v6_only: bool,
        exclude_subnets: Vec<IpNet>,
        stats_output_path: String
    ) -> Result<Self, Box<dyn Error>> {
        let mut p = PacketHandler {
            asn_reader: maxminddb::Reader::open_readfile(String::from(asn_path))?,
            cc_reader: maxminddb::Reader::open_readfile(String::from(ccdb_path))?,
            target_subnets,
            cc_filter,
            asn_filter,
            limiter,
            seed: [0u8; 32],
            v4_only,
            v6_only,
            exclude_subnets,
            stats: HashMap::new(),
            stats_output_path,
        };
        OsRng.fill_bytes(&mut p.seed);
        Ok(p)
    }

    pub fn append_to_stats(&mut self, ip_pkt: &IpPacket, o_tcp_pkt: &Option<TcpPacket>, supplemental_fields: &SupplementalFields, comments: &mut Vec<EnhancedPacketOption<'_>> ) {
        match o_tcp_pkt {
            Some(tcp_pkt) => {
        let curr_flow = Flow::new(ip_pkt, tcp_pkt);
        if !self.stats.contains_key(&curr_flow) {
            let curr_stats = FlowStats::new(ip_pkt, tcp_pkt, supplemental_fields);
            self.stats.insert(curr_flow, curr_stats);
            comments.append(&mut self.stats[&curr_flow].clone().into());
        }
        else {
            if let Some(x) = self.stats.get_mut(&curr_flow) {
                x.append(ip_pkt, tcp_pkt); 
            }
            comments.append(&mut self.stats[&curr_flow].clone().into());
        }
    },
    None => {},
}
    }

    pub fn get_supplemental(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<SupplementalFields, PacketError> {
        let direction = self.should_anonymize(src, dst);
        let ip_of_interest = match direction {
            AnonymizeTypes::None => Err(PacketError::Skip)?,
            AnonymizeTypes::Upload => src,
            AnonymizeTypes::Download => dst,
        };

        let (asn, prefix) = self.get_asn(ip_of_interest)?;
        let subnet = IpNet::new(ip_of_interest, prefix.try_into().unwrap_or(32))
            .unwrap()
            .trunc();

        let country = self.get_cc(ip_of_interest)?;
        debug!("{src} -> {dst}");

        Ok(SupplementalFields {
            cc: country,
            asn,
            subnet,
            direction: direction == AnonymizeTypes::Upload,
        })
    }

    fn should_anonymize(&self, src: IpAddr, dst: IpAddr) -> AnonymizeTypes {
        if (self.v4_only && src.is_ipv6()) || (self.v6_only && src.is_ipv4()) {
            return AnonymizeTypes::None;
        }

        for target_subnet in &self.target_subnets {
            if target_subnet.contains(&src) {
                return AnonymizeTypes::Download;
            } else if target_subnet.contains(&dst) {
                return AnonymizeTypes::Upload;
            }
        }
        AnonymizeTypes::None
    }

    pub fn should_exclude(&self, src: IpAddr) -> bool {
        // if (self.v4_only && src.is_ipv6()) || (self.v6_only && src.is_ipv4()) {
        //     return AnonymizeTypes::None;
        // }

        for exclude_subnet in &self.exclude_subnets {
            if exclude_subnet.contains(&src) {
                return true;
            }
        }
        false
    }

    fn get_asn(&self, addr: IpAddr) -> Result<(u32, usize), PacketError> {
        // Requires Nightly
        let (asn, prefix) = if addr.is_loopback() {
            match addr {
                IpAddr::V4(_) => (0, 8),
                IpAddr::V6(_) => (0,128),
            }
        } else if let IpAddr::V6(a6) = addr && a6.is_unique_local(){
            (0, 7)
        } else if !addr.is_global() {
            match addr {
                IpAddr::V4(_) => (0, 24),
                IpAddr::V6(_) => (0, 128),
            }
        } else {
            let (asn_rec, prefix) = match self.asn_reader.lookup_prefix::<geoip2::Asn>(addr){
                Ok((a, p)) => (a,p),
                Err(e) => Err(PacketError::OtherError(Box::new(e)))?
            };
            let asn = asn_rec.autonomous_system_number.unwrap_or(0);
            (asn, prefix)
        };

        // if the ASN filter list is empty or if the provided asn in question
        // is in our acceptable ASN list we want this packet, otherwise skip
        if !(self.asn_filter.is_empty() || self.asn_filter.contains(&asn)) {
            Err(PacketError::SkipASN)?
        }

        Ok((asn, prefix))
    }

    fn get_cc(&self, addr: IpAddr) -> Result<String, PacketError> {
        // Requires Nightly
        let country = if addr.is_loopback() {
            String::from("lo")
        } else if let IpAddr::V6(a6) = addr && a6.is_unique_local(){
            String::from("lo")
        } else if !addr.is_global() {
            String::from("pv")
        } else {
            let country_rec: geoip2::Country = self.cc_reader.lookup(addr)?;
            String::from(country_rec.country.ok_or(PacketError::SkipMissingGeoIP)?.iso_code.ok_or(PacketError::SkipMissingGeoIP)?)
        };

        // if the Country Code filter list is empty or if the provided cc in question
        // is in our acceptable Country Code list we want this packet, otherwise skip
        if !(self.cc_filter.is_empty() || self.cc_filter.contains(&country)) {
            return Err(PacketError::SkipCC)?;
        }
        Ok(country)
    }

    // pub fn print_stats(&self){
    //     for (fl, flst) in self.stats.iter() {
    //         // println!("\n{}\n{}\n-", fl, flst);
    //     }

    // }

    pub fn output_csv(&self) -> Result<(), Box<dyn Error>>{
        let mut wtr = Writer::from_path(self.stats_output_path.clone())?;

        // write headers
        wtr.write_record(&["flow_key","packet_count", "asn", "cc",  "min_ipid_delta", "max_ipid_delta", "anom_ipid_t0", "anom_ipid_t1", "anom_ipid_t2", "min_ttl", "max_ttl", "anom_ttl_t0", "flow_label", "min_hop_limit", "max_hop_limit", "anom_hop_t0"])?;

        // write stats object
        for (fl, flst) in self.stats.iter(){

            let mut to_write = vec![format!("{}:{}->{}:{}", fl.src_ip,fl.src_port,fl.dst_ip, fl.dst_port), format!("{}",flst.packet_count)];

            to_write.push(format!("{}",flst.asn));
            to_write.push(format!("{}",flst.cc));

            // v4
            match &flst.ipids {
                Some(i) => { 
                    match i.min_offset {
                        Some(mo) => {to_write.push(format!("{}",mo));}
                        None => {to_write.push("NaN".to_string());}
                    }
                    match i.max_offset {
                        Some(mo) => {to_write.push(format!("{}",mo));}
                        None => {to_write.push("NaN".to_string());}
                    }
                    for n in 0..3 {to_write.push(format!("{}", i.anomalous_pkts[n]));}
                }
                None => { for _ in 0..5 {to_write.push("NaN".to_string());}}
            }
            match &flst.ttl_range {
                Some(t) => { to_write.push(format!("{}",t.min_ttl)); to_write.push(format!("{}",t.max_ttl)); to_write.push(format!("{}",t.anomalous_pkts[0]));}
                None => { for _ in 0..3 {to_write.push("NaN".to_string());}}
            }

            // v6
            match flst.flow_label {
                Some(lab) => { to_write.push(format!("{}",lab));}
                None => { to_write.push("NaN".to_string());}
            }
            match &flst.hop_limit_range {
                Some(h) => { to_write.push(format!("{}",h.min_hop)); to_write.push(format!("{}",h.max_hop)); to_write.push(format!("{}",h.anomalous_pkts[0]));}
                None => { for _ in 0..3 {to_write.push("NaN".to_string());}}
            }
        let _ = wtr.write_record(to_write);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
    use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    use pcap_file::pcapng::PcapNgWriter;
    use pcap_file::DataLink;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::Packet;
    use tempfile::tempfile;

    #[test]
    fn test_pcapng() -> Result<(), Box<dyn Error>> {
        let mut packet_bytes = hex::decode("002688754a810cc47ac3674a08004500002c000040004006a70dc07abe005e4ab6f901bb4b0ee583bf75000000016012a56493dd0000020405b4")?;
        let eth = MutableEthernetPacket::new(&mut packet_bytes).ok_or("failed to parse eth")?;

        let file = tempfile()?;
        // let file = File::create("out.pcapng.gz").expect("Error creating file");
        let e = GzEncoder::new(file, Compression::default());
        let mut pcapng_writer = PcapNgWriter::new(e)?;

        let data = eth.packet();

        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![],
        };

        let packet = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_secs(0),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: vec![
                EnhancedPacketOption::Comment(Cow::Borrowed("cc:IR")),
                EnhancedPacketOption::Comment(Cow::Borrowed("asn:12345")),
            ],
        };

        // Write back parsed Block
        pcapng_writer.write_pcapng_block(interface)?;
        pcapng_writer.write_pcapng_block(packet)?;

        Ok(())
    }
}
