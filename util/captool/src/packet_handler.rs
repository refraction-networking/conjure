use crate::flows::LimiterState;
use crate::limit::LimitError;

use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;

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

    pub stats: HashMap<Flow, FlowStats>,

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

/// Statistics for a given Flow
pub struct FlowStats {
    pub packet_count: u32,
    // ipv4
    pub ipids: Option<Vec<u16>>,
    pub ttl_range: Option<Vec<u8>>,

    // ipv6
    pub flow_label: Option<u32>,
    pub hop_limit_range: Option<Vec<u8>>,
    // tcp
    // pub TCPOptions: bool,
}

impl FlowStats {
    pub fn new(ip_pkt: &IpPacket, _tcp_pkt: &TcpPacket) -> FlowStats {
        match ip_pkt {
            IpPacket::V4(pkt) => FlowStats {
                packet_count: 1,
                ipids: Some(vec![pkt.get_identification()]),
                ttl_range: Some(vec![pkt.get_ttl()]),
                flow_label: None,
                hop_limit_range: None,
                // TCPOptions: ,
            },
            IpPacket::V6(pkt) => FlowStats {
                packet_count: 1,
                ipids: None,
                ttl_range: None,
                flow_label: Some(pkt.get_flow_label()),
                hop_limit_range: Some(vec![pkt.get_hop_limit()]),
                // TCPOptions: ,
            },
        }
    }

    pub fn append(&mut self, ip_pkt: &IpPacket, _tcp_pkt: &TcpPacket) {
        match ip_pkt {
            IpPacket::V4(pkt) =>
            {
                self.packet_count += 1;
                self.ipids.as_mut().expect("identification of ipv4 packet not initialized").push(pkt.get_identification());
                self.ttl_range.as_mut().expect("ttl of ipv4 packet not initialized").push(pkt.get_ttl());
            },
            IpPacket::V6(pkt) => {
                self.packet_count += 1;
                self.hop_limit_range.as_mut().expect("hop limit of ipv6 packet not initialized").push(pkt.get_hop_limit());
            },
        }
    }
}

impl fmt::Display for FlowStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} packets in flow", self.packet_count)
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
            stats: HashMap::new(),
        };
        OsRng.fill_bytes(&mut p.seed);
        Ok(p)
    }

    pub fn append_to_stats(&mut self, ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) {
        let curr_flow = Flow::new(ip_pkt, tcp_pkt);
        if !self.stats.contains_key(&curr_flow) {
            let curr_stats = FlowStats::new(ip_pkt, tcp_pkt);
            self.stats.insert(curr_flow, curr_stats);
            debug!("new flow! {}\n{}", curr_flow, self.stats[&curr_flow]);
        }
        else {
            if let Some(x) = self.stats.get_mut(&curr_flow) {
                x.append(ip_pkt, tcp_pkt); debug!("{}\n{}", curr_flow, self.stats[&curr_flow]);
            }
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
