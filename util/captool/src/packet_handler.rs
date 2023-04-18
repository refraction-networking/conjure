use std::borrow::Cow;
use std::error::Error;
use std::net::IpAddr;

use ipnet::IpNet;
use maxminddb::{geoip2, Reader};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct PacketHandler {
    pub asn_reader: Reader<Vec<u8>>,
    pub cc_reader: Reader<Vec<u8>>,

    // target_subnets is used to determine whether source or destination is the address we need
    // to anonymize.
    pub target_subnets: Vec<IpNet>,

    // cc_filter allows us to rule out packets we are not interested in capturing before processing them
    pub cc_filter: Vec<String>,
    // asn_filter allows us to rule out packets we are not interested in capturing before processing them
    pub asn_filter: Vec<u32>,

    pub seed: [u8; 32],
}

pub struct SupplementalFields {
    pub cc: String,
    pub asn: u32,
    pub subnet: IpNet,
    pub direction: bool,
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
    pub fn create(asn_path: &str, ccdb_path: &str) -> Result<Self, Box<dyn Error>> {
        let mut p = PacketHandler {
            asn_reader: maxminddb::Reader::open_readfile(String::from(asn_path))?,
            cc_reader: maxminddb::Reader::open_readfile(String::from(ccdb_path))?,
            target_subnets: vec!["192.122.190.0/24".parse()?],
            cc_filter: vec![],
            asn_filter: vec![],
            seed: [0u8; 32],
        };
        OsRng.fill_bytes(&mut p.seed);
        Ok(p)
    }

    pub fn get_supplemental(
        &self,
        src: IpAddr,
        dst: IpAddr,
    ) -> Result<SupplementalFields, Box<dyn Error>> {
        let direction = self.should_anonymize(src, dst);
        let ip_of_interest = match direction {
            AnonymizeTypes::None => return Err("skip")?,
            AnonymizeTypes::Upload => src,
            AnonymizeTypes::Download => dst,
        };

        let (asn_rec, prefix) = self
            .asn_reader
            .lookup_prefix::<geoip2::Asn>(ip_of_interest)?;
        let asn = asn_rec.autonomous_system_number.unwrap();
        if !self.is_asn_of_interest(asn) {
            return Err("skip")?;
        }
        let subnet = IpNet::new(ip_of_interest, prefix.try_into().unwrap())
            .unwrap()
            .trunc();

        let country_rec: geoip2::Country = self.cc_reader.lookup(ip_of_interest).unwrap();
        let country = String::from(country_rec.country.unwrap().iso_code.unwrap());
        if !self.is_cc_of_interest(&country) {
            return Err("skip")?;
        }

        Ok(SupplementalFields {
            cc: country,
            asn,
            subnet,
            direction: direction == AnonymizeTypes::Upload,
        })
    }

    fn should_anonymize(&self, src: IpAddr, dst: IpAddr) -> AnonymizeTypes {
        for target_subnet in &self.target_subnets {
            if target_subnet.contains(&src) {
                return AnonymizeTypes::Download;
            } else if target_subnet.contains(&dst) {
                return AnonymizeTypes::Upload;
            }
        }
        AnonymizeTypes::None
    }

    // returns true if the Country Code filter list is empty or if the provided cc in question
    // is in our acceptable Country Code list.
    fn is_cc_of_interest(&self, cc: &String) -> bool {
        self.cc_filter.is_empty() || self.cc_filter.contains(&cc)
    }

    // returns true if the ASN filter list is empty or if the provided cc in question
    // is in our acceptable ASN list.
    fn is_asn_of_interest(&self, asn: u32) -> bool {
        self.asn_filter.is_empty() || self.asn_filter.contains(&asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

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
        // let file = File::create("out.pcap").expect("Error creating file");
        let mut pcapng_writer = PcapNgWriter::new(file)?;

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
            // ,subnet:192.168.0.0/16,len:16
        };

        // Write back parsed Block
        pcapng_writer.write_pcapng_block(interface)?;
        pcapng_writer.write_pcapng_block(packet)?;

        Ok(())
    }
}
