use hmac::{Hmac, Mac};
use ipnet::{IpBitAnd, IpBitOr, IpNet};
use pcap::Linktype;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use sha2::Sha256;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::limit::Limit;
use crate::packet_handler::SupplementalFields;

type HmacSha256 = Hmac<Sha256>;

#[allow(dead_code, clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub enum PacketType {
    TCPSYN,
    TCPOther,
    UDP,
    Other, // Anything other than the useful ones.
}

impl Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TCPSYN => write!(f, "tcp-syn"),
            Self::TCPOther => write!(f, "tcp"),
            Self::UDP => write!(f, "udp"),
            Self::Other => write!(f, "other"),
        }
    }
}

#[derive(Debug)]
pub enum IpPacket<'p> {
    V4(Ipv4Packet<'p>),
    V6(Ipv6Packet<'p>),
}

impl<'p> IpPacket<'p> {
    fn ports(&'p self) -> Result<(u16, u16), Box<dyn Error>> {
        match self.next_layer() {
            IpNextHeaderProtocols::Tcp => {
                let t = TcpPacket::new(self.payload()).ok_or("broken udp packet")?;
                Ok((t.get_source(), t.get_destination()))
            }
            IpNextHeaderProtocols::Udp => {
                let u = UdpPacket::new(self.payload()).ok_or("broken udp packet")?;
                Ok((u.get_source(), u.get_destination()))
            }
            _ => Err("no ports for this protocol".into()),
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(v4) => v4.payload(),
            IpPacket::V6(v6) => v6.payload(),
        }
    }

    pub fn next_layer(&'p self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::V4(v4) => v4.get_next_level_protocol(),
            IpPacket::V6(v6) => v6.get_next_header(),
        }
    }
}

#[derive(Debug)]
pub enum MutableIpPacket<'p> {
    V4(MutableIpv4Packet<'p>),
    V6(MutableIpv6Packet<'p>),
}

impl<'p> From<MutableIpv4Packet<'p>> for MutableIpPacket<'p> {
    fn from(value: MutableIpv4Packet<'p>) -> Self {
        MutableIpPacket::V4(value)
    }
}
impl<'p> From<MutableIpv6Packet<'p>> for MutableIpPacket<'p> {
    fn from(value: MutableIpv6Packet<'p>) -> Self {
        MutableIpPacket::V6(value)
    }
}

impl<'p> TryFrom<(&'p mut [u8], Linktype)> for MutableIpPacket<'p> {
    type Error = ();

    fn try_from(input: (&'p mut [u8], Linktype)) -> Result<Self, Self::Error> {
        let (data, link_type) = input;
        if data.is_empty() {
            Err(())?
        }
        match link_type {
            Linktype::IPV4 => Ok(MutableIpv4Packet::new(data).ok_or(())?.into()),
            Linktype::IPV6 => Ok(MutableIpv6Packet::new(data).ok_or(())?.into()),
            Linktype::ETHERNET => {
                if data.len() < 14 {
                    // println!("ETH SHORT");
                    Err(())?
                }
                match u16::from_be_bytes([data[12], data[13]]) {
                    0x0800 => Ok(MutableIpPacket::V4(
                        MutableIpv4Packet::new(&mut data[14..]).ok_or(())?,
                    )),
                    0x86DD => Ok(MutableIpPacket::V6(
                        MutableIpv6Packet::new(&mut data[14..]).ok_or(())?,
                    )),
                    0x8100 => {
                        if data.len() < 18 {
                            Err(())?
                        }
                        match u16::from_be_bytes([data[15], data[16]]) {
                            0x0800 => Ok(MutableIpPacket::V4(
                                MutableIpv4Packet::new(&mut data[17..]).ok_or(())?,
                            )),
                            0x86DD => Ok(MutableIpPacket::V6(
                                MutableIpv6Packet::new(&mut data[17..]).ok_or(())?,
                            )),
                            _ => Err(())?,
                        }
                    }
                    _ => Err(())?,
                }
            }
            Linktype::RAW => match data[0] & 0xF0 {
                0x40 => Ok(MutableIpv4Packet::new(data).ok_or(())?.into()),
                0x60 => Ok(MutableIpv6Packet::new(data).ok_or(())?.into()),
                _ => Err(())?,
            },
            _ if link_type.0 == 12 => {
                // For some reason tun interfaces say "RAW" type, but use id 12 which isn't a real value.
                match data[0] & 0xF0 {
                    0x40 => Ok(MutableIpv4Packet::new(data).ok_or(())?.into()),
                    0x60 => Ok(MutableIpv6Packet::new(data).ok_or(())?.into()),
                    _ => Err(())?,
                }
            }
            _ => Err(()),
        }
    }
}

impl<'p> MutableIpPacket<'p> {
    pub fn get_packet_type(&self) -> PacketType {
        let next_layer = self.next_layer();
        match self {
            MutableIpPacket::V4(v4) => match next_layer {
                IpNextHeaderProtocols::Udp => PacketType::UDP,
                IpNextHeaderProtocols::Tcp => {
                    let t4 = match TcpPacket::new(v4.payload()) {
                        Some(t) => t,
                        None => return PacketType::Other,
                    };
                    if t4.get_flags() & 0x02 != 0 {
                        PacketType::TCPSYN
                    } else {
                        PacketType::TCPOther
                    }
                }
                _ => PacketType::Other,
            },
            MutableIpPacket::V6(v6) => match next_layer {
                IpNextHeaderProtocols::Udp => PacketType::UDP,
                IpNextHeaderProtocols::Tcp => {
                    let t6 = match TcpPacket::new(v6.payload()) {
                        Some(t) => t,
                        None => return PacketType::Other,
                    };
                    if t6.get_flags() & 0x02 != 0 {
                        PacketType::TCPSYN
                    } else {
                        PacketType::TCPOther
                    }
                }
                _ => PacketType::Other,
            },
        }
    }

    pub fn set_source(&'p mut self, addr: SocketAddr, r: u32) -> Result<(), Box<dyn Error>> {
        let next_layer = self.next_layer();
        match self {
            MutableIpPacket::V4(v4) => {
                if let IpAddr::V4(a4) = addr.ip() {
                    v4.set_source(a4)
                };
                match next_layer {
                    IpNextHeaderProtocols::Tcp => {
                        let t4 = MutableTcpPacket::new(v4.payload_mut());
                        t4.ok_or("unparseable tcp")?.set_source(addr.port());
                    }
                    IpNextHeaderProtocols::Udp => {
                        let u4 = MutableUdpPacket::new(v4.payload_mut());
                        u4.ok_or("unparseable udp")?.set_source(addr.port());
                    }
                    _ => {}
                }
            }
            MutableIpPacket::V6(v6) => {
                if let IpAddr::V6(a6) = addr.ip() {
                    v6.set_source(a6);
                    v6.set_flow_label(r)
                };
                match next_layer {
                    IpNextHeaderProtocols::Tcp => {
                        let t6 = MutableTcpPacket::new(v6.payload_mut());
                        t6.ok_or("unparseable tcp")?.set_source(addr.port());
                    }
                    IpNextHeaderProtocols::Udp => {
                        let u6 = MutableUdpPacket::new(v6.payload_mut());
                        u6.ok_or("unparseable udp")?.set_source(addr.port());
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn set_destination(&mut self, addr: SocketAddr, r: u32) -> Result<(), Box<dyn Error>> {
        let next_layer = self.next_layer();
        match self {
            MutableIpPacket::V4(v4) => {
                if let IpAddr::V4(a4) = addr.ip() {
                    v4.set_destination(a4)
                };
                match next_layer {
                    IpNextHeaderProtocols::Tcp => {
                        let t4 = MutableTcpPacket::new(v4.payload_mut());
                        t4.ok_or("unparseable tcp")?.set_destination(addr.port());
                    }
                    IpNextHeaderProtocols::Udp => {
                        let u4 = MutableUdpPacket::new(v4.payload_mut());
                        u4.ok_or("unparseable udp")?.set_destination(addr.port());
                    }
                    _ => {}
                }
            }
            MutableIpPacket::V6(v6) => {
                if let IpAddr::V6(a6) = addr.ip() {
                    v6.set_destination(a6);
                    v6.set_flow_label(r)
                };
                match next_layer {
                    IpNextHeaderProtocols::Tcp => {
                        let t6 = MutableTcpPacket::new(v6.payload_mut());
                        t6.ok_or("unparseable tcp")?.set_destination(addr.port());
                    }
                    IpNextHeaderProtocols::Udp => {
                        let u6 = MutableUdpPacket::new(v6.payload_mut());
                        u6.ok_or("unparseable udp")?.set_destination(addr.port());
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn source(&'p self) -> IpAddr {
        match self {
            MutableIpPacket::V4(v4) => IpAddr::V4(v4.get_source()),
            MutableIpPacket::V6(v6) => IpAddr::V6(v6.get_source()),
        }
    }

    pub fn destination(&'p self) -> IpAddr {
        match self {
            MutableIpPacket::V4(v4) => IpAddr::V4(v4.get_destination()),
            MutableIpPacket::V6(v6) => IpAddr::V6(v6.get_destination()),
        }
    }

    pub fn next_layer(&'p self) -> IpNextHeaderProtocol {
        match self {
            MutableIpPacket::V4(v4) => v4.get_next_level_protocol(),
            MutableIpPacket::V6(v6) => v6.get_next_header(),
        }
    }

    pub fn to_immutable(&self) -> IpPacket {
        match self {
            MutableIpPacket::V4(v4) => IpPacket::V4(v4.to_immutable()),
            MutableIpPacket::V6(v6) => IpPacket::V6(v6.to_immutable()),
        }
    }

    pub fn packet(&self) -> *const [u8] {
        match self {
            MutableIpPacket::V4(v4) => v4.packet(),
            MutableIpPacket::V6(v6) => v6.packet(),
        }
    }

    pub fn anonymize<'l, L>(
        &'p mut self,
        seed: [u8; 32],
        info: SupplementalFields,
        limiter: &'l mut Option<L>,
    ) -> Result<&'p [u8], Box<dyn Error>>
    where
        &'l mut L: Limit + 'l,
    {
        let src_or_dst = info.direction;

        let src = self.source();
        let dst = self.destination();
        let (src_port, dst_port) = self.to_immutable().ports()?;
        let packet_type = self.get_packet_type();

        debug!("{src}:{src_port} -> {dst}:{dst_port}");
        let s = format_str(src_or_dst, src, dst, src_port, dst_port);

        if let Some(ref mut l) = &mut limiter.as_mut() {
            if let Err(e) = l.count_or_drop_many(
                // vec![info.asn.into(), info.cc.clone().into()],
                vec![info.asn.into()],
                s.clone(),
                packet_type,
            ) {
                // if we fail to count for some reason (full for one of the fields or term flag
                // return err). The error value is available if we want more in debug print / return
                Err(e)?
            }
        }

        let hmac_bytes = get_hmac(seed, s.as_bytes());

        let p = self.packet();

        // We ned to randomize the IPv6 flow label if the flow is ipv6.
        let flow_label = u32::from_be_bytes([
            hmac_bytes[18],
            hmac_bytes[19],
            hmac_bytes[20],
            hmac_bytes[21],
        ]);
        if src_or_dst {
            let new_addr = substitute_addr(&src, info.subnet, hmac_bytes)?;
            self.set_source(new_addr, flow_label)?;
        } else {
            let new_addr = substitute_addr(&dst, info.subnet, hmac_bytes)?;
            self.set_destination(new_addr, flow_label)?;
        }

        unsafe { Ok(&*p) }
    }
}

fn substitute_addr(a: &IpAddr, s: IpNet, r: Vec<u8>) -> Result<SocketAddr, Box<dyn Error>> {
    if r.len() < 18 {
        return Err("not enough random bytes passed")?;
    }

    let new_p = ((r[0] as u16) << 8) | r[1] as u16;
    let new_a = match a {
        IpAddr::V4(a4) => {
            let addr: IpAddr;
            let out: [u8; 4] = r[2..6].try_into()?;
            if let IpAddr::V4(netmask) = s.netmask() {
                if let IpAddr::V4(hostmask) = s.hostmask() {
                    let upper = a4.bitand(netmask);
                    let lower = Ipv4Addr::from(out).bitand(hostmask);
                    addr = IpAddr::V4(upper.bitor(lower));
                } else {
                    return Err("IP version mismatch")?;
                }
            } else {
                return Err("IP version mismatch")?;
            }
            addr
        }
        IpAddr::V6(a6) => {
            let addr: IpAddr;
            let out: [u8; 16] = r[2..18].try_into()?;
            if let IpAddr::V6(netmask) = s.netmask() {
                if let IpAddr::V6(hostmask) = s.hostmask() {
                    let upper = a6.bitand(netmask);
                    let lower = Ipv6Addr::from(out).bitand(hostmask);
                    addr = IpAddr::V6(upper.bitor(lower));
                } else {
                    return Err("IP version mismatch")?;
                }
            } else {
                return Err("IP version mismatch")?;
            }
            addr
        }
    };

    Ok(SocketAddr::new(new_a, new_p))
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

fn get_hmac(seed: [u8; 32], m: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&seed).expect("HMAC can take key of any size");
    mac.update(m);

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes`, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeats
    // the security provided by the `CtOutput`
    result.into_bytes()[..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::Linktype;
    use pnet::packet::Packet;

    #[test]
    fn test_ip_end_to_end() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let is_upload = false;
        let net = IpNet::V4("94.74.182.249/21".parse()?);

        let mut packet_bytes = hex::decode("002688754a810cc47ac3674a08004500002c000040004006a70dc07abe005e4ab6f901bb4b0ee583bf75000000016012a56493dd0000020405b4")?;
        let data: (&mut [u8], Linktype) = (&mut packet_bytes, Linktype::ETHERNET);
        let mut ip = MutableIpPacket::try_from(data).unwrap();

        assert_eq!(ip.source(), "192.122.190.0".parse::<IpAddr>()?);
        assert_eq!(ip.destination(), "94.74.182.249".parse::<IpAddr>()?,);

        let extra = SupplementalFields {
            subnet: net,
            cc: String::from("ir"),
            asn: 12345,
            direction: is_upload,
        };

        let ip_pkt_out = ip.anonymize(seed, extra, &mut None)?;

        let ip4 = Ipv4Packet::new(ip_pkt_out).ok_or("broken ip layer")?;
        assert_eq!(ip4.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ip4.get_source(), "192.122.190.0".parse::<Ipv4Addr>()?);
        assert!(
            net.contains(&IpAddr::V4(ip4.get_destination())),
            "{:?} does not contain {:?}",
            net,
            ip4.get_destination()
        );
        assert_eq!(ip4.get_destination(), "94.74.177.171".parse::<Ipv4Addr>()?);

        Ok(())
    }

    #[test]
    fn test_ip_end_to_end_v6() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let is_upload = true;
        let net = IpNet::V6("1234::1/64".parse()?);

        let mut packet_bytes = hex::decode("00000000000000000000000086dd600cdd3e002806401234000000000000000000000000000120010000000000000000000000000001ed34115cd1a5623100000000a002ffc4003000000204ffc40402080a05fb55260000000001030307")?;
        let data: (&mut [u8], Linktype) = (&mut packet_bytes, Linktype::ETHERNET);
        let mut ip = MutableIpPacket::try_from(data).unwrap();

        assert_eq!(ip.source(), "1234::1".parse::<IpAddr>()?);
        assert_eq!(ip.destination(), "2001::1".parse::<IpAddr>()?,);

        let extra = SupplementalFields {
            subnet: net,
            cc: String::from("ir"),
            asn: 12345,
            direction: is_upload,
        };

        let d_out = ip.anonymize(seed, extra, &mut None)?;

        let ip_pkt_out = Ipv6Packet::new(d_out).unwrap();

        assert_eq!(ip_pkt_out.get_destination(), "2001::1".parse::<Ipv6Addr>()?);
        assert_ne!(ip_pkt_out.get_source(), "1234::1".parse::<Ipv6Addr>()?);
        assert!(
            net.contains(&IpAddr::V6(ip_pkt_out.get_source())),
            "{:?} does not contain {:?}",
            net,
            ip_pkt_out.get_source()
        );

        let tcp = TcpPacket::new(ip_pkt_out.payload()).ok_or("broken tcp packet")?;
        assert_eq!(4444, tcp.get_destination());
        assert_ne!(60724, tcp.get_source()); // make sure the port was randomized.
        Ok(())
    }

    #[test]
    fn test_ip_hmac_substiture_addr() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let subnet: IpNet = "10.12.0.0/16".parse()?;

        let src: IpAddr = IpAddr::V4("10.12.34.56".parse()?);
        let dst: IpAddr = IpAddr::V4("1.2.3.4".parse()?);
        let src_port = 3456;
        let dst_port = 7890;
        let s1 = format_str(true, src, dst, src_port, dst_port);
        assert_eq!(s1, "10.12.34.56:3456->1.2.3.4:7890");
        let hm = get_hmac(seed, s1.as_bytes());

        let new_addr = substitute_addr(&src, subnet, hm)?;
        assert!(
            subnet.contains(&new_addr.ip()),
            "{subnet:?} does not contain {new_addr:?}"
        );

        Ok(())
    }

    #[test]
    fn test_ip_hmac_substiture_addr_v6() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let subnet: IpNet = "1ff::/64".parse()?;

        let src: IpAddr = IpAddr::V6("1ff::2001".parse()?);
        let dst: IpAddr = IpAddr::V6("2001:2222::dead:beef".parse()?);
        let src_port = 3456;
        let dst_port = 7890;
        let s1 = format_str(true, src, dst, src_port, dst_port);
        assert_eq!(s1, "[1ff::2001]:3456->[2001:2222::dead:beef]:7890");
        let hm = get_hmac(seed, s1.as_bytes());

        let new_addr = substitute_addr(&src, subnet, hm)?;
        assert!(
            subnet.contains(&new_addr.ip()),
            "{subnet:?} does not contain {new_addr:?}"
        );
        Ok(())
    }

    #[test]
    fn test_ip_hmac() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let hmac_bytes = get_hmac(seed, b"input message");

        let expected =
            hex::decode("f5a562d6097bf812abbd7830e4cdb3c0f5d115c2bb8a5a861750ae1116dff7d4")
                .unwrap();
        assert_eq!(hmac_bytes[..], expected[..]);
        Ok(())
    }

    #[test]
    fn test_ip_hmac_reverse_v4() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];

        let src: IpAddr = IpAddr::V4("10.12.34.56".parse()?);
        let dst: IpAddr = IpAddr::V4("1.2.3.4".parse()?);
        let src_port = 3456;
        let dst_port = 7890;
        let s1 = format_str(true, src, dst, src_port, dst_port);
        assert_eq!(s1, "10.12.34.56:3456->1.2.3.4:7890");
        let s2 = format_str(false, dst, src, dst_port, src_port);
        assert_eq!(s1, s2);

        let hm = get_hmac(seed, s1.as_bytes());
        let expected_hm =
            hex::decode("1b284c47ac28518b0489e6e2140d9bc2c6169f48faa7edd78cab3005588d2266")
                .unwrap();
        assert_eq!(hm[..], expected_hm[..]);
        Ok(())
    }

    #[test]
    fn test_ip_hmac_reverse_v6() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];

        let src: IpAddr = IpAddr::V6("1ff::2001".parse()?);
        let dst: IpAddr = IpAddr::V6("2001:2222::dead:beef".parse()?);
        let src_port = 3456;
        let dst_port = 7890;
        let s1 = format_str(true, src, dst, src_port, dst_port);
        assert_eq!(s1, "[1ff::2001]:3456->[2001:2222::dead:beef]:7890");
        let s2 = format_str(false, dst, src, dst_port, src_port);
        assert_eq!(s1, s2);

        let hm = get_hmac(seed, s1.as_bytes());
        let expected_hm =
            hex::decode("afbe350e57b9b4d3932f4507e20284270002321ddf68e9fd61e1173978fec6b0")
                .unwrap();
        assert_eq!(hm[..], expected_hm[..]);
        Ok(())
    }

    #[test]
    fn test_parse_ip() -> Result<(), Box<dyn Error>> {
        let ip4 = hex::decode("4500002c000040004006a70dc07abe005e4ab6f901bb4b0ee583bf75000000016012a56493dd0000020405b4")?;
        let eth = hex::decode("002688754a810cc47ac3674a08004500002c000040004006a70dc07abe005e4ab6f901bb4b0ee583bf75000000016012a56493dd0000020405b4")?;
        let ip6 = hex::decode("600cdd3e002806401234000000000000000000000000000120010000000000000000000000000001ed34115cd1a5623100000000a002ffc4003000000204ffc40402080a05fb55260000000001030307")?;

        let packets = vec![ip4.clone(), ip6.clone(), eth, ip4, ip6];
        let types = vec![
            Linktype::IPV4,
            Linktype::IPV6,
            Linktype::ETHERNET,
            Linktype(12),
            Linktype::RAW,
        ];

        for (mut data, link_type) in packets.into_iter().zip(types) {
            println!("{}", hex::encode(data.clone()));
            let input: (&mut [u8], Linktype) = (&mut data, link_type);
            let ip_pkt = MutableIpPacket::try_from(input).unwrap();

            println!("{}", ip_pkt.source());
            println!("{}", ip_pkt.destination());
        }

        let other = (&mut [0u8; 32][..], Linktype::SCTP);
        assert!(MutableIpPacket::try_from(other).is_err());

        let other = (&mut [0u8; 32][..], Linktype::RAW);
        assert!(MutableIpPacket::try_from(other).is_err());

        Ok(())
    }
}
