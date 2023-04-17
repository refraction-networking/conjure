use hmac::{Hmac, Mac};
use ipnet::{IpBitAnd, IpBitOr, IpNet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use sha2::Sha256;
use std::convert::TryInto;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

type HmacSha256 = Hmac<Sha256>;

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

pub fn get_mut_ip_packet<'p>(
    eth_pkt: &'p mut MutableEthernetPacket,
) -> Option<MutableIpPacket<'p>> {
    // Must happen first so we don't have an immutable borrow during a mutable borrow
    let ethertype = eth_pkt.get_ethertype();

    let payload = eth_pkt.payload_mut();

    fn parse_v4(p: &mut [u8]) -> Option<MutableIpPacket> {
        MutableIpv4Packet::new(p).map(MutableIpPacket::V4)
    }

    fn parse_v6(p: &mut [u8]) -> Option<MutableIpPacket> {
        MutableIpv6Packet::new(p).map(MutableIpPacket::V6)
    }

    match ethertype {
        EtherTypes::Vlan => {
            if payload[2] == 0x08 && payload[3] == 0x00 {
                //let vlan_id: u16 = (payload[0] as u16)*256
                //                 + (payload[1] as u16);
                parse_v4(&mut payload[4..])
            } else if payload[2] == 0x86 && payload[3] == 0xdd {
                parse_v6(&mut payload[4..])
            } else {
                None
            }
        }
        EtherTypes::Ipv4 => parse_v4(&mut payload[0..]),
        EtherTypes::Ipv6 => parse_v6(&mut payload[0..]),
        _ => None,
    }
}

impl<'p> MutableIpPacket<'p> {
    pub fn set_source(&'p mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
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
                    v6.set_source(a6)
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

    pub fn set_destination(&mut self, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
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
                    v6.set_destination(a6)
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

    pub fn anonymize(
        &'p mut self,
        src_or_dst: bool,
        seed: [u8; 32],
        subnet: IpNet,
    ) -> Result<(), Box<dyn Error>> {
        let src = self.source();
        let dst = self.destination();
        let (src_port, dst_port) = self.to_immutable().ports()?;

        let s = format_str(src_or_dst, src, dst, src_port, dst_port);
        let hmac_bytes = get_hmac(seed, s.as_bytes());

        if src_or_dst {
            let new_addr = substitute_addr(&src, subnet, hmac_bytes)?;
            self.set_source(new_addr)?;
        } else {
            let new_addr = substitute_addr(&dst, subnet, hmac_bytes)?;
            self.set_destination(new_addr)?;
        }
        Ok(())
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
    use pnet::packet::Packet;

    #[test]
    fn test_ip_end_to_end() -> Result<(), Box<dyn Error>> {
        let seed: [u8; 32] = [0; 32];
        let is_upload = false;
        let net = IpNet::V4("94.74.182.249/21".parse()?);

        let mut packet_bytes = hex::decode("002688754a810cc47ac3674a08004500002c000040004006a70dc07abe005e4ab6f901bb4b0ee583bf75000000016012a56493dd0000020405b4")?;
        let mut eth = MutableEthernetPacket::new(&mut packet_bytes).ok_or("failed to parse eth")?;
        let mut ip = get_mut_ip_packet(&mut eth).unwrap();

        assert_eq!(ip.source(), "192.122.190.0".parse::<IpAddr>()?);
        assert_eq!(ip.destination(), "94.74.182.249".parse::<IpAddr>()?,);

        ip.anonymize(is_upload, seed, net)?;
        assert_eq!(eth.to_immutable().get_ethertype(), EtherTypes::Ipv4);

        let ip4 = Ipv4Packet::new(eth.payload()).ok_or("broken ip layer")?;
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
        let mut eth = MutableEthernetPacket::new(&mut packet_bytes).ok_or("failed to parse eth")?;
        let mut ip = get_mut_ip_packet(&mut eth).unwrap();

        assert_eq!(ip.source(), "1234::1".parse::<IpAddr>()?);
        assert_eq!(ip.destination(), "2001::1".parse::<IpAddr>()?,);

        ip.anonymize(is_upload, seed, net)?;
        assert_eq!(eth.to_immutable().get_ethertype(), EtherTypes::Ipv6);

        let ip6 = Ipv6Packet::new(eth.payload()).ok_or("broken ip layer")?;
        assert_eq!(ip6.get_next_header(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ip6.get_destination(), "2001::1".parse::<Ipv6Addr>()?);
        assert_ne!(ip6.get_source(), "1234::1".parse::<Ipv6Addr>()?);
        assert!(
            net.contains(&IpAddr::V6(ip6.get_source())),
            "{:?} does not contain {:?}",
            net,
            ip6.get_source()
        );

        let tcp = TcpPacket::new(ip6.payload()).ok_or("broken udp packet")?;
        assert_eq!(4444, tcp.get_destination());
        assert_ne!(60724, tcp.get_source()); // make sure the port was randomized.

        let mut packet2_bytes =  hex::decode("00000000000000000000000086dd600cdd3e002806402001000000000000000000000000000112340000000000000000000000000001115ced34d1a5623100000000a002ffc4003000000204ffc40402080a05fb55260000000001030307")?;

        let mut eth2 =
            MutableEthernetPacket::new(&mut packet2_bytes).ok_or("failed to parse eth")?;
        let mut ip2 = get_mut_ip_packet(&mut eth2).unwrap();
        assert_eq!(ip2.destination(), "1234::1".parse::<IpAddr>()?);
        assert_eq!(ip2.source(), "2001::1".parse::<IpAddr>()?,);
        ip2.anonymize(!is_upload, seed, net)?;

        let ip62 = Ipv6Packet::new(eth2.payload()).ok_or("broken ip layer")?;
        assert_eq!(ip62.get_destination(), ip6.get_source());

        let tcp2 = TcpPacket::new(ip62.payload()).ok_or("broken udp packet")?;
        assert_eq!(tcp.get_destination(), tcp2.get_source());
        assert_eq!(tcp.get_source(), tcp2.get_destination());

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
}
