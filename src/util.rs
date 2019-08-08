extern crate libc;
extern crate hex;
extern crate hkdf;
extern crate sha2;
extern crate ipnetwork;

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::collections::LinkedList;
use std::error::Error;

use pnet::packet::Packet;
use pnet::packet::tcp::{TcpOptionNumbers, TcpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

use self::ipnetwork::{IpNetwork};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub enum IpPacket<'p> {
    V4(Ipv4Packet<'p>),
    V6(Ipv6Packet<'p>),
}

impl<'p> IpPacket<'p> {
    pub fn tcp(&'p self) -> Option<TcpPacket<'p>> {
        let payload = match self {
            IpPacket::V4(v4) => v4.payload(),
            IpPacket::V6(v6) => v6.payload(),
        };
        TcpPacket::new(payload)
    }
}


// Pass in a host-order IPv4 addr, get a String.
#[inline]
pub fn inet_htoa(ip: u32) -> String {
    format!("{}.{}.{}.{}", (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            (ip) & 0xff)
}

// Returns host-order u32.
#[inline]
pub fn deser_be_u32_slice(arr: &[u8]) -> u32
{
    if arr.len() != 4 {
        error!("deser_be_u32_slice given bad slice. length: {}", arr.len());
        return 0;
    }

    (arr[0] as u32) << 24 |
        (arr[1] as u32) << 16 |
        (arr[2] as u32) << 8 |
        (arr[3] as u32)
}

#[inline]
pub fn deser_be_u32(arr: &[u8; 4]) -> u32
{
    (arr[0] as u32) << 24 |
        (arr[1] as u32) << 16 |
        (arr[2] as u32) << 8 |
        (arr[3] as u32)
}

// Returns (tcp_ts, tcp_ts_ecr) in host order.
pub fn get_tcp_timestamps(tcp_pkt: &TcpPacket) -> (u32, u32)
{
    match tcp_pkt.get_options_iter()
        .find(|x| x.get_number() == TcpOptionNumbers::TIMESTAMPS)
        {
            Some(p) => (deser_be_u32_slice(&p.payload()[0..4]),  // timestamp
                        deser_be_u32_slice(&p.payload()[4..8])), // echo reply
            None => (0, 0),
        }
}

// Call on two TCP seq#s from reasonably nearby within the same TCP connection.
// No need for s1 to be earlier in the sequence than s2.
// Returns whether a wraparound happened in between.
pub fn tcp_seq_is_wrapped(s1: u32, s2: u32) -> bool
{
    ((s1 as i64) - (s2 as i64)).abs() > 2147483648
}

// a <= b, guessing about wraparound
pub fn tcp_seq_lte(a: u32, b: u32) -> bool
{
    if a == b { true } else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) { !res } else { res }
    }
}

// a < b, guessing about wraparound
pub fn tcp_seq_lt(a: u32, b: u32) -> bool
{
    if a == b { false } else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) { !res } else { res }
    }
}

// Returns memory used by this process. Should be equivalent to the RES field of
// top. Units are "kB", which I'm guessing is KiB.
pub fn mem_used_kb() -> u64
{
    let my_pid: i32 = unsafe { libc::getpid() };
    let f = match File::open(format!("/proc/{}/status", my_pid)) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open /proc/{}/status: {:?}", my_pid, e);
            return 0;
        }
    };
    let buf_f = BufReader::new(f);
    for l in buf_f.lines() {
        if let Ok(line) = l {
            if line.contains("VmRSS") {
                let (_, vmrss_gone) = line.split_at(6);
                let starts_at_number = vmrss_gone.trim_left();
                if let Some(kb_ind) = starts_at_number.find("kB") {
                    let (kb_gone, _) = starts_at_number.split_at(kb_ind);
                    let just_number = kb_gone.trim_right();
                    if let Ok(as_u64) = just_number.parse::<u64>() {
                        return as_u64;
                    }
                }
            }
        } else {
            error!("Error reading /proc/{}/status", my_pid);
            return 0;
        }
    }
    error!("Failed to parse a VmRSS value out of /proc/{}/status!", my_pid);
    return 0;
}

pub struct HKDFKeys
{
    pub fsp_key: [u8; 16],
    pub fsp_iv: [u8; 12],
    pub vsp_key: [u8; 16],
    pub vsp_iv: [u8; 12],
    pub new_master_secret: [u8; 48],
    pub dark_decoy_seed: [u8; 16],
}

impl HKDFKeys
{
    pub fn new(shared_secret: &[u8]) -> Result<HKDFKeys, Box<hkdf::InvalidLength>>
    {
        // const salt: &'static str = "tapdancetapdancetapdancetapdance";
        let salt = "tapdancetapdancetapdancetapdance".as_bytes();
        let kdf = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), shared_secret);
        let info = [0u8; 0];

        let mut output = [0u8; 120];
        kdf.expand(&info, &mut output)?;

        let mut fsp_key = [0u8; 16];
        let mut fsp_iv = [0u8; 12];
        let mut vsp_key = [0u8; 16];
        let mut vsp_iv = [0u8; 12];
        let mut new_master_secret = [0u8; 48];
        let mut dark_decoy_seed = [0u8; 16];

        fsp_key.copy_from_slice(&output[0..16]);
        fsp_iv.copy_from_slice(&output[16..28]);
        vsp_key.copy_from_slice(&output[28..44]);
        vsp_iv.copy_from_slice(&output[44..56]);
        new_master_secret.copy_from_slice(&output[56..104]);
        dark_decoy_seed.copy_from_slice(&output[104..120]);

        Ok(HKDFKeys { fsp_key, fsp_iv, vsp_key, vsp_iv, new_master_secret, dark_decoy_seed }) // syntax is very edgy and not at all confusing
    }
}


pub struct FSP {
    pub vsp_size: u16,
    pub flags: u8,
    unassigned: [u8; FSP::UNUSED_BYTES],
    bytes: Vec<u8>,
}

impl FSP {
    const UNUSED_BYTES: usize = 3;
    const USED_BYTES: usize = 3;
    const LENGTH: usize = 6;
    pub const FLAG_PROXY_HEADER: u8 = 0x4;
    pub const FLAG_UPLOAD_ONLY:  u8 = (1 << 7);
	pub const FLAG_USE_TIL:      u8 = (1 << 0);
    
    pub fn fromVec(fixed_size_payload: Vec<u8>) -> Result<FSP, Box<Error>> {
        if fixed_size_payload.len() < FSP::USED_BYTES {
            let err: Box<Error> = From::from("Not Enough bytes to parse FSP".to_string());
            return Err(err)
        } else {
            let vsp_size = ((fixed_size_payload[0] as u16) << 8) + (fixed_size_payload[1] as u16);
            return Ok( FSP{vsp_size, flags: fixed_size_payload[2], unassigned: [0u8; FSP::UNUSED_BYTES], bytes: fixed_size_payload} )
        }
    }

    pub fn check_flag(&self, flag: u8) -> bool {
        if self.flags & flag != 0 {
            return true
        } else {
            return false
        }
    }

    pub fn to_vec(&self) -> &Vec<u8> {
        let vec = &self.bytes;
        return vec
    }

    pub fn use_proxy_header(&self) -> bool {
        return self.check_flag(FSP::FLAG_PROXY_HEADER)
    }

    pub fn upload_only(&self) -> bool {
        return self.check_flag(FSP::FLAG_UPLOAD_ONLY)
    }

    pub fn use_til(&self) -> bool {
        return self.check_flag(FSP::FLAG_USE_TIL)
    }
}

#[derive(Debug)]
pub struct DDIpSelector {
    pub networks: LinkedList<IpNetwork>,
}

impl DDIpSelector {
    pub fn new(subnets: &Vec<String>, dd_client_v6_support: bool ) -> Result<DDIpSelector, self::ipnetwork::IpNetworkError> {
        let mut net_list = LinkedList::new();
        for str_net in subnets.iter() {
            let net: IpNetwork = str_net.parse()?;
            if dd_client_v6_support {
                net_list.push_back(net.clone());
            } else {
                match net {
                    IpNetwork::V4(_) => net_list.push_back(net.clone()),
                    IpNetwork::V6(_) => (),
                }
            }
        }
        Ok(DDIpSelector { networks: net_list })
    }

    pub fn select(&self, seed: [u8; 16]) -> Option<IpAddr> {
        // todo: move this to ::new() and keep static table
        let mut addresses_total: u128 = 0;
        let mut id_net = LinkedList::new(); // (min_id, max_id, subnet)
        for net in self.networks.iter() {
            match *net {
                IpNetwork::V4(_) => {
                    let old_addresses_total = addresses_total;
                    addresses_total += 2u128.pow((32 - net.prefix()).into()) - 1;
                    id_net.push_back((old_addresses_total, addresses_total, net));
                }
                IpNetwork::V6(_) => {
                    let old_addresses_total = addresses_total;
                    addresses_total += 2u128.pow((128 - net.prefix()).into()) - 1;
                    id_net.push_back((old_addresses_total, addresses_total, net));
                }
            }
        }

        let mut id = array_as_u128_be(&seed);
        if id >= addresses_total {
            id = id % addresses_total;
        }

        for elem in id_net.iter() {
            if elem.0 < id && elem.1 >= id {
                match elem.2 {
                    IpNetwork::V4(netv4) => {
                        let min_ip_u32: u32 = array_as_u32_be(&netv4.ip().octets());
                        let ip_u32 = min_ip_u32 + ((id - elem.0) as u32);
                        return Some(IpAddr::from(Ipv4Addr::from(ip_u32)));
                    }
                    IpNetwork::V6(netv6) => {
                        let min_ip_u128 = array_as_u128_be(&netv6.ip().octets());
                        let ip_u128 = min_ip_u128 + (id - elem.0);
                        return Some(IpAddr::from(Ipv6Addr::from(ip_u128)));
                    }
                }
            }
        }
        error!("failed to pick dark decoy IP with seed={:?}, in {:?}", seed, id_net);
        None
    }
}


fn array_as_u128_be(a: &[u8; 16]) -> u128 {
    ((a[0] as u128) << 120) +
        ((a[1] as u128) << 112) +
        ((a[2] as u128) << 104) +
        ((a[3] as u128) << 96) +
        ((a[4] as u128) << 88) +
        ((a[5] as u128) << 80) +
        ((a[6] as u128) << 72) +
        ((a[7] as u128) << 64) +
        ((a[8] as u128) << 56) +
        ((a[9] as u128) << 48) +
        ((a[10] as u128) << 40) +
        ((a[11] as u128) << 32) +
        ((a[12] as u128) << 24) +
        ((a[13] as u128) << 16) +
        ((a[14] as u128) << 8) +
        ((a[15] as u128) << 0)
}

fn array_as_u32_be(a: &[u8; 4]) -> u32 {
    ((a[0] as u32) << 24) +
        ((a[1] as u32) << 16) +
        ((a[2] as u32) << 8) +
        ((a[3] as u32) << 0)
}


#[cfg(test)]
mod tests {
    use util;
    use util::{DDIpSelector};
    use rand::Rng;
    use super::ipnetwork::{IpNetwork};

 
    #[test]
    fn mem_used_kb_parses_something()
    {
        assert!(util::mem_used_kb() > 0);
    }

    #[test]
    fn test_dd_ip_selector4() {

        let dd_ip_selector = match DDIpSelector::new(
            &vec![String::from("192.122.190.0/24"), String::from("2001:48a8:687f:1::/64")], 
            false) {
            Ok(dd) => dd,
            Err(e) => {
                panic!("failed to make Dark Decoy IP selector: {}", e);
            }
        };

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        println!("{:?}\n", dd_ip_selector.select(seed_bytes));

        for net in dd_ip_selector.networks.iter() {
            match *net {
                IpNetwork::V4(_) => {}
                IpNetwork::V6(_) => {
                    panic!("Error V6 address block found");
                }
            }
        }
    }

    #[test]
    fn test_dd_ip_selector6() {
        let dd_ip_selector = match DDIpSelector::new(
            &vec![String::from("192.122.190.0/24"), String::from("2001:48a8:687f:1::/64")],
            true) {
            Ok(dd) => dd,
            Err(e) => {
                panic!("failed to make Dark Decoy IP selector: {}", e);
            }
        };

        let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
        println!("{:?}\n", dd_ip_selector.select(seed_bytes));
    }
}
