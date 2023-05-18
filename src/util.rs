extern crate hex;
extern crate hkdf;
extern crate ipnetwork;
extern crate libc;
extern crate sha2;

use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::time::SystemTime;

use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpOptionNumbers, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

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

    pub fn udp(&'p self) -> Option<UdpPacket<'p>> {
        let payload = match self {
            IpPacket::V4(v4) => v4.payload(),
            IpPacket::V6(v6) => v6.payload(),
        };
        UdpPacket::new(payload)
    }

    pub fn next_layer(&'p self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::V4(v4) => v4.get_next_level_protocol(),
            IpPacket::V6(v6) => v6.get_next_header(),
        }
    }

    pub fn ethertype(&'p self) -> EtherType {
        match self {
            IpPacket::V4(_) => EtherTypes::Ipv4,
            IpPacket::V6(_) => EtherTypes::Ipv6,
        }
    }
}

// Pass in a host-order IPv4 addr, get a String.
#[inline]
pub fn inet_htoa(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        (ip) & 0xff
    )
}

// Returns host-order u32.
#[inline]
pub fn deser_be_u32_slice(arr: &[u8]) -> u32 {
    if arr.len() != 4 {
        error!("deser_be_u32_slice given bad slice. length: {}", arr.len());
        return 0;
    }

    (arr[0] as u32) << 24 | (arr[1] as u32) << 16 | (arr[2] as u32) << 8 | (arr[3] as u32)
}

#[inline]
pub fn deser_be_u32(arr: &[u8; 4]) -> u32 {
    (arr[0] as u32) << 24 | (arr[1] as u32) << 16 | (arr[2] as u32) << 8 | (arr[3] as u32)
}

// Returns (tcp_ts, tcp_ts_ecr) in host order.
pub fn get_tcp_timestamps(tcp_pkt: &TcpPacket) -> (u32, u32) {
    match tcp_pkt
        .get_options_iter()
        .find(|x| x.get_number() == TcpOptionNumbers::TIMESTAMPS)
    {
        Some(p) => (
            deser_be_u32_slice(&p.payload()[0..4]), // timestamp
            deser_be_u32_slice(&p.payload()[4..8]),
        ), // echo reply
        None => (0, 0),
    }
}

// Call on two TCP seq#s from reasonably nearby within the same TCP connection.
// No need for s1 to be earlier in the sequence than s2.
// Returns whether a wraparound happened in between.
pub fn tcp_seq_is_wrapped(s1: u32, s2: u32) -> bool {
    ((s1 as i64) - (s2 as i64)).abs() > 2147483648
}

// a <= b, guessing about wraparound
pub fn tcp_seq_lte(a: u32, b: u32) -> bool {
    if a == b {
        true
    } else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) {
            !res
        } else {
            res
        }
    }
}

// a < b, guessing about wraparound
pub fn tcp_seq_lt(a: u32, b: u32) -> bool {
    if a == b {
        false
    } else {
        let res = a < b;
        if tcp_seq_is_wrapped(a, b) {
            !res
        } else {
            res
        }
    }
}

// Returns memory used by this process. Should be equivalent to the RES field of
// top. Units are "kB", which I'm guessing is KiB.
pub fn mem_used_kb() -> u64 {
    let my_pid: i32 = unsafe { libc::getpid() };
    let f = match File::open(format!("/proc/{my_pid}/status")) {
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
                let starts_at_number = vmrss_gone.trim_start();
                if let Some(kb_ind) = starts_at_number.find("kB") {
                    let (kb_gone, _) = starts_at_number.split_at(kb_ind);
                    let just_number = kb_gone.trim_end();
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
    error!(
        "Failed to parse a VmRSS value out of /proc/{}/status!",
        my_pid
    );
    0
}

pub struct HKDFKeys {
    pub fsp_key: [u8; 16],
    pub fsp_iv: [u8; 12],
    pub vsp_key: [u8; 16],
    pub vsp_iv: [u8; 12],
    pub new_master_secret: [u8; 48],
    pub dark_decoy_seed: [u8; 16],
}

impl HKDFKeys {
    pub fn new(shared_secret: &[u8]) -> Result<HKDFKeys, Box<hkdf::InvalidLength>> {
        let salt = "conjureconjureconjureconjure".as_bytes();
        let kdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), shared_secret);
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

        Ok(HKDFKeys {
            fsp_key,
            fsp_iv,
            vsp_key,
            vsp_iv,
            new_master_secret,
            dark_decoy_seed,
        }) // syntax is very edgy and not at all confusing
    }
}

pub struct FSP {
    pub vsp_size: u16,
    pub flags: u8,
    // unassigned: [u8; FSP::UNUSED_BYTES],
    bytes: Vec<u8>,
}

impl FSP {
    // const UNUSED_BYTES: usize = 3;
    const USED_BYTES: usize = 3;
    pub const LENGTH: usize = 6;
    pub const FLAG_PROXY_HEADER: u8 = 0x4;
    pub const FLAG_UPLOAD_ONLY: u8 = (1 << 7);
    pub const FLAG_USE_TIL: u8 = (1 << 0);
    pub fn from_vec(fixed_size_payload: Vec<u8>) -> Result<FSP, Box<dyn Error>> {
        if fixed_size_payload.len() < FSP::USED_BYTES {
            let err: Box<dyn Error> = From::from("Not Enough bytes to parse FSP".to_string());
            Err(err)
        } else {
            let vsp_size = ((fixed_size_payload[0] as u16) << 8) + (fixed_size_payload[1] as u16);
            Ok(FSP {
                vsp_size,
                flags: fixed_size_payload[2],
                bytes: fixed_size_payload,
            })
        }
    }

    pub fn check_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn to_vec(&self) -> &Vec<u8> {
        &self.bytes as _
    }

    pub fn to_bytes(&self) -> [u8; FSP::LENGTH] {
        let mut array = [0; FSP::LENGTH];
        array.copy_from_slice(&self.bytes);
        array
    }

    pub fn use_proxy_header(&self) -> bool {
        self.check_flag(FSP::FLAG_PROXY_HEADER)
    }

    pub fn upload_only(&self) -> bool {
        self.check_flag(FSP::FLAG_UPLOAD_ONLY)
    }

    pub fn use_til(&self) -> bool {
        self.check_flag(FSP::FLAG_USE_TIL)
    }
}

pub fn precise_time_ns() -> u128 {
    let duration_since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    duration_since_epoch.as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_used_kb_parses_something() {
        assert!(mem_used_kb() > 0);
    }
}
