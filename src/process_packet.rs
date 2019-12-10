use libc::size_t;
use regex::Regex;
use std::os::raw::c_void;
use std::panic;
use std::slice;
use std:: str;
use std::collections::HashSet;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpPacket,TcpFlags};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::u8;
//use elligator;
use flow_tracker::{Flow, FlowNoSrcPort};
use dd_selector::DDIpSelector;
use PerCoreGlobal;
use util::{IpPacket, FSP};
use elligator;
use protobuf;
use signalling::ClientToStation;


const TLS_TYPE_APPLICATION_DATA: u8 = 0x17;
const SPECIAL_PACKET_PAYLOAD: &'static str = "'This must be Thursday,' said Arthur to himself, sinking low over his beer. 'I never could get the hang of Thursdays.'";
//const SQUID_PROXY_ADDR: &'static str = "127.0.0.1";
//const SQUID_PROXY_PORT: u16 = 1234;

//const STREAM_TIMEOUT_NS: u64 = 120*1000*1000*1000; // 120 seconds

lazy_static! {
    static ref HOSTNAME_RE : Regex = Regex::new(r"Host: (?P<hostname>[^(\r\n)]+)").unwrap();
}

fn get_ip_packet<'p>(eth_pkt: &'p EthernetPacket) -> Option<IpPacket<'p>>
{
    let payload = eth_pkt.payload();

    fn parse_v4<'a>(p: &[u8]) -> Option<IpPacket> {
        match Ipv4Packet::new(p) {
            Some(pkt) => Some(IpPacket::V4(pkt)),
            None => None
        }
    }

    fn parse_v6(p: &[u8]) -> Option<IpPacket> {
        match Ipv6Packet::new(p) {
            Some(pkt) => Some(IpPacket::V6(pkt)),
            None => None
        }
    }

    match eth_pkt.get_ethertype() {
        EtherTypes::Vlan => {
            if payload[2] == 0x08 && payload[3] == 0x00 {
                //let vlan_id: u16 = (payload[0] as u16)*256
                //                 + (payload[1] as u16);
                parse_v4(&payload[4..])
            } else if payload[2] == 0x86 && payload[3] == 0xdd {
                parse_v6(&payload[4..])
            } else {
                None
            }
        },
        EtherTypes::Ipv4 => parse_v4(&payload[0..]),
        EtherTypes::Ipv6 => parse_v6(&payload[0..]),
        _ => None,
    }
}

// The jumping off point for all of our logic. This function inspects a packet
// that has come in the tap interface. We do not yet have any idea if we care
// about it; it might not even be TLS. It might not even be TCP!
#[no_mangle]
pub extern "C" fn rust_process_packet(ptr: *mut PerCoreGlobal,
                                      raw_ethframe: *mut c_void,
                                      frame_len: size_t)
{
    #[allow(unused_mut)]
    let mut global = unsafe { &mut *ptr };

    let rust_view_len = frame_len as usize;
    let rust_view = unsafe {
        slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len as usize)
    };
    global.stats.packets_this_period += 1;
    global.stats.bytes_this_period += rust_view_len as u64;

    let eth_pkt = match EthernetPacket::new(rust_view) {
        Some(pkt) => pkt,
        None => return,
    };

    match get_ip_packet(&eth_pkt) {
        Some(IpPacket::V4(pkt)) => global.process_ipv4_packet(pkt, rust_view_len),
        Some(IpPacket::V6(pkt)) => global.process_ipv6_packet(pkt, rust_view_len),
        None => return,
    }
}

fn is_tls_app_pkt(tcp_pkt: &TcpPacket) -> bool
{
    let payload = tcp_pkt.payload();
    payload.len() > 5 && payload[0] == TLS_TYPE_APPLICATION_DATA
}

impl PerCoreGlobal
{
    // frame_len is supposed to be the length of the whole Ethernet frame. We're
    // only passing it here for plumbing reasons, and just for stat reporting.
    fn process_ipv4_packet(&mut self, ip_pkt: Ipv4Packet, frame_len: usize)
    {
        self.stats.ipv4_packets_this_period += 1;

        // Ignore packets that aren't TCP
        if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return;
        }
        let ip = IpPacket::V4(ip_pkt);

        {
            // Check TCP/443
            let tcp_pkt = match ip.tcp() {
                Some(pkt) => pkt,
                None => return,
            };
            self.stats.tcp_packets_this_period += 1;

            // Ignore packets that aren't -> 443.
            // libpnet getters all return host order. Ignore the "u16be" in their
            // docs; interactions with pnet are purely host order.
            if tcp_pkt.get_destination() != 443 {
                return;
            }
        }
        self.stats.tls_packets_this_period += 1; // (HTTPS, really)
        self.stats.tls_bytes_this_period += frame_len as u64;
        self.process_tls_pkt(ip);
    }

    fn process_ipv6_packet(&mut self, ip_pkt: Ipv6Packet, frame_len: usize)
    {
        self.stats.ipv6_packets_this_period += 1;

        if ip_pkt.get_next_header() != IpNextHeaderProtocols::Tcp {
            return;
        }
        let ip = IpPacket::V6(ip_pkt);

        {
            let tcp_pkt = match ip.tcp() {
                Some(pkt) => pkt,
                None => return,
            };
            self.stats.tcp_packets_this_period += 1;

            if tcp_pkt.get_destination() != 443 {
                return;
            }
        }
        self.stats.tls_packets_this_period += 1;
        self.stats.tls_bytes_this_period += frame_len as u64;

        //debug!("v6 -> {} {} bytes", ip_pkt.get_destination(), ip_pkt.get_payload_length());
        self.process_tls_pkt(ip);
    }

    // Takes an IPv4 packet
    // Assumes (for now) that TLS records are in a single TCP packet
    // (no fragmentation).
    // Fragments could be stored in the flow_tracker if needed.
    pub fn process_tls_pkt(&mut self,
                           ip_pkt: IpPacket)
    {
        let tcp_pkt = match ip_pkt.tcp() {
            Some(pkt) => pkt,
            None => return,
        };

        let flow = Flow::new(&ip_pkt, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();

        if panic::catch_unwind(||{ tcp_pkt.payload(); }).is_err() {
            return;
        }

        let dd_flow = FlowNoSrcPort::from_flow(&flow);
        if self.flow_tracker.is_registered_dark_decoy(&dd_flow) {
            // Tagged flow! Forward packet to whatever
            if  (tcp_flags & TcpFlags::SYN) != 0  && (tcp_flags & TcpFlags::ACK) == 0 {
                if flow.src_ip != Ipv4Addr::new(192, 122, 200, 231) &&
                   flow.src_ip !=  IpAddr::V6(Ipv6Addr::new(0x2001,0x48a8,0x687f,2,0,0,0,2)) 
                {
                    debug!("Connection for registered Phantom {}", flow);
                }
            }
            // Update expire time
            self.flow_tracker.mark_dark_decoy(&dd_flow);

            // Forward packet...
            self.forward_pkt(&ip_pkt);
            // TODO: if it was RST or FIN, close things
            return;
        }

        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0
        {
            self.stats.port_443_syns_this_period += 1;

            self.flow_tracker.begin_tracking_flow(&flow);
            return;
        } else if (tcp_flags & TcpFlags::RST) != 0 || (tcp_flags & TcpFlags::FIN) != 0 {
            self.flow_tracker.stop_tracking_flow(&flow);
            return;
        }

        if !self.flow_tracker.is_tracked_flow(&flow) {
            return;
        }

        if  is_tls_app_pkt(&tcp_pkt) {
            match self.check_dark_decoy_tag(&flow, &tcp_pkt) {
                true => {
                    // debug!("New Conjure registration detected in {},", flow);
                    // self.flow_tracker.mark_dark_decoy(&dd_flow);
                    // not removing flow from stale_tracked_flows for optimization reasons:
                    // it will be removed later
                },
                false => {}
            };
            self.flow_tracker.stop_tracking_flow(&flow);
        }else {
            self.check_connect_test_str(&flow, &tcp_pkt);
        }
    }

    fn forward_pkt(&mut self, ip_pkt: &IpPacket)
    {
        let data = match ip_pkt {
            IpPacket::V4(p) => p.packet(),
            IpPacket::V6(p) => p.packet(),
        };

        let mut tun_pkt = Vec::with_capacity(data.len()+4);
        // These mystery bytes are a link-layer header; the kernel "receives"
        // tun packets as if they were really physically "received". Since they
        // weren't physically received, they do not have an Ethernet header. It
        // looks like the tun setup has its own type of header, rather than just
        // making up a fake Ethernet header.
        let raw_hdr = match ip_pkt {
            IpPacket::V4(_p) => [0x00, 0x01, 0x08, 0x00],
            IpPacket::V6(_p) => [0x00, 0x01, 0x86, 0xdd],
        };
        tun_pkt.extend_from_slice(&raw_hdr);
        tun_pkt.extend_from_slice(data);

        self.tun.send(tun_pkt).unwrap_or_else(|e|{
            warn!("failed to send packet into tun: {}", e); 0});

    }

    fn check_dark_decoy_tag(&mut self,
                            flow: &Flow,
                            tcp_pkt: &TcpPacket) -> bool
    {
        self.stats.elligator_this_period += 1;
        match elligator::extract_payloads(&self.priv_key, &tcp_pkt.payload()) {
            Ok(res) => {
                // res.0 => shared secret
                // res.1 => Fixed size payload
                // res.2 => variable size payload (c2s)

                // Get Reg Decoy hostname from HTTP request in tcp payload

                let http_req = str::from_utf8(tcp_pkt.payload()).unwrap();
                let reg_decoy_hostname = match HOSTNAME_RE.captures(http_req) {
                    Some(cap) => cap.name("hostname").map_or("", |m| m.as_str()),
                    None => "",
                };

                // form message for zmq
                let mut zmq_msg: Vec<u8> = Vec::new();

                let mut shared_secret = res.0.to_vec();
                zmq_msg.append(&mut shared_secret);

                let mut fsp = res.1.to_vec(); 
                zmq_msg.append(&mut fsp);

                // VSP --> ClientToStation
                let mut vsp = res.2.to_vec();
                zmq_msg.append(&mut vsp);
                
                let repr_str = hex::encode(res.0);
                // Log new registration with shared reg decoy ip, reg decoy hostname, and shared secret, 
                debug!("New registration {}, {}, {}", flow, reg_decoy_hostname, repr_str);

                match self.zmq_sock.send(&zmq_msg, 0){
                    Ok(_)=> return true,
                    Err(e) => {
                        warn!("Failed to send registration information over ZMQ: {}", e);
                        return false
                    },
                }
            },
            Err(_e) => {
                return false;
            }
        }
    }

    fn check_connect_test_str(&mut self, flow: &Flow, tcp_pkt: &TcpPacket) {
        match str::from_utf8(tcp_pkt.payload()) {
            Ok(payload) => {
                if payload == SPECIAL_PACKET_PAYLOAD {
                    debug!("Validated traffic from {}:{} to {}:{}", 
                        flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
                }
            },
            Err(_) => {},
        }
    }
} // impl PerCoreGlobal

fn usize_to_u8(a: usize) -> Option<u8> {
    if a > u8::MAX as usize {
        None
    } else {
        Some(a as u8)
    }
}



