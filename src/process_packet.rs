use libc::size_t;
use std::os::raw::c_void;
use std::panic;
use std::slice;
use std::str;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::u8;
//use elligator;
use flow_tracker::{Flow, FlowNoSrcPort};
// use dd_selector::DDIpSelector;
use elligator;
use protobuf::Message;
use signalling::{C2SWrapper, RegistrationSource};
use util::IpPacket;
use PerCoreGlobal;

const TLS_TYPE_APPLICATION_DATA: u8 = 0x17;
const SPECIAL_PACKET_PAYLOAD: &str = "'This must be Thursday,' said Arthur to himself, sinking low over his beer. 'I never could get the hang of Thursdays.'";
// Domain which this DNS encoding is representing: "xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR.FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k.mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU.SuifuqZ"
const SPECIAL_UDP_PAYLOAD: &[u8] = b"\x38xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR\x38FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k\x38mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU\x07SuifuqZ";
//const SQUID_PROXY_ADDR: &'static str = "127.0.0.1";
//const SQUID_PROXY_PORT: u16 = 1234;

//const STREAM_TIMEOUT_NS: u64 = 120*1000*1000*1000; // 120 seconds

fn get_ip_packet<'p>(eth_pkt: &'p EthernetPacket) -> Option<IpPacket<'p>> {
    let payload = eth_pkt.payload();

    fn parse_v4(p: &[u8]) -> Option<IpPacket> {
        Ipv4Packet::new(p).map(IpPacket::V4)
    }

    fn parse_v6(p: &[u8]) -> Option<IpPacket> {
        Ipv6Packet::new(p).map(IpPacket::V6)
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
        }
        EtherTypes::Ipv4 => parse_v4(&payload[0..]),
        EtherTypes::Ipv6 => parse_v6(&payload[0..]),
        _ => None,
    }
}

/// The jumping off point for all of our logic. This function inspects a packet
/// that has come in the tap interface. We do not yet have any idea if we care
/// about it; it might not even be TLS. It might not even be TCP!
///
/// # Safety
/// this function is sae to use when: todo!()
#[no_mangle]
pub unsafe extern "C" fn rust_process_packet(
    ptr: *mut PerCoreGlobal,
    raw_ethframe: *mut c_void,
    frame_len: size_t,
) {
    #[allow(unused_mut)]
    let mut global = &mut *ptr;

    let mut rust_view_len = frame_len;
    let rust_view = slice::from_raw_parts_mut(raw_ethframe as *mut u8, frame_len);

    // If this is a GRE, we want to ignore the GRE overhead in our packets
    rust_view_len -= global.gre_offset;

    global.stats.packets_this_period += 1;
    global.stats.bytes_this_period += rust_view_len as u64;

    let eth_pkt = match EthernetPacket::new(&rust_view[global.gre_offset..]) {
        Some(pkt) => pkt,
        None => return,
    };

    let ip_pkt = match get_ip_packet(&eth_pkt) {
        Some(pkt) => pkt,
        None => return, // Ignore packet types other than IPv4 and IPv6
    };

    match ip_pkt.ethertype() {
        EtherTypes::Ipv4 => global.stats.ipv4_packets_this_period += 1,
        EtherTypes::Ipv6 => global.stats.ipv6_packets_this_period += 1,
        _ => {}
    };

    match ip_pkt.next_layer() {
        IpNextHeaderProtocols::Tcp => {
            let tcp_pkt = match ip_pkt.tcp() {
                Some(pkt) => pkt,
                None => return,
            };
            global.handle_tcp_pkt(tcp_pkt, &ip_pkt, frame_len);
        }
        IpNextHeaderProtocols::Udp => {
            let udp_pkt = match ip_pkt.udp() {
                Some(pkt) => pkt,
                None => return,
            };
            global.handle_udp_pkt(udp_pkt, &ip_pkt, frame_len);
        }
        _ => {} // ignore any protocols other than UDP and TCP
    }
}

fn is_tls_app_pkt(tcp_pkt: &TcpPacket) -> bool {
    let payload = tcp_pkt.payload();
    payload.len() > 5 && payload[0] == TLS_TYPE_APPLICATION_DATA
}

impl PerCoreGlobal {
    // // frame_len is supposed to be the length of the whole Ethernet frame. We're
    // // only passing it here for plumbing reasons, and just for stat reporting.
    fn handle_tcp_pkt(&mut self, tcp_pkt: TcpPacket, ip_pkt: &IpPacket, frame_len: usize) {
        self.stats.tcp_packets_this_period += 1;

        let flow = Flow::new(ip_pkt, &tcp_pkt);
        if self.check_for_tagged_flow(&flow, ip_pkt).is_some() {
            return;
        }

        if tcp_pkt.get_destination() == 443 {
            self.stats.tls_packets_this_period += 1;
            self.stats.tls_bytes_this_period += frame_len as u64;

            //debug!("v6 -> {} {} bytes", ip_pkt.get_destination(), ip_pkt.get_payload_length());
            self.process_tls_pkt(ip_pkt);
        }
    }

    fn handle_udp_pkt(&mut self, udp_pkt: UdpPacket, ip_pkt: &IpPacket, frame_len: usize) {
        // TODO - this is not necessarily what we want to track.
        // We might add more verbose logging from `debug/not-src-443`
        if udp_pkt.get_destination() == 443 {
            self.stats.tls_packets_this_period += 1;
            self.stats.tls_bytes_this_period += frame_len as u64;
        }

        let flow = Flow::new_udp(ip_pkt, &udp_pkt);
        if self.check_for_tagged_flow(&flow, ip_pkt).is_some() {
            return;
        }

        if udp_pkt.get_destination() == 53 {
            let flow = Flow::new_udp(ip_pkt, &udp_pkt);
            self.check_udp_test_str(&flow, &udp_pkt);
        }
    }

    fn check_for_tagged_flow(&mut self, flow: &Flow, ip_pkt: &IpPacket) -> Option<()> {
        let cj_flow = FlowNoSrcPort::from_flow(flow);
        if self.flow_tracker.is_phantom_session(&cj_flow) {
            // Handle packet destined for registered IP
            match self.filter_station_traffic(flow.src_ip.to_string()) {
                // traffic was sent by another station, likely liveness testing.
                None => {}

                // Non station traffic, forward to application to handle
                Some(_) => {
                    // Update expire time if necessary
                    self.flow_tracker.update_phantom_flow(&cj_flow);
                    // Forward packet...
                    self.forward_pkt(ip_pkt);
                    // TODO: if it was RST or FIN, close things
                    return Some(());
                }
            }
        }
        None
    }

    // Takes an IPv4 packet Assumes (for now) that TLS records are in a single
    // TCP packet (no fragmentation). Fragments could be stored in the
    // flow_tracker if needed.
    pub fn process_tls_pkt(&mut self, ip_pkt: &IpPacket) {
        let tcp_pkt = match ip_pkt.tcp() {
            Some(pkt) => pkt,
            None => return,
        };

        let flow = Flow::new(ip_pkt, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();

        if panic::catch_unwind(|| tcp_pkt.payload()).is_err() {
            return;
        }

        let cj_flow = FlowNoSrcPort::from_flow(&flow);
        if self.flow_tracker.is_phantom_session(&cj_flow) {
            // Handle packet destined for registered IP
            match self.filter_station_traffic(flow.src_ip.to_string()) {
                // traffic was sent by another station, likely liveness testing.
                None => {}

                // Non station traffic, forward to application to handle
                Some(_) => {
                    if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
                        // debug!("Connection for registered Phantom {}", flow);
                    }
                    // Update expire time if necessary
                    self.flow_tracker.update_phantom_flow(&cj_flow);
                    // Forward packet...
                    self.forward_pkt(ip_pkt);
                    // TODO: if it was RST or FIN, close things
                    return;
                }
            }
        }

        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
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

        if is_tls_app_pkt(&tcp_pkt) {
            match self.check_dark_decoy_tag(&flow, &tcp_pkt) {
                true => {
                    // debug!("New Conjure registration detected in {},", flow);
                    // self.flow_tracker.mark_dark_decoy(&cj_flow);
                    // not removing flow from stale_tracked_flows for optimization reasons:
                    // it will be removed later
                }
                false => {}
            };
            self.flow_tracker.stop_tracking_flow(&flow);
        } else {
            self.check_connect_test_str(&flow, &tcp_pkt);
        }
    }

    fn forward_pkt(&mut self, ip_pkt: &IpPacket) {
        let data = match ip_pkt {
            IpPacket::V4(p) => p.packet(),
            IpPacket::V6(p) => p.packet(),
        };

        let mut tun_pkt = Vec::with_capacity(data.len() + 4);
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

        self.tun.send(tun_pkt).unwrap_or_else(|e| {
            warn!("failed to send packet into tun: {}", e);
            0
        });
    }

    fn check_dark_decoy_tag(&mut self, flow: &Flow, tcp_pkt: &TcpPacket) -> bool {
        self.stats.elligator_this_period += 1;
        match elligator::extract_payloads(&self.priv_key, tcp_pkt.payload()) {
            Ok(res) => {
                // res.0 => shared secret
                // res.1 => Fixed size payload
                // res.2 => variable size payload (c2s)

                // form message for zmq
                let mut zmq_msg = C2SWrapper::new();

                let shared_secret = res.0.to_vec();
                let (src, decoy) = flow.export_addrs();
                let vsp = res.2;

                zmq_msg.set_shared_secret(shared_secret);
                zmq_msg.set_registration_payload(vsp);
                zmq_msg.set_registration_source(RegistrationSource::Detector);
                zmq_msg.set_decoy_address(decoy);
                zmq_msg.set_registration_address(src);

                let repr_str = hex::encode(res.0);
                debug!("New registration {}, {}", flow, repr_str);

                let zmq_payload = match zmq_msg.write_to_bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to generate ZMQ payload: {}", e);
                        return false;
                    }
                };

                match self.zmq_sock.send(&zmq_payload, 0) {
                    Ok(_) => true,
                    Err(e) => {
                        warn!("Failed to send registration information over ZMQ: {}", e);
                        false
                    }
                }
            }
            Err(_e) => false,
        }
    }

    fn check_connect_test_str(&mut self, flow: &Flow, tcp_pkt: &TcpPacket) {
        if let Ok(payload) = str::from_utf8(tcp_pkt.payload()) {
            if payload == SPECIAL_PACKET_PAYLOAD {
                debug!("Validated traffic from {}", flow)
            }
        }
    }

    fn check_udp_test_str(&mut self, flow: &Flow, udp_pkt: &UdpPacket) {
        if udp_pkt
            .payload()
            .windows(SPECIAL_UDP_PAYLOAD.len())
            .any(|sub| sub == SPECIAL_UDP_PAYLOAD)
        {
            debug!("Validated UDP traffic from {}", flow)
        }
    }

    /// Checks if the traffic seen is from a participating station byt checking the
    /// source address. Returns Some if traffic is from anything other that a station.
    ///
    /// This exists to prevent the detector from forwarding liveness check traffic
    /// to the application wasting resources in the process.
    ///
    /// Todo -> Move address list to some external config
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// let flow_src_station = String::from("192.122.200.231");
    /// let flow_src_client = String::from("128.138.89.172");
    ///
    /// let station = filter_station_traffic(flow_src_station);
    /// let client = filter_station_traffic(flow_src_client);
    ///
    /// assert_eq!(None, station);
    /// assert_eq!(Some(()), client);
    /// ```
    ///
    fn filter_station_traffic(&mut self, src: String) -> Option<()> {
        for addr in self.filter_list.iter() {
            if src == *addr {
                return None;
            }
        }

        Some(())
    }
} // impl PerCoreGlobal

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use toml;
    use StationConfig;

    #[test]
    fn test_filter_station_traffic() {
        env::set_var("CJ_STATION_CONFIG", "./application/config.toml");

        // --
        let conf_path = env::var("CJ_STATION_CONFIG").unwrap();

        let contents =
            fs::read_to_string(conf_path).expect("Something went wrong reading the file");

        // let value = contents.parse::<Value>().unwrap();
        let value: StationConfig = toml::from_str(&contents).unwrap();

        let nets = value.detector_filter_list;

        for net in nets.iter() {
            println!("{net}");
        }
    }
}
