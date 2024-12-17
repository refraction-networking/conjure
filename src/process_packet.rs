use libc::size_t;
use retina_core::protocols::stream::quic::QuicConn;
use tls_parser::NamedGroup;
use std::io::BufWriter;
use std::io::Cursor;
use std::os::raw::c_void;
use std::panic;
use std::slice;
use std::str;
use std::u8;
use tuntap::TunTap;
use webrtc_dtls::cipher_suite::cipher_suite_aes_128_gcm_sha256::CipherSuiteAes128GcmSha256;
use webrtc_dtls::cipher_suite::CipherSuite;
use webrtc_dtls::content::ContentType;
use webrtc_dtls::handshake::handshake_random;
use webrtc_dtls::record_layer::record_layer_header;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use webrtc_dtls::record_layer::record_layer_header::RecordLayerHeader;

//use elligator;
use flow_tracker::{Flow, FlowNoSrcPort};
// use dd_selector::DDIpSelector;
use elligator;
use protobuf::Message;
use signalling::{C2SWrapper, RegistrationSource};
use util::IpPacket;
use PerCoreGlobal;

use crate::c_api;

const TLS_TYPE_APPLICATION_DATA: u8 = 0x17;
const SPECIAL_PACKET_PAYLOAD: &str = "'This must be Thursday,' said Arthur to himself, sinking low over his beer. 'I never could get the hang of Thursdays.'";
// Domain which this DNS encoding is representing: "xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR.FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k.mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU.SuifuqZ"
const SPECIAL_UDP_PAYLOAD: &[u8] = b"\x38xCKe9ECO5lNwXgd5Q25w0C2qUR7whltkA8BbyNokGIp5rzzm0hc7yqbR\x38FAP3S9w7oLrvvei7IphdwZEKUvF5iZeSdtDFEDc6cIDiv11aTNkOp08k\x38mRISHvoeSWSgMOjkbR2un5XKpJEZIK31Bc2obUGRIoY2tpxm6RUV5nOU\x07SuifuqZ";
//const SQUID_PROXY_ADDR: &'static str = "127.0.0.1";
//const SQUID_PROXY_PORT: u16 = 1234;

//const STREAM_TIMEOUT_NS: u64 = 120*1000*1000*1000; // 120 seconds

const CID_SIZE: usize = 8;
const PRIV_KEY_SIZE: usize = 32;

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

fn forward_pkt(tun: &mut TunTap, ip_pkt: &IpPacket) {
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

    tun.send(tun_pkt).unwrap_or_else(|e| {
        warn!("failed to send packet into tun: {}", e);
        0
    });
}

fn check_dtls_cid(payload: &[u8], privkey: &[u8]) -> bool {
    if payload.len() < 3 {
        // report!("payload.len() < 3",);
        return false;
    }

    if !(payload[0] == 0x19 && payload[1] == 0xfe && payload[2] == 0xfd) {
        // report!("not type dtls cid",);
        return false;
    }

    let mut reader = Cursor::new(payload);
    let mut h = match RecordLayerHeader::unmarshal_cid(CID_SIZE, &mut reader) {
        Ok(record) => record,
        Err(_) => {
            return false;
        }
    };

    if h.content_type != ContentType::ConnectionID {
        return false;
    }

    let start = record_layer_header::RECORD_LAYER_HEADER_SIZE + CID_SIZE;
    if payload.len() < (start + PRIV_KEY_SIZE) {
        // pkt too small to contain key
        return false;
    }

    let mut representative = payload[start..start + PRIV_KEY_SIZE].to_vec();
    representative[31] &= 0x3f;

    let mut shared_secret = [0u8; 32];
    c_api::c_get_shared_secret_from_representative(
        &mut shared_secret,
        &mut representative,
        &privkey,
    );

    let mut content = payload[start + PRIV_KEY_SIZE..].to_vec();
    let mut cipher = CipherSuiteAes128GcmSha256::new(false);

    let rand = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret);
    let mut master_secret = [0u8; 48];
    if rand.expand(&[], &mut master_secret).is_err() {
        return false;
    }

    if cipher
        .init(
            &master_secret,
            &[0u8; handshake_random::HANDSHAKE_RANDOM_LENGTH],
            &[0u8; handshake_random::HANDSHAKE_RANDOM_LENGTH],
            false,
        )
        .is_err()
    {
        return false;
    }

    h.content_len = content.len() as u16;
    let mut payload_no_key = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(payload_no_key.as_mut());
        if h.marshal(&mut writer).is_err() {
            return false;
        }
    }

    payload_no_key.append(&mut content);

    return cipher.decrypt_cid(CID_SIZE, &payload_no_key).is_ok();
}

fn check_quic_kyber(payload: &[u8], _privkey: &[u8], conn: &mut QuicConn) -> bool {
    conn.parse_packet(payload, true);
    if let Some(ch) = &conn.tls.client_hello {
        for share in &ch.key_shares {
            if share.group.0 == 0x6399 {
                return true
            }
        }
    }
    return false;
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
            return;
        }

        if udp_pkt.get_destination() == 443 && !self.quic_conn_tracker.contains_key(&flow) {
            self.quic_conn_tracker.insert(flow, QuicConn::new());
        }

        if !self
            .flow_tracker
            .session_key_exists(&FlowNoSrcPort::from_flow(&flow).to_string())
            && !check_dtls_cid(udp_pkt.payload(), &self.priv_key)
            && if let Some(conn) = self.quic_conn_tracker.get_mut(&flow) {
                !check_quic_kyber(udp_pkt.payload(), &self.priv_key, conn)
            } else {
                false
            }
            // && !check_quic_kyber(udp_pkt.payload(), &self.priv_key, &mut QuicConn::new())
        {
            return;
        }

        self.flow_tracker
            .insert_or_update_key(&FlowNoSrcPort::from_flow(&flow).to_string());
        forward_pkt(&mut self.dtls_cid_tun, ip_pkt);
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
                    forward_pkt(&mut self.tun, ip_pkt);
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
                    forward_pkt(&mut self.tun, ip_pkt);
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
                zmq_msg.registration_payload = Some(vsp).into();
                zmq_msg.set_registration_source(RegistrationSource::Detector);
                zmq_msg.set_decoy_address(decoy);
                zmq_msg.set_registration_address(src);

                let zmq_payload = match zmq_msg.write_to_bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to generate ZMQ payload: {}", e);
                        return false;
                    }
                };

                match self.zmq_sock.send(zmq_payload, 0) {
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
    use std::path::PathBuf;
    use retina_core::protocols::stream::quic::QuicConn;
    use toml;
    use StationConfig;

    use crate::process_packet::check_dtls_cid;
    use crate::process_packet::check_quic_kyber;

    #[test]
    fn test_filter_station_traffic() {
        let mut conf_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        conf_path.push("cmd/application/app_config.toml");

        print!("{}", conf_path.to_str().unwrap());
        let contents =
            fs::read_to_string(conf_path).expect("Something went wrong reading the file");

        // let value = contents.parse::<Value>().unwrap();
        let value: StationConfig = toml::from_str(&contents).unwrap();

        let nets = value.detector_filter_list;

        for net in nets.iter() {
            println!("{net}");
        }
    }

    #[test]
    fn test_filter_dtls() {
        let privkey =
            hex::decode("203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60")
                .expect("failed to decode privkey");

        //DTLSv1.2 Record Layer: Connection ID
        // Special Type: Connection ID (25)
        // Version: DTLS 1.2 (0xfefd)
        // Epoch: 1
        // Sequence Number: 225
        // Connection ID: f9fe8492ec0f8c66
        // Length: 121
        // Encrypted Record Content: 995ad2b0d98ff1ec52af54ac60135ab60340f19218c6139a1629cfc4917a0b8ca9b8da26…
        let udp_payload = hex::decode("19fefd000100000000007e89672aa48beec9220079b5977cd87c009bcb987bad8660902c473ec6596f1f250043cfc956c748138e7d17cdfeb1b24f7420c0db7634d99b015229cd0fc35d540c8772e1716c31726038ba2c8ebb1a01fdb0f07d4db3db4871608362c45687d1104ad4b1d3de96435fbec39d9e01749656b9043024a27f8a965cf7a245220fe34c7196").expect("failed to decode udp payload");

        assert!(check_dtls_cid(&udp_payload, &privkey))
    }

    #[test]
    fn test_filter_quic_kyber() {
        let privkey =
            hex::decode("203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60")
                .expect("failed to decode privkey");

        // QUIC IETF
        // QUIC Connection information
        // [Packet Length: 1230]
        // 1... .... = Header Form: Long Header (1)
        // .1.. .... = Fixed Bit: True
        // ..00 .... = Packet Type: Initial (0)
        // [.... 00.. = Reserved: 0]
        // [.... ..00 = Packet Number Length: 1 bytes (0)]
        // Version: 1 (0x00000001)
        // Destination Connection ID Length: 8
        // Destination Connection ID: d6f3de1a041191fe
        // Source Connection ID Length: 0
        // Token Length: 0
        // Length: 1212
        // [Packet Number: 1]
        // Payload [truncated]: 1010...
        // CRYPTO
        let udp_payload_1 = hex::decode("c80000000108d6f3de1a041191fe000044bc251010cd1d87188a85bafbad8fb80b0b5fbba042d0e407434d55bdf4c57e45f14901bded3820364e3e4149f1f2c5c068c165f38f92d0c58434ed78a7ccddb63260ab20064fecbc2fdf44c082ac9ba3ad1e31a8e65442dcdf113885d3bd84c377d5c2f2f28ffd4eb2dc8ff68531f3e2030d408a45c92754bea5923207645297eb54721064cd91e2cde790eddf2d5e11ca867b2a9d238933cdc560123ad5ce101915beac9d5dd9f06b0d99e1485b66b90639dbb3092100899d54dfea1fe46aad3c655e22638b2f2126c1639abc71e8342132220ff5a47148f895fbe71abe662e503e53fa7e543d7e5ba320163b6406de3e420f9679c537af14afa8c9af6653c64c5d82f8e8fa62ae32ea08b727d65a058e8d789470e1bc2e848e9ff9fc65e8b8700ed30c035990a09aa02294c240110e20fc81e957556d63432d03884f4c9ad4d65b5d9c66d8807a4146b7fce698856dc3c9f6b8b39f559983341531a44a93f922697bac3c242390f7a45a90bbdff335eb880364d724954798e3f95bbdca0039f01c6202b46c47ff5c949903bbc4fef9eea7d28688b1e3bfb090a9e702f7b92613b56d9ea026976687718a92a74b3c460e75ea373c6e783e9c118dbcba20d5e49c8fd98fe8f30fd9db42ef192b833a73248262348e5a2bcb3670e7c5e46b64391a2a8ba887de9bdb9d0526d2dea8e4c13b9e64c08040ebf7e7dff32760049662e8ab4e340cdfe18fa5f0023e75cf5d6934b6c5dad970710ca6aa2c7288d17feda7ee51bdcdd246773f2553e95bbd85a69e7d2970a412a3318245ebb47be7e8a88920e95cbdd324d888d26daf65f9c19181c6695ff73a3693f64ac3a386ca6c2502c7c4216a9680382c7da2eae1b06e72d44004f86803980a89be3d8b56b2eaf363fc2181b2e4fe4ae71eddd0837cabcec210396756f8d98c3935bc56db7316be01b087e1e2bab59589eed06e167beb8043062d57d771562fdfb8ca0fa4f66b1de2cead8b69a5e962bb4165fd5c9b9237aee212907e96c076c86d0e6f8aacce86694869913ef47f28ae1dc1a358ddfa37e7b64d3d2e427cb5b7187ee9ee719f0472e010b98ba789e2cc6e39037a2b1108cacb7241df5ac194a969b1506e4d0f4f2c9cf16c69e77878f0a313ab16062cedfde7f4533fe9c2601757ba38deec1ec748c83a31e55cfa17604688432d22a075c767a7775b42d218677762bcb86296ca3ca40d7fb78a480dce0e77cef3f9c3f4a1ec9fc98ab113ad0bbfbbb903b71cb70d23ff2e7ade70871e7439d915aeb23b21dc473a1edb3a59bc3a8f9b31a9bee2ac134bc513ca51f5df048d13a525ee8c226ad6ccc099f38812c5c94447eceeda7118a482280676905da833c3b1f01a588fc6037d857a61ee5afb741ac9f0ed35ce48ad78f07480c098b56754abbe050a370b5de80c7c9750cfbdcdd3789de4069a57d57cbe48438a67d7cf2dabf74d091b7caaa99ae9a2a14871b7847da49b72e9921d95b999919a1ce60a67d80efc9459aa5dd63c9ee046f8aef30d7b350a9605cc89705f29b57e11a22f63b1530954a0ace082aba929ace68bd3a458d93cddb3d7c1f5084678ea87462165feed3b65ea23d0b9b25a4f2cf41c2b3cd5b408cc7758a260552feca04bfb7ae477682826a8e6c1cb444a2c230906c97a4f7fee8213cc80872081dc7126d1f4242cc69316770c295bc19ea13c775ef7b80e")
            .expect("failed to decode udp payload");

        // QUIC IETF
        // QUIC Connection information
        // [Packet Length: 1230]
        // 1... .... = Header Form: Long Header (1)
        // .1.. .... = Fixed Bit: True
        // ..00 .... = Packet Type: Initial (0)
        // [.... 00.. = Reserved: 0]
        // [.... ..00 = Packet Number Length: 1 bytes (0)]
        // Version: 1 (0x00000001)
        // Destination Connection ID Length: 8
        // Destination Connection ID: d6f3de1a041191fe
        // Source Connection ID Length: 0
        // Token Length: 0
        // Length: 1212
        // [Packet Number: 2]
        // Payload [truncated]: 5a72...
        // PING
        // PADDING Length: 1
        // PING
        // PING
        // PING
        // PADDING Length: 2
        // PING
        // PING
        // CRYPTO
        // PADDING Length: 285
        // PING
        // CRYPTO
        // PADDING Length: 322
        // CRYPTO
        // CRYPTO
        let udp_payload_2 = hex::decode("cb0000000108d6f3de1a041191fe000044bc4a5a72a3fadcff87edfbce28d23c8c78a690045a5f7efb348562c4e7ce818f481d8ae99bd03d78d76f9269755b5e100980f257e4316183817caf83d9fedd2555acee4070715a809f356b2fbe5f95f6c254b9863e423470af4bb33626a67b5661821752fa54b8d37b686a7444787318a40efc9f87e4f929b146e1ddb466a9ff486d8d315b01381791d0456ac20dda6de7cd3378bbe80faa9c0e48bb45d66180d727c6f383cd154654226cab78f5f5455bc1dcd0f1197544652260a8c2d1cb331b08c9a7ddb49ba14e63a136004e21cfe60273f5d1af59520ce211f2ca47733fd113a02bfa8565d66e1f15fed6f6da905af8a5bb9bda2ccc331ac9881cba31de456572b65fc11fe2445939cc0364bf91431c3a5317ea0b58147efc690bdefa94d1abe67de13e62611fa627cf01d5943744b5c2a397f958eb76851b7b5995650279a73f6e04a6cc22aa0503c673eef79905b3cbee36b31213df0f22f23e0b75bb8f77f90acd8864bc85921636f17671cd00e4c7e269406ec6df383063760a626a22fbdd15320aad06817929e1ed307264ae9e222ee9362f47d3d793f6753d96a2d6e2844e6d0d3dc09511f9c1874203de8dd0e4b48ff1f5a14e42bfae7134bc8be5751e27b669f71645f7fcb0188cba57a19b38502fef309fa3a3175f013d4f0fe1b99fb6bf28b00eaa97d8bb9856efed926abdab5a632809857f2f29de476e7b33ec7eb8ddc07980474b28dfd50f600a3988b64f6d8e9f024deaad8a5111c4056acdf3858060518d2f194b7eb543feeb57c66c137653c54ac7cdd46a87a7aee0c947f6997a91ae64d52961dd2dd3c62598a4a4448cd374e05a23b37282fcbf186a3b15ec308bd17697ab419eaf5c5d2fbb182e4f57cee37588bd6c23e2ecfdbd83c397823162bcaf6d88c6f8140b06bb3c9602f302f8474db00db9b8bf0122a73b8a1b12dcc9263ab6e97ed84950a2882dbac5097d6b75ba258a34e07316286193facd67f3789d0d74b16faa42011243b8dde8112ba8fabe33ad0f6e397a5bd23f0c306f63d96a975a2fe4a0977061037fc4ec5be729e8467ebe282b0b551bf17108f747ebeb8920c367a228081489b96a011a8af4f2881caa3e9b8a4fbad4a6223b2b773dce24a749c4cebbb79f3c4081d54ef15fc84c72e525571f8544f14acccae55da0f50b0abb8675b3b77cba485b38d4b3f5d734ac6a47fe92cb71fbba7ab5fc81f3356c68a54a49de6d34ef0428f090a336616e77a3622332ce934ec8cc54c8e07b1472ba25ed25dced00f8665dff16d635a42f6c4ec1ff2de0040717f08c91621c8000abbf8a5c579dd6208df923303d1ed6332763f521ef57a9c5e9d0fe0e22f20ce28e80be33aef759b9b1aa39fd5b2f5694da51ec9923dc6a61c613ad191e0535a1046571acf6598dd5b4d0d35161369eabf1e65227c949b5285f1823b9f8967a515fb085adc8cfdc6c09e0f80f36f54c4e7e5b330d342cc42c7d34ad20a6b7729be6066d3e9c8c23be456769f0b6f69414b84aa03659cdbaf2e53a24cf96df98665c9c9c87f3d8be64401da5b5fd6a3f7b49f46d39925df3fb92dce6379269c4c23962075dc68844da6a1426e0409bdb6a45a52322693e26be8e61b462de0008354e888623cc8be18833e6d275df19f88a1ac52c377fd7c1d543fc7531d04c0852d6188fc3052b332e1c3681aaf729be82bc6e093e787f")
            .expect("failed to decode udp payload");
        let mut quic_conn = QuicConn::new();
        assert!(!check_quic_kyber(&udp_payload_1, &privkey, &mut quic_conn));
        assert!(check_quic_kyber(&udp_payload_2, &privkey, &mut quic_conn));
    }
}
