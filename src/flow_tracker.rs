use std::collections::{HashSet, VecDeque};
use util::precise_time_ns;

use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::{IpAddr, SocketAddr};

use std::fmt;
use util::IpPacket;

use sessions::SessionTracker;

// All members are stored in host-order, even src_ip and dst_ip.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

// flow log client should only ever be set at initialization so this should
// never result in a race condition. Also all threads read the same
// environment variable so they will all set it the same.
pub static mut FLOW_CLIENT_LOG: bool = false;
impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let socket_src = SocketAddr::new(self.src_ip, self.src_port);
        let socket_dst = SocketAddr::new(self.dst_ip, self.dst_port);

        unsafe {
            match FLOW_CLIENT_LOG {
                true => write!(f, "{} -> {}", socket_src, socket_dst),
                false => write!(f, "_ -> {}", socket_dst),
            }
        }
    }
}

impl Flow {
    pub fn new(ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> Flow {
        match ip_pkt {
            IpPacket::V4(pkt) => Flow {
                src_ip: IpAddr::V4(pkt.get_source()),
                dst_ip: IpAddr::V4(pkt.get_destination()),
                src_port: tcp_pkt.get_source(),
                dst_port: tcp_pkt.get_destination(),
            },
            IpPacket::V6(pkt) => Flow {
                src_ip: IpAddr::V6(pkt.get_source()),
                dst_ip: IpAddr::V6(pkt.get_destination()),
                src_port: tcp_pkt.get_source(),
                dst_port: tcp_pkt.get_destination(),
            },
        }
    }

    pub fn new_udp(ip_pkt: &IpPacket, udp_pkt: &UdpPacket) -> Flow {
        match ip_pkt {
            IpPacket::V4(pkt) => Flow {
                src_ip: IpAddr::V4(pkt.get_source()),
                dst_ip: IpAddr::V4(pkt.get_destination()),
                src_port: udp_pkt.get_source(),
                dst_port: udp_pkt.get_destination(),
            },
            IpPacket::V6(pkt) => Flow {
                src_ip: IpAddr::V6(pkt.get_source()),
                dst_ip: IpAddr::V6(pkt.get_destination()),
                src_port: udp_pkt.get_source(),
                dst_port: udp_pkt.get_destination(),
            },
        }
    }

    pub fn from_parts(sip: IpAddr, dip: IpAddr, sport: u16, dport: u16) -> Flow {
        Flow {
            src_ip: sip,
            dst_ip: dip,
            src_port: sport,
            dst_port: dport,
        }
    }

    pub fn export_addrs(&self) -> (Vec<u8>, Vec<u8>) {
        let src_bytes = match self.src_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        let dst_bytes = match self.dst_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        (src_bytes, dst_bytes)
    }

    pub fn set_log_client(log: bool) {
        unsafe {
            FLOW_CLIENT_LOG = log;
        }
    }
}

// All members are stored in host-order, even src_ip and dst_ip.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct FlowNoSrcPort {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl fmt::Display for FlowNoSrcPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let socket_src = SocketAddr::new(self.src_ip, 0);
        let socket_dst = SocketAddr::new(self.dst_ip, self.dst_port);

        unsafe {
            match FLOW_CLIENT_LOG {
                true => write!(f, "{} -> {}", socket_src, socket_dst),
                false => write!(f, "_ -> {}", socket_dst),
            }
        }
    }
}

impl FlowNoSrcPort {
    pub fn new(ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> FlowNoSrcPort {
        match ip_pkt {
            IpPacket::V4(pkt) => FlowNoSrcPort {
                src_ip: IpAddr::V4(pkt.get_source()),
                dst_ip: IpAddr::V4(pkt.get_destination()),
                dst_port: tcp_pkt.get_destination(),
            },
            IpPacket::V6(pkt) => FlowNoSrcPort {
                src_ip: IpAddr::V6(pkt.get_source()),
                dst_ip: IpAddr::V6(pkt.get_destination()),
                dst_port: tcp_pkt.get_destination(),
            },
        }
    }
    pub fn from_parts(sip: IpAddr, dip: IpAddr, dport: u16) -> FlowNoSrcPort {
        FlowNoSrcPort {
            src_ip: sip,
            dst_ip: dip,
            dst_port: dport,
        }
    }
    pub fn from_flow(f: &Flow) -> FlowNoSrcPort {
        FlowNoSrcPort {
            src_ip: f.src_ip,
            dst_ip: f.dst_ip,
            dst_port: f.dst_port,
        }
    }

    pub fn export_addrs(&self) -> (Vec<u8>, Vec<u8>) {
        let src_bytes = match self.src_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        let dst_bytes = match self.dst_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        (src_bytes, dst_bytes)
    }
}

pub struct SchedEvent {
    // Nanoseconds since an unspecified epoch (precise_time_ns()).
    drop_time: u128,
    flow: Flow,
}

pub struct FlowTracker {
    // Keys present in this map are potentially tagged flows.
    // Key not present in map => sure flow isn't of interest. Ignore all non-SYN packets.
    // Key present, value InTLSHandshake => don't yet know if it's of interest yet
    tracked_flows: HashSet<Flow>,

    // stale_drops_tracked is used to periodically drop idle flows that are being tracked.
    stale_drops_tracked: VecDeque<SchedEvent>,

    // Known dark decoy destination IPs that should be picked up.
    // Map values are timeouts, which are used to drop stale dark decoys
    pub phantom_flows: SessionTracker,
    // pub phantom_flows: Arc<RwLock<HashMap<IpAddr, u64>>>,
}

// Amount of time that we timeout all flows
const TIMEOUT_TRACKED_NS: u128 = 30 * 1000 * 1000 * 1000;
//const FIN_TIMEOUT_NS: u64 = 2*1000*1000*1000;

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTracker {
    pub fn new() -> FlowTracker {
        let ret = FlowTracker {
            tracked_flows: HashSet::new(),
            phantom_flows: SessionTracker::new(),
            stale_drops_tracked: VecDeque::with_capacity(16384),
        };

        // launch thread to ingest from redis
        ret.phantom_flows.spawn_update_thread();
        ret
    }
    pub fn begin_tracking_flow(&mut self, flow: &Flow) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_drops_tracked.push_back(SchedEvent {
            drop_time: precise_time_ns() + TIMEOUT_TRACKED_NS,
            flow: *flow,
        });
        // Begin tracking as a potential TD flow (if not already in the set).
        self.tracked_flows.insert(*flow);
    }

    pub fn is_phantom_session(&self, flow: &FlowNoSrcPort) -> bool {
        self.phantom_flows.is_tracked_session(flow)
    }

    pub fn is_tracked_flow(&self, flow: &Flow) -> bool {
        self.tracked_flows.contains(flow)
    }

    /// used to update (increase) the time that we  consider a session
    /// valid for tracking purposes. Called when packets from a session are
    /// seen so that forwarding continues past the original registration timeout.
    pub fn update_phantom_flow(&mut self, flow: &FlowNoSrcPort) {
        self.phantom_flows.update_session(flow)
    }

    pub fn stop_tracking_flow(&mut self, flow: &Flow) {
        self.tracked_flows.remove(flow);
    }

    // drop_stale_tracked_flows returns the number of tracked flows that it drops.
    fn drop_stale_tracked_flows(&mut self) -> usize {
        let right_now = precise_time_ns();
        let num_tracked_flows_before = self.tracked_flows.len();
        loop {
            let flow = match self.stale_drops_tracked.front() {
                Some(cur) => {
                    if cur.drop_time <= right_now {
                        Some(cur.flow)
                    } else {
                        None
                    }
                }
                None => None,
            };
            match flow {
                Some(flow) => {
                    self.stale_drops_tracked.pop_front();
                    self.tracked_flows.remove(&flow);
                }
                None => {
                    // entries in stale_drops_tracked are supposed to be sorted by time, so
                    // once we see a flow that doesn't need to be removed, then
                    // there is no need to check further
                    return num_tracked_flows_before - self.tracked_flows.len();
                }
            }
        }
    }

    // drop_stale_phantom_flows returns the number of registered dark decoy
    // flows that it drops.
    fn drop_stale_phantom_flows(&mut self) -> usize {
        self.phantom_flows.drop_stale_sessions()
    }

    // This function returns the number of flows that it drops.
    #[allow(non_snake_case)]
    pub fn drop_all_stale_flows(&mut self) -> usize {
        self.drop_stale_tracked_flows() + self.drop_stale_phantom_flows()
    }

    pub fn count_tracked_flows(&self) -> usize {
        self.tracked_flows.len()
    }
    pub fn count_phantom_flows(&self) -> usize {
        self.phantom_flows.len()
    }
}

#[cfg(test)]
mod tests {
    use flow_tracker::{Flow, FlowNoSrcPort};
    use std::fmt::Write;

    #[test]
    fn test_flow_display_format() {
        Flow::set_log_client(false);

        let flow6 = Flow {
            src_ip: "2601::abcd:ef00".parse().unwrap(),
            dst_ip: "26ff::1".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow6).expect("Error occurred while trying to write in String");
        assert_eq!(output, "_ -> [26ff::1]:443");

        let flow4 = Flow {
            src_ip: "10.22.0.1".parse().unwrap(),
            dst_ip: "128.138.97.6".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow4).expect("Error occurred while trying to write in String");
        assert_eq!(output, "_ -> 128.138.97.6:443");

        let flow_n6 = FlowNoSrcPort {
            src_ip: "2601::abcd:ef00".parse().unwrap(),
            dst_ip: "26ff::1".parse().unwrap(),
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow_n6).expect("Error occurred while trying to write in String");
        assert_eq!(output, "_ -> [26ff::1]:443");

        let flow_n4 = FlowNoSrcPort {
            src_ip: "10.22.0.1".parse().unwrap(),
            dst_ip: "128.138.97.6".parse().unwrap(),
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow_n4).expect("Error occurred while trying to write in String");
        assert_eq!(output, "_ -> 128.138.97.6:443");

        Flow::set_log_client(true);

        let flow6 = Flow {
            src_ip: "2601::abcd:ef00".parse().unwrap(),
            dst_ip: "26ff::1".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow6).expect("Error occurred while trying to write in String");
        assert_eq!(output, "[2601::abcd:ef00]:5672 -> [26ff::1]:443");

        let flow4 = Flow {
            src_ip: "10.22.0.1".parse().unwrap(),
            dst_ip: "128.138.97.6".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow4).expect("Error occurred while trying to write in String");
        assert_eq!(output, "10.22.0.1:5672 -> 128.138.97.6:443");

        let flow_n6 = FlowNoSrcPort {
            src_ip: "2601::abcd:ef00".parse().unwrap(),
            dst_ip: "26ff::1".parse().unwrap(),
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow_n6).expect("Error occurred while trying to write in String");
        assert_eq!(output, "[2601::abcd:ef00]:0 -> [26ff::1]:443");

        let flow_n4 = FlowNoSrcPort {
            src_ip: "10.22.0.1".parse().unwrap(),
            dst_ip: "128.138.97.6".parse().unwrap(),
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow_n4).expect("Error occurred while trying to write in String");
        assert_eq!(output, "10.22.0.1:0 -> 128.138.97.6:443");
    }

    #[test]
    fn test_flow_export_addrs() {
        let flow = Flow {
            src_ip: "10.22.0.1".parse().unwrap(),
            dst_ip: "128.138.97.6".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let (src, dst) = flow.export_addrs();
        print!("{:?} {:?}", src, dst);
        assert_eq!(vec![10, 22, 0, 1], src);
        assert_eq!(vec![128, 138, 97, 6], dst);

        let flow6 = Flow {
            src_ip: "2601::abcd:ef00".parse().unwrap(),
            dst_ip: "26ff::1".parse().unwrap(),
            src_port: 5672,
            dst_port: 443,
        };

        let (src, dst) = flow6.export_addrs();
        print!("{:?} {:?}", src, dst);
        assert_eq!(
            vec![0x26, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x00],
            src
        );
        assert_eq!(
            vec![0x26, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst
        );
    }
}
