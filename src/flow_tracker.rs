use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{RwLock, Arc};
use std::thread;
use time::precise_time_ns;
use redis;

use std::net::{IpAddr, SocketAddr};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use util::IpPacket;
use std::fmt;

// All members are stored in host-order, even src_ip and dst_ip.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Flow
{
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}


impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let socket_src = SocketAddr::new(self.src_ip, self.src_port);
        let socket_dst = SocketAddr::new(self.dst_ip, self.dst_port);
        write!(f, "{} -> {}",socket_src, socket_dst)
    }
}

impl Flow
{
    pub fn new(ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> Flow
    {
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

    pub fn new_udp(ip_pkt: &IpPacket, udp_pkt: &UdpPacket) -> Flow
    {
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

    pub fn from_parts(sip: IpAddr, dip: IpAddr, sport: u16, dport: u16) -> Flow
    {
        Flow { src_ip: sip, dst_ip: dip, src_port: sport, dst_port: dport }
    }
}

// All members are stored in host-order, even src_ip and dst_ip.
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct FlowNoSrcPort
{
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}


impl fmt::Display for FlowNoSrcPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:* -> {}:{}", self.src_ip, self.dst_ip, self.dst_port)
    }
}

impl FlowNoSrcPort {
    pub fn new(ip_pkt: &IpPacket, tcp_pkt: &TcpPacket) -> FlowNoSrcPort
    {
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
    pub fn from_parts(sip: IpAddr, dip: IpAddr,  dport: u16) -> FlowNoSrcPort
    {
        FlowNoSrcPort { src_ip: sip, dst_ip: dip, dst_port: dport }
    }
    pub fn from_flow(f: &Flow) -> FlowNoSrcPort {FlowNoSrcPort{src_ip: f.src_ip, dst_ip: f.dst_ip, dst_port: f.dst_port}}
}

pub struct SchedEvent
{
    // Nanoseconds since an unspecified epoch (precise_time_ns()).
    drop_time: u64,
    flow: Flow,
}

pub struct FlowTracker
{
    // Keys present in this map are potentially tagged flows.
    // Key not present in map => sure flow isn't of interest. Ignore all non-SYN packets.
    // Key present, value InTLSHandshake => don't yet know if it's of interest yet
    tracked_flows: HashSet<Flow>,

    // stale_drops_tracked is used to periodically drop idle flows that are being tracked.
    stale_drops_tracked: VecDeque<SchedEvent>,

    // Known dark decoy destination IPs that should be picked up.
    // Map values are timeouts, which are used to drop stale dark decoys
    pub dark_decoy_flows: Arc<RwLock<HashMap<IpAddr, u64>>>,

    redis_conn: redis::Connection,

}

// Amount of time that we timeout all flows
const TIMEOUT_TRACKED_NS: u64 = 30 * 1000 * 1000 * 1000;
const TIMEOUT_DARK_DECOYS_NS: u64 = 300 * 1000 * 1000 * 1000;
//const FIN_TIMEOUT_NS: u64 = 2*1000*1000*1000;

fn get_redis_conn() -> redis::Connection
{
    let client = redis::Client::open("redis://127.0.0.1/").expect("Can't open Redis");
    let con = client.get_connection().expect("Can't get Redis connection");
    con
}

fn update_pubsub_map(map: Arc<RwLock<HashMap<IpAddr, u64>>>)
{

    let mut con = get_redis_conn();
    let mut pubsub = con.as_pubsub();
    pubsub.subscribe("dark_decoy_map").expect("Can't subscribe to Redis");

    loop {
        let msg = pubsub.get_message().unwrap();
        let payload : Vec<u8> = msg.get_payload().unwrap();

        //let ip_addr = IpAddr::from([128u8, 138u8, 244u8, 42u8]);
        let ip_addr = match payload.len() {
            4 => {  let mut a: [u8; 4] = [0; 4];
                    a.copy_from_slice(&payload[0..4]);
                    Some(IpAddr::from(a)) },
            16 => { let mut a: [u8; 16] = [0; 16];
                    a.copy_from_slice(&payload[0..16]);
                    Some(IpAddr::from(a)) },
            _ => None,
        };

        if let Some(ip) = ip_addr {
            // Get writable map
            let mut mmap = map.write().expect("RwLock broken");

            // Insert
            let expire_time = precise_time_ns() + TIMEOUT_DARK_DECOYS_NS;
            *mmap.entry(ip).or_insert(expire_time) = expire_time;

            // Get rid of it
            drop(mmap);

            debug!("Added registered ip {} from redis", ip);
        }
    }
}

impl FlowTracker
{
    pub fn new() -> FlowTracker
    {

        let ret = FlowTracker
            {
                tracked_flows: HashSet::new(),
                dark_decoy_flows: Arc::new(RwLock::new(HashMap::new())),
                redis_conn: get_redis_conn(),
                stale_drops_tracked: VecDeque::with_capacity(16384),
            };

        let write_map = Arc::clone(&ret.dark_decoy_flows);
        thread::spawn(move || { update_pubsub_map(write_map) });

        ret
    }
    pub fn begin_tracking_flow(&mut self, flow: &Flow)
    {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_drops_tracked.push_back(
            SchedEvent {
                drop_time: precise_time_ns() + TIMEOUT_TRACKED_NS,
                flow: *flow,
            });
        // Begin tracking as a potential TD flow (if not already in the set).
        self.tracked_flows.insert(*flow);
    }

    pub fn is_registered_dark_decoy(&self, flow: &FlowNoSrcPort) -> bool
    {
        let map = self.dark_decoy_flows.read().expect("RwLock broken");
        map.contains_key(&flow.dst_ip)
    }

    pub fn is_tracked_flow(&self, flow: &Flow) -> bool
    {
        self.tracked_flows.contains(&flow)
    }

    pub fn mark_dark_decoy(&mut self, flow: &FlowNoSrcPort)
    {

        let already_known = self.is_registered_dark_decoy(flow);

        let expire_time = precise_time_ns() + TIMEOUT_DARK_DECOYS_NS;
        let mut map = self.dark_decoy_flows.write().expect("RwLock Broken");
        *map.entry(flow.dst_ip).or_insert(expire_time) = expire_time;

        if !already_known {
            // Publish to redis
            let octs = match flow.dst_ip {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            redis::cmd("PUBLISH").arg("dark_decoy_map").arg(octs).execute(&self.redis_conn);
        }
    }

    pub fn stop_tracking_flow(&mut self, flow: &Flow)
    {
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
                },
                None => {
                    // entries in stale_drops_tracked are supposed to be sorted by time, so
                    // once we see a flow that doesn't need to be removed, then
                    // there is no need to check further
                    return num_tracked_flows_before - self.tracked_flows.len();
                }
            }
        }
    }

    // drop_stale_dark_decoy_flows returns the number of registered dark decoy flows that it drops.
    fn drop_stale_dark_decoy_flows(&mut self) -> usize {
        let right_now = precise_time_ns();

        let mut map = self.dark_decoy_flows.write().expect("RwLock Broken");
        let num_dark_decoys_before = map.len();
        // Dark Decoys Map is not sorted by timeout, so need to check all
        map.retain(|_, v| ( *v > right_now));
        let num_dark_decoys_after = map.len();
        if num_dark_decoys_before != num_dark_decoys_after {
            debug!("Dark Decoys drops: {} - > {}", num_dark_decoys_before, num_dark_decoys_after);
        }
        num_dark_decoys_after - num_dark_decoys_before
    }

    // This function returns the number of flows that it drops.
    #[allow(non_snake_case)]
    pub fn drop_all_stale_flows(&mut self) -> usize
    {
        self.drop_stale_tracked_flows() + self.drop_stale_dark_decoy_flows()
    }

    pub fn count_tracked_flows(&self) -> usize
    {
        self.tracked_flows.len()
    }
    pub fn count_dark_decoy_flows(&self) -> usize
    {
        let map = self.dark_decoy_flows.read().expect("RwLock Broken");
        map.len()
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_flow_display_format() {
        use Flow;
        use std::fmt::Write;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let flow6 = Flow {
            src_ip: IpAddr::V6(Ipv6Addr::new(0x2601, 0, 0, 0, 0, 0, 0xabcd, 0xef00)),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0x26ff, 0, 0, 0, 0, 0, 0, 1)),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow6)
            .expect("Error occurred while trying to write in String");
        assert_eq!(output, "[2601::abcd:ef00]:5672 -> [26ff::1]:443");


        let flow4 = Flow {
            src_ip: IpAddr::V4(Ipv4Addr::new(10,22,0,1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(128,138,97,6)),
            src_port: 5672,
            dst_port: 443,
        };

        let mut output = String::new();
        write!(&mut output, "{}", flow4)
            .expect("Error occurred while trying to write in String");
        assert_eq!(output, "10.22.0.1:5672 -> 128.138.97.6:443");
    }
}
