use std::collections::{HashMap, HashSet, VecDeque};
use time::precise_time_ns;

use std::net::IpAddr;
use pnet::packet::tcp::TcpPacket;

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
        write!(f, "{}:{} -> {}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
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

#[derive(Copy, Clone)]
enum FlowState
{
    InTLSHandshake,
    // After SYN, before first app packet (might signal us)
    ActiveTag(u64),     // Upon a signal, we create the specified flow
    // client -> client-specified dark decoy
    // and tag it with this.
    // The u64 is the time (ns) that this times out.
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

    // Known dark decoy flows that should be picked up.
    // Map values are timeouts, which are used to drop stale dark decoys
    pub dark_decoy_flows: HashMap<FlowNoSrcPort, u64>,

}

// Amount of time that we timeout all flows
const TIMEOUT_TRACKED_NS: u64 = 30 * 1000 * 1000 * 1000;
const TIMEOUT_DARK_DECOYS_NS: u64 = 30 * 1000 * 1000 * 1000;
//const FIN_TIMEOUT_NS: u64 = 2*1000*1000*1000;

impl FlowTracker
{
    pub fn new() -> FlowTracker
    {
        FlowTracker
            {
                tracked_flows: HashSet::new(),
                dark_decoy_flows: HashMap::new(),

                stale_drops_tracked: VecDeque::with_capacity(16384),
            }
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
        self.dark_decoy_flows.contains_key(&flow)
    }

    pub fn is_tracked_flow(&self, flow: &Flow) -> bool
    {
        self.tracked_flows.contains(&flow)
    }

    pub fn mark_dark_decoy(&mut self, flow: &FlowNoSrcPort)
    {
        let expire_time = precise_time_ns() + TIMEOUT_DARK_DECOYS_NS;
        *self.dark_decoy_flows.entry(*flow).or_insert(expire_time) = expire_time;
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

        let num_dark_decoys_before = self.dark_decoy_flows.len();
        // Dark Decoys Map is not sorted by timeout, so need to check all
        self.dark_decoy_flows.retain(|_, v| ( *v > right_now));
        let num_dark_decoys_after = self.dark_decoy_flows.len();
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
        self.dark_decoy_flows.len()
    }
}
