#[macro_use]
extern crate arrayref;
//extern crate lazycell;
extern crate libc;
#[macro_use]
extern crate log;
extern crate pnet;
extern crate rand;
extern crate time;
extern crate errno;

extern crate radix; // https://github.com/refraction-networking/radix


use std::mem::transmute;
use time::precise_time_ns;

use radix::PrefixTree;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;


// Must go before all other modules so that the report! macro will be visible.
#[macro_use]
pub mod logging;

pub mod c_api;
pub mod elligator;
pub mod flow_tracker;
pub mod process_packet;
pub mod util;

use flow_tracker::FlowTracker;

// Global program state for one instance of a TapDance station process.
pub struct PerCoreGlobal
{
    priv_key: [u8; 32],

    lcore: i32,
    pub flow_tracker: FlowTracker,

    // Just some scratch space for mio.
    //events_buf: Events,

    pub stats: PerCoreStats,

    // List of IP prefixes we'll respond to as dark decoys
    pub ip_tree:   PrefixTree,
}

// Tracking of some pretty straightforward quantities
pub struct PerCoreStats
{
    pub elligator_this_period: u64,
    pub packets_this_period: u64,
    pub ipv4_packets_this_period: u64,
    pub ipv6_packets_this_period: u64,
    pub tcp_packets_this_period: u64,
    pub tls_packets_this_period: u64,
    pub bytes_this_period: u64,
    //pub reconns_this_period: u64,
    pub tls_bytes_this_period: u64,
    pub port_443_syns_this_period: u64,
    //pub cli2cov_raw_etherbytes_this_period: u64,

    // CPU time counters (cumulative)
    tot_usr_us: i64,
    tot_sys_us: i64,
    // For computing measurement duration (because period won't be exactly 1
    // sec). Value is nanoseconds since an unspecified epoch. (It's a time,
    // not a duration).
    last_measure_time: u64,

    pub not_in_tree_this_period: u64,
    pub in_tree_this_period: u64,
}

const IP_LIST_PATH: &'static str = "/var/lib/dark-decoy.prefixes";


impl PerCoreGlobal
{
    fn new(priv_key: [u8; 32], the_lcore: i32) -> PerCoreGlobal
    {

        PerCoreGlobal {
            priv_key: priv_key,
            lcore: the_lcore,
            flow_tracker: FlowTracker::new(),
            stats: PerCoreStats::new(),
            ip_tree: PrefixTree::new(),
        }
    }

    fn read_ip_list(&mut self)
    {
        let f = match File::open(IP_LIST_PATH) {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to read {}: {:?}", IP_LIST_PATH, e);
                return;
            }
        };
        #[allow(unused_mut)]
        let mut file = BufReader::new(&f);
        for line in file.lines() {
            let res = self.ip_tree.add_cidr(&line.unwrap());
            if res.is_err() {
                error!("Bad IP list: {:?}", res);
                return;
            }
        }

    }

}

impl PerCoreStats
{
    fn new() -> PerCoreStats
    {
        PerCoreStats { elligator_this_period: 0,
                       packets_this_period: 0,
                       ipv4_packets_this_period: 0,
                       ipv6_packets_this_period: 0,
                       tcp_packets_this_period: 0,
                       tls_packets_this_period: 0,
                       bytes_this_period: 0,
                       //reconns_this_period: 0,
                       tls_bytes_this_period: 0,
                       port_443_syns_this_period: 0,
                       //cli2cov_raw_etherbytes_this_period: 0,

                       tot_usr_us: 0,
                       tot_sys_us: 0,
                       last_measure_time: precise_time_ns(),

                        not_in_tree_this_period: 0,
                        in_tree_this_period: 0 }
    }
    fn periodic_status_report(&mut self, tracked: usize, sessions: usize)
    {
        let cur_measure_time = precise_time_ns();
        let (user_secs, user_usecs, sys_secs, sys_usecs) =
            c_api::c_get_cpu_time();
        let user_microsecs: i64 = user_usecs + 1000000 * user_secs;
        let sys_microsecs: i64 = sys_usecs + 1000000 * sys_secs;

        /*
        let measured_dur_ns = cur_measure_time - self.last_measure_time;
        let total_cpu_usec = (user_microsecs + sys_microsecs)
                     - (self.tot_usr_us + self.tot_sys_us);
        */
        /*
        report!("status {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
                0,
                self.packets_this_period,
                self.tls_packets_this_period,
                self.bytes_this_period,
                total_cpu_usec,
                get_rounded_time(),
                measured_dur_ns,
                util::mem_used_kb(),
                0,
                tracked,
                sessions,
                self.tls_bytes_this_period,
                self.port_443_syns_this_period,
                0,
                0);
        */
        report!("stats {} pkts ({} v4, {} v6) {} tls tree: {} out {} in, {} tracked flows {} tags checked",
            self.packets_this_period,
            self.ipv4_packets_this_period,
            self.ipv6_packets_this_period,
            self.tls_packets_this_period,
            self.not_in_tree_this_period,
            self.in_tree_this_period,
            tracked,
            self.elligator_this_period);

        self.elligator_this_period = 0;
        self.packets_this_period = 0;
        self.ipv4_packets_this_period = 0;
        self.ipv6_packets_this_period = 0;
        self.tcp_packets_this_period = 0;
        self.tls_packets_this_period = 0;
        self.bytes_this_period = 0;
        //self.reconns_this_period = 0;
        self.tls_bytes_this_period = 0;
        self.port_443_syns_this_period = 0;

        self.tot_usr_us = user_microsecs;
        self.tot_sys_us = sys_microsecs;
        self.last_measure_time = cur_measure_time;

        self.not_in_tree_this_period = 0;
        self.in_tree_this_period = 0;
    }
}


#[no_mangle]
pub extern "C" fn rust_periodic_report(ptr: *mut PerCoreGlobal)
{
    #[allow(unused_mut)]
    let mut global = unsafe { &mut *ptr };
    global.stats.periodic_status_report(
        global.flow_tracker.count_tracked_flows(), 0);
}

#[repr(C)]
pub struct RustGlobalsStruct
{
    global: *mut PerCoreGlobal,
}

#[no_mangle]
pub extern "C" fn rust_detect_init(lcore_id: i32, ckey: *const u8)
-> RustGlobalsStruct
{

    logging::init(log::LogLevel::Debug, lcore_id);

    let key = *array_ref![unsafe{std::slice::from_raw_parts(ckey, 32 as usize)},
                            0, 32];

    let s = format!("/tmp/dark-decoy-reporter-{}.fifo", lcore_id);
    c_api::c_open_reporter(s);
    report!("reset");

    let mut global = PerCoreGlobal::new(key, lcore_id);
    global.read_ip_list();

    debug!("Initialized rust core {}", lcore_id);

    RustGlobalsStruct { global: unsafe { transmute(Box::new(global)) } }
                        //fail_map: unsafe { transmute(Box::new(fail_map)) },
                        //cli_conf: unsafe { transmute(Box::new(cli_conf)) } }
}

// Called so we can tick the event loop forward. Must not block.
#[no_mangle]
pub extern "C" fn rust_event_loop_tick(_ptr: *mut PerCoreGlobal)
{

}

// Drops TLS flows that took too long to send their first app data packet,
// RSTs decoy flows a couple of seconds after the client's FIN, and
// errors-out cli-stream-less sessions that took too long to get a new stream.
#[no_mangle]
pub extern "C" fn rust_periodic_cleanup(ptr: *mut PerCoreGlobal)
{
    #[allow(unused_mut)]
    let mut global = unsafe { &mut *ptr };
    global.flow_tracker.drop_stale_flows();

    /*
    // Any session that hangs around for 30 seconds with a None cli stream
    // should be errored out. These check events are scheduled every time a
    // stream ends (token removed from driver map).
    global.cli_ssl_driver.check_sessions_progress(&global.id2sess);
    global.cli_psv_driver.check_sessions_progress(&global.id2sess);

    // Any stream that hangs around [longer than the system's largest timeout]
    // should be treated as broken.
    global.cli_ssl_driver.check_streams_progress(&global.id2sess);
    global.cli_psv_driver.check_streams_progress(&global.id2sess);
    */
}


