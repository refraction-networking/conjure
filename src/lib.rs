#[macro_use]
extern crate arrayref;
extern crate libc;
#[macro_use]
extern crate log;
extern crate aes_gcm;
extern crate chrono;
extern crate errno;
extern crate hex;
extern crate pnet;
extern crate rand;

extern crate protobuf;
extern crate redis;
extern crate serde;
extern crate serde_derive;
extern crate toml;
extern crate tuntap; // https://github.com/ewust/tuntap.rs
extern crate zmq;

use std::mem::transmute;
use util::precise_time_ns;

use serde_derive::Deserialize;
use std::env;
use std::fs;

use std::ffi::CStr;
use std::os::raw::c_char;

use tuntap::{TunTap, IFF_TUN};

// Must go before all other modules so that the report! macro will be visible.
#[macro_use]
pub mod logging;

pub mod c_api;
pub mod elligator;
pub mod flow_tracker;
pub mod process_packet;
pub mod sessions;
pub mod signalling;
pub mod util;

use flow_tracker::{Flow, FlowTracker};

// Global program state for one instance of a TapDance station process.
pub struct PerCoreGlobal {
    priv_key: [u8; 32],

    lcore: i32,
    pub flow_tracker: FlowTracker,

    // Rc<RefCell<>> ??
    // pub sessions: HashMap<Flow, SessionState>,
    // Just some scratch space for mio.
    //events_buf: Events,
    pub tun: TunTap,

    pub stats: PerCoreStats,

    // ZMQ socket for sending information to the dark decoy application
    zmq_sock: zmq::Socket,

    // Filter list of addresses to ignore traffic from. This primarily functions to prevent liveness
    // testing from other stations in a conjure cluster from clogging up the logs with connection
    // notifications.
    filter_list: Vec<String>,

    // If we're reading from a GRE tap, we can provide an optional offset that we read
    // into the packet (skipping the GRE header).
    gre_offset: usize,
}

// Tracking of some pretty straightforward quantities
pub struct PerCoreStats {
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
    last_measure_time: u128,

    pub not_in_tree_this_period: u64,
    pub in_tree_this_period: u64,
}

// Currently used to parse the Toml config. If this needs to play a larger role
// in the future this can be added to the PerCoreGlobal.
#[derive(Deserialize)]
struct StationConfig {
    detector_filter_list: Vec<String>,
}

const STATION_CONF_PATH: &str = "CJ_STATION_CONFIG";

impl PerCoreGlobal {
    fn new(priv_key: [u8; 32], the_lcore: i32, workers_socket_addr: &str) -> PerCoreGlobal {
        let tun = TunTap::new(IFF_TUN, &format!("tun{the_lcore}")).unwrap();
        tun.set_up().unwrap();

        // Setup ZMQ
        let zmq_ctx = zmq::Context::new();
        let zmq_sock = zmq_ctx.socket(zmq::PUB).unwrap();
        zmq_sock
            .connect(workers_socket_addr)
            .expect("failed connecting to ZMQ");

        // Parse toml station config to get filter list
        let conf_path = env::var(STATION_CONF_PATH).unwrap();
        let contents = fs::read_to_string(conf_path)
            .expect("Something went wrong reading the station config file");
        let value: StationConfig =
            toml::from_str(&contents).expect("Failed to parse toml station config");

        // Also all threads read the same environment variable so they will all
        // set it the same, race condition for setting client ip logging doesn't
        // affect the outcome. LOG_CLIENT_IP set in conjure.conf
        let client_ip_logging_str = env::var("LOG_CLIENT_IP").unwrap();
        match client_ip_logging_str.as_ref() {
            "true" => Flow::set_log_client(true),
            "false" => Flow::set_log_client(false),
            &_ => Flow::set_log_client(false), // default disable
        };

        let gre_offset = match env::var("PARSE_GRE_OFFSET") {
            Ok(val) => val.parse::<usize>().unwrap(),
            Err(env::VarError::NotPresent) => 0,
            Err(_) => {
                println!("Error, can't parse PARSE_GRE_OFFSET");
                0
            }
        };

        debug!("gre_offset: {}", gre_offset);

        PerCoreGlobal {
            priv_key,
            lcore: the_lcore,
            // sessions: HashMap::new(),
            flow_tracker: FlowTracker::new(),
            tun,
            stats: PerCoreStats::new(),
            zmq_sock,
            filter_list: value.detector_filter_list,
            gre_offset,
        }
    }
}

impl PerCoreStats {
    fn new() -> PerCoreStats {
        PerCoreStats {
            elligator_this_period: 0,
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
            in_tree_this_period: 0,
        }
    }
    fn periodic_status_report(&mut self, tracked: usize, dark_decoys: usize) {
        let cur_measure_time = precise_time_ns();
        let (user_secs, user_usecs, sys_secs, sys_usecs) = c_api::c_get_cpu_time();
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
        report!(
            "stats {} pkts ({} v4, {} v6) dark decoy flows {} tracked flows {} tags checked {}",
            self.packets_this_period,
            self.ipv4_packets_this_period,
            self.ipv6_packets_this_period,
            dark_decoys,
            tracked,
            self.elligator_this_period
        );

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

///
/// # Safety
///
#[no_mangle]
pub unsafe extern "C" fn rust_periodic_report(ptr: *mut PerCoreGlobal) {
    #[allow(unused_mut)]
    let mut global = &mut *ptr;
    global.stats.periodic_status_report(
        global.flow_tracker.count_tracked_flows(),
        global.flow_tracker.count_phantom_flows(),
    );
}

#[repr(C)]
pub struct RustGlobalsStruct {
    global: *mut PerCoreGlobal,
}

///
/// # Safety
///
#[no_mangle]
pub unsafe extern "C" fn rust_detect_init(
    lcore_id: i32,
    ckey: *const u8,
    workers_socket_addr: *const c_char,
) -> RustGlobalsStruct {
    logging::init(log::LogLevel::Debug, lcore_id);

    let key = *array_ref![std::slice::from_raw_parts(ckey, 32_usize), 0, 32];

    let s = format!("/tmp/dark-decoy-reporter-{lcore_id}.fifo");
    c_api::c_open_reporter(s);
    report!("reset");

    let addr: &CStr = CStr::from_ptr(workers_socket_addr);

    let global = PerCoreGlobal::new(key, lcore_id, addr.to_str().unwrap());

    debug!("Initialized rust core {}", global.lcore);

    RustGlobalsStruct {
        global: transmute(Box::new(global)),
    }
    //fail_map: unsafe { transmute(Box::new(fail_map)) },
    //cli_conf: unsafe { transmute(Box::new(cli_conf)) } }
}

// Called so we can tick the event loop forward. Must not block.
#[no_mangle]
pub extern "C" fn rust_event_loop_tick(_ptr: *mut PerCoreGlobal) {}

/// Drops TLS flows that took too long to send their first app data packet,
/// RSTs decoy flows a couple of seconds after the client's FIN, and
/// errors-out cli-stream-less sessions that took too long to get a new stream.
///
/// # Safety
///
#[no_mangle]
pub unsafe extern "C" fn rust_periodic_cleanup(ptr: *mut PerCoreGlobal) {
    #[allow(unused_mut)]
    let mut global = &mut *ptr;
    global.flow_tracker.drop_all_stale_flows();

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
