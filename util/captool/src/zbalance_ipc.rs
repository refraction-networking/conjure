use libc::{suseconds_t, time_t, timeval};
use std::ffi::{c_int, c_void, CString};
use std::ptr::null_mut;
use std::slice;
use std::time::{Duration, Instant};

use errno::errno;

use crate::error::Error;

pub struct ZbalanceIPCCapture {
    _runner: zbalance_ipc_runner,
    _start: Instant,
}

unsafe impl Send for ZbalanceIPCCapture {}

impl ZbalanceIPCCapture {
    pub fn new(cluster: i32, queue: i32) -> Result<ZbalanceIPCCapture, Error> {
        let mut zbalance_ipc_capture = ZbalanceIPCCapture {
            _runner: zbalance_ipc_runner {
                g_buf: null_mut(),
                g_pool: null_mut(),
                g_queue: null_mut(),
                buf_len: PF_BURST_SIZE as c_int,
                cluster_id: cluster as c_int,
                queue_id: queue as c_int,
            },
            _start: Instant::now(),
        };

        unsafe {
            let ret = init_runner(&mut &mut zbalance_ipc_capture._runner);
            if ret < 0 {
                // if the return value is less than 0 return the errno error
                let e = errno();
                return Err(format!("Error: {} {}", e.0, e).into());
            }
        }

        Ok(zbalance_ipc_capture)
    }

    pub fn next_zbalance_packet(&mut self) -> Result<&mut [u8], Error> {
        let mut zbalance_packet = zbalance_packet {
            size: 0,
            bytes: null_mut(),
        };
        unsafe {
            let ret = next_packet(&mut self._runner, &mut zbalance_packet);
            if ret < 0 {
                // if the return value is less than 0 return the errno error
                let e = errno();
                return Err(format!("Error: {} {}", e.0, e).into());
            }
        }
        unsafe {
            Ok(slice::from_raw_parts_mut(
                zbalance_packet.bytes as *mut u8,
                zbalance_packet.size as usize,
            ))
        }
    }

    pub fn set_bpf_filter<S: Into<String>>(&mut self, filter: S) -> Result<(), Error> {
        let c_filter = CString::new(filter.into())?;
        unsafe {
            let ret = set_filter(&mut self._runner, c_filter.as_ptr());
            if ret < 0 {
                // if the return value is less than 0 return the errno error
                let e = errno();
                Err(format!("Error: {} {}", e.0, e).into())
            } else {
                Ok(())
            }
        }
    }

    pub fn time_since_start(&self) -> timeval {
        duration_to_timeval(self._start.elapsed())
    }
}

impl Drop for ZbalanceIPCCapture {
    fn drop(&mut self) {
        unsafe {
            close(&mut self._runner);
        }
    }
}

pub const PF_BURST_SIZE: u32 = 16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct zbalance_ipc_runner {
    g_queue: *const c_void,
    g_pool: *const c_void,
    g_buf: *const c_void,

    buf_len: c_int,
    cluster_id: c_int,
    queue_id: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct zbalance_packet {
    size: c_int,
    bytes: *const c_void,
}

extern "C" {
    /// create a runner object that will maintain state for a pfring zbalance ipc ingest queue
    fn init_runner(runner: &mut &mut zbalance_ipc_runner) -> ::std::os::raw::c_int;

    #[allow(dead_code)]
    /// Read a burst of up to `buf_len` packets from the queue.
    fn next_packet_burst(runner: *mut zbalance_ipc_runner) -> ::std::os::raw::c_int;

    /// Read the next packet from the queue
    fn next_packet(
        runner: *mut zbalance_ipc_runner,
        packet: *mut zbalance_packet,
    ) -> ::std::os::raw::c_int;

    /// Apply a BPF filter from text.
    fn set_filter(
        runner: *mut zbalance_ipc_runner,
        filter: *const libc::c_char,
    ) -> ::std::os::raw::c_int;

    /// cleanup after a runner object, detaching from pfring and freeing resources
    fn close(runner: *mut zbalance_ipc_runner) -> ::std::os::raw::c_int;
}

fn duration_to_timeval(duration: Duration) -> timeval {
    let seconds = duration.as_secs() as time_t;
    let microseconds = (duration.subsec_micros() as suseconds_t) * 1000;

    timeval {
        tv_sec: seconds,
        tv_usec: microseconds,
    }
}
