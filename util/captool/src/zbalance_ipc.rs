


use std::slice;
use std::ffi::{c_void, c_int};
use std::ptr::{self, null_mut};


pub struct ZbalanceIPCCapture {
    _runner: zbalance_ipc_runner,
}

impl ZbalanceIPCCapture {
    fn new(cluster: i32, queue: i32) -> ZbalanceIPCCapture {
        let mut zbalance_ipc_capture = ZbalanceIPCCapture{
            _runner: zbalance_ipc_runner{
                g_buf: null_mut(),
                g_pool: null_mut(),
                g_queue: null_mut(),
                buf_len: PF_BURST_SIZE as c_int,
                cluster_id: cluster as c_int,
                queue_id: queue as c_int,
            }
        };

        unsafe { init_runner(&mut &mut zbalance_ipc_capture._runner); }

        zbalance_ipc_capture
    }

    pub fn next_zbalance_packet(&mut self) -> &mut [u8] {
        let mut zbalance_packet = zbalance_packet{
            size: 0,
            bytes: null_mut(),
        };
        unsafe { next_packet(&mut self._runner, &mut zbalance_packet); }
        unsafe {
            slice::from_raw_parts_mut(zbalance_packet.bytes as *mut u8, zbalance_packet.size as usize)
        }
    }
}


impl Drop for ZbalanceIPCCapture {
    fn drop(&mut self) {
        unsafe { close(&mut self._runner); }
    }
}

pub const _TD_LOADKEY_H_: u32 = 1;
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
    bytes: *const c_void
}

extern "C" {
    fn init_runner(runner: &mut &mut zbalance_ipc_runner);

    fn create_runner(
        ptr: *mut *mut zbalance_ipc_runner,
    ) -> ::std::os::raw::c_int;

    fn next_packet_burst(runner: *mut zbalance_ipc_runner) -> ::std::os::raw::c_int;

    fn next_packet(runner: *mut zbalance_ipc_runner, packet: *mut zbalance_packet) -> ::std::os::raw::c_int;

    fn set_filter(
        runner: *mut zbalance_ipc_runner,
        filter: *mut ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;

    fn unset_filter(runner: *mut zbalance_ipc_runner) -> ::std::os::raw::c_int;

    fn close(runner: *mut zbalance_ipc_runner) -> ::std::os::raw::c_int;
}
