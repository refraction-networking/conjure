#![allow(non_snake_case)]

//use std::os::raw::c_void;
use libc::size_t;

//use signalling::ClientConf;

//HACKY_CFG_NO_TEST_BEGIN

//#[cfg(not(test))]
//#[link(name = "tapdance")]
extern {
    fn get_cpu_time(usr_secs: *mut i64, usr_micros: *mut i64, 
                    sys_secs: *mut i64, sys_micros: *mut i64);

    fn open_reporter(fname: *const u8); // const char *
    fn write_reporter(msg: *const u8, len: size_t);

    fn send_packet_to_proxy(id: u8, pkt: *const u8, len: size_t) -> i32;
}

pub fn c_get_cpu_time() -> (i64, i64, i64, i64)
{
    let mut usr_secs: i64 = 0;
    let mut usr_us: i64 = 0;
    let mut sys_secs: i64 = 0;
    let mut sys_us: i64 = 0;
    unsafe { get_cpu_time(&mut usr_secs as *mut i64, &mut usr_us as *mut i64,
                          &mut sys_secs as *mut i64, &mut sys_us as *mut i64); }
    (usr_secs, usr_us, sys_secs, sys_us)
}

pub fn c_open_reporter(fname: String)
{
    unsafe {
        open_reporter(fname.as_ptr()); }
}

pub fn c_write_reporter(msg: String)
{
    //let n =
    unsafe { write_reporter(msg.as_ptr(), msg.len()); }
}

pub fn c_send_packet_to_proxy(id: u8, pkt: &[u8]) -> i32
{
    unsafe { send_packet_to_proxy(id, pkt.as_ptr(), pkt.len()) }
}
