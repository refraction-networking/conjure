#![allow(non_snake_case)]

use libc::size_t;

//#[cfg(not(test))]
#[link(name = "tapdance")]
extern "C" {
    // Creates a forge socket with the given TCP parameters,
    // and attaches an SSL object to it with the given TLS params.
    // Returned ptr is the SSL object. The underlying (forged) TCP fd is written
    // to forged_fd_out.
    //
    // local_ip, local_port, remote_ip, remote_port should all be net-order.
    // The rest are host-order.
    /*
    fn make_forged_tls(local_ip: u32, local_port: u16,
                       remote_ip: u32, remote_port: u16,
                       tcp_seq: u32, tcp_ack: u32,
                       cli_tcp_win: u16, cli_advertised_wscale: u8,
                       tcp_mss: u16,
                       tcp_ts: u32, tcp_ts_ecr: u32,
                       master_secret: *const u8, master_secret_len: usize,
                       cipher_suite: u16, client_random: *const u8,
                       server_random: *const u8,
                       app_data: *const u8, app_data_len: usize,
                       // Outputs
                       plaintext: *mut u8, plaintext_len: *mut i32,
                       forged_fd_out: *mut i32) -> *mut c_void;
    */

    // For the station; given a tag, return the payload.
    // returns the number of bytes written into out.
    // must provide a 32-byte out_aes buffer
    fn get_payload_from_tag(
        station_privkey: *const u8,
        stego_payload: *mut u8,
        stego_len: size_t,
        // Outputs
        out: *mut u8,
        out_len: size_t,
        out_aes: *mut u8,
    ) -> size_t; // 32 bytes

    // AES 128 GCM: 16-byte key, 12-byte IV
    fn decrypt_aes_gcm(
        key: *const u8,
        iv: *const u8,
        ciphertext: *const u8,
        ciphertext_len: size_t,
        pt_out: *mut u8,
        pt_len: size_t,
    ) -> size_t;

    fn get_cpu_time(
        usr_secs: *mut i64,
        usr_micros: *mut i64,
        sys_secs: *mut i64,
        sys_micros: *mut i64,
    );

    fn open_reporter(fname: *const u8); // const char *

    #[allow(dead_code)]
    fn write_reporter(msg: *const u8, len: size_t);

    // Send a TCP RST to daddr:dport, spoofed from saddr:sport. seq must be the
    // last ACK val observed from the targeted host, so it won't ignore the ACK.
    // saddr, daddr, sport, dport, seq must all be network order. HOWEVER,
    // note that c_tcp_send_rst_pkt() does to_be() on all of these, so
    // give c_tcp_send_rst_pkt() (but NOT this fn) host-order arguments!
    //fn tcp_send_rst_pkt(saddr: u32, daddr: u32,
    //                    sport: u16, dport: u16, seq: u32);
    //fn get_global_cli_conf() -> *const c_void;
    //fn add_to_global_cli_download_count(input: u64);
    //fn reset_global_cli_download_count();
    //fn get_global_cli_download_count() -> u64;
    //fn get_mut_global_failure_map() -> *mut c_void;

    fn get_shared_secret_from_tag(
        station_privkey: *const u8,
        stego_payload: *mut u8,
        stego_payload_len: size_t,
        shared_secret_out: *mut u8,
    ) -> size_t;
}

pub fn c_get_payload_from_tag(
    station_privkey: &[u8],
    stego_payload: &mut [u8],
    out: &mut [u8],
    out_len: size_t,
    aes_out: &mut [u8],
) -> size_t {
    assert_eq!(
        aes_out.len(),
        32,
        "Need to provide a 32-byte buffer space for AES key/IV to get_payload_from_tag"
    );

    unsafe {
        get_payload_from_tag(
            station_privkey.as_ptr(),
            stego_payload.as_mut_ptr(),
            stego_payload.len(),
            out.as_mut_ptr(),
            out_len,
            aes_out.as_mut_ptr(),
        )
    }
}

pub fn c_get_shared_secret_from_tag(
    station_privkey: &[u8],
    stego_payload: &mut [u8],
    shared_secret_out: &mut [u8],
) -> size_t {
    assert_eq!(
        shared_secret_out.len(),
        32,
        "Need to provide a 32-byte buffer space for shared_secret_out"
    );

    unsafe {
        get_shared_secret_from_tag(
            station_privkey.as_ptr(),
            stego_payload.as_mut_ptr(),
            stego_payload.len(),
            shared_secret_out.as_mut_ptr(),
        )
    }
}

pub fn c_decrypt_aes_gcm(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut pt_out: Vec<u8> = Vec::with_capacity(ciphertext.len());
    let pt_len = unsafe {
        decrypt_aes_gcm(
            key.as_ptr(),
            iv.as_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            pt_out.as_mut_ptr(),
            ciphertext.len(),
        )
    };

    unsafe {
        pt_out.set_len(pt_len);
    }

    pt_out
}

pub fn c_get_cpu_time() -> (i64, i64, i64, i64) {
    let mut usr_secs: i64 = 0;
    let mut usr_us: i64 = 0;
    let mut sys_secs: i64 = 0;
    let mut sys_us: i64 = 0;
    unsafe {
        get_cpu_time(
            &mut usr_secs as *mut i64,
            &mut usr_us as *mut i64,
            &mut sys_secs as *mut i64,
            &mut sys_us as *mut i64,
        );
    }
    (usr_secs, usr_us, sys_secs, sys_us)
}

pub fn c_open_reporter(fname: String) {
    unsafe {
        open_reporter(fname.as_ptr());
    }
}

#[cfg(not(test))]
pub fn c_write_reporter(msg: String) {
    //let n =
    unsafe {
        write_reporter(msg.as_ptr(), msg.len());
    }
}

//HACKY_CFG_NO_TEST_END*/
//HACKY_CFG_YES_TEST_BEGIN
/*
fn SSL_read(ssl: *mut c_void, output: *mut u8, out_len: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_write(ssl: *mut c_void, input: *const u8, in_len: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_get_error(ssl: *const c_void, ret: i32) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
fn SSL_free(ssl: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_read(ssl: *mut c_void, output: &mut [u8])
-> Result<usize, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_write(ssl: *mut c_void, input: &[u8])
-> Result<usize, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_shutdown(ssl: *mut c_void)
-> Result<bool, i32>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_SSL_free(ssl: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_ugh_ssl_err()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_ERR_clear_error()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_new_membio()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_BIO_write(bio: *mut c_void, data: &[u8]) -> i32
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_BIO_free_all(bio: *mut c_void)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_make_forged_tls(local_ip: u32, local_port: u16,
                         remote_ip: u32, remote_port: u16,
                         tcp_seq: u32, tcp_ack: u32,
                         cli_tcp_win: u16, cli_advertised_wscale: u8,
                         tcp_mss: u16, tcp_ts: u32, tcp_ts_ecr: u32,
                         master_secret: &[u8], cipher_suite: u16,
                         client_random: &[u8], server_random: &[u8],
                         app_data: &[u8], forged_fd_out: *mut i32)
-> *mut c_void
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_make_forged_memory_tls(master_secret: &[u8], cipher_suite: u16,
    client_random: &[u8], server_random: &[u8], app_data: &[u8],
    from_cli_membio: *mut c_void, unused_to_cli_membio: *mut c_void)
-> *mut c_void
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}


pub fn c_get_payload_from_tag(station_privkey: &[u8],
                                 stego_payload: &mut [u8],
                                 out: &mut [u8], out_len: size_t) -> size_t
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}

pub fn c_get_cpu_time() -> (i64, i64, i64, i64)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_open_reporter(fname: String)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
*/

#[cfg(test)]
pub fn c_write_reporter(_msg: String) {
    panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");
}
#[cfg(test)]
pub fn c_tcp_send_rst_pkt(_saddr: u32, _daddr: u32, _sport: u16, _dport: u16, seq: u32) {
    panic!("c_tcp_send_rst_pkt({}) called", seq);
}
/*
pub fn c_get_global_cli_conf() -> *const ClientConf
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_add_to_global_cli_download_count(input: u64)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_add_decoy_failure(failed: &String)
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn get_global_failure_map_rawptr() -> *mut HashMap<String, usize>
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_reset_global_cli_download_count()
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
pub fn c_get_global_cli_download_count() -> u64
{panic!("YOU ARE TESTING AND THIS FUNCTION IS NOT MOCKED YET!");}
//HACKY_CFG_YES_TEST_END*/
