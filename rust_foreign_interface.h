#ifndef _INCLGUARD_CLONERING_RUST_INTERFACE_H_
#define _INCLGUARD_CLONERING_RUST_INTERFACE_H_

#define TD_KEYLEN_BYTES (32)

struct RustGlobalsStruct
{
	void *global;
};

// We specifically name this something different to avoid accidentally linking
// against the otherwise compatible rust_tapdance
struct RustGlobalsStruct rust_detect_init(
	int32_t cur_lcore_id, uint8_t (*station_keys)[TD_KEYLEN_BYTES], uint8_t numkeys, char *workers_socket_addr);
uint8_t rust_update_cli_conf(void *conf_ptr);
uint8_t rust_process_packet(
	void *rust_global, void *c_raw_ethframe, size_t c_frame_len);
uint8_t rust_event_loop_tick(void *rust_global);
// uint8_t rust_update_overloaded_decoys(void* rust_global);
uint8_t rust_periodic_report(void *rust_global);
uint8_t rust_periodic_cleanup(void *rust_global);

int send_packet_to_proxy(uint8_t id, uint8_t *pkt, size_t len);

#endif //_INCLGUARD_CLONERING_RUST_INTERFACE_H_
