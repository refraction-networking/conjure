#ifndef _FORGE_H
#define _FORGE_H

#include <linux/types.h>

#define SOCK_FORGE      9   /* new protocol */
#define TCP_STATE       18  /* new TCP sockopt */

struct tcp_state {
	__be32      src_ip;
	__be32      dst_ip;

	__be16      sport;
	__be16      dport;
	__u32       seq;
	__u32       ack;
	__u32	    snd_una;	/* First byte we want an ack for */

	__u8        tstamp_ok;
	__u8        sack_ok;
	__u8        wscale_ok;
	__u8        ecn_ok;
	__u8        snd_wscale;
	__u8        rcv_wscale;

	__u32       snd_wnd;
	__u32       rcv_wnd;

	__u32       ts_recent;  /* Timestamp to echo next. */
	__u32       ts_val;     /* Timestamp to use next. */

	__u32       mss_clamp;

	/*
	 * Fields that are below the TCP layer, but that we
	 * might want to mess with anyway.
	 */
	__s16       inet_ttl;   /* unicast IP ttl (use -1 for the default) */
};

#endif
