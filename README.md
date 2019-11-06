# dark-decoys

## Install

### Install dependencies

```sh
sudo apt install libzmq3-dev redis-server
go get -d -u -t github.com/refraction-networking/gotapdance/...
go get -d github.com/go-redis/redis

```

### Install PF_RING

1. [Install PF_RING kernel module](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#kernel-module-installation)

2. [Install PF_RING Libpfring and Libpcap](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#libpfring-and-libpcap-installation)

### Build the station

```sh
make

#future
# sudo make install
```

## Setup

```sh
# Add prerouting rules for ipv4 and ipv6 to Destination NAT (DNAT) to change destination IP addr
sudo iptables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to 192.122.200.231:41245
sudo ip6tables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to [2001:48a8:687f:2::2]:41245

# Disable Reverse_Path Filtering so that we may deal with spoofed addresses.
sudo sysctl -w net.ipv4.conf.tun0.rp_filter=0

# Make sure INPUT iptables has an accept for `tun0` (isn't blocking packets after they're DNAT'd)
sudo iptables -I INPUT 1 -i tun0 -j ACCEPT
sudo ip6tables -I INPUT 1 -i tun0 -j ACCEPT


# Repeat for `tun1`/`tun2`/`tun3`/etc... if you have multiple cores
# ...
```

## Run

```sh
> dark_decoy  -c <cluster_id> -i zc:<iface> [opts]

# Options

#     REQUIRED
#     -c  <cluster_id> - The cluster id specified to PF_RING when starting `zbalance_ipc`
#     -i  <g_iface_name> - The interface on which PF_RING Zero Copy is running.

#     OPTIONAL
#     -n  <cpu_procs> - Number of cores to be used (default -1 = all cores)
#     -s <skip_core> - specify core_id to be skipped when allocating threads.
#     -K <keyfile_name> - Specify custom private key to be used by station
#     -a <zmq_address> - Custom Address of ZMQ server

#     DEBUG
#     -l <log_interval> - In seconds, interval between logging of bandwidth, tag checks/s, etc.
#     -o <core_affinity_offset> - Start processes on $core_affinity_offset+$cpu_procs.
#             This allows us to run debug/production pf_rings on different cores
#             entirely (which rust likes), and with different cluster_ids.
```
