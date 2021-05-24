<p align="center">
<a href="https://refraction.network"><img src="https://user-images.githubusercontent.com/5443147/30133006-7c3019f4-930f-11e7-9f60-3df45ee13d9d.png" alt="refract"></a>
<h1 class="header-title" align="center">Conjure Refraction Station</h1>

<p align="center">Refraction Networking is a free-to-use anti-censorship technology, that places proxies at Internet Service Providers, so they are harder to block. This repository implements the conjure stations system including various registration channels, transport protocols, and configuration options.</p>
<p align="center">
<a href="https://github.com/refraction-networking/conjure/actions/workflows/build.yml"><img src="https://github.com/refraction-networking/conjure/actions/workflows/build.yml/badge.svg"></a>
<!-- <a href="https://godoc.org/github.com/refraction-networking/conjure/"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a> -->
<a href="https://goreportcard.com/report/github.com/refraction-networking/conjure"><img src="https://goreportcard.com/badge/github.com/refraction-networking/conjure"></a>
</p>

### See also 

[Refraction Client Library](https://github.com/refraction-networking/gotapdance) - gotapdance
pure golang library and client binaries for testing and connecting to refraction systems.

[Tapdance Station](https://github.com/refraction-networking/tapdance) - Tapdance
station code implementing the previous iteration of refraction networking development.

## Requirements

```sh
sudo apt install libzmq3-dev redis-server
go get -d -u -t github.com/refraction-networking/gotapdance/...
go get -d github.com/go-redis/redis

```

### Install PF_RING

1. [Install PF_RING kernel module](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#kernel-module-installation)

2. [Install PF_RING Libpfring and Libpcap](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#libpfring-and-libpcap-installation)

## Install

This is an abridged install and configuration process, for expanded install instructions,
configuration options, or multi-station deployments see [the wiki](https://github.com/refraction-networking/conjure/wiki).

Build the station

```sh
make

#future
# sudo make install
```

### Configure

To have a functional station modify a few configuration file.

Define global paths, core usage, and pf_ring parameters in `sysconfig/conjure.conf`

```conf
# ============[ REQUIRED ]============
# The interface(s) which PF_RING Zero Copy will tap.
CJ_IFACE="zc:enp179s0f0,zc:enp179s0f1"

Public addresses that of non-tap interface - used for kernel DNAT 
IP4_ADDR="<PUBLIC_STATION_V4_ADDRESS>"
IP6_ADDR="<PUBLIC_STATION_V6_ADDRESS>"

```

Define application parameters in `application/congfig.toml`

```toml
# ============[ REQUIRED ]============
## Detector
[[connect_sockets]]

address = "ipc://@detector"
type = "NULL"

```

Define the phantom subnet generations that will be supported (this can be
updated going forward with new generations) in `sysconfig/phantom_subnets.toml`

```toml
[Networks]
    [Networks.1]
        Generation = 1
        [[Networks.1.WeightedSubnets]]
            Weight = 9
            Subnets = ["192.122.190.0/24", "2001:48a8:687f:1::/64"] 

    [Networks.2]
        Generation = 2
        [[Networks.2.WeightedSubnets]]
            Weight = 9
            Subnets = ["192.122.190.0/24", "2001:48a8:687f:1::/64"] 
        [[Networks.2.WeightedSubnets]]
            Weight = 1
            Subnets = ["2001:48a8:687f:1::/96"] 
```

### Setup

Conjure relies on the kernel to handle provide DNAT to establish these rules we
need to configure and run the environment configuration script.

After defining `IP4_ADDR`, `IP6_ADDR`, and core usage parameters in the
`conjure.conf` file run the `on-reboot.sh` script to initialize all required
interfaces and rules.

```sh
./on-reboot.sh
```

Generate station keys using the libtapdance tools

```ssh
cd libtapdance && make genkey
./libtapdance/genkey
mv libtapdance/{priv,pub}key sysconfig/
```

### Run

Copy (or link) the systemd service configurations to the appropriate location

```sh
sudo cp sysconfig/*.service /etc/systemd/system/
sudo systemctl enable zbalance
sudo systemctl enable conjure-app
sudo systemctl enable conjure-det

# if enabling and supporting registration api or multi-station registration sharing
sudo systemctl enable conjure-registration-api
```

Start the station.

```sh
# zbalance has to be first or the detector will throw an error 
systemctl start zbalance

systemctl start conjure-det
systemctl start conjure-app

# if enabling and supporting registration api or multi-station registration sharing
systemctl start conjure-registration-api
```

## [FAQ](https://github.com/refraction-networking/conjure/wiki/FAQ) | [WIKI](https://github.com/refraction-networking/conjure/wiki) 
