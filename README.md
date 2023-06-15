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

[Refraction Client Library](https://github.com/refraction-networking/gotapdance) -
pure golang client library for connecting to refraction systems. Implements BOTH
conjure and tapdance.

[Tapdance Station](https://github.com/refraction-networking/tapdance) - Tapdance
station code implementing the previous iteration of refraction networking development.

## Install

This is an abridged install and configuration process, for expanded install instructions,
configuration options, or multi-station deployments see [the wiki](https://github.com/refraction-networking/conjure/wiki).

### Requirements

Building the station requires both go and rust:

- [Install Golang](https://golang.org/doc/install)

- [Install Rust](https://www.rust-lang.org/tools/install)

**Install packages and go libraries**

```sh
sudo apt install  wget git make gcc bison flex protobuf-compiler curl libssl-dev pkg-config libgmp3-dev libzmq3-dev
go get -d -u -t github.com/refraction-networking/gotapdance/...
```

**Install PF_RING**

1. [Install from Package](https://github.com/refraction-networking/conjure/wiki/PF_RING#from-packages)

2. [Install From Git / Source](https://github.com/refraction-networking/conjure/wiki/PF_RING#from-source)
    - if installing from git / source make the zbalance_ipc executable, and ensure that it is available through your `$PATH`.

### Build the station

```sh
make

## future
# sudo make install
```

### Configure

The layout of configuration expected by the default layout of a production server is:

```sh
## Station specific configuration and files go in /var/lib/conjure
$ tree /var/lib/conjure/
/var/lib/conjure/
├── app_config.toml
├── ClientConf      # if running the registration server locally
├── conjure.conf
├── phantom_subnets.toml
├── privkey
├── pubkey
└── reg_config.toml # if running the registration server locally

## Scripts, executables, and the default environment script (conjure.conf) go in /opt/conjure
$ tree /opt/conjure/
/opt/conjure/
├── bin
│   ├── application
│   ├── conjure
│   └── registration_server  # if running the registration server locally
├── on-reboot.sh
├── scripts
│   ├── install_pfring.sh
│   ├── start_application.sh
│   ├── start_detector.sh
│   ├── start_registrar.sh
│   └── start_zbalance_ipc.sh
└── sysconfig
    └── conjure.conf    # Expected by systemd services, applies overrides from /var/lib/conjure/conjure.conf
```

To run a station configuration modifications are required. This section outlines
some minimal changes, for more configuration options see the [wiki configuration page](https://github.com/refraction-networking/conjure/wiki/Configuration).

1. Define global paths, core usage, and pf_ring parameters in `sysconfig/conjure.conf`

    ```conf
    # ============[ REQUIRED ]============
    # The interface(s) which PF_RING Zero Copy will tap.
    CJ_IFACE="zc:enp179s0f0,zc:enp179s0f1"

    Public addresses that of non-tap interface - used for kernel DNAT
    IP4_ADDR="<PUBLIC_STATION_V4_ADDRESS>"
    IP6_ADDR="<PUBLIC_STATION_V6_ADDRESS>"

    ```

    Note: ipv6 in disabled by default. To enable IPv6 modify
    `application/config.toml`

    ```diff
    # Allow the station to opt out of either version of internet protocol to limit a
    # station to handling one or the other. For example, v6 on small station deployment
    # with only v6 phantom subnet,  v4 only on station with no puvlic v6 address.
    enable_v4 = true
    -enable_v6 = false
    +enable_v6 = true
    ```

2. Define application parameters in `application/app_config.toml`

    ```toml
    # ============[ REQUIRED ]============
    ## Detector
    [[connect_sockets]]

    address = "ipc://@detector"
    type = "NULL"

    ```

3. Define the phantom subnet generations that will be supported (this can be
updated going forward with new generations) in `sysconfig/phantom_subnets.toml`

    ```toml
    [Networks]
        [Networks.1]
            Generation = 1
            [[Networks.1.WeightedSubnets]]
                Weight = 9
                Subnets = ["192.122.190.0/24", "2001:0123:4567:89ab::/64"]

        [Networks.2]
            Generation = 2
            [[Networks.2.WeightedSubnets]]
                Weight = 9
                Subnets = ["192.0.0.0/24", "2001:0123:4567:89ab::/64"]
            [[Networks.2.WeightedSubnets]]
                Weight = 1
                Subnets = ["2001:0123:4567:89ab::/96"]
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

# if enabling and supporting registration server or multi-station registration sharing
sudo systemctl enable conjure-registration-server
```

Start the station.

```sh
# zbalance has to be first or the detector will throw an error
systemctl start zbalance

# Next start the detector and station application processes
systemctl start conjure-det
systemctl start conjure-app

# if enabling and supporting registration server or multi-station registration sharing
systemctl start conjure-registration-server
```

## [FAQ](https://github.com/refraction-networking/conjure/wiki/FAQ) | [WIKI](https://github.com/refraction-networking/conjure/wiki)
