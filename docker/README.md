<p align="center">
<a href="https://refraction.network"><img src="https://user-images.githubusercontent.com/5443147/30133006-7c3019f4-930f-11e7-9f60-3df45ee13d9d.png" height=65 align="middle" alt="refract"></a> <a href="https://www.docker.com/"><img src="https://docs.docker.com/assets/favicons/docs.ico" height=50 align="middle" alt="docker"></a>
<h1 class="header-title" align="center">Containerized Conjure</h1>
</p>

Allows for build of containers based on directory in one or several images.
For one image that contains all station pieces use:

```sh
make container
```

To build an individual piece of the station build with the desired target:

```sh
make target=app container
```

The options for individual targets, all built on top of 20.04:

- `det` - the detector with pfring libraries required to run using zbalance_ipc packet ingest
- `app` - the application
- `reg` -  the registration server.
- `zbalance` - pfring libraries and executables to run packet ingest.
- `sim` - all pieces of the station but the simulation build of the detector (no pfring)

---

## Build and Run

1. Build the containerized image

    ```bash
    # from the root dir of the repo
    make container
    ```

2. Create a config file `/var/lib/conjure/conjure.conf`. Set `CJ_IFACE` to be
the tap interface used by pfring, set `PF_DRIVER` to the driver for that
interface. The driver version can be found using

    `ethtool -i <iface> | grep "driver"`

    See the [README](#Configuration)
    for more information on configuring a conjure station.

    ```bash
    # /var/lib/conjure/conjure.conf
    PF_DRIVER="e1000e"
    CJ_IFACE=eth0
    CJ_PRIVKEY=/var/lib/conjure/privkey
    CJ_STATION_CONFIG=/var/lib/conjure/application_config.toml
    ```

3. Generate Keys

    ```sh
    docker run -v /home/user/conjure/libtapdance:/libtapdance -w /libtapdance gcc /bin/bash -c 'make genkey && ./genkey'

    # Copy the keys to `/var/lib/conjure/`
    cp pubkey privkey /var/lib/conjure/
    ```

    The above will create (or overwrite) keys in libtapdance folder.

4. Once per reboot setup on host for network state and shared resources (fifos, drivers, ipc, etc.)

    ```bash
    sudo ./on-reboot.sh
    ```

5. Bring services up with docker-compose

    ```bash
    # Bring services up
    docker compose -f docker/docker-compose.yaml up
    ```

    Bring services down with docker-compose

    ```sh
    docker compose -f docker/docker-compose.yaml down
    ```

---

## Configuration

While the above config is the only requirement it is not the most optimal/effective.

### List of Supported Variables and Defaults

The default linked `conjure.conf` sources `/var/lib/conjure/conjure.conf` to
allow for overrides.

The `docker-compose.yaml` file maps in `/var/lib/conjure/` from the host
allowing any configuration values in the `conjure.conf` and other configuration
files to be overridden.

```conf
# zbalance
CJ_IFACE=lo
CJ_CLUSTER_ID=98
CJ_CORECOUNT=1
CJ_COREBASE=0
ZBALANCE_HASH_MODE=1
N_QUEUE_SETS=1

# detector
CJ_CLUSTER_ID=98
CJ_CORECOUNT=1
CJ_COREBASE=0
CJ_SKIP_CORE=-1
CJ_QUEUE_OFFSET=0
CJ_LOG_INTERVAL=5
CJ_PRIVKEY=/var/lib/conjure/privkey
CJ_IP4_ADDR=127.0.0.1
CJ_IP6_ADDR=[::1]

# application
CJ_STATION_CONFIG=/var/lib/conjure/application_config.toml
PHANTOM_SUBNET_LOCATION=/var/lib/conjure/phantom_subnets.toml

# registration server
CJ_REGISTRAR_CONFIG=/var/lib/conjure/registration_config.toml
```

__CJ_CLUSTER_ID__: just a label for zbalance cluster

__CJ_CORECOUNT__: number of (threaded) cores to use for tapdance. Usually you want at most 1 less than the number available, particularly during development. Be sure to set this appropriately for production usage. A maximum of 16 cores is supported.

__CJ_COREBASE__: based core number to start with.

__CJ_SKIP_CORE__: based core number to have detector skip running on. Default=-1 (none). EG if COREBASE=0, CORECOUNT=4, and SKIP_CORE=1 then tapdance will use cores 0, 2, 3, 4. Only a single integer core number is allowed.

__CJ_QUEUE_OFFSET__: should be 0 if Tapdance is not running on the same machine. If tapdance is running this should be equal to the amount of threads that tapdance is using. ('tun' interfaces are numbered sequentially and if tadance is running 'offset' will solve the naming collision)

__CJ_PRIVKEY__: path to private key inside the docker container. Keep to default unless necessary

__CJ_STATION_CONFIG__: path to conjure configuration inside the docker container. Keep to default unless necessary

__CJ_IP4_ADDR__: Conjure station IP. Localhost works just fine. If Conjure application server located somewhere else this should be the remote IP (Central proxy mode)

__CJ_IP6_ADDR__: Same but IPv6

__PHANTOM_SUBNET_LOCATION__: Path to phantom subnets file inside the docker container. Keep to default unless necessary

__N_QUEUE_SETS__: Indicates to start_zbalance_ipc.sh to create two sets of queues. Used for
running two conjure stations or a conjure station together with tapdance.
Only options right now are 1 and anything else (which runs 2 queue sets).

__CJ_REGISTRAR_CONFIG__: Path to the configuration file for the registration api. Used by the conjure-reg service

## Troubleshooting

Run the container in an interactive environment

```bash
docker run --rm -it -net=host conjure /bin/bash
```

### PFRING

- Check the interface to see if the ZeroCopy driver is loaded:

```bash
cat /proc/net/pf_ring/dev/enp7s0/info
Name:         enp7s0
Index:        3
Address:      52:54:00:73:B2:A6
Polling Mode: NAPI
Promisc:      Enabled
Type:         Ethernet
Family:       Standard NIC
# Bound Sockets:  1
TX Queues:    1
RX Queues:    1
```

Ensure that the correct PF_RING kernel modules are a loaded:

```bash
# List available network interfaces and related drivers
$ pf_ringcfg --list-interfaces
 Name: eno3                 Driver: ixgbe      [Supported by ZC]
 Name: docker0              Driver: bridge

# Configure and load the appropriate driver (example for `ixgbe` driver)
$ pf_ringcfg --configure-driver ixgbe --rss-queues 1
$ pf_ringcfg --list-interfaces
 Name: eno3                 Driver: ixgbe      [Running ZC]
 Name: docker0              Driver: bridge
```

`--rss-queues 1` is required to disable RSS

Note: You may need to use `--force` when configuring the driver. This might
cause networking to fail, ensure physical access to the host.

For detailed and up-to-date installation instructions refer to official ntop documentation.
[Installing PF_RING from packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html#installing-from-packages)
[Installing PF_RING from source](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html)

- ERROR: pfring_zc_create_cluster error [Socket operation on non-socket]
  - Make sure CJ_IFACE is set to the correct interface
  - Make sure the interface specified by CJ_IFACE has the pfring_zc driver
    loaded ( `cat /proc/net/pf_ring/dev/<IntName>/info | grep ZC` )
  - Make sure that ports aren't already in use (for example, by another conjure instance)

### Application

- Encountered err when creating Reg: Failed to select phantom IP address: generation number not recognized
  - Make sure conjure/docker/phantom_subnets.toml contains the client's generations
  - Can be caused by clients using API trying to connect, since API is enabled by default. Can be disabled by removing `[[connect_sockets]]` entry for the API from `conjure/application/config.toml`
