<p align="center">
<a href="https://refraction.network"><img src="https://user-images.githubusercontent.com/5443147/30133006-7c3019f4-930f-11e7-9f60-3df45ee13d9d.png" height=65 align="middle" alt="refract"></a> <a href="https://www.docker.com/"><img src="https://docs.docker.com/assets/favicons/docs.ico" height=50 align="middle" alt="docker"></a>
<h1 class="header-title" align="center">Containerized Conjure</h1>
</p>

Allows for build of containers based on directory in one or several images.
For one image that contains all station pieces use:

```sh
make container
```

The `target` option allows you to build minimal individual pieces of the station. The default image
is one container with all conjure executables.

```sh
make target=app container
# The options for individual `target`s, all built on top of 20.04:
# - `det` - the detector with pfring libraries required to run using zbalance_ipc packet ingest
# - `app` - the application
# - `reg` -  the registration server.
# - `zbalance` - pfring libraries and executables to run packet ingest.
# - `sim` - all pieces of the station but the simulation build of the detector (no pfring)
```

The `pfring_ver` option allows you to control the version of pfring used in the build. The pfring
version inside the container <ins>**MUST**</ins> match the pfring version of the host. If left empty
the latest version of pfring is installed from package. This can also be set in the environment
variable `PFRING_VER` (in `conjure.conf`), though make file arguments take precedence. The
environment variable is used for automatic builds.

```sh
make target=zbalance pfring_ver="tags/7.8.0" container
# Pfring versions are checked out from the github repo and built automatically.
```

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

    See the [README](#configuration)
    for more information on configuring a conjure station.

    ```bash
    # /var/lib/conjure/conjure.conf
    PF_DRIVER="e1000e"
    CJ_IFACE=eth0
    CJ_PRIVKEY=/var/lib/conjure/privkey
    CJ_STATION_CONFIG=/var/lib/conjure/app_config.toml
    PHANTOM_SUBNET_LOCATION=/var/lib/conjure/phantom_subnets.toml
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

    In general the configuration file needed to properly run a conjure station in `/var/lib/conjure`
    are defined here. Note that the files here match the path overrides defined in step 2 above.

    ```tree
    /var/lib/conjure
    ├── app_config.toml
    ├── conjure.conf
    ├── phantom_subnets.toml
    ├── privkey
    └── # pubkey (optional)
    ```

    Bring services up

    ```bash
    docker-compose -f docker/docker-compose.yaml up
    ```

    Bring services down with docker-compose

    ```sh
    docker-compose -f docker/docker-compose.yaml down
    ```

    To enable startup on reboot copy `sysconfig/conjure-docker.service` to `/etc/systemd/system` and
    enable the service. This should run `on-reboot when the station boots, and launch the docker
    services based on the docker-compose file`/opt/conjure/docker/docker-compose.yaml`. If the
    containers do not exist they will (in theory) be built a new

    ```sh
    sudo cp sysconfig/conjure-docker.service /etc/systemd/system/
    sudo systemctl enable conjure-docker
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
PFRING_VER=latest
PF_DRIVER=""
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

**PFRING_VER**: indicates the version of pf_ring to be installed while building docker containers,
or while using `scripts/install_pfring.sh`. By default `scripts/install_pfring.sh` installs from
package, if altered the script checkout `PFRING_VER` as a branch / tag name (e.g. `dev`,
`tags/7.8.0`, `8.4.0-stable`, etc.) and builds from source.

**CJ_IFACE**: comma separated list of interfaces for pf_ring to use.

**PF_DRIVER**: driver used for the pfring network interface(s) defined in CJ_IFACE (used by
`on-reboot.sh`). If both CJ_IFACE and PF_DRIVER are undefined, `on-reboot.sh` will attempt to detect
an interface with either an i40e or ixgbe driver.

**CJ_CLUSTER_ID**: just a label for zbalance cluster

**CJ_CORECOUNT**: number of (threaded) cores to use for tapdance. Usually you want at most 1 less
than the number available, particularly during development. Be sure to set this appropriately for
production usage. A maximum of 16 cores is supported.

**CJ_COREBASE**: based core number to start with.

**CJ_SKIP_CORE**: based core number to have detector skip running on. Default=-1 (none). EG if
COREBASE=0, CORECOUNT=4, and SKIP_CORE=1 then tapdance will use cores 0, 2, 3, 4. Only a single
integer core number is allowed.

**CJ_QUEUE_OFFSET**: should be 0 if Tapdance is not running on the same machine. If tapdance is
running this should be equal to the amount of threads that tapdance is using. ('tun' interfaces are
numbered sequentially and if tadance is running 'offset' will solve the naming collision)

**CJ_PRIVKEY**: path to private key inside the docker container. Keep to default unless necessary

**CJ_STATION_CONFIG**: path to conjure configuration inside the docker container. Keep to default
unless necessary

**CJ_IP4_ADDR**: Conjure station IP. Localhost works just fine. If Conjure application server
located somewhere else this should be the remote IP (Central proxy mode)

**CJ_IP6_ADDR**: Same but IPv6

**PHANTOM_SUBNET_LOCATION**: Path to phantom subnets file inside the docker container. Keep to
default unless necessary

**N_QUEUE_SETS**: Indicates to start_zbalance_ipc.sh to create two sets of queues. Used for
running two conjure stations or a conjure station together with tapdance.
Only options right now are 1 and anything else (which runs 2 queue sets).

**CJ_REGISTRAR_CONFIG**: Path to the configuration file for the registration api. Used by the
conjure-reg service

## Troubleshooting

Run the container in an interactive environment

```bash
# you may also wish to mount the appropriate volumes. (see docker/docker-compose.yaml)
docker run --rm -it --net=host conjure /bin/bash
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
