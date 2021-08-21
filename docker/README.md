Before running the app PF_RING kernel module and hugepages need to be configured on the host system

#### PF_RING Kernel Module
Run `install_pfring_package.sh` to get the latest PF_RING on Ubuntu or Debian host.  

For detailed and up-to-date installation instructions refer to official ntop documentation.  
[Installing PF_RING from packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html#installing-from-packages)  
[Installing PF_RING from source](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html)

Note: This docker image will always build with the latest PF_RING module installed from packages.

Identify used NIC driver and inject ZC into it:
```
$ pf_ringcfg --list-interfaces
 Name: eno3                 Driver: ixgbe      [Supported by ZC]
 Name: docker0              Driver: bridge

$ pf_ringcfg --configure-driver ixgbe --rss-queues 1

$ pf_ringcfg --list-interfaces
 Name: eno3                 Driver: ixgbe      [Running ZC]
 Name: docker0              Driver: bridge
```

`--rss-queues 1` is required to disable RSS  

Note: You may need to use `--force` when configuring the driver. This might cause networking to fail, ensure physical access to the host.

#### Hugepages
There are multiple places to configure it: in pf_ring hugepages.conf file, in a script that gets run before conjure service, on a system startup etc..  
Host system configuration:
```
sysctl -w vm.nr_hugepages=512
echo "vm.nr_hugepages=512" >> /etc/sysctl.conf
```

#### Running Conjure
Dockerfile supports two sources to build from: original conjure repository from github or local source code. Default is to use original github repository. To use local source code set CUSTOM_BUILD build argument and rebuild the images. Build argument can be set by appending `--build-arg CUSTOM_BUILD=1` to `docker build` or by setting in docker-compose.yaml like so (for each service) and then running `docker-compose build`:  

```
    service:
      build:
        args:
          CUSTOM_BUILD: "1"
```

##### Configuration
The only required variable is CJ_IFACE. It should be set to the name of your tap interface. To set the correct value edit `docker-compose.yaml` file and change the value for CJ_IFACE.

Handy one-liner:  

```
sed -i 's/CJ_IFACE=.*$/CJ_IFACE=your_interface_name/g' docker-compose.yaml
```

Note: While the above config is the only requirement it is not the most optimal/effective. To fine-tune the station check the "List of Supported Variables" below and consult the [Environment Variables in Compose](https://docs.docker.com/compose/environment-variables/)



Also, you may need a new key. Here is a one-liner (change `-v /home/user/conjure/libtapdance` to where your conjure repository is situated):

```
docker run -v /home/user/conjure/libtapdance:/libtapdance -w /libtapdance gcc /bin/bash -c 'make genkey && ./genkey'
```
The above will create (or overwrite) keys in libtapdance folder. Copy privkey to /var/lib/tapdance/prod.privkey

##### Run
`docker-compose up -d`

#### List of Supported Variables and Defaults (docker-compose.yaml)
```
# zbalance
CJ_IFACE=lo
CJ_CLUSTER_ID=98
CJ_CORECOUNT=1
CJ_COREBASE=0
ZBALANCE_HASH_MODE=1

# detector
CJ_CLUSTER_ID=98
CJ_CORECOUNT=1
CJ_COREBASE=0
CJ_SKIP_CORE=-1
CJ_QUEUE_OFFSET=0
CJ_LOG_INTERVAL=5
CJ_PRIVKEY=/opt/conjure/keys/privkey
CJ_STATION_CONFIG=/opt/conjure/application/config.toml
CJ_IP4_ADDR=127.0.0.1
CJ_IP6_ADDR=[::1]

# application
CJ_STATION_CONFIG=/opt/conjure/application/config.toml
PHANTOM_SUBNET_LOCATION=/opt/conjure/sysconfig/phantom_subnets.toml
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

#### Troubleshooting
##### Zbalance
* ERROR: pfring_zc_create_cluster error [Socket operation on non-socket]
    * Make sure CJ_IFACE is set to the correct interface
    * Make sure the interface specified by CJ_IFACE has the pfring_zc driver loaded ( cat /proc/net/pf_ring/dev/<IntName>/info | grep ZC )
    * Make sure that ports aren't already in use (for example, by another conjure instance)
##### Application
* Encountered err when creating Reg: Failed to select phantom IP address: generation number not recognized
    * Make sure conjure/docker/phantom_subnets.toml contains the client's generations
    * Can be caused by clients using API trying to connect, since API is enabled by default. Can be disabled by removing [[connect_sockets]] table for API from         conjure/application/config.toml
##### Custom Build
* COPY failed: file not found in build context or excluded by .dockerignore
    * If using the docker build command, make sure to call from the conjure directory to provide build context: ```user@host:~/conjure$ docker build . -f docker/Dockerfile```
