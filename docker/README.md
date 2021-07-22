Before running the app PF_RING kernel module and hugepages need to be configured on the host system

#### PF_RING Kernel Module
Ntop does not maintain versioning of the PF_RING so the only way to get any other than latest PF_RING version it needs to be compiled from source.  
Since since this is going to be used by Conjure station it makes sense to use PF_RING version included in Conjure repository.  

```
git clone --recursive https://github.com/refraction-networking/conjure.git
cd conjure/PF_RING/kernel
apt install make gcc flex bison
make clean && make
make install
```
Now load the kernel module and make it persist over reboots.  
```
insmod pf_ring.ko min_num_slots=65536
echo pf_ring.ko min_num_slots=65536 >> /etc/modules
```

Next, compile and load NIC driver 
```
# Determine the driver family
ethtool -i eth1 | grep driver
> ixgbe

# Compile and load the corresponding driver
cd PF_RING/drivers/intel
make
cd ixgbe/ixgbe-*-zc/src
./load_driver.sh
```
To confirm that driver is loaded run   
```
cat /proc/net/pf_ring/dev/<IntName>/info | grep ZC
```

#### Hugepages
There are multiple places to configure it: in pf_ring hugepages.conf file, in a script that gets run before conjure service, on a system startup etc..  
Host system configuration:
```
sysctl -w vm.nr_hugepages=512
echo "vm.nr_hugepages=512" >> /etc/sysctl.conf
```

#### Running Conjure
Dockerfile supports two sources to build from: original conjure repository from github or local source code. Default is to use original github repository. To use local source code set CUSTOM_BUILD build argument and rebuild the images. Build argument can be set by appending `--build-arg CUSTOM_BUILD=1` to `docker build` or by setting in docker-compose build like so:
```
    service:
      build:
        args:
          CUSTOM_BUILD: "1"
```

##### Configuration
Set CJ_IFACE variable to the name of the network interface that receives conjure traffic. Easiest way is just edit the docker-file and change CJ_IFACE in `zbalance` service

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
