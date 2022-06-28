# Test environment for Conjure

This test environment uses the [libvirt](https://libvirt.org/) virtualization API with KVM/QEMU to spin up multiple networked virtual machines running conjure software. The goal of creating this environment was to have a fully open source and easily portable option for testing a conjure deployment.

Note: this is **NOT** intended for use in a deployment setting. For ease of use, there is an included ssh private key for each of the VMs (`conjure`) as well as a station private key (`config/sysconfig/privkey`) and ClientConfig (`config/sysconfig/ClientConf`).

## Requirements

The automatic build for this development environment is currently only supported for ubuntu 22.04 due to differences in libvirt and virt-manager. Manual VM configuration and station build can be done on ubuntu 20.04 LTS (remove `driver.type` option from makefile).

- libvirt
- KVM/QEMU
- iptables
- make
- virt-install (3.0 or newer -- works with 4.0.0)

You will also need to clone the conjure station and tor conjure pt repositories and set the `CONJURE_STATION_REPO` and `CONJURE_PT_REPO` environment variables to cloned repo paths

```
git clone https://github.com/cohosh/conjure.git conjure-station
cd conjure-station
git checkout testenv
export CONJURE_STATION_REPO=`pwd`
```
```
git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure.git conjure-pt
cd conjure-pt
export CONJURE_PT_REPO=`pwd`
```

## Environment overview

There are three networked virtual machines in this setup:
- The `pt` machine runs all of the tor bits including the client-side and bridge-side conjure code
- The `station` machine runs the conjure relay station and is meant to represent an ISP/edge node that has deployed conjure
- The `tap` is additionally part of the relay station setup and passively taps traffic to send to the conjure station

Client traffic from the `pt` machine is routed through the `tap` machine on its way to the outside internet, where a passive tap copies the traffic and diverts it to the `station`. From there, the client performs the registration protocol and receives a phantom proxy to connect to. The client then makes the phantom proxy connection to the station, which opens up a connection back to the bridge on the `pt` machine.

## Getting started

The host networking setup only needs to be done once per restart of the host operating system. To do so, run
```
./setup-host.sh
```

This script requires sudo access for the usage of iptables. The commands are documented in `setup.sh` and are reproduced here:

```bash
# Allow forwarded packets from internal tap network
sudo iptables -I LIBVIRT_FWO 1 -s 192.168.2.0/24 -i virbr0 -j ACCEPT
sudo iptables -I LIBVIRT_FWI 1 -d 192.168.2.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Turn off the host's ability to manipulate traffic in the internal network
echo 0 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables

# Route all inbound packets to the internal network through the tap machine
sudo ip route add 192.168.2.4 dev virbr0
sudo ip route change 192.168.2.0/24 via 192.168.2.4 dev virbr0

```

After the setup script is run, the virtual machines can be built by running:
```
make
```

You can then ssh into each machine by running
```
./conjure-ssh [pt|tap|station]
```
You may need to change permissions on the private key to get it to work properly:
```
chmod 600 conjure
```

## Using the Enironment 

If everything works as intended, you shouldn't need to alter the tap or station setups. 

###  Using the conjure client.

To test using the client, first SSH into the pt machine and pull the client code: 

```sh
./conjure-ssh pt
git clone https://github.com/refraction-networking/gotapdance.git
```
And then build the client and copy the ClientConfig to the correct location:
```sh
cd gotapdance/cli
go build .

cp ~/ClientConf assets/
```

Open a transparent proxy connection to a `<forward address>` using the gotapdance cli:

```
# Using the bidirectional registration API
./cli -connect-addr="<forward address>" -registrar 'api' -api-endpoint="http://192.168.2.2:8080/register-bidirectional"

# Using the registration API
./cli -connect-addr="<forward address>" -registrar 'api' -api-endpoint="http://192.168.2.2:8080/register"

#using the decoy registrar
./cli -connect-addr="<forward address>" -registrar 'decoy'
```

This opens a listener on port 10500 which clients can then transprently proxy traffic through to their chosen `<forward address>`

```sh
nc 127.0.0.1 10500
```


See the cli documentaiton for more details on cli usage.

### Trying out the Conjure pt

To try the pt, first SSH into the pt machine and pull the pluggable transport implementation: 
```
./conjure-ssh pt
git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure.git conjure-t
```
And then build both the client and server:
```
cd conjure-pt
go build

cd ../server
go build

cd ..
```

To run the bridge, use the provided `torrc` file:
```
cd server/
tor -f torrc
```

To run the client, do the same with the `torrc-testenv file:
```
cd client
tor -f torrc-testenv
```

## Shutting down virtual machines

To shutdown the vms, you can run:

```
make shutdown
```
to turn off all of them, or you make turn them off individually by running:
```
make shutdown-[pt|tap|station]
```


## Restarting virtual machines

To restart a shutdown VM, run
```
make start
```
or 
```
make start-[pt|tap|station]
```
