# Test environment for Conjure

This test environment uses the [libvirt](https://libvirt.org/) virtualization
API with KVM/QEMU to spin up multiple networked virtual machines running conjure
software. The goal of creating this environment was to have a fully open source
and easily portable option for testing a conjure deployment.

Note: this is **NOT** intended for use in a deployment setting. For ease of use,
there is an included ssh private key for each of the VMs (`conjure`) as well as
a station private key (`config/sysconfig/privkey`) and ClientConfig
(`config/sysconfig/ClientConf`).

## Requirements

### Supported Host systems

- **Ubuntu 22.04** - The automatic build for this development environment is
currently only supported for ubuntu 22.04 due to differences in libvirt and
virt-manager.
- Ubuntu 20.04 - Manual VM configuration and station build can be done on ubuntu
20.04 LTS (remove `driver.type` option from makefile).

### Packages

- libvirt
- KVM/QEMU
- iptables
- make
- virt-install (3.0 or newer -- works with 4.0.0)
- genisoimage

You will also need to clone the conjure station repository and set the
`CONJURE_STATION_REPO` environment variable to the cloned repo path. This allows
the conjure station to be mounted on the `station` vm and launched by the
automatic setup.

```sh
git clone https://github.com/cohosh/conjure.git conjure-station
cd conjure-station
export CONJURE_STATION_REPO=`pwd`
```

Optionally the `CONJURE_H1_REPO` environment variable can be set to mount a
directory into the `h1:/home/conjure-h1/host-repo/` guest vm directory. If
`CONJURE_H1_REPO` is unset then the `h1` vm will be built without any mounted
repo and a repo can be pulled and built locally within the vm after start up.
For example the gotapdance client repository can be mounted on h1 for
development using:

```sh
# Pull the gotapdance client repo if not already available locally
# git clone https://github.com/refraaction-networking/gotapdance.git

cd <path-to>/gotapdance
export CONJURE_H1_REPO=`pwd`

# build and start the environment
sudo -E make

# connect to the h1 vm
./conjure-ssh h1

# gotapdance should now be mounted at ~/host-repo
cd host-repo/cli
go build .
```

## Environment overview

There are three networked virtual machines in this setup:

- The `h1` machine runs all of the tor bits including the client-side and bridge-side conjure code
- The `station` machine runs the conjure relay station and is meant to represent an ISP/edge node that has deployed conjure
- The `tap` is additionally part of the relay station setup and passively taps traffic to send to the conjure station

Client traffic from the `h1` machine is routed through the `tap` machine on its
way to the outside internet, where a passive tap copies the traffic and diverts
it to the `station`. From there, the client performs the registration protocol
and receives a phantom proxy to connect to.

The client then makes the phantom proxy connection to the station, which opens
up a connection to the forward address specified in the registration.

## Getting started

The host networking setup only needs to be done once per restart of the host
operating system. To do so, run

```sh
cd simulation/phantombox
sudo ./setup-host.sh
```

This script requires sudo access for the usage of iptables. The commands are
documented in `setup.sh` and are reproduced here:

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

```sh
sudo -E make
```

You can then ssh into each machine by running

```sh
./conjure-ssh [h1|tap|station]
```

You may need to change permissions on the private key to get it to work properly:

```sh
chmod 600 conjure
```

## Using the Enironment

If everything works as intended, you shouldn't need to alter the tap or station setups.

### Using the conjure client

To test using the client, either mount build the VM with the gotapdance repository mounted using `CONJURE_H1_REPO` as described above or SSH into the h1 machine and pull the client code:

```sh
# copy in the simulation ClientConfig
scp -i conjure -o IdentitiesOnly=yes config/sysconfig/ClientConf conjure-h1@192.168.122.3:~/

./conjure-ssh h1
git clone https://github.com/refraction-networking/gotapdance.git
```

And then build the client and copy the ClientConfig from `conjuure/simulation/phantombox/config/sysconfig/ClientConfig` to the correct `assets/` location:

```sh
cd gotapdance/cli
go build .

cp ~/ClientConf assets/
```

Open a transparent proxy connection to a `<forward address>` using the gotapdance cli:

```sh
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

See the [cli documentaiton](https://github.com/refraction-networking/gotapdance/tree/master/cli) for more details on cli usage.

### Trying out the Conjure Pluggable Transport

Client traffic from the `h1` machine is routed through the `tap` machine on its way to the outside internet, where a passive tap copies the traffic and diverts it to the `station`. From there, the client performs the registration protocol and receives a phantom proxy to connect to. The client then makes the phantom proxy connection to the station, which opens up a connection back to the bridge on the `h1` machine.

To try the pt, first SSH into the h1 machine and pull the pluggable transport implementation:

  ```sh
  ./conjure-ssh h1
  git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure.git conjure-pt
  cd conjure-pt
  ```

alternatively the pt repo can be mounted into the `h1` vm for developemnt be setting `CONJURE_H1_REPO` before rebuilding the VM:

  ```sh
  git clone https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/conjure.git conjure-pt
  cd conjure-pt
  export CONJURE_H1_REPO=`pwd`
  sudo -E make clean
  sudo -E make
  ```

  ```sh
  ./conjure-ssh h1
  cd host-repo
  ```

And then build both the client and server:

```sh
cd client
go build

cd ../server
go build

cd ..
```

To run the bridge, use the provided `torrc` file:

```sh
cd server/
tor -f torrc
```

To run the client, do the same with the `torrc-testenv file:

```sh
cd client
tor -f torrc-testenv
```

## Shutting down virtual machines

To shutdown the vms, you can run:

```sh
make shutdown
```

to turn off all of them, or you make turn them off individually by running:

```sh
make shutdown-[h1|tap|station]
```

Station configs backed up by build can be restored **in the conjure root directory** using:

```sh
make restore
```

## Restarting virtual machines

To restart a shutdown VM, run

```sh
make start
```

or

```sh
make start-[h1|tap|station]
```
