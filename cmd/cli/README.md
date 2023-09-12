# Gotapdance CLI version

# Build
After [downloading Golang, TD and dependencies:](../README.md)

```sh
   cd ${GOPATH:-~/go}/src/github.com/refraction-networking/gotapdance/cli # works even if GOPATH is not set
   go build -a .
```

# Usage

Simply run

```sh
./cli
```

to listen to local connections on default 10500 port.

Then, you'll have a few options:

## Configure HTTP proxy

You will need to ask your particular application(e.g. browser) to use 127.0.0.1:10500 as HTTP proxy.
In Firefox (both mobile and desktop) I prefer to type ```about:config``` into address line and set the following:

```conf
network.proxy.http_port = 10500
network.proxy.http = 127.0.0.1
network.proxy.ssl_port = 10500
network.proxy.ssl = 127.0.0.1
network.proxy.type = 1
```

To disable proxying you may simply set ```network.proxy.type``` back to ```5``` or ```0```.

The same settings are available in Firefox GUI: Preferences->Advanced->Network->Settings

## Configure ssh SOCKS proxy

If you have access to some ssh server, say `socksserver`, you can set up ssh SOCKS tunnel.
First, modify and add the following to `.ssh/config`:

```ssh
Host socksserver-td
Hostname 123.456.789.012
User cookiemonster
ProxyCommand nc -X connect -x 127.0.0.1:10500 %h %p
```

then run `ssh -D1234 socksserver-td -4`

Now in Firefox you could just go to Preferences->Advanced->Network->Settings and set SOCKSv5 host to localhost:1234.

## Some utilities use following enivoronment variables:

 ```bash
export https_proxy=127.0.0.1:10500
export http_proxy=127.0.0.1:10500
wget https://twitter.com
```

Most of the popular utilities also have a flag to specify a proxy.

## Docker

A simple dockerfile is provided that instantiates a golang environment in which to
run the cli. This is primarily meant to be used with [the GNS3 simulation
environment](https://github.com/refraction-networking/conjure/wiki/GNS3-Simulation).

To build the docker environemnt use:

```sh
# run from repo root
docker build -t gotapdance/cli -f cli/cli.dockerfile .
```

The environemnt can then be attached to using a `docker exec` or using telnet
in the case of gns3. See the [wiki page](https://docs.gns3.com/docs/emulators/create-a-docker-container-for-gns3)
for local docker image builds in gns3 for more details on setting up local
docker appliances in gns3.
