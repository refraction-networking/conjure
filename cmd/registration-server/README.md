### Registration server

Building the registration server:
Need packages:
```sh
sudo apt install libzmq3-dev libzmq5 make build-essential
```
Tested with go1.20.5


```sh
cd cmd/registration-server
make
```

## Installing bin files

```sh
cp -r conjure /opt/
mkdir /opt/conjure/bin
cp /opt/conjure/cmd/registration-server/registration-server /opt/conjure/bin/
```

## Config files in /var/lib/conjure

```sh
mkdir /var/lib/conjure/
cp conjure/sysconfig/conjure.conf /var/lib/conjure/conjure.conf
cp conjure/cmd/registration-server/reg_config.toml /var/lib/conjure/reg_config.toml
```

Edit reg_config.toml to add pubkeys for stations, and update bidirectional_api_generation to current generation.

Write phantom_subnets.toml, e.g.:
```
    [Networks.1119]
        Generation = 1119
        [[Networks.1119.WeightedSubnets]]
            Weight = 9
            Subnets = ["192.122.190.0/24", "2001:48a8:687f:1::/64"] 
        [[Networks.1119.WeightedSubnets]]
            Weight = 1
            Subnets = ["141.219.0.0/16", "35.8.0.0/16"] 
```

Put the most recent ClientConf in /var/lib/conjure/

Make private keys:
privkey comes from the stations, zmq_privkey is per-registration server
```
cd conjure/libtapdance
make
sudo cp privkey /var/lib/conjure/zmq_privkey
```

Extract the public key:
`tail -c32 zmq_privkey | basenc --z85`

Install this into the app_config.toml of all the stations, e.g.:
```
[[connect_sockets]]
address = "tcp://reg3.refraction.network:5591"
type = "CURVE"
pubkey = "ZmZ7vr]i&g+.F$JfL5beQZI*kO)rwj9b?*!7woS]"
subscription = ""
```

Setup Caddy:
```
registration.refraction.network {
    route /api/* {
        uri strip_prefix /api
        reverse_proxy localhost:8080 {
            trusted_proxies 0.0.0.0/0
        }
    }
}
```

```sh
sudo systemctl reload caddy
```


## DNS registrar

To make the DNS registrar work, we need to listen on :53. Ubuntu normally has resolvd listening there,
so we can disable it:

```sh
sudo systemctl disable systemd-resolved.service
sudo systemctl stop systemd-resolved.service
echo "nameserver 8.8.8.8" > /etc/resolv.conf
```


## Running

```sh
sudo systemctl start conjure-reg
```
