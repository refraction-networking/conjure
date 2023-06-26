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


## Config files in /var/lib/conjure

```sh
cp -r conjure /opt/
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

### DNS registrar

TODO
