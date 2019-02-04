# dark-decoys

## Install
sudo apt install libzmq3-dev


# Setup
sudo iptables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to 192.122.200.231:41245
sudo sysctl -w net.ipv6.conf.tun0.forwarding=1
