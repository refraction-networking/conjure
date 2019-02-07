# dark-decoys

## Install
sudo apt install libzmq3-dev redis-server

# Setup
sudo iptables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to 192.122.200.231:41245
sudo ip6tables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to [2001:48a8:687f:2::2]:41245
sudo sysctl -w net.ipv4.conf.tun0.rp_filter=0

And repeat for tun1/tun2/tun3/etc... if you have multiple cores

Make sure INPUT iptables has an accept for tun0 (isn't blocking packets after they're DNAT'd)
sudo iptables -I INPUT 1 -i tun0 -j ACCEPT

