# dark-decoys

## Install
sudo apt install libzmq3-dev redis-server


# Setup
sudo iptables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to 192.122.200.231:41245
sudo ip6tables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to [2001:48a8:687f:2::2]:41245

And for tun1 if you have multiple cores...

Make sure INPUT iptables has an accept for tun0 (isn't blocking packets after they're DNAT'd)
