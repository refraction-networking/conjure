# dark-decoys

## Install
sudo apt install libzmq3-dev


# Setup
sudo iptables -t nat -I PREROUTING 1 -p tcp -i tun0 -j DNAT --to 192.122.200.231:41245
sudo ip6tables -t nat -A PREROUTING -i tun0 -p tcp --dport 443 -j DNAT --to [2001:48a8:687f:2::2]:41245

Make sure INPUT iptables has an accept for tun0 (isn't blocking packets after they're DNAT'd)
