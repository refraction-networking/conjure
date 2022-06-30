#!/bin/bash

# Note: this script only needs to be run once
virsh net-update default add ip-dhcp-host \
          "<host mac='52:54:00:00:01:02' \
           name='station' ip='192.168.122.2' />" \
           --live --config 2> /dev/null
virsh net-update default add ip-dhcp-host \
          "<host mac='52:54:00:00:01:03' \
           name='h1' ip='192.168.122.3' />" \
           --live --config 2> /dev/null
virsh net-update default add ip-dhcp-host \
          "<host mac='52:54:00:00:01:04' \
           name='tap' ip='192.168.122.4' />" \
           --live --config 2> /dev/null

# Allow forwarded packets from internal tap network
sudo iptables -I LIBVIRT_FWO 1 -s 192.168.2.0/24 -i virbr0 -j ACCEPT
sudo iptables -I LIBVIRT_FWI 1 -d 192.168.2.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Turn off the host's ability to manipulate traffic in the internal network
echo 0 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables

# Ensure packets from internal tap network are properly NAT'd
sudo iptables -t nat -A LIBVIRT_PRT -s 192.168.2.0/24 ! -d 192.168.122.0/24 -j MASQUERADE

# Route all inbound packets to the internal network through the tap machine
virsh net-create network.xml
sudo ip route add 192.168.2.4 dev virbr0
sudo ip route change 192.168.2.0/24 via 192.168.2.4 dev virbr0

