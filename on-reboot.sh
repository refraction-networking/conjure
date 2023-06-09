#!/bin/bash
#
# Use this script once after reboot, and on configuration changes
# that affect variables in the config file.
# See README.md
# Run as sud

# if conjure path is unset (not empty -- unset) use the default.
if [ -z "${CJ_PATH+x}" ]; then
    CJ_PATH="/opt/conjure/"
fi

source $CJ_PATH/sysconfig/conjure.conf

CORE_COUNT=$CJ_CORECOUNT

do_or_die() {
    $1 || exit_msg "command \"$1\" failed"
}

exit_msg() {
    echo "$1"
    cd ${LAST_DIR}
    exit 1
}

# Otherwise, this section will require constant updating.
if [ "x$PF_DRIVER" = "xe1000e" ]; then
    pf_ringcfg --configure-driver e1000e --rss-queues 1
    pf_ringcfg --list-interfaces
elif [ "x$PF_DRIVER" = "xi40e" ]; then
    pf_ringcfg --configure-driver i40e --rss-queues 1
    pf_ringcfg --list-interfaces
elif [ "x$PF_DRIVER" = "xixgbe" ]; then
    pf_ringcfg --configure-driver ixgbe --rss-queues 1
    pf_ringcfg --list-interfaces
else
    exit_msg "Unknown driver $PF_DRIVER"
fi

# this allows the conntrack table to keep track of connections where the client dissapears and
# the station retransmits fins longer than the kernel will keep track of the connection. This
# works for default timeout values on linux for ubuntu 20.04 and 22.04 (others untested).
required_timeout=90
nf_conntrack_tcp_timeout_last_ack=$(sysctl --values net.netfilter.nf_conntrack_tcp_timeout_last_ack)
if [ "$nf_conntrack_tcp_timeout_last_ack" -lt "$required_timeout" ];then
        sysctl -w net.netfilter.nf_conntrack_tcp_timeout_last_ack=90
fi

# Create a tunnel for each core.
# The tunnel numbers do not match the core index per the OS,
# but instead match the count of cores being used by conjure.
echo "Setting up devices tun{${OFFSET}..$((OFFSET + CORE_COUNT -1 ))}, adding rules for them, and turning off RP filters."
do_or_die "sysctl -w net.ipv4.conf.all.rp_filter=0"
# Or maybe just set up for all of them instead?
for CORE in `seq $OFFSET $((OFFSET + CORE_COUNT -1 ))`
do
    # echo "setting up tun${CORE} ${IP4_ADDR}, ${IP6_ADDR}"
    ip tuntap del mode tun tun${CORE}
    do_or_die "ip tuntap add mode tun tun${CORE}"
    do_or_die "sysctl -w net.ipv4.conf.tun${CORE}.rp_filter=0"
    do_or_die "ip rule add iif tun${CORE} lookup custom"

    # not sure if we need to do rule below for every tun
    # `RTNETLink answers: File exists` means the route is already there; harmless, but can we avoid it?
    ip route add local 0.0.0.0/0 dev tun${CORE} table custom

    do_or_die "iptables -t nat -I PREROUTING 1 -p tcp -i tun${CORE} -j DNAT --to ${IP4_ADDR}:41245"
    do_or_die "iptables -t nat -I PREROUTING 1 -p udp -i tun${CORE} -j DNAT --to ${IP4_ADDR}:41245"
    do_or_die "ip6tables -t nat -I PREROUTING 1 -p tcp -i tun${CORE} -j DNAT --to ${IP6_ADDR}:41245"
    do_or_die "ip6tables -t nat -I PREROUTING 1 -p udp -i tun${CORE} -j DNAT --to ${IP6_ADDR}:41245"
    do_or_die "iptables -I INPUT 1 -i tun${CORE} -j ACCEPT"
    do_or_die "ip6tables -I INPUT 1 -i tun${CORE} -j ACCEPT"
done


echo "Setting up hugepages"
if [ ! -d "/mnt/hugepages" ]; then
    echo "Creating /mnt/hugepages"
    mkdir -p /mnt/hugepages || exit_msg "Failed to create /mnt/hugepages"
fi
grep -s '/mnt/hugepages' /proc/mounts > /dev/null
if [ $? -ne 0 ] ; then
    echo "Mounting /mnt/hugepages"
    mount -t hugetlbfs nodev /mnt/hugepages || exit_msg "Failed to mount /mnt/hugepages as hugetlbfs"
fi
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
if [ "$?" -ne 0 ]
then
    exit_msg "Failed to set 2048 hugepages!"
fi

