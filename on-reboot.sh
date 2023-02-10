#!/bin/bash




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
if [ ! -d "/mnt/huge" ]; then
    echo "Creating /mnt/huge"
    mkdir -p /mnt/huge || exit_msg "Failed to create /mnt/huge"
fi
grep -s '/mnt/huge' /proc/mounts > /dev/null
if [ $? -ne 0 ] ; then
    echo "Mounting /mnt/huge"
    mount -t hugetlbfs nodev /mnt/huge || exit_msg "Failed to mount /mnt/huge as hugetlbfs"
fi
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
if [ "$?" -ne 0 ]
then
    exit_msg "Failed to set 2048 hugepages!"
fi

