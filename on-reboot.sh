#!/bin/bash
#
# Use this script once after reboot, and on configuration changes
# that affect variables in the config file.
# See README.md
# Run as sudo

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

build_or_rebuild_iptables() {
    if [[ $# -lt 3 ]]; then
        exit_msg "script broken, build_or_rebuild requires iptables table, chain, and source chain names"
    fi
    local table=$1
    local chain=$2
    local src_chain=$3
    iptables -t ${table} -n -L ${chain} >/dev/null 2>&1
    if [ "$?" -eq 0 ]; then
        # Chain already exists
	while [ "$?" -eq 0 ];
	do 
	    iptables -t ${table} -D ${src_chain} -j ${chain}
	done
	iptables -t ${table} -F ${chain}
        iptables -t ${table} -X ${chain}
    fi
    echo "building chain ${chain} in table ${table}"
    iptables -t ${table} -N ${chain}
    do_or_die "iptables -t ${table} -I ${src_chain} 1 -j ${chain}"

    ip6tables -t ${table} -n -L ${chain} >/dev/null 2>&1
    if [ "$?" -eq 0 ]; then
        # Chain already exists
	while [ "$?" -eq 0 ];
	do 
	    ip6tables -t ${table} -D ${src_chain} -j ${chain}
	done
        ip6tables -t ${table} -F ${chain}
        ip6tables -t ${table} -X ${chain}
    fi
    ip6tables -t ${table} -N ${chain}
    do_or_die "ip6tables -t ${table} -I ${src_chain} 1 -j ${chain}"
}

tun_setup_fn () {
    if [[ $# -lt 2 ]]; then
        exit_msg "script broken, tun_setup requires tun id and ip table name"
    fi

    local N=$1
    local table=$2
    ip tuntap del mode tun tun${N}
    do_or_die "ip tuntap add mode tun tun${N}"
    do_or_die "sysctl -w net.ipv4.conf.tun${N}.rp_filter=0"

    local rule_condition="iif tun${N} lookup ${table}"
    # Check if the rule exists
    local output=$(ip rule show | grep "$rule_condition")
    if ! [[ -n "$output" ]]; then
        # if not, add it
        do_or_die "ip rule add iif tun${N} lookup ${table}"
    fi

    # not sure if we need to do rule below for every tun
    # `RTNETLink answers: File exists` means the route is already there; harmless, but can we avoid it?
    ip route add local 0.0.0.0/0 dev tun${N} table ${table}


    do_or_die "iptables -t nat -I CJ_PREROUTING 1 -p tcp -i tun${N} -j DNAT --to ${IP4_ADDR}:41245"
    do_or_die "iptables -t nat -I CJ_PREROUTING 1 -p udp -i tun${N} -j DNAT --to ${IP4_ADDR}:41245"
    do_or_die "ip6tables -t nat -I CJ_PREROUTING 1 -p tcp -i tun${N} -j DNAT --to ${IP6_ADDR}:41245"
    do_or_die "ip6tables -t nat -I CJ_PREROUTING 1 -p udp -i tun${N} -j DNAT --to ${IP6_ADDR}:41245"
    do_or_die "iptables -I CJ_INPUT 1 -i tun${N} -j ACCEPT"
    do_or_die "ip6tables -I CJ_INPUT 1 -i tun${N} -j ACCEPT"
}


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

# Internal Network Setup
do_or_die "sysctl -w net.ipv4.conf.default.rp_filter=0"
do_or_die "sysctl -w net.ipv4.conf.all.rp_filter=0"

rule_table_name="custom"
rule_table_check=$(ip route show table "$rule_table_name" >/dev/null 2>&1)
if [[ -z "$rule_table_check" ]]; then
  echo "adding routing table ${rule_table_name}"
  echo "200 ${rule_table_name}" >> /etc/iproute2/rt_tables
fi

build_or_rebuild_iptables nat CJ_PREROUTING PREROUTING
build_or_rebuild_iptables filter CJ_INPUT INPUT

# Create a tunnel for each core.
# The tunnel numbers do not match the core index per the OS,
# but instead match the count of cores being used by conjure.
echo "Setting up devices tun{${OFFSET}..$((OFFSET + CORE_COUNT -1 ))}, adding rules for them, and turning off RP filters."
for CORE in `seq $OFFSET $((OFFSET + CORE_COUNT -1 ))`
do
    tun_setup_fn ${CORE} ${rule_table_name}
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

