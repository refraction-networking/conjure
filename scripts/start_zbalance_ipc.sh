#!/bin/bash
set -e

if [ $(sysctl -b vm.nr_hugepages) -lt 512 ]; then
	echo 'Please set number of hugepages to at least 512.'
	echo ''
	echo 'To check current value run:'
	echo '	sysctl vm.nr_hugepages'
	echo 'OR'
	echo '	cat /proc/sys/vm/nr_hugepages'
	echo ''
	echo 'To set number of hugepages run:'
	echo '	sysctl -w vm.nr_hugepages=512'
	echo ''
	echo 'To make this setting persistent run:'
	echo '	echo "vm.nr_hugepages=512" >> /etc/sysctl.conf'
	echo ''
	exit 1;
fi

check_ZC_driver() {
	ifcname="$1"
	if [[ $ifc = "zc:"* ]]; then
	    ifcname="${ifcname#zc:}"
	fi
	if grep -q "ZC" "/proc/net/pf_ring/dev/${ifcname}/info"; then
	echo "ZC driver loaded for ${ifcname}"
	else
	echo 'Is ZC network drivers loaded? For instructions visit https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html'
	echo ''
	echo 'To check for ZC driver run:'
	echo '	cat /proc/net/pf_ring/dev/'${ifcname}'/info'
	echo 'You should see "Polling Mode: ZC/NAPI"'
	echo ''
	sleep 10
	exit 1;
	fi
}

# Run zbalance. Needed for zero-copy mode Conjure
# See README.md
# load config. will access config in /var/lib/conjure for overrides
set -a
source /opt/conjure/sysconfig/conjure.conf
set +a

# CJ_IFACE could be a CSV list of interfaces.
# Pull them apart to ensure each gets zc: prefix
ifcarg=""
IFS=',' read -r -a ifcarray <<< "${CJ_IFACE}"
didfirst=0
for ifc in "${ifcarray[@]}"
do
    ifcelem="zc:${ifc}"
    if [[ $ifc = "zc:"* ]]; then
        ifcelem=${ifc}
    fi

    check_ZC_driver ${ifcelem}

    if [ $didfirst -ne 0 ]; then
        ifcarg="$ifcarg,$ifcelem"
    else
        ifcarg=$ifcelem
        didfirst=1
    fi
done

# # Double output channel if N_QUEUE_SETS is set in config (used for two stations or TD + CJ)
if [[ N_QUEUE_SETS = 1 ]]; then
	echo "Setting up with params: -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}"
	zbalance_ipc -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}
else
	echo "Setting up with params: -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT},${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}"
	zbalance_ipc -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT},${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}
fi
