#!/bin/bash
set -e



while [ $(sysctl -b vm.nr_hugepages) -lt 512 ]
do
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
	echo ''
	echo 'Sleeping for 10 seconds'
	sleep 10
done

while [ ! $(cat "/proc/net/pf_ring/dev/${CJ_IFACE}/info" | grep ZC) ]
do
	echo 'Is ZC network drivers loaded? For instructions visit https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html'
	echo ''
	echo 'To check for ZC driver run:'
	echo '	cat /proc/net/pf_ring/dev/'${CJ_IFACE}'/info'
	echo 'You should see "Polling Mode: ZC/NAPI"'
	echo ''
	sleep 10; 
done

# TD_IFACE could be a CSV list of interfaces.
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
    if [ $didfirst -ne 0 ]; then
        ifcarg="$ifcarg,$ifcelem"
    else
        ifcarg=$ifcelem
        didfirst=1
    fi
done
echo "Setting up with params: -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}"
zbalance_ipc -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}
