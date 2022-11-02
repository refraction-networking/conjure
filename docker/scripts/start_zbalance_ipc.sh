#!/bin/bash

# Run zbalance. Needed for zero-copy mode Tapdance
# See README.md
source /opt/conjure/sysconfig/conjure.conf

ZBALANCE_HASH_MODE=1
# If the target is not the zero-copy tapdance, don't run zbalance
#if [[ "x${TD_TARGET}" != "xzc_tapdance"  && "x${TD_TARGET}" != "xzmq_tapdance" ]]; then
#    exit 0
#fi

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
zbalance_ipc -i $ifcarg -c ${CJ_CLUSTER_ID} -n ${CJ_CORECOUNT},${CJ_CORECOUNT} -m ${ZBALANCE_HASH_MODE} -g ${CJ_COREBASE}

