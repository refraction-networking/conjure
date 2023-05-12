#!/bin/bash

# Run Conjure detector process using configs in environment variables.

if [ $(id -u) -ne 0 ]; then
    echo "$0 must be run as sudo"
    exit 1
fi

# load config. will access config in /var/lib/conjure for overrides
set -a
source /opt/conjure/sysconfig/conjure.conf
set +a


if [ ! -f $CJ_PRIVKEY ]; then
    echo "Failed to open \$CJ_PRIVKEY=$CJ_PRIVKEY."
    echo "You may want to set CJ_PRIVKEY in the conjure.conf file before running the script"
    exit 1
fi

/opt/conjure/bin/conjure -c ${CJ_CLUSTER_ID} -o ${CJ_COREBASE} -n ${CJ_CORECOUNT} -l ${CJ_LOG_INTERVAL} -K ${CJ_PRIVKEY} -s ${SKIP_CORE} -z ${CJ_QUEUE_OFFSET}
