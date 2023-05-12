#!/bin/bash

# Run Conjure application process using configs in environment variables.

if [ $(id -u) -ne 0 ]; then
    echo "$0 must be run as sudo"
    exit 1
fi

# load config. will access config in /var/lib/conjure for overrides
set -a
source /opt/conjure/sysconfig/conjure.conf
set +a

if [ ! -f $CJ_STATION_CONFIG ]; then
    echo "Failed to open \$CJ_STATION_CONFIG=$CJ_STATION_CONFIG."
    echo "You may want to set CJ_STATION_CONFIG in the conjure.conf file before running the script"
    exit 1
fi

echo "station_config path: $CJ_STATION_CONFIG"

/opt/conjure/bin/application
