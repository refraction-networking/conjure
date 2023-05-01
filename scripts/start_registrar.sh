#!/bin/hash

# Run Conjure application process using configs in environment variables.

if [ $(id -u) -ne 0 ]; then
    echo "$0 must be run as sudo"
    exit 1
fi

# load config. will access config in /var/lib/conjure for overrides
set -a
source /opt/conjure/sysconfig/conjure.conf
set +a

if [ ! -f $CJ_REGISTRAR_CONFIG ]; then
    echo "Failed to open \$CJ_REGISTRAR_CONFIG=$CJ_REGISTRAR_CONFIG."
    echo "You may want to set CJ_REGISTRAR_CONFIG in the conjure.conf file before running the script"
    exit 1
fi

/opt/conjure/bin/registration-server
