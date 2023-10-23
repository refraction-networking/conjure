#!/bin/bash

#PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 phantom-sub.py

PATH="/usr/local/go/bin:$PATH"

go build zmqsub.go
BUILD_RESULT=$?
if [ $BUILD_RESULT -ne 0 ]; then
	echo "build failed"
	exit ${BUILD_RESULT}
else
	PHANTOM_SUBNET_LOCATION=/var/lib/conjure/phantom_subnets.toml ./zmqsub
fi

