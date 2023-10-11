#!/bin/bash

#PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 phantom-sub.py

go build zmqsub.go
PHANTOM_SUBNET_LOCATION=/var/lib/conjure/phantom_subnets.toml ./zmqsub

