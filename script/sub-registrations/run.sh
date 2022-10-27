#!/bin/bash

#PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 phantom-sub.py

go build zmqsub.go
PHANTOM_SUBNET_LOCATION=/opt/conjure/sysconfig/phantom_subnets.toml ./zmqsub

