#!/bin/bash

#cat data/td.plot | awk '{print $10}' | sort -n | cdf > ./data/td.cdf
#cat data/dd2.plot | awk '{print $10}' | sort -n | cdf > ./data/dd.cdf

#cat data/td.linear.plot | awk '{print $8}' | sort -n | cdf > ./data/td.cdf
#cat data/dd.linear.plot | awk '{print $8}' | sort -n | cdf > ./data/dd.cdf
cat data/td.eric.plot | awk '{print $10}' | sort -n | cdf > ./data/td.cdf
cat data/dd.eric.plot | awk '{print $10}' | sort -n | cdf > ./data/dd.cdf

gnuplot td-dd.gnuplot


