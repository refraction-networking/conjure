#!/bin/bash

#python gen-addrs.py 100000 | python count-v6-bits.py | sort -n > rand.pdf
#cat rand.pdf | cdf > rand.cdf


#cat ./data/all-by-pkt.out | grep '^2001:48a8:' | sort | uniq | python count-v6-bits.py | sort -n > merit-observed.pdf
cat ./data/ip6-16hr.out | grep '^2001:48a8:' | sort | uniq | python count-v6-bits.py | sort -n > merit-observed.pdf
cat merit-observed.pdf | cdf > merit-observed.cdf

cat merit-observed.pdf | sort -n | uniq -c > merit-observed.counts

#cat ./data/all-by-pkt.out | sort | uniq | python count-v6-bits.py | sort -n > all-observed.pdf
cat ./data/ip6-16hr.out | sort | uniq | python count-v6-bits.py | sort -n > all-observed.pdf

cat all-observed.pdf | cdf > all-observed.cdf

gnuplot bits.gnuplot

