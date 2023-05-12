# style from http://youinfinitesnake.blogspot.com/2011/02/attractive-scientific-plots-with.html

set terminal pdfcairo font "Gill Sans,12" linewidth 4 rounded

set style line 80 lt rgb "#808080"

set style line 81 lt 0  # dashed
set style line 81 lt rgb "#808080"  # grey

set grid back linestyle 81
set border 3 back linestyle 80 # Remove border on top and right.  These
             # borders are useless and make it harder
             # to see plotted lines near the border.
    # Also, put it in grey; no need for so much emphasis on a border.
set xtics nomirror
set ytics nomirror

set style line 1 lt rgb "#A00000" lw 2 pt 1
set style line 2 lt rgb "#00A000" lw 2 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9

set output './ip-bits-set.pdf'




#set yrange [0:1]
#set xrange [1:5000]
#set logscale x
set xrange [0:100]

#set format y '%.f'
set xlabel 'IPv6 address bits set'
set ylabel 'CDF of IPs'

#set datafile separator ","


plot 'rand.cdf' u 1:2 w lines title 'Random', \
    'merit-observed.cdf' u 1:2 w lines title 'Observed'


set output './ip-bits-set-pdf.pdf'
binwidth=1
bin(x,width)=width*floor(x/width)

stats 'rand.pdf'
rN = STATS_records
stats 'merit-observed.pdf'
oN = STATS_records

set ylabel '% IPs'

invsqrt2pi = 0.398942280401433
normal(x,mu,sigma)=sigma<=0?1/0:invsqrt2pi/sigma*exp(-0.5*((x-mu)/sigma)**2)

#plot 'rand.pdf' u (bin($1,binwidth)):(100.0/rN) smooth freq with boxes title 'Random', \


#plot 'merit-observed.pdf' u (bin($1,binwidth)):(100.0/oN) smooth freq with boxes title 'Observed', \
#        100*normal(x,58,5) w lines title 'Random'

plot 'merit-observed.counts' u 2:(100*$1/oN) w boxes title 'Observed',\
        100*normal(x,58,5) w lines title 'Random'



#plot 'cdf-fingerprints' u 1:2 w lines title 'Client' ls 1, \
#    'cdf-sfingerprints' u 1:2 w lines title 'Server' ls 2
