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

set output './bandwidth-up.pdf'




#set yrange [0:1]
#set xrange [1:5000]
#set logscale x
set xrange [0:60]
set logscale y
set yrange [0.001:100]

#set format y '%.f'
set xlabel 'Time (s)'
set ylabel 'Mbps'

#set datafile separator ","


plot './data/tests/dd-max-up.dat' u ($1/1000000) w lines title 'Conjure', \
    './data/tests/direct-max-up.dat' u ($1/1000000) w lines title 'Direct', \
    './data/tests/td-max-up.dat' u ($1/1000000) w lines title 'TapDance', \


set output './bandwidth-down.pdf'

#unset logscale y
set yrange [0.1:500]

plot './data/tests/dd-max-down.dat' u ($1/1000000) w lines title 'Conjure', \
    './data/tests/direct-max-down.dat' u ($1/1000000) w lines title 'Direct', \
    './data/tests/td-max-down.dat' u ($1/1000000) w lines title 'TapDance', \



