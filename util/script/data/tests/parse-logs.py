#!/usr/bin/python


import sys
import os

# 'KBytes' => 1024
# 'MBytes' => 1024*1024
# 'Mbits/sec' => 1000*1000
UNIT = {'Bytes': 1, 'KBytes': 1024, 'MBytes': 1024*1024, 'GBytes': 1024**3, \
        'bits/sec': 1, 'Kbits/sec': 1000, 'Mbits/sec': 1000**2, 'Gbits/sec': 1000**3}

# returns
# tot_tx, avg_bitrate, tot_retr
def summarize(data):
    if len(data) == 0:
        return (0, 0, 0)
    tot_tx = 0
    tot_bitrate = 0
    tot_retr = 0
    for interval, tx_bytes, bitrate, retr, cwnd in data:
        tot_tx += tx_bytes
        tot_bitrate += bitrate
        tot_retr += retr
    return (tot_tx, tot_bitrate / len(data), tot_retr)

def normalize_recv_line(line):
    return ' '.join(line.split()[2:6])

# returns an array of (interval, transfer_bytes, bitrate, retr, cwnd)
def parse_client(fn, parse_upload=True):
    data = []
    recv = ''
    send = ''
    still_parsing = True
    with open(fn, 'r') as f:
        for line in f.readlines():
            if ' sec ' in line and still_parsing:
                try:
                    if parse_upload:
                        _, _, interval, _, tx, tx_unit, bit, bit_unit, retr, cwnd, cwnd_unit = line.split()
                    else:
                        _, _, interval, _, tx, tx_unit, bit, bit_unit = line.split()
                except:
                    print 'Err: could not parse "%s" line:' % fn
                    print line
                    sys.exit(1)
                interval = int(interval.split('-')[0].split('.')[0])
                tx = int(float(tx) * UNIT[tx_unit])
                bitrate = int(float(bit) * UNIT[bit_unit])
                if parse_upload:
                    cwnd = int(float(cwnd) * UNIT[cwnd_unit])
                    data.append((interval, tx, bitrate, int(retr), cwnd))
                else:
                    data.append((interval, tx, bitrate, 0, 0))

            elif line.startswith('- - -'):
                still_parsing = False

            elif 'receiver' in line and not 'CPU' in line:
                #recv = line.split()[2:]
                recv = normalize_recv_line(line)
            elif 'sender' in line and not 'CPU' in line:
                #send = line.split()[2:]
                send = line.strip()[4:]
    return (data, recv, send)


def parse_multi_clients(fn_prefix, n=11, parse_upload=True):
    return [parse_client(fn_prefix % i, parse_upload) for i in xrange(n)]

def parse_server(fn, parse_upload=True):
    data = []    #current one
    last_data = []
    servers = []
    result_dict = {}   # recv_line => data_array
    with open(fn, 'r') as f:
        for line in f.readlines():
            if ' sec ' in line and not 'sender' in line and not 'receiver' in line:
                is_upload = len(line.split()) < 9
                if parse_upload:
                    if not(is_upload):
                        continue
                    _, _, interval, _, tx, tx_unit, bit, bit_unit, = line.split()
                interval = int(interval.split('-')[0].split('.')[0])
                tx = int(float(tx) * UNIT[tx_unit])
                bitrate = int(float(bit) * UNIT[bit_unit])

                data.append((interval, tx, bitrate, 0, 0))

            elif line.startswith('- - -'):
                if len(data) > 0:
                    servers.append(data)
                    last_data = data
                data = []
            elif ' receiver' in line:
                recv = normalize_recv_line(line)
                if recv in result_dict:
                    print 'Warning: "%s" already in the dictionary...' % recv
                result_dict[recv] = last_data

    return servers, result_dict

dark_decoy_upload_clients = parse_multi_clients('dark-decoys-%d.log')
direct_upload_clients = parse_multi_clients('direct-noproxy-%d.log')
tapdance_upload_clients = parse_multi_clients('tap-dance-%d.log')


servers, server_result_dict = parse_server('all-servers.log')
#('serverside.log')


print 'Server receives:'
print 'MB     Mbps'
for server in servers:
    tot_tx, avg_bitrate, tot_retr = summarize(server)
    print '%d MB   %.2f Mbit/s' % (int(round(float(tot_tx) / 1024**2)),\
            round(float(avg_bitrate) / 1000**2, 2))
    #print tot_tx, avg_bitrate

print '-----'



def get_max_bw(data):
    max_i = None
    max_br = None
    for i, (tot_tx, avg_bitrate, tot_retr) in enumerate([summarize(d) for d, _, _ in data]):
        if max_i is None or avg_bitrate > max_br:
            max_i = i
            max_br = avg_bitrate
    return data[max_i][0]

def reunit(x):
    if x < 1024:
        return '%d B' % x
    elif x < 1024**2:
        return '%d KB' % x/1024
    return '%d MB' % (x/1024**2)

def reunit_speed(x):
    if x < 1000:
        return '%d bit/s' % x
    elif x < 1000**2:
        return '%d Kbit/s' % (x/1000)
    return '%d Mbit/s' % (x/1000**2)



def print_data_sum(data):
    global server_result_dict
    max_tx = None
    max_i = None
    max_recv = None
    i = 0
    for cli, recv, send in data:
        tot_tx, avg_bitrate, tot_retr = summarize(cli)
        print '%d  %s  %s' % (i, reunit(tot_tx), reunit_speed(avg_bitrate))

        if max_i is None or max_tx < tot_tx:
            max_tx = tot_tx
            max_i = i
            max_recv = recv
        i += 1
        #int(round(float(tot_tx) / 1024**2)),\
        #round(float(avg_bitrate) / 1000**2, 2))
    print '   Max: %d' % max_i
    print '   %s' % max_recv
    if max_recv in server_result_dict:
        return server_result_dict[max_recv]
    return None
    #return max_i



print 'Dark Decoy uploads (%d):' % len(dark_decoy_upload_clients)
max_dd_up_server = print_data_sum(dark_decoy_upload_clients)

print '-----'
print 'Direct uploads (%d):' % len(direct_upload_clients)
max_dir_up_server = print_data_sum(direct_upload_clients)

print '-----'
print 'Tapdance:'
max_td_up_server = print_data_sum(tapdance_upload_clients)


#print get_max_bw(dark_decoy_upload_clients)

def write_server_bitrates_to_file(fn, server_dat):
    with open(fn, 'w') as f:
        for i, tx, bitrate, _, _ in server_dat:
            f.write('%d\n' % bitrate)


write_server_bitrates_to_file('td-max-up.dat', max_td_up_server)
write_server_bitrates_to_file('direct-max-up.dat', max_dir_up_server)
write_server_bitrates_to_file('dd-max-up.dat', max_dd_up_server)


################## DOWNLOAD

dark_decoy_download_clients = parse_multi_clients('dark-decoys-reverse-%d.log', parse_upload=False)
direct_download_clients = parse_multi_clients('direct-noproxy-reverse-%d.log', parse_upload=False)
tapdance_download_clients = parse_multi_clients('tap-dance-reverse-%d.log', parse_upload=False)


write_server_bitrates_to_file('dd-max-down.dat', get_max_bw(dark_decoy_download_clients))
write_server_bitrates_to_file('direct-max-down.dat', get_max_bw(direct_download_clients))
write_server_bitrates_to_file('td-max-down.dat', get_max_bw(tapdance_download_clients))

