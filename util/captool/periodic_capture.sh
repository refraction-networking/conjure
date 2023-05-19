#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

concatenate_paths() {
   base_path=${1}
   sub_path=${2}
   full_path="${base_path:+$base_path/}$sub_path"
   full_path=$(realpath ${full_path})
   echo $full_path
}

# Parameters - all here are examples

bin_dir="./"
captool=$(concatenate_paths $bin_dir "/captool")

data_dir="./"
out_fname="ir-$(date -u +%FT%H%MZ")"
output_fpath="$(concatenate_paths $data_dir "${out_fname}.pcapng.gz")"
output_config="$(concatenate_paths $data_dir "${out_fname}.cfg")"

target_subnet="192.168.0.0/24,2001::/64"
interfaces="eno1"
asn_file="./asn_list.txt"
asn_list="$([ -f $asn_file ] && cat $asn_file)"
flows_per_asn=10000
packets_per_flow=100
packet_total=300000
timeout="3h"

# the capture tool
if [[ -z "$asn_list" ]]; then
    # echo "no asn list"
    RUST_BACKTRACE=1 $captool -t "$target_subnet" -i "$interfaces" --lfa "$flows_per_asn" --ppf "$packets_per_flow" --lp "$packet_total" -o "$output_fpath" --timeout "$timeout"
else
    # echo "no asn list"
    RUST_BACKTRACE=1 $captool -t "$target_subnet" -i "$interfaces" --lfa "$flows_per_asn" --ppf "$packets_per_flow" --lp "$packet_total" -o "$output_fpath" --timeout "$timeout" -a  "$asn_list"
fi

unset should_sync
# should_sync="true"
if ! [[ -z "$should_sync" ]]; then
    # Remote Copy params
    local_user="${USER}"
    remote_user="ubuntu"
    analysis_server="127.0.0.1"
    identity_file="$HOME/.ssh/sync_ed25519"
    remote_data_dir="~/"

    # Sync the Captured File and the dumped config for the capture to the analysis VM
    /sbin/runuser - refraction-worker -c "/usr/bin/scp -i ${identity_file} $output_fpath $output_config ${remote_user}@${analysis_server}:${remote_data_dir}"

fi
