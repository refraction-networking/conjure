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

data_dir="./"
target_subnet="192.168.0.0/24"
out_fname="ir-$(date -u +%FT%H%MZ")"
output_fpath="$(concatenate_paths $data_dir "${out_fname}.pcapng.gz")"
output_config="$(concatenate_paths $data_dir "${out_fname}.cfg")"
interfaces="eno1"
asn_file="./asn_list.txt"
asn_list="$([ -f $asn_file ] && cat $asn_file)"
limit_per_asn=1000
timeout="4h"

# Run the capture tool
if [[ -z "$asn_list" ]]; then
    RUST_BACKTRACE=1 ./captool -t "$target_subnet" -i "$interfaces" --lpa "$limit_per_asn" -o "$output_fpath" -t "$timeout"
else
    RUST_BACKTRACE=1 ./captool -t "$target_subnet" -i "$interfaces" -a "$asn_list" --lpa "$limit_per_asn" -o "$output_fpath" -t "$timeout"
fi

unset should_sync
# should_sync="true"
ifdef should_sync; then

    # Remote Copy params
    remote_user="ubuntu"
    analysis_server="127.0.0.1"
    identity_file="$HOME/.ssh/sync_ed25519"
    remote_data_dir="~/"

    # Sync the Captured File and the dumped config for the capture to the analysis VM
    scp -i ${identity_file} $output_fpath $output_config ${remote_user}@${analysis_server}:${remote_data_dir}
fi