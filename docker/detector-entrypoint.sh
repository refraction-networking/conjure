#!/bin/bash

CORE_COUNT=${CJ_CORECOUNT:-2}
OFFSET=${CJ_QUEUE_OFFSET:-2}

cleanup() {
  echo $(ps aux)
  start-stop-daemon --stop --oknodo --retry 15 -n dark-decoy
  #pkill dark-decoy
  echo $(ps aux)
  for CORE in `seq $OFFSET $((OFFSET + CORE_COUNT -1 ))`
  do
    echo "Cleaning up"
    tun_int=tun${CORE}
    ip6tables -D INPUT -i ${tun_int} -j ACCEPT
    ip6tables -t nat -D PREROUTING -p tcp -i ${tun_int} -j DNAT --to ${CJ_IP6_ADDR}:41245
    iptables -D INPUT -i ${tun_int} -j ACCEPT
    iptables -t nat -D PREROUTING -p tcp -i ${tun_int} -j DNAT --to ${CJ_IP4_ADDR}:41245
    ip tuntap del mode tun ${tun_int}
  done
}

trap 'true' SIGTERM


sysctl -w net.ipv4.conf.all.route_localnet=1
sysctl -w net.ipv4.conf.all.rp_filter=0

for CORE in `seq $OFFSET $((OFFSET + CORE_COUNT -1 ))`
do
  tun_int=tun${CORE}
  if [[ -f /sys/class/net/${tun_int}/tun_flags ]]
  then
    echo "Tunnel ${tun_int} found. Skipping creation."
  else
    ip tuntap add mode tun ${tun_int}
  fi
  sysctl -w net.ipv4.conf.${tun_int}.rp_filter=0
  sysctl -w net.ipv4.conf.${tun_int}.route_localnet=1

  rules=$(iptables -t nat -L PREROUTING -v|grep ${tun_int})
  if [ $? == 0 ]
  then
    echo "The following iptables rules were found for ${tun_int}:"
    echo ${rules}
    echo
    echo "Skipping ipv4 firewall configuration for ${tun_int}"
  else
    echo "Adding iptables rules for ${tun_int}"
    iptables -t nat -I PREROUTING 1 -p tcp -i ${tun_int} -j DNAT --to ${CJ_IP4_ADDR}:41245
    iptables -I INPUT 1 -i ${tun_int} -j ACCEPT
  fi

  rules=$(ip6tables -t nat -L PREROUTING -v|grep ${tun_int})
  if [ $? == 0 ]
  then
    echo "The following ip6tables rules were found for ${tun_int}:"
    echo ${rules}
    echo
    echo "Skipping ipv6 firewall configuration for ${tun_int}"
  else
    echo "Adding ip6tables rules for ${tun_int}"
    ip6tables -t nat -I PREROUTING 1 -p tcp -i ${tun_int} -j DNAT --to ${CJ_IP6_ADDR}:41245
    ip6tables -I INPUT 1 -i ${tun_int} -j ACCEPT
  fi
done
echo "Prerequisite configuration complete."
/opt/conjure/dark-decoy -c ${CJ_CLUSTER_ID} -o ${CJ_COREBASE} -n ${CJ_CORECOUNT} -l ${CJ_LOG_INTERVAL} -K ${CJ_PRIVKEY} -s ${CJ_SKIP_CORE} -z ${CJ_QUEUE_OFFSET} &
wait $!
cleanup


