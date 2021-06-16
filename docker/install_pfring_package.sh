#!/bin/bash
OS=$(lsb_release -si)
RELEASE=$(lsb_release -sr)
CODENAME=$(lsb_release -sc)

function no_support {
        echo "Script does not support selected parameters or OS ${OS} ${CODENAME} ${RELEASE}."
        echo "Check https://packages.ntop.org/apt-stable/ for more information."
	exit 1
}

if [[ $EUID -ne 0 ]]; then
     echo "This script must be run as root" 
     exit 1
fi

case "$OS" in
        Ubuntu)
                echo "OS: Ubuntu"
                case $RELEASE in
                        20.04 | 18.04)
                                apt-get install software-properties-common wget
                                add-apt-repository universe
                                wget https://packages.ntop.org/apt-stable/${RELEASE}/all/apt-ntop-stable.deb
                                apt install ./apt-ntop-stable.deb
                                ;;
                        16.04)
                                wget https://packages.ntop.org/apt-stable/${RELEASE}/all/apt-ntop-stable.deb
                                apt install ./apt-ntop-stable.deb
                                ;;
                        *)
                                no_support
                                ;;
                esac
                ;;
        Debian)
                echo "OS: Debian"
                case $CODENAME in
                        buster | stretch)
                                echo ${CODENAME} requires 'contrib' apt sources. Do you want to enable?
                                read -p "[N/y]" enable_contrib
                                if [ ${enable_contrib:-N} = 'y' ]
                                then
                                        echo "Enabling 'contrib' sources in /etc/apt/sources.list"
                                        sed -i.bak -e '/contrib/ ! s/^deb.*debian\.org.*$/\0 contrib/' /etc/apt/sources.list
                                        wget https://packages.ntop.org/apt-stable/${CODENAME}/all/apt-ntop-stable.deb
                                        apt install ./apt-ntop-stable.deb
                                else
                                        no_support
                                fi
                                ;;
                        jessie)
                                wget https://packages.ntop.org/apt-stable/jessie/all/apt-ntop-stable.deb
                                dpkg -i apt-ntop-stable.deb
                                echo "deb http://archive.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
                                echo 'Acquire::Check-Valid-Until no;' > /etc/apt/apt.conf.d/99no-check-valid-until
                                apt-get update && apt-get install libjson-c2
                                ;;
                        *)
                                no_support
                                ;;
                esac
                ;;
        *)
                no_support
                ;;
esac
apt-get clean all
apt-get update
apt-get install pfring-dkms nprobe ntopng n2disk cento
apt-get install pfring-drivers-zc-dkms
