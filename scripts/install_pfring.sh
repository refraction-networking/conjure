
#!/bin/bash


# This script is designed to fill a specific need within the conjure docker container build.
# Use elsewhere at your own risk.

# pfring_ver=7.8.0

echo "pfring version: ${pfring_ver}"
# if the pfring_version is set to latest (default) or unset install from package, else install from source using version.
if [ "$pfring_ver" = "latest" ] || [ -z "$pfring_ver" ]; then
 	# install pf_ring deps
	echo "installing latest pf_ring from package"
 	apt-get update && apt-get install -yq wget lsb-release gnupg
 	wget https://packages.ntop.org/apt-stable/20.04/all/apt-ntop-stable.deb
 	apt-get install -yq ./apt-ntop-stable.deb

 	apt-get update && sudo apt-get install -yq pfring pfring-dkms
else
	echo "installing pf_ring ${pfring_ver}"
	apt-get update
	apt-get -yq install wget lsb-release gnupg libelf1 git build-essential linux-virtual flex bison libnuma-dev libnl-genl-3-dev dkms debhelper
	apt-get clean all

	mkdir -p /usr/local/include/linux/
	git clone https://github.com/ntop/PF_RING.git
	cd PF_RING
	git checkout ${pfring_ver} -b build-${pfring_ver}
	cd kernel
	./configure
	sudo make -f Makefile.dkms deb
	make install
	mkdir -p /local/include/linux/
	cp linux/pf_ring.h /usr/local/include/linux/
	cd ..
	make
	make install
fi
