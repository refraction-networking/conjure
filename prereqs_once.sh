#!/bin/bash
#
# Set up basic prereqs for building and running Conjure
# Run this once per new machine. See README.md

TMPDIR=/tmp/cj-prereqs


# For CI, allow running as root
# But for normal installs, running as root will usually cause problems,
# as your .cargo directory will be owned by root.
# Symptoms: make (cargo build) fails when run by non-root.
if [ $(id -u) -eq 0 ]; then
    alias sudo=''
fi

sudo rm -rf "${TMPDIR}"
mkdir -p "${TMPDIR}"
cd "${TMPDIR}"
if [ $? -ne 0 ]; then
    echo "$0: failed to create tmpdir ${TMPDIR}"
    exit 1
fi

isDocker(){
    local cgroup=/proc/1/cgroup
    test -f $cgroup && [[ "$(<$cgroup)" = *:cpuset:/docker/* ]]
}

isDockerBuildkit(){
    local cgroup=/proc/1/cgroup
    test -f $cgroup && [[ "$(<$cgroup)" = *:cpuset:/docker/buildkit/* ]]
}

isDockerContainer(){
    [ -e /.dockerenv ]
}

install_deps() {
    echo "INSTALLING DEPENDENCIES..."

    sudo apt-get update && sudo apt-get install -yf automake build-essential bison flex \
	    libtool libpcap-dev \
	    libnuma-dev libargtable2-dev lunzip \
	    python python-protobuf protobuf-compiler \
	    libprotobuf-dev golang-protobuf-extensions-dev \
	    daemontools libzmq3-dev pkg-config curl

    if [ -z ${is_docker_build+x} ]; then 
        sudo apt-get install -yf linux-virtual
    else
        sudo apt-get install -yf linux-headers-$(uname -r)
    fi


    if [ $? -ne 0 ]; then
	echo "$0: installing packages failed"
	exit 1
    fi
}

fetch_file() {
    # Pull a file out of the local cache, if we can find it.
    # Otherwise, fetch it from the given URL.
    #
    # If the filename and the URL don't match, you'll probably
    # get garbage.  This is not detected right now.

    if [ ! ${TMPDIR+x} ]; then
	echo "$0: TMPDIR not set in fetch_file"
	exit 1
    fi

    local _DESTDIR="${TMPDIR}"
    local _URL="$1"
    local _FNAME="$2"

    # Get rid of any previous version of the file
    #
    sudo rm -f "${_DESTDIR}/${_FNAME}"

    if [ ! -d "${_DESTDIR}" ]; then
	mkdir -p "${_DESTDIR}"
    fi

    if [ -f "${CACHEDIR}/${_FNAME}" ]; then
	echo "$0: using cached copy of ${_FNAME}"
	cp "${CACHEDIR}/${_FNAME}" "${_DESTDIR}/${_FNAME}"
    else
	echo "$0: fetching ${_FNAME} from ${_URL}"
	cd "${_DESTDIR}"
	wget -nv "${_URL}"
    fi

    if [ ! -f "${_DESTDIR}/${_FNAME}" ]; then
	echo "$0: failed to get file ${_FNAME}"
	exit 1
    fi
}

install_go() {
    # INSTALL GOLANG

    if ! command -v go &> /dev/null; then
	echo "unable to find golang, installing latest." 
	curl -LO https://get.golang.org/$(uname)/go_installer && chmod +x go_installer && ./go_installer && rm go_installer
    fi
}

install_rust() {
    # INSTALL RUST

    # if you already have a version of RUST installed, it seems to be
    # easily confused by things in your $HOME/.cargo directory that
    # correspond to that version.  So blow that directory away, if there
    # is one.  This will make your first build after this slower than
    # normal (but if you've never done a build before, it won't change
    # anything)

    # NOTE: if you already have already run RUST in the current shell,
    # it may have exported environment variables which are not, for
    # some reason, reset later.  So you probably want to create a new
    # shell in which to run later commands.  TODO: there must be a
    # better way.

    cd "${TMPDIR}"
    curl -sSf https://sh.rustup.rs > install_rustup.sh
    chmod +x install_rustup.sh
    ./install_rustup.sh --default-toolchain=stable -y

    if [ $? -ne 0 ]; then
	echo "$0: installing rust failed"
	exit 1
    fi

    source "$HOME/.cargo/env"

    # cargo install --vers 1.4.5 protobuf
    # if [ $? -ne 0 ]; then
	# echo "$0: installing protobuf for rust failed"
	# exit 1
    # fi

}

install_routes() {

    sudo apt-get -yf install iproute2

    # install custom route priority, if not already done
    #
    if [ $(grep -c "200 custom" /etc/iproute2/rt_tables) -eq 0 ]; then
	sudo /bin/sh -c "echo 200 custom >> /etc/iproute2/rt_tables"
    fi
}

echo "Installing install, libssl, git, cargo..."
sudo apt-get update -y
# FIXME: Hold back kernel and kernel headers?
sudo apt-get install -y libssl-dev git libgmp3-dev wget lsb-release build-essential

install_deps

# /var/lib/conjure is hardcoded as the location of the client_config
# and overloaded_decoys files
# So we use it also for the per-machine configs
# and as the default directory for the station private key
if [ ! -d "/var/lib/conjure" ]; then
    echo "Creating /var/lib/conjure"
    sudo mkdir -p /var/lib/conjure
    if [ $? -ne 0 ]; then
	echo "$0: Could not create /var/lib/conjure"
	exit 1
    fi
fi

install_rust
install_routes
install_go

echo "CONJURE PREREQS INSTALLED"
exit 0
