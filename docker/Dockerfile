#FROM ubuntu:20.04 as build_base
FROM ubuntu:20.04 as build_base_go
#    PATH="/opt/PF_RING/userland/examples_zc:$PATH"
ARG GO_VERSION=1.15.3
ARG CUSTOM_BUILD
ARG BRANCH=master
ENV PATH="/usr/local/go/bin:/root/.cargo/bin:${PATH}" \
    GOPATH="/root/go" \
    GOROOT="/usr/local/go"

# Install dependencies: including rust and go
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y -q install wget git make gcc bison flex protobuf-compiler curl libssl-dev pkg-config libgmp3-dev libzmq3-dev && \
    apt-get clean all && \
    wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    curl https://sh.rustup.rs -sSf -o install_rust.sh; sh install_rust.sh -y && \
    cargo install protobuf-codegen

# Install PFRING to get libraries
RUN apt-get install -y -q software-properties-common wget && \
    add-apt-repository universe && \
    wget https://packages.ntop.org/apt-stable/20.04/all/apt-ntop-stable.deb && \
    apt install ./apt-ntop-stable.deb && \
    apt-get clean all && \
    apt-get update && \
    apt-get install -y -q pfring && \
    apt-get clean all 

# Get go-reddis and make sure it's version is 7.4.0.
RUN go get -u -d github.com/go-redis/redis || true && cd ${GOPATH}/src/github.com/go-redis/redis && git checkout tags/v7.4.0 -b v7-master 

# Copy docker context dir. This is used as a source if CUSTOM_BUILD is enabled
COPY . /tmp/conjure
# Get Conjure or copy a directory Dockerfile is in. Switched by CUSTOM_BUILD var
RUN    go get -d github.com/refraction-networking/conjure/...  ; \
       bash -c 'if [[ ! -z "$CUSTOM_BUILD" ]] ; then \
       rm -rf ${GOPATH}/src/github.com/refraction-networking/conjure; cp -r /tmp/conjure ${GOPATH}/src/github.com/refraction-networking/conjure ; \
       fi'

# Checkout needed branch and compile
RUN    cd /root/go/src/github.com/refraction-networking/conjure && \
    git checkout ${BRANCH} && \
    go get ./... || true && \
    make 
RUN    cp -r /root/go/src/github.com/refraction-networking/conjure /opt/conjure



FROM ubuntu:20.04 as zbalance
ENV CJ_IFACE=lo \
    CJ_CLUSTER_ID=98 \
    CJ_CORECOUNT=1 \
    CJ_COREBASE=0 \
    ZBALANCE_HASH_MODE=1
#COPY --from=build_base /opt/PF_RING /opt/PF_RING

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y -q install libelf1 

COPY --from=build_base_go /usr/bin/zbalance_ipc /usr/bin/zbalance_ipc
COPY ./docker/zbalance-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["bash", "/entrypoint.sh"]




FROM ubuntu:20.04 as detector
ENV CJ_CLUSTER_ID=98 \
    CJ_CORECOUNT=1 \
    CJ_COREBASE=0 \
    CJ_SKIP_CORE=-1 \
    CJ_QUEUE_OFFSET=0 \
    CJ_LOG_INTERVAL=5 \
    CJ_PRIVKEY=/opt/conjure/keys/privkey \
    CJ_STATION_CONFIG=/opt/conjure/application/config.toml \
    CJ_IP4_ADDR=127.0.0.1 \
    CJ_IP6_ADDR=[::1]
#COPY --from=build_base_go /opt/conjure/dark-decoy /opt/conjure/dark-decoy
COPY --from=build_base_go /opt/conjure/conjure /opt/conjure/conjure
COPY --from=build_base_go /opt/conjure/application/config.toml /opt/conjure/application/config.toml
COPY ./docker/detector-entrypoint.sh /entrypoint.sh
COPY --from=build_base_go /usr/local/lib/libpcap.so /usr/local/lib/libpcap.so

RUN apt-get update && apt-get -y -q install libzmq3-dev iproute2 iptables && apt-get clean all
ENTRYPOINT [ "/entrypoint.sh"]




FROM ubuntu:20.04 as application
ENV CJ_STATION_CONFIG=/opt/conjure/application/config.toml \
    PHANTOM_SUBNET_LOCATION=/opt/conjure/sysconfig/phantom_subnets.toml
COPY --from=build_base_go /opt/conjure/application/application /opt/conjure/application/application
RUN apt-get update && apt-get -y -q install libzmq3-dev && apt-get clean all
COPY --from=build_base_go /opt/conjure/application/config.toml ${CJ_STATION_CONFIG}
COPY --from=build_base_go /opt/conjure/application/lib/test/phantom_subnets.toml ${PHANTOM_SUBNET_LOCATION}
#COPY ./docker/application-entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/opt/conjure/application/application"]
