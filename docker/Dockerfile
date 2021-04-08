FROM ubuntu:20.04 as build_base
#    PATH="/opt/PF_RING/userland/examples_zc:$PATH"

#wget make gcc bison flex
RUN apt-get update && \
    apt-get -y -q install wget git make gcc bison flex && \
    git clone --recurse-submodule https://github.com/refraction-networking/conjure.git && \
    cd /conjure/PF_RING/userland/lib && ./configure && make && \
    cd /conjure/PF_RING/userland/libpcap && ./configure && make && \
    cd /conjure/PF_RING/userland && ./configure && make && \
    cp -r /conjure/PF_RING /opt/PF_RING && \
    apt-get clean all

FROM build_base as build_base_go
ARG GO_VERSION=1.15.3
ARG CUSTOM_BUILD
ENV PATH="/usr/local/go/bin:/root/.cargo/bin:${PATH}" \
    GOPATH="/root/go" \
    GOROOT="/usr/local/go"
COPY . /tmp/conjure


# Install rust and go
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y -q install protobuf-compiler curl libssl-dev pkg-config libgmp3-dev libzmq3-dev && \
    wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    curl https://sh.rustup.rs -sSf -o install_rust.sh; sh install_rust.sh -y && \
    cargo install protobuf-codegen

RUN go get -u -d github.com/go-redis/redis || true && cd ${GOPATH}/src/github.com/go-redis/redis && git checkout tags/v7.4.0 -b v7-master 
RUN    go get -u -d github.com/BurntSushi/toml 
RUN    bash -c 'if [[ -z "$CUSTOM_BUILD" ]] ; then \
     go get -d github.com/refraction-networking/conjure/...  ; \
     else mkdir -p ${GOPATH}/src/github.com/refraction-networking; cp -r /tmp/conjure ${GOPATH}/src/github.com/refraction-networking/conjure ; \
     fi' 
RUN    rm -rf ${GOPATH}/src/github.com/refracion-networking/conjure/PF_RING && cp -r /conjure/PF_RING ${GOPATH}/src/github.com/refraction-networking/conjure 
RUN    cd /root/go/src/github.com/refraction-networking/conjure && \
    go get ./... || true && \
    make 
RUN    cp -r /root/go/src/github.com/refraction-networking/conjure /opt/conjure




FROM ubuntu:20.04 as zbalance
ENV CJ_IFACE=lo \
    CJ_CLUSTER_ID=98 \
    CJ_CORECOUNT=1 \
    CJ_COREBASE=0 \
    ZBALANCE_HASH_MODE=1
COPY --from=build_base /opt/PF_RING /opt/PF_RING
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
COPY --from=build_base_go /opt/conjure/dark-decoy /opt/conjure/dark-decoy
COPY --from=build_base_go /opt/conjure/application/config.toml /opt/conjure/application/config.toml
COPY ./docker/detector-entrypoint.sh /entrypoint.sh
# this list will be removed in a near future
RUN touch /var/lib/dark-decoy.prefixes

RUN apt-get update && apt-get -y -q install libzmq3-dev iproute2 iptables && apt-get clean all
ENTRYPOINT [ "/entrypoint.sh"]

FROM ubuntu:20.04 as application
ENV CJ_STATION_CONFIG=/opt/conjure/application/config.toml \
    PHANTOM_SUBNET_LOCATION=/opt/conjure/sysconfig/phantom_subnets.toml
COPY --from=build_base_go /opt/conjure/application/application /opt/conjure/application/application
RUN apt-get update && apt-get -y -q install libzmq3-dev
COPY --from=build_base_go /opt/conjure/application/config.toml ${CJ_STATION_CONFIG}
COPY --from=build_base_go /opt/conjure/application/lib/test/phantom_subnets.toml ${PHANTOM_SUBNET_LOCATION}
#COPY ./docker/application-entrypoint.sh /entrypoint.sh
ENTRYPOINT [ "/opt/conjure/application/application"]
