# syntax=docker/dockerfile:1.3-labs

FROM ubuntu:20.04 AS base_pfring
ARG UNAME=conjure
ARG UID=1000
ARG GID=1000
RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME

RUN apt-get update && apt-get install -yq sudo apt-utils software-properties-common

# install pf_ring deps

COPY scripts/install_pfring.sh /
ARG pfring_ver="latest"
RUN /usr/bin/sudo pfring_ver="${pfring_ver}" /install_pfring.sh

# ------------------------------------------------------------------------------
# Development image
#
# Builds a common image that has all dependencies required to build and run
# any piece of the station. Ideally we want to redo this as little as possible.
# ------------------------------------------------------------------------------
FROM base_pfring AS dev_img

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata
COPY prereqs_once.sh /opt/conjure/

WORKDIR /opt/conjure
ENV is_docker_build YES
RUN /usr/bin/sudo ./prereqs_once.sh

WORKDIR /opt/conjure

COPY Makefile *.c *.h  /opt/conjure/
COPY libtapdance/ /opt/conjure/libtapdance
RUN make libtd

# run cargo build to allow for dependencies to cached
RUN PATH="$HOME/.cargo/bin:$PATH" cargo init --lib .
COPY Cargo.toml build.rs /opt/conjure/
RUN --mount=type=cache,target=/usr/local/cargo/registry PATH="$HOME/.cargo/bin:$PATH" cargo build --release

COPY src/ /opt/conjure/src

# A bit of magic here!
# * We're mounting that cache again to use during the build, otherwise it's not present and we'll have to download those again - bad!
# * EOF syntax is neat but not without its drawbacks. We need to `set -e`, otherwise a failing command is going to continue on
# * Rust here is a bit fiddly, so we'll touch the files (even though we copied over them) to force a new build
RUN --mount=type=cache,target=/usr/local/cargo/registry <<EOF
set -e
# update timestamps to force a new build
touch /opt/conjure/src/lib.rs
PATH="$HOME/.cargo/bin:$PATH" make rust
EOF

RUN PATH="$HOME/.cargo/bin:$PATH" make conjure-sim && mv bin/conjure bin/conjure-sim
RUN PATH="$HOME/.cargo/bin:$PATH" make conjure

COPY go.* /opt/conjure/
COPY cmd/ /opt/conjure/cmd
COPY application/ /opt/conjure/application
COPY pkg/ /opt/conjure/pkg

RUN PATH="$HOME/.go/bin/:$PATH" make app
RUN PATH="$HOME/.go/bin/:$PATH" make registration-server

# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/ /opt/conjure/scripts

# add application as default entrypoint for dev reasons.
ENTRYPOINT /opt/conjure/scripts/start_application.sh


# ------------------------------------------------------------------------------
# Production image zbalance only
# ------------------------------------------------------------------------------
FROM base_pfring as conjure_zbalance
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/start_zbalance_ipc.sh /opt/conjure/scripts/

ENTRYPOINT /opt/conjure/scripts/start_zbalance_ipc.sh

# ------------------------------------------------------------------------------
# Production image detector only (kind of, requires pfring)
# ------------------------------------------------------------------------------
FROM base_pfring as conjure_det
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig
COPY scripts/ /opt/conjure/scripts

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/bin/conjure /opt/conjure/bin/

# ------------------------------------------------------------------------------
# Production image application only
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 as conjure_app
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/ /opt/conjure/scripts

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/bin/application /opt/conjure/bin/

# ------------------------------------------------------------------------------
# Production image registration server only
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 as conjure_reg
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/ /opt/conjure/scripts/

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/bin/registration-server /opt/conjure/bin/

# ------------------------------------------------------------------------------
# Simulation image (no pfring required)
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 as conjure_sim
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/ /opt/conjure/scripts/

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/bin/conjure-sim /opt/conjure/bin/conjure
COPY --from=dev_img /opt/conjure/bin/registration-server /opt/conjure/bin/

# ------------------------------------------------------------------------------
# Production image all (default)
# ------------------------------------------------------------------------------
FROM base_pfring as conjure
# Add default configs and launch scripts
COPY sysconfig/conjure.conf /opt/conjure/sysconfig/
COPY scripts/ /opt/conjure/scripts/

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/bin/ /opt/conjure/bin/

# ENTRYPOINT /bin/bash
