# syntax=docker/dockerfile:1.3-labs

# ------------------------------------------------------------------------------
# Development image
#
# Builds a common image that has all dependencies required to build and run
# any piece of the station. Ideally we want to redo this as little as possible.
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS dev_img

ARG UNAME=conjure
ARG UID=1000
ARG GID=1000
RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME

RUN apt-get update && apt-get install -yq sudo apt-utils software-properties-common
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata

# install pf_ring deps
RUN apt-get update && apt-get install -yq wget lsb-release gnupg \
  && wget https://packages.ntop.org/apt-stable/20.04/all/apt-ntop-stable.deb \
  && apt-get install -yq ./apt-ntop-stable.deb

RUN apt-get update && sudo apt-get install -yq pfring pfring-dkms

COPY prereqs_once.sh /opt/conjure/

WORKDIR /opt/conjure
RUN /usr/bin/sudo ./prereqs_once.sh

WORKDIR /opt/conjure

COPY Makefile *.c *.h  /opt/conjure/
COPY libtapdance/ /opt/conjure/libtapdance
RUN make libtd

# run cargo build to allow for dependencies to cached
RUN PATH="$HOME/.cargo/bin:$PATH" cargo init --lib .
COPY Cargo.lock Cargo.toml build.rs /opt/conjure/
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

RUN PATH="$HOME/.cargo/bin:$PATH" make conjure

COPY go.* /opt/conjure/
COPY cmd/ /opt/conjure/cmd
COPY application/ /opt/conjure/application
COPY pkg/ /opt/conjure/pkg

RUN PATH="/usr/local/go/bin/:$PATH" make app
RUN PATH="/usr/local/go/bin/:$PATH" make registration-server

# add application as default entrypoint for dev reasons.
ENTRYPOINT /opt/conjure/application/application


# ------------------------------------------------------------------------------
# Production image
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 as conjure

# install pf_ring deps
RUN apt-get update && apt-get install -yq sudo wget lsb-release gnupg \
  && wget https://packages.ntop.org/apt-stable/20.04/all/apt-ntop-stable.deb \
  && apt-get install -yq ./apt-ntop-stable.deb

RUN apt-get update && sudo apt-get install -yq pfring pfring-dkms

RUN apt update && apt install -yq libzmq3-dev
COPY --from=dev_img /opt/conjure/application/application /opt/conjure/bin/
COPY --from=dev_img /opt/conjure/cmd/registration-server/registration-server /opt/conjure/bin/
COPY --from=dev_img /opt/conjure/conjure /opt/conjure/bin/

# ENTRYPOINT /bin/bash
