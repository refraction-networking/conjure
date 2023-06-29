
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
CC		 = ${CROSS_COMPILE}gcc #--platform=native

DEBUG_OR_RELEASE = release
RUST_LIB=./target/release/librust_dark_decoy.a
TD_LIB=./libtapdance/libtapdance.a
LIBS=${RUST_LIB} ${TD_LIB} -L/usr/local/lib -lpcap -lpfring -lzmq -lcrypto -lpthread -lrt -lgmp -ldl -lm
CFLAGS = -Wall -DENABLE_BPF -DHAVE_PF_RING -DHAVE_PF_RING_ZC -DTAPDANCE_USE_PF_RING_ZERO_COPY -O2 # -g
PROTO_RS_PATH=src/signalling.rs
EXE_DIR=./bin

all: rust libtd conjure app registration-server ${PROTO_RS_PATH}

sim: rust libtd conjure-sim app registration-server ${PROTO_RS_PATH}

rust: ./src/*.rs
	cargo build --${DEBUG_OR_RELEASE}

test:
	cargo test --${DEBUG_OR_RELEASE}

app:
	[ -d $(EXE_DIR) ] || mkdir -p $(EXE_DIR)
	go build -o ${EXE_DIR}/application ./application

libtd:
	cd ./libtapdance/ && make libtapdance.a

conjure: detect.c loadkey.c rust_util.c rust libtapdance
	[ -d $(EXE_DIR) ] || mkdir -p $(EXE_DIR)
	${CC} ${CFLAGS} -o ${EXE_DIR}/$@ detect.c loadkey.c rust_util.c ${LIBS}


conjure-sim: detect.c loadkey.c rust_util.c rust libtapdance
	[ -d $(EXE_DIR) ] || mkdir -p $(EXE_DIR)
	${CC} -Wall -O2 -o ${EXE_DIR}/conjure detect.c loadkey.c rust_util.c ${LIBS}

registration-server:
	[ -d $(EXE_DIR) ] || mkdir -p $(EXE_DIR)
	go build -o ${EXE_DIR}/registration-server ./cmd/registration-server

PARAMS := det app reg zbalance sim
target := unk
# makefile arguments take preference, if one is not provided we check the environment variable.
# If that is also missing then we use "latest" and install pfring from pkg in the docker build.
ifndef pfring_ver
	ifdef PFRING_VER
		pfring_ver := ${PFRING_VER}
	else
		pfring_ver := latest
	endif
endif

container:
ifeq (unk,$(target))
	DOCKER_BUILDKIT=1 docker build -t conjure -t pf-$(pfring_ver) -f  docker/Dockerfile --build-arg pfring_ver=$(pfring_ver) .
#	@printf "DOCKER_BUILDKIT=1 docker build -t conjure -f  docker/Dockerfile --build-arg pfring_ver=$(pfring_ver) .\n"
else ifneq  (,$(findstring $(target), $(PARAMS)))
	DOCKER_BUILDKIT=1 docker build --target conjure_$(target) -t conjure_$(target) -t pf-$(pfring_ver) -f docker/Dockerfile --build-arg pfring_ver=$(pfring_ver) .
#	@printf "DOCKER_BUILDKIT=1 docker build --target conjure_$(target) -t conjure_$(target) -f docker/Dockerfile --build-arg pfring_ver=$(pfring_ver) .\n"
else
	@printf "unrecognized container target $(target) - please use one of [ $(PARAMS) ]\n"
endif


backup-config:
	mkdir -p backup
	cp -rf sysconfig backup/
	cp application/config.toml backup/application.config.toml
	cp cmd/registration-server/config.toml backup/registration-server.config.toml

restore-config:
ifneq (,$(wildcard backup/sysconfig))
	$(RM) -rf sysconfig
	mv -f backup/sysconfig .
endif
ifneq (,$(wildcard backup/application.config.toml))
	mv backup/application.config.toml application/config.toml
endif
ifneq (,$(wildcard backup/registration-server.config.toml))
	mv backup/registration-server.config.toml cmd/registration-server/config.toml
endif
	$(RM) -rf backup

clean:
	cargo clean
	rm -f ${TARGETS} *.o *~ ${EXE_DIR}

${PROTO_RS_PATH}:
	cd ./proto/ && make

.PHONY: registration-server zmq-proxy
