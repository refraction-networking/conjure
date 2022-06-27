
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
CC		 = ${CROSS_COMPILE}gcc #--platform=native

DEBUG_OR_RELEASE = release
RUST_LIB=./target/release/librust_dark_decoy.a
TD_LIB=./libtapdance/libtapdance.a
LIBS=${RUST_LIB} ${TD_LIB} -L/usr/local/lib -lpcap -lpfring -lzmq -lcrypto -lpthread -lrt -lgmp -ldl -lm
CFLAGS = -Wall -DENABLE_BPF -DHAVE_PF_RING -DHAVE_PF_RING_ZC -DTAPDANCE_USE_PF_RING_ZERO_COPY -O2 # -g
PROTO_RS_PATH=src/signalling.rs


all: rust libtd conjure app registration-api ${PROTO_RS_PATH}

sim: rust libtd conjure-sim app registration-api ${PROTO_RS_PATH}

rust: ./src/*.rs
	cargo build --${DEBUG_OR_RELEASE}

test:
	cargo test --${DEBUG_OR_RELEASE}

app:
	cd ./application/ && make

libtd:
	cd ./libtapdance/ && make libtapdance.a

conjure: detect.c loadkey.c rust_util.c rust libtapdance
	${CC} ${CFLAGS} -o $@ detect.c loadkey.c rust_util.c ${LIBS}
# gcc -Wall -DENABLE_BPF -DHAVE_PF_RING -DHAVE_PF_RING_ZC -DTAPDANCE_USE_PF_RING_ZERO_COPY -O2 -o conjure detect.c loadkey.c rust_util.c ./target/release/librust_dark_decoy.a ./libtapdance/libtapdance.a -lpfring -lpcap -L/usr/local/lib -lzmq -lcrypto -lpthread -lrt -lgmp -ldl -lm

conjure-sim: detect.c loadkey.c rust_util.c rust libtapdance
	${CC} -Wall -02 -o conjure detect.c loadkey.c rust_util.c ${LIBS}

registration-api:
	cd ./registration-api/ && make

# Note this copies in the whole current directory as context and results in
# overly large context. should not be used to build release/production images.
custom-build:
	docker build --build-arg CUSTOM_BUILD=1 -f docker/Dockerfile .


clean:
	cargo clean
	rm -f ${TARGETS} *.o *~

${PROTO_RS_PATH}:
	cd ./proto/ && make

.PHONY: registration-api zmq-proxy
