
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
CC		 = ${CROSS_COMPILE}gcc #--platform=native

DEBUG_OR_RELEASE = release
PFRINGDIR=./PF_RING/
PFRING_LIBS=${PFRINGDIR}/userland/lib/libpfring.a ${PFRINGDIR}/userland/libpcap/libpcap.a
RUST_LIB=./target/release/librust_dark_decoy.a
LIBS=${PFRING_LIBS} ${RUST_LIB} -lpthread -lrt -lgmp -ldl -lm
CFLAGS = -Wall -DENABLE_BPF -DHAVE_PF_RING -DHAVE_PF_RING_ZC -DTAPDANCE_USE_PF_RING_ZERO_COPY -O2 # -g

all: rust dark-decoy

rust: ./src/*.rs
	cargo build --${DEBUG_OR_RELEASE}

dark-decoy: detect.c loadkey.c rust_util.c rust
	${CC} ${CFLAGS} -o $@ detect.c loadkey.c rust_util.c ${LIBS}

clean:
	cargo clean
	rm -f ${TARGETS} *.o *~

