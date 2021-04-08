


PFRING_DIR=../PF_RING
CFLAGS=-DENABLE_BFP -DHAVE_PF_RING -DHAVE_PF_RING_ZC -DTAPDANCE_USE_PF_RING_ZERO_COPY -I${PFRING_DIR}/userland/lib -I${PFRING_DIR}/kernel -O2

LIBS=${PFRING_DIR}/userland/lib/libpfring.a ${PFRING_DIR}/userland/libpcap/libpcap.a -L/usr/local/lib -lpthread -lrt -ldl -lm

cap: cap.c
	$(CC) $(CFLAGS) -o cap cap.c $(LIBS)
