# Note the implication that the targets here depend on doing make in ../../forge_socket
INCLUDE=-I../../forge_socket
CFLAGS+=-fPIC -g $(INCLUDE)

# User and System libraries
LIBS       = -lgmp -ldl

OPENSSL_STATIC_LIB = -Wl,-Bstatic -lssl -Wl,-Bstatic -lcrypto

ALL_LIBS = $(OPENSSL_STATIC_LIB) -Wl,-Bdynamic $(LIBS)

all:	libtapdance.a genkey

clean:
	rm -f libtapdance.a decode genkey test
	rm -f *.o

LIBSRC	= tapdance.c ssl_api.c elligator2.c curve25519-donna-c64.c loadkey.c tapdance_rst_spoof.c tapdance_rust_util.c
LIBOBJ	= $(LIBSRC:.c=.o)

libtapdance.a: $(LIBOBJ)
	$(AR) -rcs -o $@ $(LIBOBJ)

decode: decode.c elligator2.c curve25519-donna-c64.c
	$(CC) -o $@ $(CFLAGS) $^ $(ALL_LIBS)

genkey: genkey.c elligator2.c curve25519-donna-c64.c loadkey.c
	$(CC) -o $@ $(CFLAGS) $^ $(ALL_LIBS)

# FIXME: Is 'test' .PHONY?

test: test-tapdance.c
	$(CC) -g $^ -o $@ $(CFLAGS) $(ALL_LIBS) -L. -ltapdance -ldl

# don't really need install
install: libtapdance.a genkey
	mkdir -p $(DESTDIR)/include
	mkdir -p $(DESTDIR)/lib
	mkdir -p $(DESTDIR)/bin
	cp loadkey.h $(DESTDIR)/include
	cp libtapdance.a $(DESTDIR)/lib/
	cp genkey $(DESTDIR)/bin/
