CFLAGS=-O3 -pipe -Wall -Wextra -Wno-unused-function -pedantic -std=c99
LDLIBS=`pkg-config --libs openssl libcrypto`
libtlsc=libtlsc

.PHONY: clean all

all: $(libtlsc).a

$(libtlsc).a: TlsClient.c TlsClient.h
	$(CC)  -c TlsClient.c $(CFLAGS)
	$(AR) rcs $(libtlsc).a TlsClient.o

clean:
	rm -fv *.o *.a
