libtlsc_rpath=lib/libtlsc

CFLAGS=-O3 -pipe -Wall -Wno-unused-function -pedantic #-mtune=native -march=native
CXXFLAGS=$(CFLAGS)
LDLIBS=`pkg-config --libs openssl libcrypto` $(libtlsc_rpath).a

.PHONY: clean test all

all: main0 main

$(libtlsc_rpath).a:
	make -C lib

main0: main0.cpp ClientTls.cpp ClientTls.hpp $(libtlsc_rpath).a
	$(CXX) -c ClientTls.cpp
	$(CXX) -o main0 main0.cpp ClientTls.o $(LDLIBS) $(CXXFLAGS)

main: main.c $(libtlsc_rpath).a
	$(CC) -o main main.c $(LDLIBS) $(CFLAGS)

test: clean test.sh main main0
	./test.sh

clean:
	make -C lib clean
	rm -fv *.o *.log main main0
