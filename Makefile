CC=cc
CXX=g++

CFLAGS=-O3 -pipe -Wall -Wno-unused-function
CXXFLAGS=-O3 -pipe -Wall -Wno-unused-function
LDFLAGS=`pkg-config --libs openssl libcrypto`
LIBTLS=libtlscl

.PHONY: clean test

$(LIBTLS).a: lib/TlsClient.c lib/TlsClient.h lib/types.h
	$(CC)  -c lib/TlsClient.c $(CFLAGS)
	ar rcs $(LIBTLS).a TlsClient.o

ClientTls.o: ClientTls.cpp ClientTls.hpp
	$(CXX) -c ClientTls.cpp $(LDFLAGS) $(CXXFLAGS)

clean:
	rm -fv *.o *.a *.log main main0

main0: main0.cpp ClientTls.o $(LIBTLS).a
	$(CXX) -o main0 main0.cpp ClientTls.o $(LIBTLS).a $(LDFLAGS) $(CXXFLAGS)

main: main.c $(LIBTLS).a
	$(CC) -o main main.c $(LIBTLS).a $(LDFLAGS) $(CFLAGS)

test: clean $(LIBTLS).a test.sh main main0
	./test.sh
