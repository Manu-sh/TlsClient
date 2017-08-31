CC=cc
CXX=g++

CFLAGS=-O3 -march=native -pipe -Wall -Wno-unused-function
CXXFLAGS=-O3 -march=native -pipe -Wall -Wno-unused-function
LDFLAGS=-lssl -lcrypto
LIB_PATH=lib
LIBTLS=libtlscl
AR=ar
RM=rm -vf

.PHONY: clean test

$(LIBTLS).a: $(LIB_PATH)/TlsClient.c $(LIB_PATH)/TlsClient.h $(LIB_PATH)/types.h
	$(CC)  -c $(LIB_PATH)/TlsClient.c $(CFLAGS)
	$(AR) rcs $(LIBTLS).a TlsClient.o

ClientTls.o: ClientTls.cpp ClientTls.hpp
	$(CXX) -c ClientTls.cpp $(LDFLAGS) $(CXXFLAGS)

clean:
	$(RM) *.o *.a *.log main main0

main0: main0.cpp ClientTls.o $(LIBTLS).a
	$(CXX) -o main0 main0.cpp ClientTls.o $(LIBTLS).a $(LDFLAGS) $(CXXFLAGS)

main: main.c $(LIBTLS).a
	$(CC) -o main main.c $(LIBTLS).a $(LDFLAGS) $(CFLAGS)

test: clean $(LIBTLS).a test.sh main main0
	./test.sh
