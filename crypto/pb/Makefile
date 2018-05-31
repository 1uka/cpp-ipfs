PB = $(wildcard *.proto)
CPP = $(PB:.proto=.pb.cc)

CFLAGS=-std=c++17 -g -I.

all: $(CPP)

%.pb.cc: %.proto
	protoc --cpp_out=. $<

clean:
	rm *.pb.cc

build:
	clang++ -c -o ../../obj/crypto.pb.o crypto.pb.cc $(CFLAGS)