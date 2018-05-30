PB = $(wildcard *.proto)
CPP = $(PB:.proto=.pb.cc)

all: $(CPP)

%.pb.cc: %.proto
	protoc --cpp_out=. $<

clean:
	rm *.pb.cc