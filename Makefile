CC=clang++

CFLAGS=-std=c++17 -g -Iinclude/
LIBS=-lcryptopp -lboost_system -lboost_fiber-mt -lprotobuf
IOSFLAGS=-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -I/usr/local/Cellar/boost/1.67.0_1/include -I/usr/local/Cellar/cryptopp/7.0.0/include

SOURCES = $(shell find src -type f -name '*.cpp' -exec cut -d' ' -f2- {} \;)
OBJECTS = $(SOURCES:.cpp=.o)
EXEC = ipfs

OBJ = $(patsubst %, $(ODIR)/%, $(OBJECTS))

all: build

%.o: $(SOURCES)
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

build: $(OBJECTS)
	$(CC) $(CFLAGS) $(LIBS) -o $(EXEC) $(OBJECTS)

clean:
	rm -rf $(EXEC) $(OBJECTS)
