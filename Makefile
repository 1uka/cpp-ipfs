CC=clang++

CFLAGS=-std=c++17 -g -I.
DEPS=-lcryptopp -lboost_system -lboost_fiber-mt -lprotobuf
IOSFLAGS=-isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -I/usr/local/Cellar/boost/1.67.0_1/include -I/usr/local/Cellar/cryptopp/7.0.0/include

ODIR = obj
_OBJ = varint.o hash.o base.o addr.o stream.o key.o rsa.o secp256k1.o ed25519.o crypto.pb.o peer.o peerstore.o
OBJ = $(patsubst %, $(ODIR)/%, $(_OBJ))

$(ODIR)/%.o: libmulti/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: common/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: crypto/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: libp2p/%.cpp
	$(CC) -c -o $@ $< $(CFLAGS)


main: $(OBJ)
	$(CC) -o $@ main.cpp $^ $(CFLAGS) $(DEPS)
	# $(CC) -shared -o libipfs.so main.cpp $^ $(CFLAGS) $(DEPS)