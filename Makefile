build:
	clang++ -std=c++17 -I . -c common/varint.cpp -o obj/varint.o
	clang++ -std=c++17 -I . -c libmulti/hash.cpp -o obj/hash.o
	clang++ -std=c++17 -I . -c libmulti/base.cpp -o obj/base.o
	clang++ -std=c++17 -I . -c libmulti/addr.cpp -o obj/addr.o
	clang++ -std=c++17 -lcryptopp -lboost_system -I . -o main main.cpp obj/*.o