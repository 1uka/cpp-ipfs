build:
	clang++ -std=c++17 -I . -c libmulti/hash.cpp -o obj/hash.o
	clang++ -std=c++17 -I . -c libmulti/base.cpp -o obj/base.o
	clang++ -std=c++17 -lcryptopp -I . -o main main.cpp obj/*.o