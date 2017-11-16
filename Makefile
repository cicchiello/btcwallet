wallet-recover: bitcoin-wallet-recover.cpp ripemd160.c base58.c
	g++ -I./cryptopp -I./db-4.8.30/build_brew -I. -ggdb -Wall -O2 -o wallet-recover bitcoin-wallet-recover.cpp ripemd160.c base58.c -L./cryptopp -L./db-4.8.30/build_unix -lcryptopp -lcrypto -ldb

brute: brute.cpp ripemd160.c base58.c
	g++ -I./cryptopp -I./db-4.8.30/build_brew -I. -ggdb -Wall -O2 -o brute brute.cpp ripemd160.c base58.c -L./cryptopp -L./db-4.8.30/build_unix -lcryptopp -lcrypto -ldb

brute2: brute2.cpp ripemd160.c base58.c
	g++ -I./cryptopp -I./db-4.8.30/build_brew -I. -ggdb -Wall -O2 -o brute2 brute2.cpp ripemd160.c base58.c -L./cryptopp -L./db-4.8.30/build_unix -lcryptopp -lcrypto -ldb

needle: needle.cpp
	g++ -I./cryptopp -I./db-4.8.30/build_brew -I. -ggdb -Wall -O2 -o needle needle.cpp 
