wallet-recover: bitcoin-wallet-recover.cpp
	g++ -I./cryptopp -I./db-4.8.30/build_brew -I. -ggdb -Wall -O2 -o wallet-recover bitcoin-wallet-recover.cpp -L./cryptopp -L./db-4.8.30/build_unix -lcryptopp -ldb
