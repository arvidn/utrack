CXX=g++

utrack: main.cpp
	$(CXX) -o utrack main.cpp -lcrypto

