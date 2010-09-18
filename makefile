CXX=g++

utrack: main.cpp swarm.cpp swarm.hpp messages.hpp hash.hpp
	$(CXX) -o utrack main.cpp swarm.cpp -lcrypto -g

udp_test: test_announce.cpp
	$(CXX) -o udp_test test_announce.cpp -g
