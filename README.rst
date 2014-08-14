uTrack
======

uTrack is a very light weight, fast, multithreaded UDP bittorrent tracker.

features
--------

* UDP announce and scrape
* secure connection ID to prevent IP spoofing
* multithreaded with minimal lock contention
* incremental purging of peers to amortize CPU load
* high packet throughput via libpcap

requirements
------------

utrack requires:

* a C++11 conformant compiler (clang 3.1+ or GCC 4.7 or so)
* BSD sockets
* boost and boost-build

building
--------

run::

	b2

on the command line in the utrack root directory.

Optional build options:

+-------------------+--------------------------------------------------+
| option            | description                                      |
+===================+==================================================+
| pcap=on           | Enable libpcap support. This will improve UDP    |
|                   | performance by circumventing some of the         |
|                   | syscall overhead associated with udp sockets.    |
+-------------------+--------------------------------------------------+
| pcap=win          | Enable libpcap support and use libwinpcap        |
|                   | specific extensions. This speeds up both sending |
|                   | and receiving of packets.                        |
+-------------------+--------------------------------------------------+
| pcap=receive-only | Enable libpcap only for receiving packets, use   |
|                   | regular sockets for sending replies.             |
+-------------------+--------------------------------------------------+
| stage             | copy the resulting utrack binary to the root dir |
+-------------------+--------------------------------------------------+
| stage-test        | copy the resulting udp_test binary to the root   |
|                   | directory. (The test requires libpcap)           |
+-------------------+--------------------------------------------------+

