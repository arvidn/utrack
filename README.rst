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

utracker requires:

* a C++11 conformant compiler (clang 3.1+ or GCC 4.7 or so)
* BSD sockets

