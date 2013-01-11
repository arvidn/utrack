uTrack
======

uTrack is a very light weight, fast, multithreaded UDP bittorrent tracker for unixes.

features
--------

* UDP announce and scrape
* secure connection ID to prevent IP spoofing
* multithreaded with minimal lock contention
* incremental purging of peers to even out load

requirements
------------

utracker requires:

* a C++11 conformant compiler (clang 3.1+ or GCC 4.7 or so)
* pthreads (for read-write lock)
* openssl (libcrypto)
* BSD sockets

