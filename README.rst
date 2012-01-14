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

* GCC 4.2 or newer. Specifically the atomic intrinsic operations ``__sync_fetch_and_sub`` et.al. as well as the ``<ext/hash_map>`` extension header.
* pthreads
* openssl (libcrypto)
* BSD sockets

