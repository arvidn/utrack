uTrack
======

uTrack is a very leight weight, fast, multithreaded UDP bittorrent tracker for unixes.

features
--------

* multithreaded with minimal lock contention
* incremental purging of peers to even out load

requirements
------------

utracker requires:

* GCC. Specifically the atomic intrinsic operations ``__sync_fetch_and_sub`` et.al. as well as the ``<ext/hash_map>`` extension header.
* pthreads
* openssl (libcrypto)
* BSD sockets

