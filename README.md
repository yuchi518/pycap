# Pycap 
Pycap is a c extension for python, it connects python and libpcap.
Now, python can capture ethernet packets from pcap.

## Version
0.1

## Tech
Pycap uses a number of open source projects to work properly:
* [uthash] - A hash lib in C.

## Installation
You need to install libpcap first. Download it from http://www.tcpdump.org/ and install it in your system.
Pycap tests with libpcap v1.6.2 in Ubuntu 12.04 and 14.04.
Pycap supports Python3.2 later. (Tests in v3.2 and v3.4)

Compile pycap C extension.
```sh
$ gcc -I/usr/include/python3.4 -c pycap.c -o pycap.o
$ gcc -shared pycap.o -L/usr/local/lib -o pycap.so -lpcap
```

Or you can install it in your system.
```sh
$ sudo python3 setup.py install
```

## Run
```sh
$ ./cap.py eth0 eth1
```
Now, you capture packets from interface eth0 and eth1 and save in files (eth0.raw, eth1.raw).
Type 'stop' to stop capturing.


## Todo's
 - not sure

## License
GPLv2

