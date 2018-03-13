![doh](img/doh.png)

[![CircleCI](https://circleci.com/gh/JLospinoso/doh.svg?style=svg)](https://circleci.com/gh/JLospinoso/doh)

[![Docker Automated build](https://img.shields.io/docker/automated/jlospinoso/doh.svg)](https://hub.docker.com/r/jlospinoso/doh/)

[![Docker Repository on Quay](https://quay.io/repository/jlospinoso/doh/status "Docker Repository on Quay")](https://quay.io/repository/jlospinoso/doh)

*doh* is a SOCKS5 proxy server with several privacy features:

* All DNS queries go through [Google's DNS-over-HTTP Service](https://developers.google.com/speed/public-dns/docs/dns-over-https).

* Respects *block lists*. You fill a directory with domains you want to block, and *doh* will deny all DNS queries to the block list. (Okay so not *all* DNS queries go through Google's DOH service, because we have to *find* the DOH service.)

*  *doh* supports fixed DNS mappings. For example, we can map `dns.google.com` to `172.217.9.206`. This solves the problem of having to make a DNS request to find Google's DOH service, as well as providing you greater control over where your traffic is going if you need it.

* *doh* can (optionally) block all non-port-443 (TLS) traffic.

Typically, DNS requests are the weak link in the network-traffic-privacy chain. With *doh*, you can send *all* traffic over TLS, which means greater security for you.

# Usage

```
> doh.exe --help
Usage: doh [address] [port]:
  --address arg (=127.0.0.1)     address (e.g. 0.0.0.0)
  --port arg (=1080)             port (e.g.1080)
  -b [ --blockdir ] arg (=block) directory containing blocked domains
  -h [ --hostdir ] arg (=host)   directory containing hard-coded hosts
  -t [ --tls_only ]              force TLS only
  -d [ --dnsssec ]               force DNSSEC
  -u [ --user ] arg              username for authentication
  -p [ --password ] arg          password for authentication
  --threads arg (=2)             number of threads
  --help                         produce help message
```

# Quickstart with Docker

If you have Docker installed, running *doh* is easy:

```
> docker run -p 1080:1080 quay.io/jlospinoso/doh --address 0.0.0.0
```

# Testing *doh*

Open Firefox, then:

* Navigate to *Options*
* Scroll all the way down to *Network Proxy*
* Click *Settings*
* In the *Connection Settings*, select *Manual proxy configuration*.
* Set *SOCKS Host* to the address that *doh* is running on. For Docker on Windows, for example, the address might be 10.0.75.1. On *nix, it might be 192.168.200.1. If you're running *doh* locally, use 127.0.0.1
* Set the port to the port that *doh* is bound to. By default, it's 1080.
* Select *SOCKS v5*
* Check *Proxy DNS when using SOCKS v5*
* Click OK

Now, you can use Firefox to browse the web without exposing observable DNS requests.

# Building *doh* on Windows

Prerequisites:

* [Visual Studio 15 2017+](https://www.visualstudio.com/vs/whatsnew/)
* [CMake v3.11+](https://cmake.org/download/)
* [Boost v1.66+](http://www.boost.org/users/download/)
* [OpenSSL v1.1.0g+](https://slproweb.com/products/Win32OpenSSL.html)

```
git clone git@github.com:JLospinoso/doh
cd doh
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017"
```

Now, open `doh.sln` in the `doh/build` folder. You can build from here.

# Building *doh* on Linux

Prerequisites:

* [GCC 7.3+](https://gcc.gnu.org/gcc-7/)
* [CMake v3.11+](https://cmake.org/download/)
* [Boost v1.66+](http://www.boost.org/users/download/)
* [OpenSSL v1.1.0g+](https://www.openssl.org/)

```
git clone git@github.com:JLospinoso/doh
cd doh
mkdir build
cd build
cmake ..
make
```

# Building *doh on Docker

Prerequisites:

* [Docker](https://www.docker.com/)

```
git clone git@github.com:JLospinoso/doh
cd doh
docker build -t jlospinoso/doh:latest .
```
