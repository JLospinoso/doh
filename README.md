![doh](img/doh.png)

[![CircleCI](https://circleci.com/gh/JLospinoso/doh.svg?style=svg)](https://circleci.com/gh/JLospinoso/doh)

[![Docker Automated build](https://img.shields.io/docker/automated/jlospinoso/doh.svg)](https://hub.docker.com/r/jlospinoso/doh/)

[![Docker Repository on Quay](https://quay.io/repository/jlospinoso/doh/status "Docker Repository on Quay")](https://quay.io/repository/jlospinoso/doh)

Usage: 

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