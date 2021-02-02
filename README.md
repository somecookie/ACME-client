# ACME project

This repository contains the code for the project 1 of the course [Network Security](https://netsec.ethz.ch/courses/netsec-2020/) at ETH Zurich. The goal of the project is to provide an [Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555) client. It is not in the scope of the project to implement an ACME server. You can use [Pebble](https://github.com/letsencrypt/pebble) for this purpose. This repository also provides a DNS server which is used to resolves the DNS queries of the ACME server.

## ACME server

You can use Pebble as a basic ACME server. We provide a test root certificate at `pebble/certs/pebble.minica.pem` and a config file at `pebble/config/pebble-config.json`.

### Generate your own root certificate

First install [minica](https://github.com/jsha/minica#installation). Then run the command

```bash
minica -ca-cert pebble.minica.pem \
       -ca-key pebble.minica.key.pem \
       -domains localhost,pebble \
       -ip-addresses 0.0.0.0
```

### Run the ACME server

You can run the ACME server using the provided configuration file from the root of the project with the following command:

```bash
pebble -config pebble/config/pebble-config.json -dnsserver 127.0.0.1:10053
```

Notice that this command works only if a DNS server is running at 127.0.0.1 on port 10053. You can replace this address by any other desired DNS server.
By default `pebble` is configured to discard 5% of the valid nonces. You can avoid this behaviour using the environment variable `PEBBLE_WFE_NONCEREJECT`. 
To never reject a valid nonce as invalid run:

```bash
PEBBLE_WFE_NONCEREJECT=0 pebble -config pebble/config/pebble-config.json -dnsserver 127.0.0.1:10053
```

## ACME Client

The ACME client is the core of this project. It is implemented in [Golang](https://golang.org/) (>=1.14). 

### Components

- ACME client: An ACME client which can interact with a standard-conforming ACME server.
- DNS server: A DNS server which resolves the DNS queries of the ACME server. The DNS server runs on UDP port `10053`.
- Challenge HTTP server: An HTTP server to respond to `http-01` queries of the ACME server. This server runs on TCP port `5002`. 
- Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client. This server runs on TCP port `5001`.
- Shutdown HTTP server:  An HTTP server to receive a shutdown signal. This server runs on TCP port `5003`.

### Dependencies

In addition to Go, you should install the following libraries:

#### Go-flags
[Go-flags](https://github.com/jessevdk/go-flags) rovides an extensive command line option parser.
```bash
go get github.com/jessevdk/go-flags
```
#### Logrus
[Logrus](https://github.com/sirupsen/logrus) provides advanced logging functionalities.
```bash
go get github.com/sirupsen/logrus
```
#### DNS
[Dns](https://github.com/miekg/dns) is a Complete and usable DNS library.
```bash
go get github.com/miekg/dns
```

### Functionalities

This repository contains all the building blocks to implement a basic ACME client that has the following functionalities:

- use ACME to request and obtain certificates using the dns-01 and http-01 challenge (with fresh keys in every run)
- request and obtain certificates which contain aliases
- request and obtain certificates with wildcard domain names
- revoke certificates after they have been issued by the ACME server

### Command-line interface

A CLI is also provided. You need first to compile the main from the root:

```bash
go build main.go
```

The CLI has the following options:

```bash
Usage:
  main [OPTIONS]

Application Options:
      --cmd=[dns01|http01] Indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dnsServer-01 and http-01 challenges, respectively.
      --dir=               Directory URL of the ACME server
      --record=            IPv4 address which must be returned by your DNS server for all A-record queries
      --domain=            Domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard
                           domains have no special flag and are simply denoted by, e.g., *.example.net.
      --revoke             If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set
                           it up to use the newly obtained certificate.
      --cert=              Path to the certificate of the CA

Help Options:
  -h, --help               Show this help message
```

### Example

You can run the following command to obtain a certificate for `test.example.com` and `example.com` with the IP address
`127.0.0.1` (which will also be the DNS server's address) using the directory of the pebble server at
`https://0.0.0.0:14000/dir`. You obtain the certificate by solving the `http-01` challenges.
The pebble server issues the certificates using its private key corresponding to its certificate located at
`https://0.0.0.0:14000/dir`.

```bash
./main --cmd http01 --dir https://0.0.0.0:14000/dir --record 127.0.0.1 --domain test.example.com --domain example.com  --cert pebble/certs/pebble.minica.pem 
```


