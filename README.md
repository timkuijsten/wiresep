# WireSep

## A privilege separated implementation of WireGuard for OpenBSD

Status: **alpha**

Features:
* Privilege separation, long-term secrets in a separate process
* Short-term secrets separated per tunnel interface
* Fork/re-exec for a different memory layout between different networks
* Tight [pledge(2)] and no file system access
* Easy to read and write config file format for humans, easy to parse for
  machines (small attack surface)
* Uses connected sockets for performance and reliability

TODO:
* Improve most searches from linear to logarithmic
* Improve performance of session start and throughput
* Better support multi-homed systems (currently have to manually change
  the routing table if another source address was chosen by the kernel)
* WireGuard Cookie support
* Support hostname.if(5): Resolve NAT issues when using hostname.if(5) to bring
  up the tunnel interface
* Investigate weird issue where packets for an older ip are received on a
  reconnected socket (kernel related)

## Requirements

* OpenBSD 6.4 or higher

## Testing

Compile and run WireSep:

```sh
$ git clone https://github.com/timkuijsten/wiresep.git
$ cd wiresep
$ make
$ doas make install
```

Generate new keys with [wiresep-keygen(1)] and create a [wiresep.conf(5)] file.
Once everyting is set, run [wiresep(8)]:

```sh
$ doas wiresep -dvv
```

## Documentation

Please refer to the manuals for documentation and a configuration example:
* [wiresep-keygen(1)]
* [wiresep.conf(5)]
* [wiresep(8)]

## Threat model

Guard against compromised long-term secrets like the private key of an interface
or a pre-sharedkey with a peer. This is realized by using a separate [trusted
process](enclave.c) that is easy to audit and has the sole purpose of creating
handshake initiation and response messages. All session management and transport
data is handled by a different process. Communication with other processes is
handled with a simple IPC-protocol (see [Design](#design)).

## Design

There are three main types of processes. A *proxy* process, an *enclave*, and
one or more *ifn* processes (one per tunnel interface). On startup a master
process parses the configuration, sets up a socketpair(2) between each process
for IPC and forks and re-execs the enclave, the proxy, and one ifn process per
configured interface.

![processdesign]

Message index:
* **WGINIT**	WireGuard Handshake Initiation Message
* **WGRESP**	WireGuard Handshake Response Message
* **WGCOOKIE**	WireGuard Cookie Reply Message
* **WGDATA**	WireGuard Transport Data Message
* **CONNREQ**	Connect request, to reconnect a socket
* **SESSID**	New session session id
* **SESSKEYS**	New session keys, contains the sender and receiver transport keys
* **REQWGINIT**	Request a new handshake initiation message
* **α**	Message contains an interface id, and source and destination socket address
* **β**	Message contains an internal peer id

### Communication protocol

Communication between all processes is done over a socketpair(2) using a small
set of message types. All messages, except the *WGDATA* message consist of
fixed-size structures.

### Proxy process

The proxy listens for incoming packets on an unconnected socket and forwards
messages from the Internet to the appropriate enclave or ifn process. If the
enclave or ifn are busy, it responds to the Internet with a Wireguard cookie
reply message. It never has any short- or long-term secrets. Each ifn process
will send new session ids to the proxy so that it can easily discard any
transport data or handshake response packets with invalid session ids,
mitigating a DoS attack. All internal messages from this process contain a
source and destination address so that an ifn process can create a connected
socket, bypassing the proxy for authenticated sessions.
[proxy.c](proxy.c)

### Enclave process

The enclave takes care of all handshake messages and contains all long-term
secrets (one private key per interface and possibly a pre-sharedkey per peer).
It uses a token bucket filter to service the proxy and each ifn equally without
one overloading the others. All messages between the enclave and the ifn contain
an internal peer id. All messages from the proxy, once authenticated, result in
a connection request to the corresponding ifn to make sure the socket can get
connected.
[enclave.c](enclave.c)

### Ifn process

This process is responsible for one tunnel interface and tracks all sessions of
the peers on that interface. As soon as a session expires it requests the
enclave to create a new handshake initiation message. It handles the bulk of the
network traffic and contains only short-term secrets, namely the symmetric
ephemeral transport keys. Each peer has it's own connected socket and contains
all sessions and session timers. When a peer roams it's packets first go through
the unconnected socket of the proxy process, which then forwards the transport
data to the ifn so that the ifn can reconnect the socket of the appropriate peer
(but only if the data can be authenticated). All messages between the enclave
and an ifn process contain an internal peer id.
[ifn.c](ifn.c)

### Simple config file format

A new small parser was written using yacc(1) to support a config file that is
easy to read and write by humans and to reduce attack surface and maintenance by
keeping dependencies to a minimum. Existing config file formats like TOML, YAML,
INI, JSON, JSON5 and Human JSON are not optimal, either in writing the actual
config files or in writing a parser that supports the syntax while keeping
dependencies small and not overly complex.

## License

ISC

Copyright (c) 2018, 2019 Tim Kuijsten

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

---

[processdesign]: https://netsend.nl/wiresep/processdesign.svg?v0.5
[pledge(2)]: http://man.openbsd.org/pledge
[wiresep-keygen(1)]: https://netsend.nl/wiresep/wiresep-keygen.1.html
[wiresep.conf(5)]: https://netsend.nl/wiresep/wiresep.conf.5.html
[wiresep(8)]: https://netsend.nl/wiresep/wiresep.8.html
