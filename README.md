# WireSep

## A privilege separated implementation of WireGuard for OpenBSD

Features:
* Privilege separation, long-term secrets in a separate process
* Short-term secrets separated per tunnel interface
* Fork/re-exec for a different memory layout between different networks
* Tight [pledge(2)] and no file system access after startup
* Easy to read and write config file format for humans, easy to parse for
  machines (small attack surface)
* Uses connected sockets for performance and reliability

Status: **beta**

## Requirements

* OpenBSD 6.4 or higher

## Install and run

```sh
$ git clone https://github.com/timkuijsten/wiresep.git
$ cd wiresep
$ make
$ doas make install
```

Generate new keys with [wiresep-keygen(1)] and create a [wiresep.conf(5)] file.
A sample config can be found in
`/usr/local/share/examples/wiresep/[wiresep.conf.example](wiresep.conf.example)`.
Once everyting is set, run [wiresep(8)]:

```sh
$ doas wiresep
```

## Documentation

Refer to the manuals for documentation and a configuration example:
* [wiresep-keygen(1)]
* [wiresep.conf(5)]
* [wiresep(8)]

The design documents can be found in the [doc](doc/) directory.

## Todo

* Better support multi-homed systems (currently have to manually change
  the routing table if another source address was chosen by the kernel)
* WireGuard Cookie support

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

[pledge(2)]: http://man.openbsd.org/pledge
[wiresep-keygen(1)]: https://netsend.nl/wiresep/wiresep-keygen.1.html
[wiresep.conf(5)]: https://netsend.nl/wiresep/wiresep.conf.5.html
[wiresep(8)]: https://netsend.nl/wiresep/wiresep.8.html
