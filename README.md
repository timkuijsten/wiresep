# WireSep

## Privilege separated implementation of WireGuard for OpenBSD

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

## Install

```sh
$ doas pkg_add wiresep
```

Generate a new private key for the `tun0` interface.
```sh
$ doas wiresep-keygen tun0
```

Then create a configuration and store it in */etc/wiresep/wiresep.conf*. A
simple example looks like the following:

```
# This is an example of a server listening on the public ip 198.51.100.7 port
# 1022. It uses the tun0 device with the internal ip addresses 2001:db8::7
# and 172.16.0.1 and allows communication with the peer Jane and Joe. Jane is
# allowed to use any source ip, while Joe may only use 2001:db8::4 or
# 172.16.0.11/30 as the source ip of his packets. The private key for the tun0
# interface can be generated with `wiresep-keygen tun0`.

interface tun0 {
	ifaddr 2001:db8::7/126
	ifaddr 172.16.0.1/24

	listen 198.51.100.7:1022

	peer jane {
		pubkey BhyBpDfD7joIPPpjBW/g/Wdhiu3iVOzQhKodbsLqJ3A=
		allowedips *
	}

	peer joe {
		pubkey AhyBpDfD7joIPPpjBW/g/Wdhiu3iVOzQhKodbsLqJ3A=
		allowedips 2001:db8::4
		allowedips 172.16.0.11/30
	}
}
```
See [wiresep.conf(5)] for a complete description of the configuration file.

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

* WireGuard Cookie support

## Known issues

* Interface aliases are not supported for outbound connections. In order to
  properly support local address selection without having to rely on an
  unpledged superuser process a new system call that would combine bind(2) and
  connect(2) would be required.

## License

ISC

Copyright (c) 2018, 2019, 2020 Tim Kuijsten

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
