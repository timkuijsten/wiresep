# Session maintenance

This is a rough sketch of all aspects related to session management. It consists
of the following:
* session setup from both the responder and initiator perspective
* packet send and receive path when a valid session exists
* session expiry and destruction

Whenever a new session id is created it must be communicated to the proxy
process so that a roaming peer is recognized from its new ip address.


## Utilities and data structures

There are three main data structures regarding sessions with a peer:
1. Tentative session structure - this is used during session setup in the
   initiator scenario.
2. Next session structure - this is used during session setup in the responder
   scenario.
3. Established session structure - this is used once a session is successfully
   established for both the current and the previous session.

```
    struct sesstent {
    	enum { INACTIVE, INITREQ, INITSENT, RESPRECVD } state;
    	int64_t id;         temporary session id before enclave has chosen a random session id
    	utime_t lastreq;    the last time we asked the enclave for an initiation packet
    };

    struct sessnext {
    	enum { INACTIVE, GOTKEYS, RESPSENT } state;
    	utime_t lastvrfyinit; moment the last verified initiation packet was received
    	utime_t start;      moment the initiation packet was received from the peer
    	int64_t id;         session id of us
    	int64_t peerid;     session id of peer
    	sendctx;            send key
    	recvctx;            receive key
    };

    struct session {
    	antireplay arrecv;  receive counter bitmap
    	sendctx;            send key
    	recvctx;            receive key
    	struct peer *peer;  associated peer
    	utime_t start;      moment the handshake completed
    	utime_t expack;     time before either data or a keepalive is expected from the peer
    	uint64_t nextnonce; next number for the next packet to send
    	uint32_t id;        our session id
    	uint32_t peerid;    session id of the peer
    	char initiator;     are we the responder or initiator?
    	char kaset;         is the keepalive timer set?
    };

    sessactive(sess) {
    	if (now - sess.start >= Reject-After-Time) ||
    	    sess.nonce >= Reject-After-Messages ||
    	    (sess.expack && sess.expack < now)
    		return false
    	else
    		return true
    }

    sesstentclear() {
    	sesstent.state = INACTIVE
    	sesstent.id = -1
    	clearRekeyTimeout(sesstent)
    	sesstent.lastreq = 0
    }

    sessnextclear() {
    	sessnext.state = INACTIVE
    	sessnext.id = -1
    	sessnext.start = 0
    }

    // Request a handshake init packet from the enclave, that can then be sent
    // to the peer. Schedule a timeout to detect when the enclave doesn't
    // responde.
    sendreqhsinit() {
    	sesstent.state = INITREQ
    	request a handshake initiation packet from the enclave
    	setRekeyTimeout(sesstent, Rekey-Timeout);  5 seconds
    }

    // Ensure a handshake is in progress. If we didn't request a handshake init
    // packet from the enclave yet, request one.
    ensurehs() {
    	if sesstent.state == INACTIVE
    		sendreqhsinit()

    	sesstent.lastreq = now
    }
```


## Session initiator scenario

This is the scenario where we have data for a peer, but no active session with
the peer. This happens at startup and after previously established sessions
become invalid either because of the three-minute timeout, or because the number
of packets exceeds 2^64 − 2^4 − 1 messages. While session setup is in progress a
rekey timer will be set until rekey-attempt-time or a session is established.

0. Handle data from tunnel interface while both the current session and the
tentative session are INACTIVE.

The packet is queued and then a WireGuard initiation packet is requested from
the enclave and sent to the peer.

```
    if !sessactive(sesscurr)
    	queue packet
    	ensurehs()
```

1. Handle the event that a WireGuard initiation packet is received from the
enclave.

```
    if sesstent.state == INITREQ
    	clearRekeyTimeout(sesstent);
    	setRekeyTimeout(sesstent, Rekey-Timeout);  5 seconds
    	sesstent.id = wginit.sender
    	forward packet to peer
    	sesstent.state = INITSENT
    	notifyproxy(sesstent.id, isTent)
    else
    	drop  // too late
```

2. Once an initiation packet is sent to the peer, a WireGuard response should be
received from the peer. Send this response to the enclave for verification.

```
    if (sesstent.state == (INITSENT || RESPRECVD) &&
             sesstent.id == wgresp.receiver) {
    	forward untrusted packet to enclave
    	sesstent.state = RESPRECVD
    } else
    	drop  // too late
```

3. Handle new session keys - if the WireGuard response packet was valid, new
session keys will be received from the enclave and a new current session is
established.

```
    if sesstent.state == RESPRECVD && sesstent.id == msgkeys.sessid
    	sessprev = sesscurr
    	sesscurr = sesstent
    	sesscurr.start = now
    	sesstentclear()
    	notifyproxy(sesscurr.id, isCurr)
    	start sending data
    else
    	drop  // too late
```


## Session responder scenario

Used when a peer started negotiating a new session.

1. Handle WireGuard initiation packet from a peer.

```
    if now - sessnext.lastvrfyinit >= Rekey-Timeout
    	forward untrusted packet to enclave with current timestamp
    } else
    	drop  // too fast
```

2. Handle new session keys from enclave. The initiation packet from the peer was
valid.

```
    if sessnext.state != INACTIVE && sessnext.state != RESPSENT
    	unexpected error

    sessnext.id = msg.sessid
    sessnext.peerid = msg.peersessid
    sessnext.lastvrfyinit = msg.ifnts
    sessnext.keys = msg.keys
    sessnext.state = GOTKEYS
    notifyproxy(sessnext.id, isNext)
```

3. Handle WireGuard responder message from the enclave and send this to the peer.

```
    if sessnext.state != GOTKEYS || sessnext.peerid != wgresp.receiver
    	unexpected error

    forward packet to the peer
    sessnext.start = now
    sessnext.state = RESPSENT
```

4. Handle the first data message from the peer. Only after receiving this
message we are sure the peer is currently in the possession of its private key
so only now we can start sending data using this session.

```
    if sessnext.state != RESPSENT || sessnext.id != wgdata.receiver
    	unexpected error

    if (now - sess.start >= Reject-After-Time)
    	sessnextclear()
    	notifyproxy(sessnext.id, isDead)
    	return false

    if (authenticates(wgdata))
    	sessprev = sesscurr
    	sesscurr.id = sessnext.id
    	sesscurr.peer = peer
    	sesscurr.start = sessnext.start
    	sesscurr.expack = 0
    	sesscurr.nonce = 0
    	sessnextclear()
    	notifyproxy(sesscurr.id, isCurr)
    	forward data to tunnel device
    else
    	drop  // invalid
```


## Data send path

Packet from the tun interface to the Internet while the current session is
active.

```
    if (sessactive(sesscurr)) {
    	send packet to the peer
    	sesscurr.nonce++
    	sesscurr.keepalive-timer = 0
    	if (!sesscurr.expack)
    		sesscurr.expack = now + Keepalive-Timeout + Rekey-Timeout

    	// handle rekey-after-*
    	if (sesscurr.initiator && now - sesscurr.start >= Rekey-After-Time)
    		ensurehs()
    	else if (sesscurr.nonce >= Rekey-After-Messages)
    		ensurehs()
    } else {
    	ensurehs()
    	queue packet
    }
```

## Data receive path

Packet from the Internet to the tun interface while the session is active
(must be either the current or the previous session).

```
    if (!sessactive(sess))
    	drop
    else if (!antireplay)
    	drop
    else
    	sess.expack = 0

    // forward if not a keepalive packet
    if (datasize > 0) {
    	forward packet to tunnel device

    	// schedule keepalive timeout if not already set and
    	// not near the end of this session.
    	if (notset(keepalive-timer) && now - sess.start <
    	    Reject-After-Time - Keepalive-Timeout &&
    	    sess.nonce < Reject-After-Messages)
    		set(sess.keepalive-timer)

	// start negotiating a new session after two minutes when we still have
	// a minute before the session becomes inactive.
    	if (sess.initiator && sess == currsess &&
    	    now - sess.start >= Reject-After-Time -
    	    Keepalive-Timeout - Rekey-Timeout)
    		ensurehs()
    }
```


## Rekey and keepalive timers

### Keepalive timer expires

This happens after we received data from a peer, but had nothing to send back
within 10 seconds.

```
    send a keepalive packet to the peer
```

### Rekey timer expires

This can happen while trying to establish a new session as an initiator when
either the enclave or the peer does not respond within Rekey-Timeout, which is
five seconds.

```
    notifyproxy(sesstent, isDead);
    if now - sesstent.lastreq <= Rekey-Attempt-Time
    	sendreqhsinit()
    else
    	sesstentclear()
```
