
.. _dilation-protocol:

Audience: developers of fowl.

This describes a low-level protocol used by fowl itself; users will never see this.


Dilation Application Protocol
=============================

Once a "Dilated Magic Wormhole" has been established, we have:

- a connection to our peer;
- a "control" subchannel;
- the ability to open more subchannels;

All subchannels are in-order, reliable and durable message-pipes.
"Durable" and "reliable" here means that the underlying Dilation code does the hard work of re-connecting to the peer -- we don't have to worry about acknowledgements, re-connection, re-trying, etc.

Thus it can sometimes take more time than expected for bytes to be delivered (for example, if some re-connecting is going on behind the scenes).


Overall Philosophy
------------------

The program `fowld` is providing a way for a control program (possibly the `fowl` CLI or TUI, or a third-party GUI) to open and forward streams.
Thus when we say "user" in this document, we mean that control program.
Messaging to human users will be via the control program (i.e. they won't see the JSON messages described here directly, usually).

We want this to be as easy as possible, but also to mimic the "real" Dilation experience -- for many use-cases, `fowl` may be a "stepping stone" to using a language-specific implementation of Dilation (if / when non-Python ones arrive).


General Message Format
----------------------

All structured messages on the control or any other channel use `msgpack`_ for encoding.
Every message starts with 2 bytes indicating its length.
Then follow that many bytes constituting a complete `msgpack`_ message.

An exception to the above is for subchannels: once they switch to "forwarding mode", raw stream bytes are forwarded (not `msgpack`_ messages).

Remember that Dilation subchannels are actually _record_ pipes -- they are sending authenticated, encrypted, length-delimited messages.


Control Subchannel
------------------

XXX: I think we maybe want "reply-id's" on the requests, and one reply (eventually) per request.

-> opening a listener can take arbitrary time (e.g. consider an
 "onion" listener that launches tor), and can fail for a number of
 reasons
-> the sending side would like to know if the listen failed, or succeeded
-> one use-case is tests (currently it looks for a "listening" signal
 from the other side, we could add a "rejected" message too, but an
 explicit req/reply might better ... even if we have a user visible "rejected
 listen" message _as well))

We use the control subchannel to send requests to the other peer.

So, when we're asked to open a listener on the far end, we send a message over the control channel.
All control messages decode to a ``dict`` and will have at least a ``kind`` key.

``"kind": "remote-to-local"``
`````````````````````````````

An incoming message of this kind instructs us to open a local listener.
Upon any connection to this listener, we open a "forwarding subchannel" (see next section).

The message comes with some data::

    {
        "kind": "remote-to-local",
        "listen-endpoint": "tcp:1234:interface=localhost",
        "connect-endpoint": "tcp:localhost:4444",
        "reply-id": 9381
    }

This says that we should open a local listener on ``"listen-endpoint"`` -- which is to say on ``"tcp:1234:interface=localhost"``, which is a Twisted server-style endpoint string (so can be passed to ``serverFromString()``).

The ``"reply-id"`` must be a unique identifier for this message; it may be "retired" once a reply has been sent over the control channel.
There will be exactly one reply; a positive one if we have successfully listened or a negative on if that failed.
Setting up a listener may take arbitrary time (consider a Tor "Onion service" listener thay may need to launch Tor, etc).
Software on the other end may ask its human to allow/deny connections -- humans may take considerable time to answer.
Failures may be due to policy (e.g. the other peer refuses to listen on an interface or port) or technical errors (port already in use, as but one example).

The reply-id may be any number between 1 and 2^53 - 1 (to support JavaScript implementations).
We recommend simply starting at 1 and incrementing for each request.

Replies look like::

    {
        "kind": "listener-response",
        "reply-id": 9381,
        "listening": True
    }

The `"reply-id"` MUST match a previously-received outstanding request.
Only a single response may ever be made for a particular `"reply-id"`.
The `"listening"` boolean indicates if the request succeeded or not.

XXX: consider adding a "reason" field to indicate why a listen failed.


Upon every connection to this local port (assuming a listener is established), we will open a "forwarding subchannel" to the other side (see next section); ``"connect-endpoint"`` is used here.

So in this case, for every local connection on port 1234 a subchannel is opened to the other side, and an initial `msgpack`_ message asking to connect to ``"tcp:localhost:4444"`` is sent.
This string is a Twisted *client*-style endpoint string (so ``clientFromString()`` can parse it).
The other side sends a reply when they've connected (or failed).
After this, the connection switches to simply forward all received bytes back for forth.

Notice in this example the ports are different!
That's okay, but it will be more common to use the very same port.

Ports are **especially important for Web applications** which often fail if the ports don't line up (because browsers consider the port part of the Origin).
So if you are forwarding Web (or WebSocket) connections, you'll probably want the same port on both sides.

Because we use Twisted endpoint strings, many protocols are possible on either side: unix-sockets, tor network connections, or anything that supports the appropriate interfaces.

.. WARNING::

   This flexibility can be both good and bad; part of the stdin/out protocol can include a "consent" API allowing controlling applications (ultimately, users) to allow or deny each connection or listener.
   If you do this, **we recommend whitelisting** only known-good kinds of strings for most users.

   In ``fowl`` itself there are command-line options to both widen and further limit the defaults.

.. NOTE::

   Without any options, only localhost TCP connections are allowed.


.. _forwarding-subchannel:

Forwarding Subchannel
---------------------

A forwarding subchannel is opened whenever a new connection to a listener is made.
There is a brief handshake, and then the connection merely forwards bytes as they are received (from either end).

The handshake consists of the initiating side sending a single length-prefixed `msgpack`_ messsage (the length is an unsigned short, two bytes).
The handshake message decodes to a ``dict`` consisting of::

    {
        "local-destination": "tcp:localhost:4444",
    }

This tells the side where to connect.
If it is "okay" to connect to this endpoint (per policy, or the consent API) that is attempted.

Once the connection succeeds or fails (or, fails to pass policy) a reply message is sent back.
The reply message is also an unsigned-short-prefixed `msgpack`_ message which is a ``dict``::

    {
        "connected": True,
    }

If this is ``False`` then an error occurred and the subchannel should be closed.
Otherwise the connection switches to forwarding data back and forth.

XXX: consider adding a "reason" string to the reply?

No bytes shall be forwarded until the reply is received; once the reply is received only forwarded bytes occur on the subchannel (no more structured messages).

Note that there may be multiple subchannels open "at once" so an application may asynchronously open and await the completion of an arbitrary number of connections.


.. _msgpack: https://msgpack.org
