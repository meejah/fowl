
.. _dilation-protocol:

Dilation Application Protocol
=============================

Once a "Dilated Magic Wormhole" has been established, we have:

- a connection to our peer;
- a "control" subchannel;
- the ability to open more subchannels;

All subchannels are in-order, reliable and durable streams.
"Durable" and "reliable" here means that the underlying Dilation code does the hard work of re-connecting to the peer -- we don't have to worry about acknowledgements, re-connection, re-trying, etc.

Thus it can sometimes take more time than expected for bytes to be delivered (for example, if some re-connecting is going on behind the scenes).


General Message Format
----------------------

All messages on the control or any other channel use `msgpack`_ for encoding.
Every message starts with 2 bytes indicating its length.
Then follow that many bytes constituting a complete `msgpack`_ message.


Control Subchannel
------------------

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
    }

This says that we should open a local listener on ``"listen-endpoint"`` -- which is to say on ``"tcp:1234:interface=localhost"``, which is a Twisted server-style endpoint string (so can be passed to ``serverFromString()``).

Upon every connection to this local port, we will open a "forwarding subchannel" to the other side (see next section); ``"connect-endpoint"`` is used here.

So in this case, for every local connection on port 1234 a subchannel is opened to the other side, and an opening message asking to connect to ``"tcp:localhost:4444"`` is sent.
This string is a Twisted *client*-style endpoint string (so ``clientFromString()`` can parse it).
The other side sends a reply when they've connected (or failed).
After this, the connection switches to simply forward all received bytes back for forth.

Notice in this example the ports are different!
That's okay, but it will be more common to use the very same port.

This is **especially important for Web applications** which often fail if the ports don't line up (because browsers consider the port part of the Origin).

Because we use Twisted endpoint strings, many protocols are possible on either side: unix-sockets, tor network connections, or anything that supports the interfaces.

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
There is a brief handshake, and then the connection merely forward bytes as they are received (from either end).

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


.. _msgpack: https://msgpack.org
