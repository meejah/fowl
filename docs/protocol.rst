
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

Any structured messages on channels use `msgpack`_ for encoding.
Every message starts with 2 bytes indicating its length.
Then follow that many bytes constituting a complete `msgpack`_ message.

An exception to the above is for subchannels: once they switch to "forwarding mode", raw stream bytes are forwarded (not `msgpack`_ messages).

Remember that Dilation subchannels are actually _record_ pipes -- they are sending authenticated, encrypted, length-delimited messages.


Kinds of Subchannels
--------------------

There are two kinds of subchannel protocols that fowl speaks:

- `"fowl"` for setting up a single forwarded-stream;
- `"fowl-commands"` for request/response commands


Requests to the Other Peer
--------------------------

We speak the `"fowl-commands"` subprotocol to ask our peer to take action.
All requests decode to a ``dict`` and will have at least a ``kind`` key.
This is a simple request/response flow: for each request made, a single response is received.
Each request is answered in order.
You can make multiple requests "at the same time" by opening multiple ``"fowl-commands"`` subchannels.


``"kind": "request-listener"``
`````````````````````````````

An incoming message of this kind instructs us to open a local listener.
Upon any connection to this listener, we open a "forwarding subchannel" (see next section).

The message comes with some data::

    {
        "kind": "request-listener",
        "unique-name": "<arbitrary string>",
        "listen-port": null,
    }

This requests a service with some given name be started.
The "daemon-style" software is thus running on the *other* peer.
If the value of ``"listen-port"`` is not ``null`` then it indicates what port we must listen on -- if this is not possible, it's an error.

By default the value of this is ``null`` and in that situation we choose a random port.
This port is not given to the other peer, as they have no reason to know what port we used.
(One case where ``"listen-port"`` is required is for Web things, which need the very same port on both sides)

Replies look like::

    {
        "kind": "listener-response",
        "unique-name": "<arbitrary string>",
        "listening": True,
        "desired-port": null
    }

The ``"listening"`` boolean indicates if the request succeeded or not.
The ``"desired-port"`` value mirrors what was requested via ``"listen-port"`` (either ``null`` or a number).

For "negative" responses, a reason may be included::

    {
        "kind": "listener-response",
        "unique-name": "<arbitrary string>",
        "listening": False,
        "reason": "Against local policy"
    }

Upon every connection to this local port (assuming a listener is established), we will open a "forwarding subchannel" to the other side (see next section).


.. _forwarding-subchannel:

Forwarding Subchannel
---------------------

A forwarding subchannel is opened whenever a new connection to a listener is made.
There is a brief handshake, and then the connection merely forwards bytes as they are received (from either end).

The handshake consists of the initiating side sending a single length-prefixed `msgpack`_ messsage (the length is an unsigned short, two bytes).
The handshake message decodes to a ``dict`` consisting of::

    {
        "unique-name": "<arbitrary-string>"
    }

This tells the side where to connect.
That is because each ``"remote"`` must be paired with a ``"local"`` -- that is, if the first peer does a ``"remote"`` with ``"unique-name": "foo"`` then the other peer must do a ``"local"`` command with ``"unique-name": "foo"`` before the "foo" service is ready.

It doesn't matter which peer does the ``"remote"`` or the ``"local"`` but there must be exactly one of each for any given service to appear.

Once the connection succeeds or fails a reply message is sent back.
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
