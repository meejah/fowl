
.. messages:

Valid Messages
==============

Every message is valid JSON.
All messages MUST include a ``"message"`` key which indicates what sort of message it is.

We differentiate between "stdin" and "stdout" messages -- that is, things the program tells the user and things the user tells the program.
Here, "user" is often another program.


.. stdin_messages:

Valid ``stdin`` Messages
------------------------


.. stdout_messages:

Valid ``stdout`` Messages
-------------------------


``"message": "code"``
`````````````````````

This message is emitted once per session by the side that starts the interaction.
It is usually the first message.

Keys included:

- ``"code"``: the allocated Wormhole code, like ``42-universe-everything``.


``{"message": "connected"}``
````````````````````````````

This message is emitted to both sides once per session, after the Dilation connection has been successfully set up.
There is no other information in this message.


``{"message": "forward"}``
``````````````````````````

When this message is sent, it instructs the client to ask the *other* side to open a listener.
It also tells the client how to forward connections it gets upon that listener.
These messages look like this::

    {
        "message": "forward",
        "endpoint": "tcp:8000:interface=localhost",
        "local-endpoint": "tcp:localhost:8000"
    }

Since this is basically "the" core feature of ``fow`` lets consider an example:

The partners want to pair-program using ``tty-share``.
So, one side has to set up a ``localhost`` server and the other side has to connect to it.

By default, ``tty-share`` runs on port ``8000``.
So, let's say "our" side decides to run the server.
We then ask the *other* side to open a listener on ``tcp:8000:interface=localhost`` (these are Twisted "endpoint strings", discussed later) which forwards connections to us, on ``tcp:localhost:8000``.

(In this particular case, being an HTTP protocol, the ports must be the same -- but that's not true for every protocol).

This means, then, that our partner can run ``tty-share http://localhost:8000/s/local/`` (the "client type" connection) and the listener we opened on their side will accept the connetion -- and then open a client-type connection on *our* side to ``localhost:8000`` where our server is running.

The above is done over a Dilation subchannel.
We forward data back and forth over this subchannel.
Mostly this is literally just dumping bytes back and forth as they're received, but there's a leading ``msgpack`` encoded information packet (details in the lower-level protocol, which isn't relevant here).
