
.. messages:

Control Messages
================

External programs control ``fowl`` by running it as a subprocess and exchanging messages via ``stdin`` and ``stdout``.

Every message is valid JSON.
All messages MUST include a ``"message"`` key which indicates what sort of message it is.

We differentiate between "stdout" and "stdin" messages -- that is, things the program tells the user and things the user tells the program.
Here, "user" is often another program.

Note that there is a lightweight protocol spoken via Dilation; see :ref:`dilation-protocol` for an explanation, but do not confuse that protocol with this document.


.. stdin_messages:

Valid ``stdin`` Messages
------------------------

``kind=local``
`````````````````

This listens on a local port and establishes a :ref:`forwarding-subchannel` to the other side (making a client-type connection on that side).

Example::

    {
        "message": "local",
        "listen-endpoint": "<Twisted server-style endpoint-string>",
        "connect-endpoint": "<Twisted client-style endpoint-string>",
    }

**FIXME**: requests should have a unique ID (replys must match them) ... OR we have to block reading stdin until we're done each request (so there aren't two in-flight) OR we have to keep track internally and answer in the correct order?


``kind=remote``
``````````````````

This asks the *other* side to listen on a local port, establishing :ref:`forwarding-subchannels` back to this side upon connections.
That is, the inverse of the ``kind=local`` kind.

Example::

    {
        "message": "remote",
        "listen-endpoint": "<Twisted server-style endpoint-string>",
        "connect-endpoint": "<Twisted client-style endpoint-string>",
    }
    }


.. stdout_messages:

Valid ``stdout`` Messages
-------------------------

``kind=welcome``
`````````````````````

This message is emitted to both sides once per session once we connect to the Mailbox Server.

- ``"welcome"``: a ``dict`` containing whatever the Mailbox server sent in its Welcome message.


``kind=code-allocated``
`````````````````````

This message is emitted once per session by the side that starts the interaction.
It is usually the first message.

Keys included:

- ``"code"``: the allocated Wormhole code, like ``42-universe-everything``.


``kind=peer-connected``
`````````````````````

This message is emitted to both sides once per session, after the Dilation connection has been successfully set up.
There is no other information in this message.


