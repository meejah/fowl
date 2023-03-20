
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



