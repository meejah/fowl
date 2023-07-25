fowl Usage
==========

``fowl`` is a command-line tool intended to be run in a terminal session or as a subprocess by a higher-level co-ordination program (e.g. a GUI, or a WAMP client).

All interactions (besides CLI options) are via a line-based protocol: each line is a complete JSON object.

The ``fowl repl`` subcommand provides a user-friendly version that can translate "actually human-readable" commands to and from JSON.

``fowl invite``
---------------

One side has to begin first, and this side runs ``fowl invite``.
This uses the Magic Wormhole protocol to allocate a short, one-time code.

This results in one of the valid ``stdout`` messages being emitted::

    ``{"message": "code", "wormhole-code": "123-foo-bar"}``

For all valid messages, see :ref:`messages`.

This code is used by the "other end" to join this forwarding session with ``fowl accept``.
Once that side has successfully set up, we will see a message::

    ``{"message": "connected"}``

After this, we reach the more "symmetric" state of the session: although under the hood one side is randomly "the Follower" and one side is "the Leader" in the Dilation session, at our level either side can request forwards from the other.

See below.


``fowl accept``
---------------

One side has to begin the session second, and they run this command.
This command consumes a Wromhole code and must receive it from the human who ran the ``fowl invite`` command.

Once the Magic Wormhole protocol has successfully set up a Dilation connection, a message will appear on ``stdout``::

    ``{"message": "connected"}``

After this, we reach the more "symmetric" state of the session: although under the hood one side is randomly "the Follower" and one side is "the Leader" in the Dilation session, at our level either side can request forwards from the other.

See below.


Successful Session: Symmetric Messaging
---------------------------------------

Both sides are set up.

We now enter a state where either side can make requests of the other.
All requests are "asynchronous", in the sense that replies are not definitely right after requests.
Therefore we attach an ``id`` to all requests which is matched with a reply
(XXX can we say "exactly one reply" here? hopefully!)s


Request a Remote Listener
~~~~~~~~~~~~~~~~~~~~~~~~~

"Our" side wants the "other" side to start listening on a local port.
So, we "ask" them via a ``"message": "forward"`` request.

That side may have an aritrarily complex process around this request, and ultimately either accepts or rejects it.
For example, it may simply have a policy on what ports to whitelist.
Or, it may ask the human via some UI whether to allow the forward or not.
Regardless, it takes some time to answer the request.

Upon success, the other side listens locally on a particular port.
Whenever something connects to that port, a subchannel is opened to our side and we make a localhost *client-type* request over the *same port* (this latter point is important for some protocols, for example HTTP).
