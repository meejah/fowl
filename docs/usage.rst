``fowld`` versus ``fowl``
====================

This project actually ships two CLI tools: ``fowld`` and ``fowl``.

One is intended for automated, programmatic use (``fowld``) and the other is intended for human use (``fowl``).

Most users will only ever use ``fowl``.
Programs that integrate with or otherwise want stable, machine-parsable output and input will use ``fowld``.
Under the hood, ``fowl`` commands actually use ``fowld``.


Philsophy of Commands
-----------------------

The commands that ``fowld`` accepts and the message it outputs MUST all be well-formed JSON lines.
Generally, backwards-incompatibilities SHOULD be avoided.

There should be few (ideally no) command-line options for ``fowld``.
Programs integrating with it should expect to use any version of the software.

.. note::

   Since this is still in rapid development we don't make any promises
   about backwards compatibility yet, but will expect in future to
   have a protocol version that will increment with any breaking
   changes.

By contrast, the ``fowl`` program accepts human-typed argument, asks questions the humans are expected to answer and produces message that humans are expected to read.

Although we'll still avoid gratuitous compatilibity problems, the output SHOULD NOT be considered machine-parsable and may change from release to release.


``fowld`` Usage
===============

``fowld`` is a command-line tool intended to be run in a terminal session or as a subprocess by a higher-level co-ordination program (e.g. a GUI, or a WAMP client, or ``fowl``).

All interactions (besides CLI options) are via a line-based protocol: each line is a complete JSON object.

Most humans should use ``fowl`` instead.

See :ref:`frontend-protocol` for details on the stdin / stdout protocol that is spoken by ``fowld``.


``fowl`` Usage
==============

``fowl`` is a friendly, human-centric frontend to start or join a forwarding session.
You may specify streams to forward and rules to accept forwarded streams.

We are cautious by default, so any incoming stream requests will result in a "y/n" style question on the command-line (unless overridden by options specifically allowing streams).

Since the Dilation protocol is fairly symmetric, most options are available under ``fowl`` instead of the sub-commands ``fowl accept`` and ``fowl invite``

For example, whether you started or joined a session, either side can ask the other side to start forwarding a port.
Thus, the options for what to allow are required on both sides.


``fowl invite``
---------------

One side has to begin first, and this side runs ``fowl invite``.
This uses the Magic Wormhole protocol to allocate a short, one-time code.


This code is used by the "other end" to join this forwarding session with ``fowl accept``.
Once that side has successfully set up, we will see a message:

.. code-block:: json

    {
        "message": "connected"
    }

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
