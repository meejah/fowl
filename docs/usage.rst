``fowld`` versus ``fowl``
====================

This project actually ships two CLI tools: ``fowld`` and ``fowl``.

One is intended for automated, programmatic use (``fowld``) and the other is intended for human use (``fowl``).

Most users will only ever use ``fowl``.

Programs that integrate with (or otherwise want stable, machine-parsable output) will use ``fowld``.
Under the hood, ``fowl`` commands actually use ``fowld`` (via a Python API).
All functionality should be available to users of either program.

If you want very similar operation to ``fowld``, but without having to remember JSON syntax, use ``fowl tui``.


High-Level Overview
-------------------

What we aim to accomplish here is to easily set up the forwarding of TCP or Unix streams over a secure, identity-less and durable connection.

These streams may be anything at all -- but the core use-case is aimed at eliminating the need to run public-IP services.
Our canonical "hello world" example is a simple chat system: running ``nc`` (aka "netcat") on one side, and ``telnet`` on the other (see :ref:`hello-world-chat` for a fully-worked example).

Although ``nc`` and ``telnet`` provide no security, using them here we get an end-to-end-encrypted chat session.
We also get "durability" (if one side loses conenction or changes to a different network, we will eventually resume uninterrupted).
We do not have to change the ``nc`` or ``telnet`` programs at all (they can already connect to and listen upon ``localhost`` -- that's all we need).

The general flow of a session is that one side "starts" it (allocating a secret code), and the second side "joins" it (consuming the secret coe).
These codes can be used precisely once: if a bad actor guesses or intercepts the code, your partner will know (because it won't work for them).

You may also gain additional security by using the "verifier" feature, if desired (this ensures that you're 100% definitely communicating with the intended party).
See the `magic-wormhole documentation <>`_ for a full security discussion.


Philsophy of Commands
---------------------

The ``fowl`` program accepts human-typed arguments, asks questions that humans are expected to answer and produces messages for humans to read.
Many options are available via normal command-line arguments.

Although we'll still avoid gratuitous compatilibity problems, the output SHOULD NOT be considered machine-parsable and may change from release to release.

By contrast, the commands that ``fowld`` accepts and the messages it outputs MUST all be well-formed JSON lines.
Generally, backwards-compatibility SHOULD be available.

There should be few (ideally no) command-line options for ``fowld``.
Programs integrating with it should be able to use any version of the software (that is, to upgrade seamlessly).

.. note::

   Since this is still in rapid development we don't make any promises
   about backwards compatibility *yet*, but will expect in future to
   have a protocol version that will increment with any breaking
   changes.


``fowl`` Usage
==============

``fowl`` is a friendly, human-centric frontend to start or join a forwarding session.
You may specify streams to forward and rules to accept forwarded streams.

We are cautious by default, so any incoming stream requests will result in a "y/n" style question on the command-line (unless overridden by options specifically allowing streams).

Since the Dilation protocol is fairly symmetric, most options are available under ``fowl`` instead of the sub-commands ``fowl accept`` and ``fowl invite``

For example, whether you started or joined a session, either side can ask the other side to start forwarding a port (``--remote``) or start one on the near side (``--local``).
Thus, the options for what to allow are required on both sides.


Overview of a Session
---------------------

Using ``fowl`` involves two computers.
One computer runs ``fowl invite`` and the other computer runs ``fowl accept``.

After this, a lot of things are "symmetric" in that either side can listen on a port (or cause the peer to listen on a port) and subsequently forward data over resulting connections.

The "symmetric" parts are described in the next session, following which are things specific to the "accept" or the "invite" side.


Common ``fowl`` Options: An Example
-----------------------------------

Both subcommands ``accept`` and ``invite`` share a series of options for setting up streaming connections.

Either side may have a listener on a local port; this listener will accept any incoming connection, create a Wormhole subchannel, and ask the other side to make a particular local connection.

The normal use-case here is that you're running a daemon on one of the two peers and you wish to have the other peer be able to reach it.

Let's take SSH as an example: the computer "desktop" is running an SSH daemon on the usual port 22.
One this side we run ``fowl invite``, which produces a code.

On the computer called "laptop" we run ``fowl accept``, consuming the code.

So to use SSH over this Wormhole connnection, we want to have a listener appear on the "laptop" (because the "desktop" computer already has a listener: the SSH daemon on port 22).

We have two choices here: either the "desktop" or the "laptop" side may initiate the listening; if we do it on the "desktop" side we use the ``"remote"`` command and if we do it on the "laptop" side we use the ``"local"`` command.

The ``"remote"`` and ``"local"`` commands are mirrors of each other and both have a ``"listen"`` and ``"connect"`` value -- what changes is _where_ that value is used.
In a ``"remote"`` command, the ``"listen"`` value is used on the "far" side, whereas in a ``"local"`` command the ``"listen"`` value is used on the near side.

So back to our example, we want the "laptop" to open a new listener.

On the "laptop" machine we'd use something like ``--local 22`` to indicate that we'd like to listen on port ``22`` (and forward to the same port on the other side).
Maybe we can't listen on ``22``, though, so we might want to listen on ``1234`` but still forward to ``22`` on the far side; this is expressed with ``--local 1234:22``

To flip this around, on the "desktop" machine we could do ``--remote 22`` or ``--remote 1234:22`` to use the same values from above.

.. NOTE::

    If you're using ``fowld`` directly, the above correspond to ``{"kind": "remote", "listen": "tcp:1234:interface=localhost", "connect": "tcp:localhost:22}`` from the "desktop" machine or ``{"kind": "local", "listen": "tcp:1234:interface=localhost", "connect": "tcp:localhost:22}`` from the "laptop" machine.


Common ``fowl`` Options
-----------------------

* ``--local port:[remote-port]``: listen locally on ``port``. On any connection to this port, we will ask the peer to open a connection on its end to ``port`` (instead to ``remote-port`` if specified).

* ``--remote port:[local-port]``: listen on the remote peer's ``port``. On any connection to this port (on the peer's side), we will ask our local side to open a connection to ``port`` (or instead to ``local-port`` if specified).



``fowl invite``
---------------

One side has to begin first, and this side runs ``fowl invite``.
This uses the Magic Wormhole protocol to allocate a short, one-time code.


This code is used by the "other end" to join this forwarding session with ``fowl accept``.
Once that side has successfully set up, we will see a message::

    Peer is connected.
    Verifier: b191 e9d1 fd27 be77 f576 c3e7 f30d 1ff3 e9d3 840b 7f8e 1ce2 6730 55f4 d1fc bb4f

After this, we reach the more "symmetric" state of the session: although under the hood one side is randomly "the Follower" and one side is "the Leader" in the Dilation session, at our level either side can request forwards from the other.

The "Verifier" is a way to confirm that the session keys match; confirming both sides have the same verifier is optional.
However, confirming them means you can be 100% sure (instead of 99.85% sure or 1 in 65536) nobody has become a MitM.

See below.


``fowl accept``
---------------

One side has to be the "second" user to a session and that person runs this command.
``fowl accept`` consumes a Wormhole code and must receive it from the human who ran the ``fowl invite`` command.

Once the Magic Wormhole protocol has successfully set up a Dilation connection, a message will appear on ``stdout``::

    Peer is connected.
    Verifier: b191 e9d1 fd27 be77 f576 c3e7 f30d 1ff3 e9d3 840b 7f8e 1ce2 6730 55f4 d1fc bb4f

After this, we reach the more "symmetric" state of the session: although under the hood one side is randomly "the Follower" and one side is "the Leader" in the Dilation session, at our level either side can request forwards from the other.

Generally ports to forward are specified on the command-line (and "policy" type options to allow or deny these are also expressed as command-line options).
In case no "policy" options were specified, the user will be interactively asked on every stream that the other side proposes to open.


``fowld`` Usage
===============

``fowld`` is a command-line tool intended to be run in a terminal session or as a subprocess by a higher-level co-ordination program (e.g. a GUI, or a WAMP client, or ``fowl``).

All interactions (besides CLI options) are via a line-based protocol: each line is a complete JSON object.

Most humans should use ``fowl`` instead.

See :ref:`frontend-protocol` for details on the stdin / stdout protocol that is spoken by ``fowld``.
