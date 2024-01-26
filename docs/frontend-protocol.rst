
.. _frontend-protocol:

The ``fowld`` Frontend Protocol
================================

The ``fowld`` program speaks a line-based protocol on stdin and stdout.

Every message is a single line, terminated with a single newline (``\n``) character.
Every message is a complete and valid JSON message, encoded in UTF8.
Every message is a ``dict`` (aka "JSON object").

Thus, controller programs can deserialize each line as a ``dict`` (or mapping, or your language's equivalent).

Since ``fowl`` itself uses ``fowld`` under the hood, this project has examples of parsing and producing these messages.

We now go over the keys that particular messages have.

.. WARNING::

    XXX Do we want a request-id for "things controllers send" (and then we can reference this request-id when answering the request).
    - pro: more explicit
    - pro: multiple outstanding requests
    - con: more complex

    If we _do_ have request-ids, the controller can "load up" forward requests and then when (if?) we finally connect to a peer, they can be honoured.
    (Other way around: controller would get an error right away because "we can't do that now" or whatever)




The ``"kind"`` Key
--------------------

Every single message MUST have a ``"kind"`` key.
This tells the parser what sort of message it is (and hence what other keys may be present).

It is a protocol error to emit a message without a ``"kind"`` key.
Hereafter, we refer to all messages by their "kind".

An "input" message is one that ``fowld`` accepts on stdin.

An "output" message is one that ``fowld`` may produce on stdout.


Input: ``kind: local``
----------------------

This message asks ``fowld`` to start listening on a local port -- any subsequent connections on this local port cause the *remote* side to open a corresponding connection (possibly on a different port or protocol).

Keys allowed in this message:

- ``endpoint`` (required): a Twisted server-style endpoint string specifying where to listen locally
- ``connect-endpoint`` (required): a Twisted client-style endpoint string specifying what connection to open on the other end

For example:

.. code-block:: json

    {
        "kind": "local",
        "endpoint": "tcp:8000:interface=localhost",
        "connect-endpoint": "tcp:localhost:80"
    }

In this example, we will open a listener on our machine on TCP port ``8000`` and interface ``localhost``.
Whenever a new connection is opened on our machine, we will ask the other side to connect to port ``80`` on *their* notion of ``localhost``.

Remember that these can be anything that Twisted understands, including from installed plugins.
**Be careful**: a malicous "other end" could cause all sorts of shenanigans.

You are only limited to streaming endpoints (i.e. no UDP) but they do not have to be TCP.
For example, one side could use ``unix:/tmp/socket`` to open a listener (or connection) on Unix-domain socket.
With `txtorcon <https://meejah.ca/projects/txtorcon>`_ one could have ``onion:...`` Tor endpoints on either end.

Once the listener is established, we'll issue a ``kind: listening`` output.


Input: ``kind: remote``
--------------------------------

This will cause ``fowld`` to request a listener on the *other* side.
There is symmetry here: the same thing could be accomplished by that other side instead issuing a ``kind: local`` request.

Keys allowed in this message:

- ``listen-endpoint`` (required): a Twisted server-style endpoint string specifying where to listen (on the other end).
- ``connect-endpoint`` (required): a Twisted client-style endpoint string specifying what to connect to (on this side) for each connection that happens on the other side.

To directly mirror the example from the ``local`` command:

.. code-block:: json

    {
        "kind": "remote",
        "listen-endpoint": "tcp:8000:interface=localhost",
        "connect-endpoint": "tcp:localhost:80"
    }

This will be a mirror-image of the other example.
That is, we'll cause the far end to start listening on its TCP port ``8000`` on interface ``localhost``.
Any connection to that will open a near-side connection to port 80 via TCP.

The far-side ``fowld`` will issue a ``kind: listening`` message when it has started listening.


Output: ``kind: listening``
-----------------------------

This message is issued by ``fowld`` when it has opened a listening socket on that side.

So, if a ``kind: local`` had initiated the listening, this message would appear on that same side.
If instead it was a ``kind: remote-to-local`` then it would appear on the far side.

An example message:

.. code-block:: json

    {
        "kind": "listening",
        "endpoint": "tcp:8080:interface=localhost",
        "connect-endpoint": "tcp:80"
    }

Guidance for UX: the user should be made aware their machine is listening on a particular port / interface.


Output: ``kind: error``
--------------------------

Some sort of error has happened.

This message MUST have a ``message`` key containing a freeform error message.
It MAY have additional fields depending on the kind of error (XXX good idea? Hard to produce strict parser...)

An example message:

.. code-block:: json

    {
        "kind": "error",
        "message": "Unknown control command: foo"
    }

Guidance for UX: most errors are probably interesting to the user.


Output: ``kind: connected``
-----------------------------

The ``fowld`` process has successfully connected to the Mailbox Server.
No other keys are present.

Guidance for UX: the user should be informed that progress has been made (e.g. the Mailbox Server is available).


Output: ``kind: forward-bytes``
--------------------------------

The ``fowld`` process has forwarded some bytes successfully.

Keys present:

- ``id`` (required): the sub-connection id, a unique number
- ``bytes`` (required): how many bytes are forwarded in this messsage

Guidance for UX: the user may be curious to know if a connection is alive, what its throughput is, etc.

XXX probably want to distinguish direction (hacked in as ``hello: foo`` on one of the directions currently).


Output: ``kind: local-connection``
----------------------------------

We have received a connection on one of our local listeners.

Keys present:

- ``id`` (required): the sub-connection id, a unique number

Guidance for UX: the user should be informed that something is interacting with our listener.


Output: ``kind: connect-local``
-------------------------------

The other side has asked us to make a local connection.

Keys present:

- ``id`` (required): the sub-connection id, a unique number
- ``endpoint`` (required): the Twisted client-style endpoint we will attempt a connection to

Guidance for UX: the user should be informed that something is interacting with our listener.