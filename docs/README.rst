Forward over Wormhole
=====================

Why?
-----

We sometimes pair-program but don't like the idea of sending keystrokes over a third-party server.

What?
------

The command-line tool ``fow`` allows you to forward any streaming connection over `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ which is a *persistent*, strongly-encrypted session.

The command-line tool ``fow`` allows you use any client/server program over `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ which provides a *persistent*, strongly-encrypted session with no need for pre-shared keys.

Conceptually, this is somewhat similar to combining ``ssh -R`` and ``ssh -L``.
Key features:

- no need to pre-exchange keys
- simple, one-time-use codes that are easy to transcribe
- secure (full-strength keys via SPAKE2)
- easily integrate with tools that listen on or connect to localhost


Motivational Example
--------------------

We sometimes pair-program while using `tty-share <https://tty-share.com/>`_, but don't like the idea of sending keystrokes over a third-party server.
With ``fow``, one side can run a localhost ``tty-share`` server and the other side can run a ``tty-share`` client that connects to a ``localhost`` endpoint -- data flows over the wormhole connection (only).

Key advantage: *no need to expose keystrokes to a third-party server*.


How Did We Get Here?
-----------------------

I wanted to write a pair-programming application in Haskell, but didn't


How Does It Work?
-----------------

``fow`` uses the "`Dilation <https://magic-wormhole.readthedocs.io/en/latest/api.html#dilation>`_" feature of the `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ protocol.

This means that a Magic Wormhole Mailbox server is used to perform a SPAKE2 exchange via short (but one-time only) pairing codes.
This is a secure method, but we don't repeat the arguments here.
After this, an E2E-encrypted direct P2P connection (or, in some cases, via a "transit relay" service) is established between the two computers (the one that created the wormhole code, and the one that consumed it).

The key encrypting messages on this connection is only known to the two computers; the Mailbox server cannot see contents. (It, like any attacker, could try a single guess at the wormhole code). See the `Magic Wormhole documentation <https://magic-wormhole.readthedocs.io/en/latest/welcome.html#design>`_ for more details on this.

The "Dilation" feature further extends the above protocol to provide subchannels and "durability" -- this means the overall connection survives network changes, disconnections, etc. You can change WiFi networks or put one computer to sleep yet remain connected.

What ``fow`` adds is a way to set up any number of localhost listeners on either end, forwarding data over subchannels.
The always-present "control" subchannel is used to co-ordinate opening and closing such listeners.

With some higher-level co-ordination, ``fow`` may be used to set up complex workflows between participants, integrating services that would "traditionally" demand a server on a public IP address.

Another way to view this: streaming network services can integrate the Magic Wormhole protocol without having to find, link, and use a magic-wormhole library (along with the implied code-changes) -- all integration is via local streams.
(There *are* implementations in a few languages so you could take that route if you prefer).


Installation and Basic Usage
----------------------------

``fow`` is a Python program using the `Twisted <https://twisted.org>`_ asynchronous networking library.

You may install it with ``pip``::

    pip install fow

Once this is done, ``fow`` will appear on your ``PATH``.
Run it for instructions on use.

In accordance with best practices, we recommend using a ``virtualenv`` to install all Python programs.
Never use ``sudo pip``.
To create a virtualenv in your checkout of ``fow``, for example::

    python -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install fow
    # or: ./venv/bin/pip install --editable .
    ./venv/bin/fow


Other Platforms
---------------

We welcome contributions from people experienced with packaging for other installation methods; please get in touch!


Stability and Releases
----------------------

This is an early release of, essentially, a proof-of-concept.
While we intend to make it a stable base to put co-ordination software on top, it is not yet there.
APIs may change, options may change.
If you are developing on top of ``fow``, please get in touch so we know what you need 😊

All releases are on PyPI with versioning following a `CalVer <https://calver.org>`_ variant: ``year.month.number``, like ``23.4.0`` (for the first release in April, 2023).

See ``NEWS.rst`` for specific release information.
