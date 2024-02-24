Forward over Wormhole, Locally (fowl)
=====================================

Get TCP streams from one computer to another, safely.

(The base protocol below `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ provides a powerful account-less, peer-to-peer networking solution -- ``fowl`` helps you use this power immediately with existing programs)


.. image:: docs/_static/logo.svg
    :width: 100%
    :scale: 50%
    :align: right
    :alt: Fowl Logo: a chicken head with two blue ethernet cables


🤔 Why?
-------

We sometimes pair-program but don't like the idea of sending keystrokes over a third-party server.

For more context, see my blog posts: `Forwarding Streams over Magic Wormhole <https://meejah.ca/blog/fow-wormhole-forward>`_ and `Wizard Gardens vision <https://meejah.ca/blog/wizard-gardens-vision>`_.


What?
------

The command-line tool ``fowl`` allows you use any client/server program over `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ which provides a *persistent*, strongly-encrypted session with no need for pre-shared keys.

Conceptually, this is somewhat similar to combining ``ssh -R`` and ``ssh -L``.
``fowl`` may be used to set up complex workflows directly between participants, integrating services that would "traditionally" demand a server on a public IP address.

Key features:

- no need to pre-exchange keys
- simple, one-time-use codes that are easy to transcribe
- secure (full-strength keys via SPAKE2)
- integrate with tools that can listen on or connect to localhost

This allows an author to write a "glue" program in *any language* that ties together unchanged networked progams. The communcation channel is: set up *without pre-shared secrets*; *fully encrypted*; and *survives IP address changes or outages*. All this with *no action required at the application level*, it is just a normal localhost TCP (or UNIX) streaming socket.


Motivational Example
--------------------

When pair-programming using `tty-share <https://tty-share.com/>`_ one handy option is to use the default, public server.
However, *I don't like the idea of sending keystrokes over a third-party server* that I don't run.

I could fire up such a server myself and use it with my friends, but with ``fowl``, one side can run a localhost ``tty-share`` server and the other side can run a ``tty-share`` client that connects to a ``localhost`` endpoint -- data flows over the wormhole connection (only).

Key advantage: *no need to expose keystrokes to a third-party server*.

Additional advantage: *no need to set up a server on a public IP address*.


Why is This Particular Yak Being Shorn?
---------------------------------------

I wanted to write a pair-programming application in Haskell, but didn't want to implement Dilation in the Magic Wormhole Haskell library (maybe one day!)

It also occurred to me that other people might like to experiment with Magic Wormhole (and advanced features like Dilation) in languages that lack a Magic Wormhole implementation -- that is, most of them!

So, the first step in "write a Haskell pair-programming utility" became "write and release a Python program" :)


How Does It Work?
-----------------

``fowl`` uses the "`Dilation <https://magic-wormhole.readthedocs.io/en/latest/api.html#dilation>`_" feature of the `Magic Wormhole <https://github.com/magic-wormhole/magic-wormhole>`_ protocol.

This means that a Magic Wormhole Mailbox server is used to perform a SPAKE2 exchange via short (but one-time only) pairing codes.
For details on the security arguments, please refer to `the Magic Wormhole documentation <https://magic-wormhole.readthedocs.io/>`_.
After this, an E2E-encrypted direct P2P connection (or, in some cases, via a "transit relay" service) is established between the two computers;
that is, between the computer that created the wormhole code, and the one that consumed it.

The key encrypting messages on this connection is only known to the two computers; the Mailbox server cannot see contents. (It, like any attacker, could try a single guess at the wormhole code). See the `Magic Wormhole documentation <https://magic-wormhole.readthedocs.io/en/latest/welcome.html#design>`_ for more details on this.

The "Dilation" feature further extends the above protocol to provide subchannels and "durability" -- this means the overall connection survives network changes, disconnections, etc.
You can change WiFi networks or put one computer to sleep yet remain connected.

What ``fowl`` adds is a way to set up any number of localhost listeners on either end, forwarding data over subchannels.
The always-present "control" subchannel is used to co-ordinate opening and closing such listeners.

With some higher-level co-ordination, ``fowl`` may be used to set up complex workflows between participants, integrating services that would "traditionally" demand a server on a public IP address.

Another way to view this: streaming network services can integrate the Magic Wormhole protocol without having to find, link, and use a magic-wormhole library (along with the implied code-changes) -- all integration is via local streams.
(There *are* implementations in a few languages so you could take that route if you prefer).

Who Should Use This?
--------------------

While it's definitely possible to use ``fowl`` "directly", the intent is that some other program -- some "glue" code -- is running ``fowl`` as a sub-process.

The line-based JSON communication facilitates this.

This means the main users of ``fowl`` are expected to be other programmers who know how to start a long-running subprocess and communicate with it via stdin and stdout.

This program will also co-ordinate the running of client-type or server-type networking applications that accomplish some goal useful to users. For example, "pair-programming" (for my case).

Some other ideas to get you started:

- "private" / invite-only streaming (one side runs video source, invited sides see it)
- on-demand tech support or server access (e.g. set up limited-time SSH, VNC, etc)
- ...


Installation and Basic Usage
----------------------------

``fowl`` is a Python program using the `Twisted <https://twisted.org>`_ asynchronous networking library.

You may install it with ``pip``::

    pip install fowl

Once this is done, ``fowl`` will appear on your ``PATH``.
Run it for instructions on use.

In accordance with best practices, we recommend using a ``virtualenv`` to install all Python programs.
Never use ``sudo pip``.
To create a virtualenv in your checkout of ``fowl``, for example::

    python -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install fowl
    # or: ./venv/bin/pip install --editable .
    ./venv/bin/fowl


Other Platforms
---------------

We welcome contributions from people experienced with packaging for other installation methods; please get in touch!


Stability and Releases
----------------------

This is an early release of, essentially, a proof-of-concept.
While we intend to make it a stable base to put co-ordination software on top, it is not yet there.
APIs may change, options may change.
If you are developing on top of ``fowl``, please get in touch so we know what you need 😊

All releases are on PyPI with versioning following a `CalVer <https://calver.org>`_ variant: ``year.month.number``, like ``23.4.0`` (for the first release in April, 2023).

See ``NEWS.rst`` for specific release information.
