fow Usage
=========

``fow`` is a command-line tool intended to be run in a terminal session or as a subproecss by a higher-level co-ordination program (e.g. a GUI, or a WAMP client).

All interactions (besides CLI options) are via a line-based protocol: each line is a complete JSON object.

The ``fow repl`` subcommand provides a user-friendly version that can translate "actually human-readable" commands to and from JSON.

``fow invite``
--------------

One side has to begin first, and this side runs ``fow invite``.
This uses the Magic Wormhole protocol to allocate a short, one-time code.

This results in one of the valid ``stdout`` messages being emitted::

    {"message": "code", "wormhole-code": "123-foo-bar"}

For all valid messages, see :ref:`messages`.
