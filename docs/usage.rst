fow Usage
=========

``fow`` is a command-line tool intended to be run in a terminal session or as a subproecss by a higher-level co-ordination program (e.g. a GUI, or a WAMP client).

All interactions (besides CLI options) are via a line-based protocol: each line is a complete JSON object.

The ``fow repl`` subcommand provides a user-friendly version that can translate "actually human-readable" commands to and from JSON.
