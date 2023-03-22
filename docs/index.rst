
fow: Forward Over Wormhole
==========================

``fow`` is a tool that utilizes `Magic Wormhole <http://magic-wormhole.io>`_ and its Dilation feature to forward arbitrary streams over an easy-to-setup yet secure connection.

There are no logins, no identities and the server can't see content because it's end-to-end (E2E) encrypted.
Additionally, the server is often not involved in the "bulk transport" of bytes at all as the protocol prefers P2P connections.

Conceptually, this is similar to ``ssh -R`` and ``ssh -L``.

Sound interesting? Read on!

.. toctree::
   :maxdepth: 2

   README
   usage
   messages
   protocol
