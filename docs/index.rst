
fowl: Forward Over Wormhole, Locally
=======================================

``fowl`` is a tool that utilizes `Magic Wormhole <http://magic-wormhole.io>`_ and its Dilation feature to forward arbitrary TCP streams over an easy-to-setup yet secure and human-mediated connection.
**Peers** communicate to each other over an **end-to-end encrypted** connection, and can use client-type or server-type network services from each side.
Permitted services and ports are based on consent of each peer.

.. image:: fowl-forward-light.png
  :width: 100%
  :alt: Fowl forwarding a connection, with traffic visualization and some ascii-art showing connected peers

There are no logins, no identities and the server can't see content because everything is end-to-end (E2E) encrypted between exactly two peers.
Additionally, the server is usually not involved in the "bulk transport" of bytes at all as the protocol prefers P2P connections.

Conceptually, this is somewhat similar to ``ssh -R`` and ``ssh -L`` except without pre-shared or long-term secrets.
Unlike ``ssh``, reconnection is invisible to the forwarded applications.

Sound interesting? Read on!

.. toctree::
   :maxdepth: 2

   README
   api
   usage
   releases
   frontend-protocol
   protocol
