import binascii
import automat

from .messages import (
    Welcome,
    CodeAllocated,
    PeerConnected,
    SendMessageToPeer,
    GotMessageFromPeer,
    WormholeClosed,
    PleaseCloseWormhole,
)


class FowlDaemon:
    """
    This is the core 'fowld' protocol.

    This class MUST NOT do any I/O or any asynchronous things (no
    "async def" or Deferred-returning methods).

    There are two main pieces of I/O that we are concerned with here:
    - stdin / stdout, line-based JSON messages
    - wormhole interactions

    Most users of fowld will see the stdin/stdout message (only), as
    that is how we communicate with the outside world.

    Internally (e.g. "tui", "fowl invite", tests) we are concerned
    with both kinds of interactions. Especially for tests, sometimes
    we want to "not actually interact" with the wormhole (but instead
    confirm what this class _wants_ to do).

    Follwing https://sans-io.readthedocs.io/how-to-sans-io.html and
    related ideas and posts, instances of this class interact SOLELY
    through "input" methods, or FowlCommandMessage (via the "input"
    method "command()").

    The `message_handler` you pass here will get instances of
    `FowlOutputMessage` and is expected to "do the I/O" as
    appropriate; in the "normal" case this means either dumping a JSON
    line to stdout or calling a wormhole method (causing I/O to the
    peer or mailbox server).

    On the "input" side, JSON on stdin becomes `FowlCommandMessage`
    instances, which are translated into the correct input method to
    call. In the "normal" case this means parsing incoming lines with
    `parse_fowld_command` and translating that to an appropriate call
    to an `@m.input()` decorated method (e.g. got_welcome(),
    code_allocated(), etc ..)

    XXX: would it be more clear to just have a .command() and de-multiplex in here?
    """
    m = automat.MethodicalMachine()
    set_trace = m._setTrace

    def __init__(self, config, fowl_status_tracker, command_handler):
        self._config = config
        self._messages = []  # pending plaintext messages to peer
        self._verifier = None
        self._versions = None
        self._status_tracker = fowl_status_tracker
        self._command_out = command_handler

    def _emit_command(self, msg):
        """
        Internal helper to pass a command up to our IO handler
        """
        self._command_out(msg)

    @m.state(initial=True)
    def waiting_code(self):
        """
        """

    @m.state()
    def waiting_peer(self):
        """
        Do not yet have a peer
        """

    @m.state()
    def verifying_version(self):
        """
        Does our peer have compatible versions?
        """

    @m.state()
    def connected(self):
        """
        Normal processing, our peer is connected
        """

    @m.state()
    def closing(self):
        """
        We have asked to close the wormhole, wait until it is
        closed
        """

    @m.state()
    def closed(self):
        """
        Nothing more to accomplish, the wormhole is closed
        """

    @m.input()
    def got_welcome(self, hello):
        """
        We have received a 'Welcome' message from the server
        """

    @m.input()
    def code_allocated(self, code):
        """
        We have a wormhole code (either because it was "set" or because we
        allcoated a new one).
        """
        # this happens either because we "set-code" or because we
        # asked for a new code (i.e. "invite" or "accept") from the
        # OUTSIDE (i.e. controlling function)

    @m.input()
    def peer_connected(self, verifier: bytes, peer_features: dict):
        """
        We have a peer

        :param verifier: a tagged hash of the peers symmetric
            key. This should match what our peer sees (users can
            verify out-of-band for extra security)

        :param peer_features: arbitrary JSON-able data from the peer,
            intended to be used for protocol and other negotiation. A
            one-time, at-startup pre-communication mechanism (definitely
            before any other messages). Also serves as key-confirmation.
        """

    @m.input()
    def version_ok(self, verifier, peer_features):
        """
        Our peer version is compatible with ours
        """

    @m.input()
    def version_incompatible(self, verifier, peer_features):
        """
        We cannot speak with this peer
        """

    @m.input()
    def shutdown(self, result):
        """
        The wormhole has closed
        """

    @m.output()
    def emit_code_allocated(self, code):
        self._status_tracker.code_allocated(code)

    @m.output()
    def emit_peer_connected(self, verifier, peer_features):
        """
        """
        self._status_tracker.peer_connected(
            binascii.hexlify(verifier).decode("utf8"),
            peer_features,
        )
        from .messages import Ready
        self._command_out(Ready())

    @m.output()
    def emit_welcome(self, hello):
        self._status_tracker.welcomed(self._config.relay_url, hello)

    @m.output()
    def verify_version(self, verifier, peer_features):
        """
        Check that our peer supports the right features
        """
        features = peer_features.get("fowl", {}).get("features", [])
        # note: if we add a feature we will want to do an intersection
        # or something and then trigger different behavior depending
        # what our peer supports .. for now there's only one thing,
        # and it MUST be supported
        print("got features", features)
        from ._proto import SUPPORTED_FEATURES  # FIXME
        if set(features) == set(SUPPORTED_FEATURES):
            self.version_ok(verifier, peer_features)
        else:
            self.version_incompatible(verifier, peer_features)

    @m.output()
    def emit_close_wormhole(self):
        self._emit_command(
            PleaseCloseWormhole("versions are incompatible") # XXX hardcoded bad
        )

    waiting_code.upon(
        code_allocated,
        enter=waiting_peer,
        outputs=[emit_code_allocated],
    )
    waiting_code.upon(
        got_welcome,
        enter=waiting_code,
        outputs=[emit_welcome]
    )
    waiting_code.upon(
        shutdown,
        enter=closed,
        outputs=[]
    )

    waiting_peer.upon(
        got_welcome,
        enter=waiting_peer,
        outputs=[emit_welcome]
    )
    waiting_peer.upon(
        peer_connected,
        enter=verifying_version,
        outputs=[verify_version]
    )
    verifying_version.upon(
        version_ok,
        enter=connected,
        outputs=[emit_peer_connected],
    )
    verifying_version.upon(
        version_incompatible,
        enter=closing,
        outputs=[emit_close_wormhole],
    )
    waiting_peer.upon(
        shutdown,
        enter=closed,
        outputs=[]
    )

    connected.upon(
        shutdown,
        enter=closed,
        outputs=[]
    )
    # XXX need to tie in "requests from peer" and "local requests" to
    # the state-machine ... right? e.g. RemoteListener and
    # LocalListener commands aren't used ... we queue them up until
    # connected, then emit the right shit after connected + verified
    # etc...
    # connected.upon(
    #     request_listener,
    #     enter=connected,
    #     outputs=[],
    # )
    closing.upon(
        shutdown,
        enter=closed,
        outputs=[]
    )
    # XXX there's no notification to go from "connected" to
    # "waiting_peer" -- because Dilation will silently "do the right
    # thing" (so we don't need to). But it would be nice to tell the
    # user if we're between "generations" or whatever
