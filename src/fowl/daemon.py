import binascii
import automat

from .messages import (
    Welcome,
    CodeAllocated,
    PeerConnected,
    SendMessageToPeer,
    GotMessageFromPeer,
    WormholeClosed,
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

    def __init__(self, reactor, config, message_handler):
        self._reactor = reactor
        self._config = config
        self._messages = []  # pending plaintext messages to peer
        self._verifier = None
        self._versions = None
        self._message_out = message_handler

    def _emit_message(self, msg):
        """
        Internal helper to pass a message to our external message handler
        (and do something useful on error)
        """
        try:
            self._message_out(msg)
        except Exception as e:
            print(f"Error in user code sending a message: {e}")
            print(type(e), e)

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
    def connected(self):
        """
        Normal processing, our peer is connected
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
    def peer_connected(self, verifier: bytes, versions: dict):
        """
        We have a peer

        :param verifier: a tagged hash of the peers symmetric
            key. This should match what our peer sees (users can
            verify out-of-band for extra security)

        :param versions: arbitrary JSON-able data from the peer,
            intended to be used for protocol and other negotiation. A
            one-time, at-startup pre-communication mechanism (definitely
            before any other messages). Also serves as key-confirmation.
        """

    @m.input()
    def got_message(self, plaintext):
        """
        We received a message from our peer
        """

    @m.input()
    def send_message(self, plaintext):
        """
        Pass a new message to our peer
        """

    @m.input()
    def shutdown(self, result):
        """
        The wormhole has closed
        """

    @m.output()
    def emit_code_allocated(self, code):
        self._emit_message(CodeAllocated(code))

    @m.output()
    def emit_peer_connected(self, verifier, versions):
        """
        """
        self._emit_message(
            PeerConnected(
                binascii.hexlify(verifier).decode("utf8"),
                versions,
            )
        )

    @m.output()
    def emit_send_message(self, plaintext):
        self._emit_message(
            SendMessageToPeer(
                plaintext,
            )
        )

    @m.output()
    def emit_got_message(self, plaintext):
        self._emit_message(
            GotMessageFromPeer(
                plaintext,
            )
        )

    @m.output()
    def emit_welcome(self, hello):
        self._emit_message(
            Welcome(self._config.relay_url, hello)
        )

    @m.output()
    def verify_version(self, verifier, versions):
        try:
            core = versions["fowl"]["features"]["core"]

            assert core is not None, "fowl -> features -> core doesn't exist in peer app_version"
            # no particular content for this yet, empty-dict
        except KeyError:
            # XXX need to send a protocol error to the machine, end
            # the connection
            print("didn't like", versions)
            pass

    @m.output()
    def queue_message(self, plaintext):
        self._message_queue.append(plaintext)

    @m.output()
    def send_queued_messages(self):
        to_send, self._messages = self._messages, []
        for m in to_send:
            self.emit_send_message(m)

    @m.output()
    def emit_shutdown(self, result):
        self._emit_message(
            WormholeClosed(result)
        )

    waiting_code.upon(
        code_allocated,
        enter=waiting_peer,
        outputs=[emit_code_allocated],
    )
    waiting_code.upon(
        send_message,
        enter=waiting_code,
        outputs=[queue_message]
    )
    waiting_code.upon(
        got_welcome,
        enter=waiting_code,
        outputs=[emit_welcome]
    )
    waiting_code.upon(
        shutdown,
        enter=closed,
        outputs=[emit_shutdown]
    )

    waiting_peer.upon(
        send_message,
        enter=waiting_peer,
        outputs=[queue_message]
    )
    waiting_peer.upon(
        got_welcome,
        enter=waiting_peer,
        outputs=[emit_welcome]
    )
    waiting_peer.upon(
        got_message,
        enter=waiting_peer,
        outputs=[emit_got_message]
    )
    waiting_peer.upon(
        peer_connected,
        enter=connected,
        outputs=[verify_version, emit_peer_connected, send_queued_messages],
    )
    waiting_peer.upon(
        shutdown,
        enter=closed,
        outputs=[emit_shutdown]
    )

    connected.upon(
        send_message,
        enter=connected,
        outputs=[emit_send_message]
    )
    connected.upon(
        got_message,
        enter=connected,
        outputs=[emit_got_message]
    )
    connected.upon(
        shutdown,
        enter=closed,
        outputs=[emit_shutdown]
    )
    # XXX there's no notification to go from "connected" to
    # "waiting_peer" -- because Dilation will silently "do the right
    # thing" (so we don't need to). But it would be nice to tell the
    # user if we're between "generations" or whatever
