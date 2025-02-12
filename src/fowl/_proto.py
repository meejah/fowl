from __future__ import print_function

import os
import sys
import json
import binascii
import textwrap
import functools
import struct
from base64 import b16encode
from typing import IO, Callable, TextIO
from functools import partial
from itertools import count

import click
import humanize
from attrs import frozen, define, asdict, Factory as AttrFactory

import msgpack
import automat
from twisted.internet import reactor
from twisted.internet.defer import Deferred, ensureDeferred, DeferredList, race, CancelledError
from twisted.internet.task import deferLater
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.error import ConnectionDone
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver
from zope.interface import directlyProvides
from wormhole.cli.public_relay import RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL
import wormhole.errors as wormhole_errors

from .observer import When
from .messages import (
    SetCode,
    AllocateCode,
    GrantPermission,
    DangerDisablePermissionCheck,
    RemoteListener,
    LocalListener,

    Welcome,
    Listening,
    RemoteListeningSucceeded,
    RemoteListeningFailed,
    RemoteConnectFailed,
    PeerConnected,
    CodeAllocated,
    BytesOut,
    BytesIn,
    IncomingConnection,
    IncomingDone,
    IncomingLost,
    OutgoingConnection,
    OutgoingDone,
    OutgoingLost,
    WormholeClosed,
    WormholeError,
    GotMessageFromPeer,

    Ping,
    Pong,

    FowlOutputMessage,
    FowlCommandMessage,

    PleaseCloseWormhole,
)
from .policy import IClientListenPolicy, IClientConnectPolicy, AnyConnectPolicy, AnyListenPolicy



APPID = u"meejah.ca/wormhole/forward"
WELL_KNOWN_MAILBOXES = {
    "default": PUBLIC_MAILBOX_URL,
    "local": "ws://localhost:4000/v1",
    "winden": "wss://mailbox.mw.leastauthority.com/v1",
    # Do YOU run a public mailbox service? Contact the project to
    # consider having it listed here
}
SUPPORTED_FEATURES = [
    "core-v1",  # the only version of the protocol so far
]


def _sequential_id():
    """
    Yield a stream of IDs, starting at 1
    """
    next_id = 0
    while True:
        next_id += 1
        yield next_id


allocate_connection_id = partial(next, _sequential_id())


#@frozen
@define  ## could be @frozen, but for "policy" ... hmmm
class _Config:
    """
    Represents a set of validated configuration
    """
    relay_url: str = PUBLIC_MAILBOX_URL
    code: str = None
    code_length: int = 2
    use_tor: bool = False
    appid: str = APPID
    debug_state: bool = False
    stdout: IO = sys.stdout
    stderr: IO = sys.stderr
    create_stdio: Callable = None  # returns a StandardIO work-alike, for testing
    debug_file: IO = None  # for state-machine transitions
    commands: list[FowlCommandMessage] = AttrFactory(list)
    connect_policy: IClientConnectPolicy = None
    listen_policy: IClientListenPolicy = None
    output_debug_messages: TextIO = None  # Option<Writable>


async def wormhole_from_config(reactor, config, wormhole_create=None):
    """
    Create a suitable wormhole for the given configuration.

    :returns DeferredWormhole: a wormhole API
    """
    if wormhole_create is None:
        from wormhole import create as wormhole_create

    tor = None
    if config.use_tor:
        tor = await get_tor(reactor)
        # XXX use a Message
        print(
            json.dumps({
                "kind": "tor",
                "version": tor.version,
            }),
            file=config.stdout,
            flush=True,
        )

    w = wormhole_create(
        config.appid or APPID,
        config.relay_url,
        reactor,
        tor=tor,
        timing=None,  # args.timing,
        _enable_dilate=True,
        versions={
            "fowl": {
                "features": SUPPORTED_FEATURES,
            }
        }
    )
    if config.debug_state:
        w.debug_set_trace("forward", file=config.stdout)
    return w


@frozen
class Connection:
    endpoint: str
    i: int = 0
    o: int = 0
    listener_id: str = "unknown"


async def frontend_accept_or_invite(reactor, config):

    connections = dict()
    when_explicitly_closed_d = Deferred()
    we_closed_d = Deferred()
    peer_connected = False

    @functools.singledispatch
    def output_message(msg):
        print(f"UNhandled output: {msg}")

    @output_message.register(WormholeError)
    def _(msg):
        print(f"ERROR: {msg.message}", file=config.stderr)
        print(msg)

    @output_message.register(Pong)
    def _(msg):
        print(f"Pong: {b16encode(msg.ping_id)}: {msg.time_of_flight}s")

    @output_message.register(CodeAllocated)
    def _(msg):
        print(f"Secret code: {msg.code}")

    @output_message.register(PeerConnected)
    def _(msg):
        nonlocal peer_connected
        peer_connected = True
        nice_verifier = " ".join(
            msg.verifier[a:a+4]
            for a in range(0, len(msg.verifier), 4)
        )
        print(f"Peer is connected.\nVerifier: {nice_verifier}")

    @output_message.register(Listening)
    def _(msg):
        print(f"Listening: {msg.listen}")

    @output_message.register(RemoteListeningSucceeded)
    def _(msg):
        print(f"Peer is listening: {msg.listen} (-> {msg.connect})")

    @output_message.register(RemoteListeningFailed)
    def _(msg):
        print(f"Peer failed to listen: {msg.listen}: {msg.reason}")

    @output_message.register(IncomingConnection)
    def _(msg):
        connections[msg.id] = Connection(msg.endpoint, 0, 0, msg.listener_id)

    @output_message.register(RemoteConnectFailed)
    def _(msg):
        print("Forwarding to {} failed: {}".format(connections[msg.id].endpoint, msg.reason))
        # we will get an OutgoingDone(msg.id) for this one too, so do not delete here!
        # (XXX should maybe mark it as "failed" somehow?)
        ##del connections[msg.id]

    @output_message.register(IncomingLost)
    def _(msg):
        try:
            del connections[msg.id]
            print(f"Lost: {msg.id}: {msg.reason}")
        except KeyError:
            print("WEIRD: got IncomingLost(id={}) but don't have that connection".format(msg.id))

    @output_message.register(IncomingDone)
    def _(msg):
        try:
            del connections[msg.id]
            print(f"{msg.id}: closed")
        except KeyError:
            print("WEIRD: got IncomingDone(id={}) but don't have that connection".format(msg.id))

    @output_message.register(OutgoingLost)
    def _(msg):
        try:
            del connections[msg.id]
            print(f"Lost: {msg.id}: {msg.reason}")
        except KeyError:
            print("WEIRD: got OutgoingLost(id={}) but don't have that connection".format(msg.id))

    @output_message.register(OutgoingDone)
    def _(msg):
        try:
            del connections[msg.id]
            print(f"{msg.id}: closed")
        except KeyError:
            print("WEIRD: got OutgoingDone(id={}) but don't have that connection".format(msg.id))

    @output_message.register(OutgoingConnection)
    def _(msg):
        connections[msg.id] = Connection(msg.endpoint, 0, 0, msg.listener_id)

    @output_message.register(BytesIn)
    def _(msg):
        print(msg)
        connections[msg.id] = Connection(
            connections[msg.id].endpoint,
            connections[msg.id].i + msg.bytes,
            connections[msg.id].o,
            "fixme"
        )

    @output_message.register(BytesOut)
    def _(msg):
        connections[msg.id] = Connection(
            connections[msg.id].endpoint,
            connections[msg.id].i,
            connections[msg.id].o + msg.bytes,
            "fixme"
        )

    @output_message.register(WormholeClosed)
    def _(msg):
        print(f"Closed: {msg.result}")
        print("doing callback", we_closed_d)
        we_closed_d.callback(None)

    @output_message.register(Welcome)
    def _(msg):
        print("Connected.")
        if "motd" in msg.welcome:
            print(textwrap.fill(msg.welcome["motd"].strip(), 80, initial_indent="    ", subsequent_indent="    "))

    @output_message.register(GotMessageFromPeer)
    def _(msg):
        print(f"Message from peer: {msg}")
        # XXX part of experimental / PoC "explicit shutdown" flow;
        # probably move to FowlWormhole or similar if useful
        if json.loads(msg.message) == {"closing": True}:
            print("  -> closing!")
            fowl_wh._wormhole.send_message(json.dumps({"closed": True}).encode("utf8"))
            ##w.close()  # --> actually want to tell mainloop to exit
            when_explicitly_closed_d.callback(None)
            fowl_wh._wormhole.close()
        if json.loads(msg.message) == {"closed": True}:
            print("  -> closed!")
            fowl_wh._wormhole.send_message(json.dumps({"closed": True}).encode("utf8"))
            when_explicitly_closed_d.callback(None)

    fowl_wh = await create_fowl(config, output_message)
    fowl_wh.start()

    ##@daemon.set_trace
    def _(o, i, n):
        print("{} --[ {} ]--> {}".format(o, i, n))

    #XXX kind of experimental / PoC for "close down a session nicely";
    #move to FowlWormhole if actually useful
    async def disconnect_session():
        if peer_connected:
            ##print("disconnecting nicely, sending closing=True")
            fowl_wh._wormhole.send_message(json.dumps({"closing": True}).encode("utf8"))
            # XXX we want to wait for "the other side's" phase=closing message {"closed": True}
            # (what would {"closed": False} even mean, though?)
            ##print("waiting for explicitly_closed_d")  # ...but with brief timeout?
            # XXX (what's a good timeout here? "until user gets bored?")
            await race([
                when_explicitly_closed_d,
                deferLater(reactor, 5.1, lambda: None),
            ])
            print("explicitly closed!")

        try:
            await fowl_wh.close_wormhole()
        except wormhole_errors.LonelyError:
            # maybe just say nothing? why does the user care about
            # this? (they probably hit ctrl-c anyway, how else can you get here?)
            print("Wormhole closed without peer")
        print("done")

    ### XXX use PleaseCloseWormhole, approximately
    reactor.addSystemEventTrigger("before", "shutdown", lambda: ensureDeferred(disconnect_session()))

    if config.code is not None:
        fowl_wh.command(
            SetCode(config.code)
        )
    else:
        fowl_wh.command(
            AllocateCode(config.code_length)
        )

    for command in config.commands:
        fowl_wh.command(command)

    last_displayed = None
    while not we_closed_d.called:
        await deferLater(reactor, 1, lambda: None)
        if connections and last_displayed != set(connections.values()):
            for ident in sorted(connections.keys()):
                conn = connections[ident]
                print(f"{ident}: {humanize.naturalsize(conn.i)} in, {humanize.naturalsize(conn.o)} out")
            last_displayed = set(connections.values())


class SubchannelForwarder(Protocol):
    """
    This is the side of the protocol that was listening .. so it has
    opened a subchannel and sent the initial message. So the
    state-machine here is waiting for the reply before forwarding
    data.

    Forwards data to the `.other_protocol` from the Factory.
    """
    m = automat.MethodicalMachine()

    @m.state(initial=True)
    def await_confirmation(self):
        """
        Waiting for the reply from the other side.
        """

    @m.state()
    def evaluating(self):
        """
        Making the local connection.
        """

    @m.state()
    def forwarding_bytes(self):
        """
        All bytes go to the other side.
        """

    @m.state()
    def finished(self):
        """
        We are done (something went wrong or the wormhole session has been
        closed)
        """

    @m.input()
    def got_bytes(self, data):
        """
        received some number of bytes
        """

    @m.input()
    def no_confirmation(self):
        """
        Don't need to wait for a message
        """

    @m.input()
    def got_reply(self, msg):
        """
        Got a complete message (without length prefix)
        """

    @m.input()
    def remote_connected(self):
        """
        The reply message was positive
        """

    @m.input()
    def remote_not_connected(self, reason):
        """
        The reply message was negative
        """

    @m.input()
    def too_much_data(self, reason):
        """
        Too many bytes sent in the reply.
        """
        # XXX is this really an error in this direction? i think only
        # on the other side...

    @m.input()
    def subchannel_closed(self, reason):
        """
        Our subchannel has closed
        """

    @m.output()
    def find_message(self, data):
        """
        Buffer 'data' and determine if a complete message exists; if so,
        inject that input.
        """
        self._buffer += data
        bsize = len(self._buffer)

        if bsize >= 2:
            msgsize, = struct.unpack("!H", self._buffer[:2])
            if bsize > msgsize + 2:
                self.too_much_data()
                return
            elif bsize == msgsize + 2:
                msg = msgpack.unpackb(self._buffer[2:2 + msgsize])
                # this used to have a callLater(0, ..) for the
                # got_reply -- not sure this can happen "in practice",
                # but in testing at least the server can start sending
                # bytes _immediately_ so we must call synchronously..
                return self.got_reply(msg)
        return

    @m.output()
    def check_message(self, msg):
        """
        Initiate the local connection
        """
        if msg.get("connected", False):
            self.remote_connected()
        else:
            self.remote_not_connected(msg.get("reason", "Unknown"))

    @m.output()
    def send_queued_data(self):
        """
        Confirm to the other side that we've connected.
        """
        self.factory.other_proto.transport.resumeProducing()
        self.factory.other_proto._maybe_drain_queue()

    @m.output()
    def emit_remote_failed(self, reason):
        self.factory.message_out(
            RemoteConnectFailed(self.factory.conn_id, reason)
        )

    @m.output()
    def close_connection(self):
        """
        Shut down this subchannel.
        """
        self.transport.loseConnection()

    @m.output()
    def close_other_connection(self):
        """
        Shut down this subchannel.
        """
        self.factory.other_proto.transport.loseConnection()

    @m.output()
    def forward_bytes(self, data):
        """
        Send bytes to the other side
        """
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]
            self.factory.message_out(
                BytesOut(self.factory.conn_id, len(d))
            )
            self.factory.other_proto.transport.write(d)

#    @m.output()
#    def emit_incoming_lost(self):
#        # do we need a like "OutgoingLost"?
#        self.factory.message_out(IncomingLost(self.factory.conn_id, "Unknown"))

    await_confirmation.upon(
        no_confirmation,
        enter=forwarding_bytes,
        outputs=[]
    )
    await_confirmation.upon(
        got_bytes,
        enter=await_confirmation,
        outputs=[find_message]
    )
    await_confirmation.upon(
        too_much_data,
        enter=finished,
        outputs=[close_connection]
    )
    await_confirmation.upon(
        got_reply,
        enter=evaluating,
        outputs=[check_message]
    )
    await_confirmation.upon(
        subchannel_closed,
        enter=finished,
        outputs=[],####emit_incoming_lost],
    )

    evaluating.upon(
        remote_connected,
        enter=forwarding_bytes,
        outputs=[send_queued_data]
    )
    evaluating.upon(
        remote_not_connected,
        enter=evaluating,
        outputs=[emit_remote_failed, close_connection]
    )
    evaluating.upon(
        subchannel_closed,
        enter=finished,
        outputs=[]
    )
    forwarding_bytes.upon(
        got_bytes,
        enter=forwarding_bytes,
        outputs=[forward_bytes]
    )
    forwarding_bytes.upon(
        subchannel_closed,
        enter=finished,
        outputs=[close_other_connection]
    )

    finished.upon(
        got_reply,
        enter=finished,
        outputs=[]
    )

    do_trace = m._setTrace

    def connectionMade(self):
        self._buffer = b""
        # self.do_trace(lambda o, i, n: print("{} --[ {} ]--> {}".format(o, i, n)))

        self.local = self.factory.other_proto
        self.factory.other_proto.remote = self
        msg = msgpack.packb({
            "local-destination": self.factory.endpoint_str,
            "listener-id": self.factory.listener_id,
        })
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)

        self.factory.message_out(
            OutgoingConnection(self.factory.conn_id, self.factory.endpoint_str, self.factory.listener_id)
        )

        # MUST wait for reply first -- queueing all data until
        # then
        self.factory.other_proto.transport.pauseProducing()

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        if isinstance(reason, ConnectionDone):
            self.factory.message_out(
                OutgoingDone(self.factory.conn_id)
            )
        else:
            self.factory.message_out(
                OutgoingLost(self.factory.conn_id, str(reason))
            )
        self.subchannel_closed(str(reason))
        if self.factory.other_proto:
            self.factory.other_proto.transport.loseConnection()


class ConnectionForward(Protocol):
    """
    The protocol we speak on connections _we_ make to local
    servers. So this basically _just_ forwards bytes.
    """
    m = automat.MethodicalMachine()

    @m.state(initial=True)
    def forwarding_bytes(self):
        """
        All bytes go to the other side.
        """

    @m.state()
    def finished(self):
        """
        We are done (something went wrong or the wormhole session has been
        closed)
        """

    @m.input()
    def got_bytes(self, data):
        """
        received some number of bytes
        """

    @m.input()
    def stream_closed(self, reason):
        """
        The local server has closed our connection
        """

    @m.output()
    def forward_bytes(self, data):
        """
        Send bytes to the other side.

        This will be from the 'actual server' side to our local client
        """
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]
            self.factory.message_out(
                BytesIn(self.factory.conn_id, len(d))
            )
            self.factory.other_proto.transport.write(d)

    @m.output()
    def close_other_side(self, reason):
        try:
            if self.factory.other_proto:
                self.factory.other_proto.transport.loseConnection()
        except Exception:
            pass

    @m.output()
    def emit_incoming_done(self, reason):
        if isinstance(reason.value, ConnectionDone):
            self.factory.message_out(
                IncomingDone(self.factory.conn_id)
            )
        else:
            self.factory.message_out(
                IncomingLost(self.factory.conn_id, str(reason))
            )

    forwarding_bytes.upon(
        got_bytes,
        enter=forwarding_bytes,
        outputs=[forward_bytes]
    )
    forwarding_bytes.upon(
        stream_closed,
        enter=finished,
        outputs=[emit_incoming_done, close_other_side]
    )

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        self.stream_closed(reason)


class LocalServer(Protocol):
    """
    Listen on an endpoint. On every connection: open a subchannel,
    follow the protocol from _forward_loop above (ultimately
    forwarding data).
    """

    def connectionMade(self):
        self.queue = []
        self.remote = None
        self._conn_id = allocate_connection_id()

        # XXX refactor into SubchannelForwarder.onOpen or whatever, since that exists anyway?
        def got_proto(proto):
            return proto

        # XXX do we need registerProducer somewhere here?
        factory = Factory.forProtocol(SubchannelForwarder)
        factory.other_proto = self
        factory.conn_id = self._conn_id
        factory.listener_id = self.factory.listener_id
        factory.endpoint_str = self.factory.endpoint_str
        factory.config = self.factory.config
        factory.message_out = self.factory.message_out
        # Note: connect_ep here is the Wormhole provided
        # IClientEndpoint that lets us create new subchannels -- not
        # to be confused with the endpoint created from the "local
        # endpoint string"
        d = self.factory.connect_ep.connect(factory)
        d.addCallback(got_proto)

        def err(f):
            self.factory.message_out(
                WormholeError(
                    str(f.value),
                    # extra={"id": self._conn_id}
                )
            )
        d.addErrback(err)
        return d

    def _maybe_drain_queue(self):
        while self.queue:
            msg = self.queue.pop(0)
            self.remote.transport.write(msg)
        self.queue = None

    def connectionLost(self, reason):
        # XXX causes duplice local_close 'errors' in magic-wormhole ... do we not want to do this?)
        if self.remote is not None and self.remote.transport:
            self.remote.transport.loseConnection()

    def dataReceived(self, data):
        self.factory.message_out(
            BytesIn(self._conn_id, len(data))
        )
        self.remote.transport.write(data)


class Incoming(Protocol):
    """
    Handle an incoming Dilation subchannel. This will be from a
    listener on the other end of the wormhole.

    There is an opening message, and then we forward bytes.

    The opening message is a length-prefixed blob; the first 2
    bytes of the stream indicate the length (an unsigned short in
    network byte order).

    The message itself is msgpack-encoded.

    A single reply is produced, following the same format: 2-byte
    length prefix followed by a msgpack-encoded payload.

    The opening message contains a dict like::

        {
            "local-desination": "tcp:localhost:1234",
        }

    The "forwarding" side (i.e the one that opened the subchannel)
    MUST NOT send any data except the opening message until it
    receives a reply from this side. This side (the connecting
    side) may deny the connection for any reason (e.g. it might
    not even try, if policy says not to).

    XXX want some opt-in / permission on this side, probably? (for
    now: anything goes)
    """

    m = automat.MethodicalMachine()
    set_trace = m._setTrace

    @m.state(initial=True)
    def await_message(self):
        """
        The other side must send us a message
        """

    @m.state()
    def local_policy_check(self):
        """
        A connection has come in; we must check our policy
        """

    @m.state()
    def local_connect(self):
        """
        The initial message tells us where to connect locally
        """

    @m.state()
    def forwarding_bytes(self):
        """
        We are connected and have done the proper information exchange;
        now we merely forward bytes.
        """

    @m.state()
    def finished(self):
        """
        Completed the task of forwarding (e.g. client closed connection,
        subchannel closed, fatal error, etc)
        """

    @m.input()
    def policy_bad(self, msg):
        """
        The local policy check has failed (not allowed)
        """

    @m.input()
    def policy_ok(self, msg):
        """
        The local policy check has succeeded (allowed)
        """

    @m.input()
    def got_bytes(self, data):
        """
        We received some bytes
        """

    @m.input()
    def too_much_data(self, reason):
        """
        We received too many bytes (for the first message).
        """

    @m.input()
    def got_initial_message(self, msg):
        """
        The entire initial message is received (`msg` excludes the
        length-prefix but it is not yet parsed)
        """

    @m.input()
    def subchannel_closed(self, reason):
        """
        This subchannel has been closed
        """

    @m.input()
    def connection_made(self):
        """
        We successfully made the local connection
        """

    @m.input()
    def connection_failed(self, reason):
        """
        Making the local connection failed
        """

    @m.output()
    def close_connection(self, reason):
        """
        We wish to close this subchannel
        """
        self.transport.loseConnection()

    @m.output()
    def close_local_connection(self):
        """
        We wish to close this subchannel
        """
        if self._local_connection and self._local_connection.transport:
            self._local_connection.transport.loseConnection()

    @m.output()
    def forward_data(self, data):
        assert self._buffer is None, "Internal error: still buffering"
        assert self._local_connection is not None, "expected local connection by now"
        self._local_connection.transport.write(data)
        self.factory.message_out(
            BytesOut(self._conn_id, len(data))
        )

    @m.output()
    def find_message(self, data):
        """
        Buffer this data and determine if we have a single message yet
        """
        # state-machine shouldn't allow this, but just to be sure
        assert self._buffer is not None, "Internal error: buffer is gone"

        self._buffer += data
        bsize = len(self._buffer)
        if bsize >= 2:
            expected_size, = struct.unpack("!H", self._buffer[:2])
            if bsize >= expected_size + 2:
                first_msg = self._buffer[2:2 + expected_size]
                self._buffer = None
                # there should be no "leftover" data
                if bsize > 2 + expected_size:
                    ##raise RuntimeError("protocol error: more than opening message sent")
                    self.too_much_data("Too many bytes sent")
                    return
                # warning: recursive state-machine message
                self.got_initial_message(msgpack.unpackb(first_msg))

    @m.output()
    def send_negative_reply(self, reason):
        """
        Tell our peer why we're closing them
        """
        self._negative(reason)

    @m.output()
    def send_negative_reply_subchannel(self):
        """
        Tell our peer local policy doesn't let the connection happen.
        """
        pass#self._negative("XXXAgainst local policy")

    def _negative(self, reason):
        msg = msgpack.packb({
            "connected": False,
            "reason": reason,
        })
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)


    @m.output()
    def send_positive_reply(self):
        """
        Reply to the other side that we've connected properly
        """
        # XXX there's other sections like this; factor to pack_netstring() or something
        msg = msgpack.packb({
            "connected": True,
        })
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)

    @m.output()
    def emit_incoming_connection(self, msg):
        self.factory.message_out(
            IncomingConnection(self._conn_id, msg["local-destination"], msg.get("listener-id", None))
        )

    @m.output()
    def do_policy_check(self, msg):
        # note: do this policy check after the IncomingConnection
        # message is emitted (otherwise there will be cases where we
        # emit _just_ a IncomingLost which is confusing)
        if self.factory.config.connect_policy is not None:
            ep = clientFromString(reactor, msg["local-destination"])
            if not self.factory.config.connect_policy.can_connect(ep):
                # warning: synchronous state-machine use
                self.policy_bad(msg)
            else:
                # warning: synchronous state-machine use
                self.policy_ok(msg)

    @m.output()
    def local_disconnect(self):
        self._negative("Against local policy")
        self.transport.loseConnection()

    @m.output()
    def emit_incoming_lost(self, msg):
        self.factory.message_out(
            IncomingLost(
                self._conn_id,
                f"Incoming connection against local policy: {msg['local-destination']}"
            )
        )

    @m.output()
    def establish_local_connection(self, msg):
        """
        FIXME
        """
        ep = clientFromString(reactor, msg["local-destination"])

        factory = Factory.forProtocol(ConnectionForward)
        factory.other_proto = self
        factory.config = self.factory.config
        factory.conn_id = self._conn_id
        factory.message_out = self.factory.message_out

#emit was here

        d = ep.connect(factory)

        def bad(fail):
            # ideally maybe want a @output method send_incoming_lost or so?
            self.factory.message_out(
                IncomingLost(
                    self._conn_id,
                    f"{msg['local-destination']}: {fail.getErrorMessage()}",
                )
            )
            reactor.callLater(0, lambda: self.connection_failed(fail.getErrorMessage()))
            return None

        def assign(proto):
            # if we hit the error-case above, we "handled" it so want
            # to return None -- but this pushes us into the "success"
            # / callback side, albiet with "None" as the value
            self._local_connection = proto
            if self._local_connection is not None:
                reactor.callLater(0, lambda: self.connection_made())
            return proto
        d.addErrback(bad)
        d.addCallback(assign)

    await_message.upon(
        got_bytes,
        enter=await_message,
        outputs=[find_message]
    )
    await_message.upon(
        too_much_data,
        enter=finished,
        outputs=[close_connection]
    )
    await_message.upon(
        got_initial_message,
        enter=local_policy_check,
        outputs=[emit_incoming_connection, do_policy_check]
    )

    local_policy_check.upon(
        policy_ok,
        enter=local_connect,
        outputs=[establish_local_connection]
    )
    local_policy_check.upon(
        policy_bad,
        enter=finished,
        outputs=[local_disconnect, emit_incoming_lost]
    )

    await_message.upon(
        subchannel_closed,
        enter=finished,
        outputs=[],
    )
    local_connect.upon(
        connection_made,
        enter=forwarding_bytes,
        outputs=[send_positive_reply]
    )
    local_connect.upon(
        connection_failed,
        enter=finished,
        outputs=[send_negative_reply, close_connection]
    )
    # this will happen if our policy doesn't allow this port, for example
    local_connect.upon(
        subchannel_closed,
        enter=finished,
        outputs=[],
    )

    forwarding_bytes.upon(
        got_bytes,
        enter=forwarding_bytes,
        outputs=[forward_data]
    )
    forwarding_bytes.upon(
        subchannel_closed,
        enter=finished,
        outputs=[close_local_connection]
    )

    finished.upon(
        subchannel_closed,
        enter=finished,
        outputs=[]  # warning? why does this happen?
    )

    # logically kind-of makes sense, but how are we getting duplicate closes?
    # finished.upon(
    #     subchannel_closed,
    #     enter=finished,
    #     outputs=[],
    # )

    # API methods from Twisted
    # Ideally all these should do is produce some input() to the machine
    def connectionMade(self):
        """
        Twisted API
        """
        self._conn_id = allocate_connection_id()
        # XXX first message should tell us where to connect, locally
        # (want some kind of opt-in on this side, probably)
        self._buffer = b""
        self._local_connection = None
        # def tracer(o, i, n):
        #     print("{} --[ {} ]--> {}".format(o, i, n))
        # self.set_trace(tracer)

    def connectionLost(self, reason):
        """
        Twisted API
        """
#        self.factory.message_out(
#            IncomingLost(self._conn_id, reason)
#        )
        self.subchannel_closed(reason)

    def dataReceived(self, data):
        """
        Twisted API
        """
        self.got_bytes(data)


##XXX needs a shutdown path
## this is currently via "cancel"
## so need a "await FowlDaemon.shutdown()" or similar which can do
## async stuff like shut down all listeners, etc etc

## refactoring _forward_loop etc
##XXX doesn't exist yet but ... @implementer(IWormholeDelegate)


class FowlWormhole:
    """
    Does I/O related to a wormhole connection.
    Co-ordinates between the wormhole, user I/O and the daemon state-machine.
    """

    def __init__(self, reactor, wormhole, daemon, config):
        self._reactor = reactor
        self._listening_ports = []
        self._wormhole = wormhole
        self._config = config
        self._daemon = daemon
        self._done = When() # we have shut down completely
        self._connected = When()  # our Peer has connected
        self._got_welcome = When()  # we received the Welcome from the server
        self.connect_ep = self.control_proto = None

    # XXX wants to be an IService?
    async def stop(self):
        for port in self._listening_ports:
            # note to self port.stopListening and port.loseConnection are THE SAME
            port.stopListening()
        if self.control_proto is not None:
            self.control_proto.transport.loseConnection()
            await self.control_proto.when_done()
        await self._wormhole.close()
        # XXX put "session ending" code here, if it's useful

    # XXX wants to be an IService?
    def start(self):

        # tie "we got a code" into the state-machine
        ensureDeferred(self._wormhole.get_code()).addCallbacks(
            self._daemon.code_allocated,
            self._handle_error,
        )

        # pass on the welcome message
        ensureDeferred(self._wormhole.get_welcome()).addCallbacks(
            lambda hello: self._daemon.got_welcome(hello),
            self._handle_error,
        )

        # when we get the verifier and versions, we emit "peer
        # connected"
        # (note that wormhole will "error" these Deferreds when the
        # wormhole shuts down early, e.g. with LonelyError -- but we
        # handle that elsewhere, so ignore errors here)
        results_d = DeferredList(
            [
                self._wormhole.get_verifier(),
                self._wormhole.get_versions(),
            ],
            consumeErrors=True,
        )

        @results_d.addCallback
        def got_results(results):
            for ok, exc in results:
                if not ok:
                    self._handle_error(exc)
                    return
            verifier = results[0][1]
            versions = results[1][1]
            ###print(f"versions: {versions}")
            # XXX should "do stuff" with this, e.g. per
            # https://github.com/meejah/fowl/issues/45 at least "we
            # speak Fowl Application Protocol" or so

            d = self._do_dilate()
            @d.addCallback
            def did_dilate(arg):
                self._daemon.peer_connected(verifier, versions)
                return arg

        # hook up "incoming message" to input
        def got_message(plaintext):
            self._daemon.got_message(plaintext)
            ensureDeferred(self._wormhole.get_message()).addCallback(
                got_message,
            ).addErrback(self._handle_error)
        ensureDeferred(self._wormhole.get_message()).addCallback(
            got_message,
        ).addErrback(self._handle_error)

        # hook up wormhole closed to input
        def was_closed(why):
            if isinstance(why, str):
                reason = why
            elif isinstance(why.value, wormhole_errors.LonelyError):
                reason = "lonely"
            elif why.value.args:
                reason = why.value.args[0]
            else:
                reason = str(why)
            self._done.trigger(self._reactor, reason)
            self._daemon.shutdown(reason)
        ensureDeferred(self._wormhole._closed_observer.when_fired()).addBoth(was_closed)

    # public API methods

    async def close_wormhole(self):
        """
        Shut down the wormhole
        """
        # XXX see also the whole "how to shutdown half-close etc"
        await self._wormhole.close()
        # once the wormhole "actually" closes, the state-machine will
        # trigger our "stop" codepath

    def command(self, command: FowlCommandMessage) -> None:
        """
        Process an incoming command
        """

        @functools.singledispatch
        async def cmd(msg):
            print(f"Unprocessed command: {msg}")

        @cmd.register(AllocateCode)
        async def _(msg):
            if msg.length:
                self._wormhole.allocate_code(msg.length)
            else:
                self._wormhole.allocate_code()

        @cmd.register(SetCode)
        async def _(msg):
            self._wormhole.set_code(msg.code)

        @cmd.register(LocalListener)
        async def _(msg):
            await self.when_connected()
            assert self.connect_ep is not None, "need connect ep"
            await _local_to_remote_forward(self._reactor, self._config, self.connect_ep, self._listening_ports.append, self._daemon._message_out, msg)
            # XXX cheating? private access (_daemon._message_out)

        @cmd.register(RemoteListener)
        async def _(msg):
            await self.when_connected()
            assert self.control_proto is not None, "need control_proto"
            msg = await _remote_to_local_forward(self.control_proto, msg)
            self._daemon._message_out(msg)
            # XXX cheating? private access (_daemon._message_out)

        @cmd.register(GrantPermission)
        async def _(msg):
            self._config.connect_policy.ports.extend(msg.connect)
            self._config.listen_policy.ports.extend(msg.listen)
            print(
                "Permission granted. Listen={}, Connect={}".format(
                    self._config.listen_policy,
                    self._config.connect_policy,
                ),
                file=self._config.stderr,
                flush=True,
            )

        @cmd.register(DangerDisablePermissionCheck)
        async def _(msg):
            try:
                self._config.connect_policy = AnyConnectPolicy()
                self._config.listen_policy = AnyListenPolicy()
                print("DANGER. All connect / listen endpoints allowed.", file=self._config.stderr, flush=True)
            except Exception as e:
                print("BAD", type(e))

        @cmd.register(Ping)
        async def _(msg):
            if hasattr(self._wormhole, "_boss"):
                if hasattr(self._wormhole._boss, "_D"):
                    if self._wormhole._boss._D._manager is not None:
                        def got_pong(round_trip):
                            self._daemon._message_out(Pong(msg.ping_id, round_trip))
                        self._wormhole._boss._D._manager.send_ping(msg.ping_id, got_pong)
                    else:
                        raise Exception("Cannot send ping: not in Dilation")
                else:
                    raise Exception("Cannot send ping: no Dilation manager")
            else:
                raise Exception("Cannot send ping: no boss")

        ensureDeferred(cmd(command)).addErrback(self._handle_error)

    # our own callbacks / notifications

    async def get_welcome(self):
        return await self._got_welcome.when_triggered()

    def when_done(self):
        return self._done.when_triggered()

    def when_connected(self):
        """
        Our peer has connected.

        Fires with the "verifier" of the peer (this is an optional
        measure whereby users may compare these; if they're identical
        they are communicating with the intended partner)
        """
        return self._connected.when_triggered()

    def _do_dilate(self):
        self.control_ep, self.connect_ep, self.listen_ep = self._wormhole.dilate(
            transit_relay_location="tcp:magic-wormhole-transit.debian.net:4001",
        )
        d = ensureDeferred(self._post_dilation_setup())
        d.addErrback(self._handle_error)
        return d

    def _handle_error(self, f):
        # hmm, basically any of the "wormhole callbacks" we asked for
        # stuff will definitely "errback" when we end the wormhole --
        # sometimes with WormholeClosed, or LonelyError -- but also we
        # should feedback those into the state-machine ONLY from one,
        # like get_message (?) -- but what do we do with the others?
        if isinstance(f.value, (wormhole_errors.WormholeClosed, wormhole_errors.LonelyError)):
            pass
        else:
            self._report_error(f.value)

    def _report_error(self, e):
        self._daemon._message_out(
            WormholeError(str(e))
        )

    async def _post_dilation_setup(self):
        # listen for commands from the other side on the control channel
        assert self.control_ep is not None, "Need control connection"
        fac = Factory.forProtocol(Commands)
        fac.config = self._config
        fac.message_out = self._daemon._message_out  # XXX
        fac.reactor = self._reactor
        fac.connect_ep = self.connect_ep  # so we can pass it command handlers
        self.control_proto = await self.control_ep.connect(fac)

        # listen for incoming subchannel OPENs
        in_factory = Factory.forProtocol(Incoming)
        in_factory.config = self._config
        in_factory.connect_ep = self.connect_ep
        in_factory.message_out = self._daemon._message_out
        listen_port = await self.listen_ep.listen(in_factory)
        self._listening_ports.append(listen_port)

        await self._wormhole.get_unverified_key()
        verifier_bytes = await self._wormhole.get_verifier()  # might WrongPasswordError
        self._connected.trigger(self._reactor, verifier_bytes)



# FowlDaemon is the state-machine
#  - ultimately, it goes some notifications from 'the wormhole' but only via the I/O thing
#  - no "async def" / Deferred-returning methods
#  - no I/O
#
# FowlWormhole is "the I/O thing"
#  - can do async
#  - can do I/O
#  - proxies I/O and async'ly things

from .daemon import FowlDaemon  # noqa: E402


def maybe_int(i):
    if i is None:
        return None
    return int(i)


# XXX FIXME
# NOTES
# 
# since we want "fowl" to use "fowld" we have two options:
# - start a subprocess and use stdin/out
# - sans-io style (send "messages" in / out of _forward_loop or so)
#
# Would like the second; so we can interact in unit-tests (or here)
# via parsed commands. e.g. we have an AGT union-type, and every
# input-message is a class
def fowld_command_to_json(msg: FowlCommandMessage) -> dict:
    """
    Turn the given `msg` into a corresponding JSON-friendly dict
    (suitable for json.dumps() for example)
    """

    js = asdict(msg)
    # XXX maybe a @singledispatch would give better feedback when we
    # miss one...
    @functools.singledispatch
    def output_command(msg):
        raise RuntimeError(f"Unhandled message: {msg}")

    @output_command.register(GrantPermission)
    def _(msg):
        js["kind"] = "grant-permission"

    @output_command.register(DangerDisablePermissionCheck)
    def _(msg):
        js["kind"] = "danger-disable-permission-check"

    @output_command.register(LocalListener)
    def _(msg):
        js["kind"] = "local"
        js["listen"] = msg.listen
        js["connect"] = msg.connect

    @output_command.register(RemoteListener)
    def _(msg):
        js["kind"] = "remote"
        js["listen"] = msg.listen
        js["connect"] = msg.connect

    @output_command.register(AllocateCode)
    def _(msg):
        js["kind"] = "allocate-code"
        js["length"] = getattr(msg, "length", None)

    @output_command.register(SetCode)
    def _(msg):
        js["kind"] = "set-code"
        js["code"] = msg.code

    @output_command.register(Ping)
    def _(msg):
        js["kind"] = "ping"
        js["ping_id"] = msg.ping_id

    output_command(msg)
    return js


def parse_fowld_command(json_str: str) -> FowlCommandMessage:
    """
    Parse the given JSON message assuming is a command for fowld
    """
    cmd = json.loads(json_str)
    try:
        kind = cmd["kind"]
        del cmd["kind"]
    except KeyError:
        raise ValueError("No 'kind' in command")

    def parser(cls, item_parsers, optional_parsers):
        def parse(js):
            args = {}
            for k, process in item_parsers:
                try:
                    args[k] = js[k] if process is None else process(js[k])
                except KeyError:
                    raise ValueError('"{}" is missing'.format(k))
            for k, process in optional_parsers:
                try:
                    args[k] = js[k] if process is None else process(js[k])
                except KeyError:
                    pass
            return cls(**args)
        return parse

    def is_valid_port(port):
        if isinstance(port, int) and port >= 1 and port < 65536:
            return port
        raise ValueError(f"Invalid port: {port}")

    def port_list(proposed):
        if isinstance(proposed, list):
            return [
                is_valid_port(port) for port in proposed
            ]
        raise ValueError("Port-list must be a list of ints")

    kind_to_message = {
        "allocate-code": parser(AllocateCode, [], [("length", maybe_int)]),
        "set-code": parser(SetCode, [("code", None)], []),
        "local": parser(LocalListener, [("listen", None), ("connect", None)], []),
        "remote": parser(RemoteListener, [("listen", None), ("connect", None)], []),
        "grant-permission": parser(GrantPermission, [("listen", port_list), ("connect", port_list)], []),
        "danger-disable-permission-check": parser(DangerDisablePermissionCheck, [], []),
        "ping": parser(Ping, [("ping_id", None)], []),
    }
    return kind_to_message[kind](cmd)


def fowld_output_to_json(msg: FowlOutputMessage) -> dict:
    """
    Turn the given `msg` into a corresponding JSON-friendly dict
    (suitable for json.dumps() for example)
    """
    # XXX maybe a @singledispatch would give better feedback when we
    # miss one...
    js = asdict(msg)
    js["kind"] = {
        Welcome: "welcome",
        WormholeClosed: "closed",
        CodeAllocated: "code-allocated",
        PeerConnected: "peer-connected",
        Listening: "listening",
        RemoteListeningFailed: "remote-listening-failed",
        RemoteListeningSucceeded: "remote-listening-succeeded",
        RemoteConnectFailed: "remote-connect-failed",
        OutgoingConnection: "outgoing-connection",
        OutgoingLost: "outgoing-lost",
        OutgoingDone: "outgoing-done",
        IncomingConnection: "incoming-connection",
        IncomingLost: "incoming-lost",
        IncomingDone: "incoming-done",
        BytesIn: "bytes-in",
        BytesOut: "bytes-out",
        WormholeError: "error",
        Pong: "pong",
    }[type(msg)]
    return js


def parse_fowld_output(json_str: str) -> FowlOutputMessage:
    """
    Parse the given JSON message assuming it came from fowld.
    :raises: ValueError if it's an invalid message.
    """
    cmd = json.loads(json_str)
    try:
        kind = cmd["kind"]
        del cmd["kind"]
    except KeyError:
        raise ValueError("No 'kind' in command")

    def parser(cls, item_parsers):
        def parse(js):
            args = {}
            for k, process in item_parsers:
                try:
                    args[k] = js[k] if process is None else process(js[k])
                except KeyError:
                    raise ValueError(f'"{k}" is missing')
            return cls(**args)
        return parse

    kind_to_message = {
        "welcome": parser(Welcome, [("url", None), ("welcome", None)]),
        "wormhole-closed": parser(WormholeClosed, [("result", None)]),
        "allocate-code": parser(AllocateCode, [("length", maybe_int)]),
        "set-code": parser(SetCode, [("code", None)]),
        "code-allocated": parser(CodeAllocated, [("code", None)]),
        "peer-connected": parser(PeerConnected, [("verifier", binascii.unhexlify), ("versions", None)]),
        "listening": parser(Listening, [("listener_id", None), ("listen", None), ("connect", None)]),
        "remote-listening-failed": parser(RemoteListeningFailed, [("listen", None), ("reason", None)]),
        "remote-listening-succeeded": parser(RemoteListeningSucceeded, [("listen", None), ("connect", None), ("listener_id", None)]),
        "remote-connect-failed": parser(RemoteConnectFailed, [("id", int), ("reason", None)]),
        "outgoing-connection": parser(OutgoingConnection, [("id", int), ("endpoint", None), ("listener_id", None)]),
##        "outgoing-lost": parser(),
        "outgoing-done": parser(OutgoingDone, [("id", int)]),
        "incoming-connection": parser(IncomingConnection, [("id", int), ("endpoint", None), ("listener_id", None)]),
        "incoming-lost": parser(IncomingLost, [("id", int), ("reason", None)]),
        "incoming-done": parser(IncomingDone, [("id", int)]),
        "bytes-in": parser(BytesIn, [("id", int), ("bytes", int)]),
        "bytes-out": parser(BytesOut, [("id", int), ("bytes", int)]),
        "closed": parser(WormholeClosed, [("result", str)]),
        "pong": parser(Pong, [("ping_id", bytes), ("time_of_flight", float)]),
    }
    return kind_to_message[kind](cmd)



async def create_fowl(config, output_fowl_message):
    w = await wormhole_from_config(reactor, config)

    if config.debug_file:
        kind = "invite" if config.code is None else "accept"
        w.debug_set_trace(kind, which="B N M S O K SK R RC L C T", file=config.debug_file)

    def command_message(msg):
        if isinstance(msg, PleaseCloseWormhole):
            d = ensureDeferred(fowl.close_wormhole())
            d.addErrback(lambda f: print(f"Error closing: {f.value}"))

    sm = FowlDaemon(config, output_fowl_message, command_message)

#    @sm.set_trace
    def _(start, edge, end):
        print(f"trace: {start} --[ {edge} ]--> {end}")
    fowl = FowlWormhole(reactor, w, sm, config)
    return fowl

async def forward(reactor, config):
    """
    Set up a wormhole and process commands relating to forwarding.

    That is, run the main loop of the forward:
       - perform setup (version stuff etc)
       - wait for commands (as single-line JSON messages) on stdin
       - write results to stdout (as single-line JSON messages)
       - service subchannels

    See docs/messages.rst for more
    """
    def output_fowl_message(msg):
        js = fowld_output_to_json(msg)
        print(
            json.dumps(js),
            file=config.stdout,
            flush=True,
        )


    fowl = await create_fowl(config, output_fowl_message)
    fowl.start()

    # arrange to read incoming commands from stdin
    create_stdio = config.create_stdio or StandardIO
    dispatch = LocalCommandDispatch(config, fowl)
    create_stdio(dispatch)

    try:
        await Deferred()
    except CancelledError:
        await fowl.stop()


async def _local_to_remote_forward(reactor, config, connect_ep, on_listen, on_message, cmd):
    """
    Listen locally, and for each local connection create an Outgoing
    subchannel which will connect on the other end.
    """
    # XXX these lines are "uncovered" but we clearly run them ... so
    # something wrong with subprocess coverage?? again???
    ep = serverFromString(reactor, cmd.listen)

    if config.listen_policy is not None:
        if not config.listen_policy.can_listen(ep):
            raise ValueError('Policy doesn\'t allow listening on "{}"'.format(ep._port))

    listener_id = b16encode(os.urandom(3)).decode("ascii")
    factory = Factory.forProtocol(LocalServer)
    factory.config = config
    factory.listener_id = listener_id
    factory.endpoint_str = cmd.connect
    factory.connect_ep = connect_ep
    factory.message_out = on_message
    port = await ep.listen(factory)
    on_listen(port)
    on_message(Listening(listener_id, cmd.listen, cmd.connect))


async def _remote_to_local_forward(control_proto, cmd):
    """
    Ask the remote side to listen on a port, forwarding back here
    (where our Incoming subchannel will be told what to connect
    to).
    """
    reply = await control_proto.request_forward(cmd)
    return reply


class Commands(Protocol):
    """
    Listen for (and send) commands over the command subchannel
    """

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self._ports = []
        self._done = When()
        # outstanding requests, awaiting replies
        self._remote_requests = dict()
        self._local_requests = dict()
        self._create_request_id = count(1)

    def request_forward(self, cmd):
        rid = next(self._create_request_id)
        msg = msgpack.packb({
            "kind": "remote-to-local",
            "listen-endpoint": cmd.listen,
            "connect-endpoint": cmd.connect,
            "reply-id": rid,
        })
        d = Deferred()
        self._local_requests[rid] = d, cmd
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)
        return d

    def when_done(self):
        return self._done.when_triggered()

    def dataReceived(self, data):
        # XXX can we depend on data being "one message"? or do we need length-prefixed?
        bsize = len(data)
        assert bsize >= 2, "expected at least 2 bytes"
        expected_size, = struct.unpack("!H", data[:2])
        assert bsize == expected_size + 2, "data has more than the message: {} vs {}: {}".format(bsize, expected_size + 2, repr(data[:55]))
        msg = msgpack.unpackb(data[2:])
        if msg["kind"] == "listener-response":
            rid = int(msg["reply-id"])
            d, original_cmd = self._local_requests[rid]
            del self._local_requests[rid]

            if msg["listening"]:
                d.callback(RemoteListeningSucceeded(msg.get("listener-id"), original_cmd.listen, original_cmd.connect))
            else:
                d.callback(RemoteListeningFailed(original_cmd.listen, msg.get("reason", "Missing reason")))

        elif msg["kind"] == "remote-to-local":
            rid = int(msg["reply-id"])
            assert rid >= 1 and rid < 2**53, "reply-id out of range"
            self._remote_requests[rid] = None

            listen_ep = serverFromString(reactor, msg["listen-endpoint"])

            if self.factory.config.listen_policy is not None:
                if not self.factory.config.listen_policy.can_listen(listen_ep):
                    self._reply_negative(rid, "Against local policy")
                    self.transport.loseConnection()
                    return

            #XXX FIXME why did i have to add 'listener_id' code in two places??
            listener_id = b16encode(os.urandom(3)).decode("ascii")
            factory = Factory.forProtocol(LocalServer)
            factory.config = self.factory.config
            factory.message_out = self.factory.message_out
            factory.connect_ep = self.factory.connect_ep
            factory.endpoint_str = msg["connect-endpoint"]
            factory.listener_id = listener_id

            # XXX this can fail (synchronously) if address in use (e.g.)
            d = listen_ep.listen(factory)
            self._remote_requests[rid] = d

            def got_port(port):
                self._reply_positive(rid, listener_id)
                self.factory.message_out(
                    Listening(
                        listener_id,
                        msg["listen-endpoint"],
                        msg["connect-endpoint"],
                    )
                )
                self._ports.append(port)
                return port

            def error(f):
                self._reply_negative(rid, f.getErrorMessage())
                self.factory.message_out(
                    WormholeError(
                        'Failed to listen on "{}": {}'.format(
                            msg["listen-endpoint"],
                            f.value,
                        )
                    )
                )
            d.addCallback(got_port)
            d.addErrback(error)
            # XXX should await port.stopListening() somewhere...at the appropriate time
        else:
            self.factory.message_out(
                WormholeError(
                    "Unknown control command: {msg[kind]}",
                )
            )

    def _reply_positive(self, rid, listener_id):
        """
        Send a positive reply to a remote request
        """
        return self._reply_generic(rid, listening=True, listener_id=listener_id)

    def _reply_negative(self, rid, reason=None):
        """
        Send a negative reply to a remote request
        """
        return self._reply_generic(rid, listening=False, reason=reason)

    def _reply_generic(self, rid, listening, reason=None, listener_id=None):
        """
        Send a positive or negative reply to a remote request
        """
        if rid in self._remote_requests:
            content = {
                "kind": "listener-response",
                "reply-id": rid,
                "listener-id": listener_id,
                "listening": bool(listening),
            }
            if reason is not None and not listening:
                content["reason"] = str(reason)
            reply = msgpack.packb(content)
            prefix = struct.pack("!H", len(reply))
            self.transport.write(prefix + reply)
            del self._remote_requests[rid]
        else:
            raise ValueError(
                "Replied to '{}' but it is not outstanding".format(rid)
            )

    async def _unregister_ports(self):
        unreg = self._ports
        self._ports = []
        for port in unreg:
            # "might return Deferred" sucks...
            d = port.stopListening()
            if d is not None:
                await d

    def connectionLost(self, reason):
        d = ensureDeferred(self._unregister_ports())

        @d.addCallback
        def _(_):
            self._done.trigger(self.factory.reactor, None)


class LocalCommandDispatch(LineReceiver):
    """
    Wait for incoming commands (as lines of JSON) and dispatch them.
    """
    delimiter = b"\n"

    def __init__(self, cfg, fowl):
        super(LocalCommandDispatch, self).__init__()
        self.config = cfg
        self.fowl = fowl

    def connectionMade(self):
        pass

    def lineReceived(self, line):
        try:
            cmd = parse_fowld_command(line)
            self.fowl.command(cmd)
        except Exception as e:
            print(f"{line.strip()}: failed: {e}")


async def get_tor(
        reactor,
        tor_control_port=None,
        stderr=sys.stderr):
    """
    Create an ITorManager suitable for use with wormhole.create()

    This will attempt to connect to well-known ports and failing that
    will launch its own tor subprocess.
    """
    from wormhole._interfaces import ITorManager

    try:
        import txtorcon
    except ImportError:
        raise click.UsageError(
            'Cannot find txtorcon library (try "pip install txtorcon")'
        )

    # Connect to an existing Tor, or create a new one. If we need to
    # launch an onion service, then we need a working control port (and
    # authentication cookie). If we're only acting as a client, we don't
    # need the control port.

    # we could add a way for the user to configure the Tor endpoint if
    # desired .. but for now we just try the usual suspects, then
    # launch one if that fails.

    # control_ep = clientFromString(reactor, tor_control_port)
    # with all defaults, tries:
    # unix:/var/run/tor/control, localhost:9051, localhost:9151
    try:
        tor = await txtorcon.connect(reactor)
    except Exception as e:
        print(
            f"Failed to connect to Tor: {e}\nAttempting to run Tor",
            file=stderr,
            flush=True,
        )

        def progress(done, tag, summary):
            print(f"Tor: {done}: {tag}: {summary}", file=stderr)

        try:
            tor = await txtorcon.launch(
                reactor,
                progress_updates=progress,
                # data_directory=,
                # tor_binary=,
            )
        except Exception as e:
            raise click.UsageError(
                f"Failed to connect to Tor, then failed to launch: {e}",
            )

    directlyProvides(tor, ITorManager)
    return tor
