from __future__ import print_function

import os
import sys
import json
import binascii
import functools
import struct
import signal
from typing import IO, Callable, TextIO
from functools import partial
from itertools import count

import click
import humanize
from attrs import frozen, define, asdict, Factory as AttrFactory

from rich.live import Live

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
from zope.interface import directlyProvides, implementer
from wormhole.cli.public_relay import RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL, TRANSIT_RELAY
import wormhole.errors as wormhole_errors
from wormhole import SubchannelAddress

from .observer import When, Next
from .tcp import allocate_tcp_port
from .messages import (
    SetCode,
    AllocateCode,
    GrantPermission,
    DangerDisablePermissionCheck,
    RemoteListener,
    LocalListener,

    Welcome,
    Listening,
    ListeningFailed,
    AwaitingConnect,
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

    Ping,
    Pong,

    FowlOutputMessage,
    FowlCommandMessage,

    PleaseCloseWormhole,
)
from .policy import IClientListenPolicy, IClientConnectPolicy, AnyConnectPolicy, AnyListenPolicy
from .status import _StatusTracker
from .visual import render_status



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
    output_debug_messages: TextIO = None  # Option<Writable>
    output_status: TextIO = None  # Option<Readable>


async def wormhole_from_config(reactor, config, on_status, wormhole_create=None):
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
        dilation=True,
        versions={
            "fowl": {
                "features": SUPPORTED_FEATURES,
            }
        },
        on_status_update=on_status,
    )
    if config.debug_state:
        w.debug_set_trace("forward", file=config.stdout)
    return w


@frozen
class Connection:
    endpoint: str
    i: int = 0
    o: int = 0
    unique_name: str = "unknown"



async def frontend_accept_or_invite(reactor, config):
    """
    This runs the core of the default 'fowl' behavior:
      - creates a code (or: consumes a code)
      - creates any local listeners
      - creates any remote listeners
      - await incoming subchannels:
        - attempt local connection (if permitted by policy)
        - forward traffic until one side closes
      - await connects on local listeners:
        - open subchannel
        - request far-side connection
        - forward traffic until one side closes
    """

    status_tracker = _StatusTracker()

    fowl_wh = await create_fowl(config, status_tracker)
    fowl_wh.start()

    # testing a TUI style output UI, maybe optional?
    def render():
        return render_status(status_tracker.current_status, reactor.seconds())
    from rich.console import Console
    console = Console(force_terminal=True)
    live = Live(get_renderable=render, console=console)

    ### XXX use PleaseCloseWormhole, approximately
    reactor.addSystemEventTrigger("before", "shutdown", lambda: ensureDeferred(fowl_wh.disconnect_session()))

    if config.code is not None:
        fowl_wh.command(
            SetCode(config.code)
        )
    else:
        fowl_wh.command(
            AllocateCode(config.code_length)
        )

    async def issue_commands():
        await fowl_wh.when_connected()
        for command in config.commands:
            fowl_wh.command(command)
    d = ensureDeferred(issue_commands())

    @d.addErrback
    def command_issue_failed(f):
        print(f"Failed to issue command: {f}")

    done_d = fowl_wh.when_done()

    # debugging: "rich" is decent at showing you stuff printed out,
    # but for reasons unknown to me it doesn't show "unhandled error"
    # from Twisted -- replace "with live:" here with "if 1:" to see
    # more error stuff (but of course no TUI)
    #if 1:
    with live:
        while not done_d.called:
            await deferLater(reactor, 0.25, lambda: None)


class FowlNearToFar(Protocol):
    """
    This is the side of the protocol that was listening .. so a local
    connection has come in, creating an instance of this protocol.

    In ``connectionMade`` we send the initial message. So the
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
        # we _had_ a queue in this, but nothing ever put anything into
        # it ..
        # self.factory.other_proto._maybe_drain_queue()

    @m.output()
    def emit_remote_failed(self, reason):
        print("bad", reason)
        self.factory.coop._status_tracker.outgoing_lost(
            self.factory.conn_id,
            reason,
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
            self.factory.coop._status_tracker.bytes_out(
                self.factory.conn_id,
                len(d),
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
        # might be "better state-machine" to do the message-sending in
        # an @output and use this method to send "connected()" @input
        # or similar?
        self._buffer = b""
        # self.do_trace(lambda o, i, n: print("{} --[ {} ]--> {}".format(o, i, n)))

        self.local = self.factory.other_proto
        self.factory.other_proto.remote = self
        self.transport.write(
            _pack_netstring(
                msgpack.packb({
                    "unique-name": self.factory.unique_name,
                })
            )
        )

        self.factory.coop._status_tracker.outgoing_connection(
            self.factory.unique_name,
            self.factory.conn_id,
        )

        # MUST wait for reply first -- queueing all data until
        # then
        self.factory.other_proto.transport.pauseProducing()

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        self.subchannel_closed(str(reason))
        if self.factory.other_proto:
            self.factory.other_proto.transport.loseConnection()
        if isinstance(reason, ConnectionDone):
            self.factory.coop._status_tracker.outgoing_done(
                self.factory.conn_id,
            )
        else:
            self.factory.coop._status_tracker.outgoing_lost(
                self.factory.conn_id,
                str(reason),
            )


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
            self.factory.coop._status_tracker.bytes_in(
                self.factory.conn_id,
                len(d),
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
            self.factory.coop._status_tracker.incoming_done(
                self.factory.conn_id,
            )
        else:
            self.factory.coop._status_tracker.incoming_lost(
                self.factory.conn_id,
                str(reason),
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
        self.remote = None
        self.conn_id = allocate_connection_id()

        # XXX do we need registerProducer somewhere here?
        # XXX make a real Factory subclass instead
        factory = Factory.forProtocol(FowlNearToFar)
        factory.other_proto = self
        factory.conn_id = self.conn_id
        factory.unique_name = self.factory.unique_name
        factory.coop = self.factory.coop
        # Note: connect_ep here is the Wormhole provided
        # IClientEndpoint that lets us create new subchannels -- not
        # to be confused with the endpoint created from the "local
        # endpoint string"
        d = self.factory.connect_ep.connect(factory)

        def err(f):
            self.factory.coop._status_tracker.error(str(f.value))
        d.addErrback(err)
        return d

    def connectionLost(self, reason):
        # XXX causes duplice local_close 'errors' in magic-wormhole ... do we not want to do this?)
        if self.remote is not None and self.remote.transport:
            self.remote.transport.loseConnection()

    def dataReceived(self, data):
        self.factory.coop._status_tracker.bytes_in(
            self.conn_id,
            len(data),
        )
        self.remote.transport.write(data)


class LocalServerFarSide(Protocol):
    """
    """

    def connectionMade(self):
        self.remote = None
        self.conn_id = allocate_connection_id()

        # XXX do we need registerProducer somewhere here?
        # XXX make a real Factory subclass instead
        factory = Factory.forProtocol(FowlNearToFar)
        factory.other_proto = self
        factory.conn_id = self.conn_id
        factory.unique_name = self.factory.unique_name
        factory.coop = self.factory.coop

        connect_ep = self.factory.coop.subchannel_connector()
#XXXX we want "a local connection" endpoint
        d = ensureDeferred(connect_ep.connect(factory))

        def err(f):
            self.factory.coop._status_tracker.error(
                str(f.value),
            )
        d.addErrback(err)

        def got_proto(proto):
            print("proto", proto)
        d.addCallback(got_proto)
        return d

    def connectionLost(self, reason):
        # XXX causes duplice local_close 'errors' in magic-wormhole ... do we not want to do this?)
        if self.remote is not None and self.remote.transport:
            self.remote.transport.loseConnection()

    def dataReceived(self, data):
        self.factory.coop._status_tracker.bytes_in(
            self.conn_id,
            len(data),
        )
        self.remote.transport.write(data)


class FowlSubprotocolListener(Factory):

    def __init__(self, reactor, coop, status):
        self.reactor = reactor
        self.coop = coop
        self.status = status
        super(FowlSubprotocolListener, self).__init__()

    def buildProtocol(self, addr):
        # 'addr' is a SubchannelAddress
        assert addr.subprotocol == "fowl", f"unknown subprotocol name: {addr}"
        p = FowlFarToNear()  # XXX cross-the-road joke in the naming? plz??
        p.factory = self
        return p


def _pack_netstring(data):
    """
    :param bytes data: data to length-prefix

    :returns: a binary 'netstring' with a length prefix encoded as a
    unsigned 16-bit integer.
    """
    if len(data) >= 2**16:
        raise ValueError("Too many bytes to encode in 16-bit integer")
    prefix = struct.pack("!H", len(data))
    return prefix + data



class FowlFarToNear(Protocol):
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
        self.factory.coop._status_tracker.bytes_out(
            self.conn_id,
            len(data),
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
        self.factory.coop._status_tracker.incoming_lost(
            self.conn_id,
            reason,
        )

    def _negative(self, reason):
        self.transport.write(
            _pack_netstring(
                msgpack.packb({
                    "connected": False,
                    "reason": reason,
                })
            )
        )


    @m.output()
    def send_positive_reply(self):
        """
        Reply to the other side that we've connected properly
        """
        self.transport.write(
            _pack_netstring(
                msgpack.packb({
                    "connected": True,
                })
            )
        )

    @m.output()
    def emit_incoming_connection(self, msg):
        self.factory.coop._status_tracker.incoming_connection(
            msg.get("unique-name", None),
            self.conn_id,
        )

    @m.output()
    def do_policy_check(self, msg):
        # note: do this policy check after the IncomingConnection
        # message is emitted (otherwise there will be cases where we
        # emit _just_ a IncomingLost which is confusing)

        # XXX instead of a "policy check" we should just ask our Coop
        # what port to use for this service-name -- either random or
        # pre-defined or whatever
        # (nah, we want to check if any FowlCoop has a "roost" for this service name?)
        name = msg.get("unique-name", None)
        if name is None or name not in self.factory.coop._services:
            self.policy_bad(f'No service "{name}"')
            return
        channel = self.factory.coop._services[name]
        port = msg.get("listen-port", None)
        if port is not None:
            if channel.listen_port != port:
                self.policy_bad(
                    f'Remote specified {port} for service {name} but '
                    'we have {channel.listen_port} here.'
                )
                return
        self.policy_ok(msg)

    @m.output()
    def local_disconnect(self):
        self._negative("Against local policy")
        self.transport.loseConnection()

    @m.output()
    def emit_incoming_lost(self, msg):
        self.factory.coop._status_tracker.incoming_lost(
            self.conn_id,
            f"Incoming connection against local policy: {msg}",
        )

    @m.output()
    def establish_local_connection(self, msg):
        """
        FIXME
        """
        ep = self.factory.coop.local_connect_endpoint(msg["unique-name"])
        ##ep = self.factory.coop.connect_endpoint(msg["unique-name"])
        ###ep = clientFromString(reactor, msg["local-destination"])

        factory = Factory.forProtocol(ConnectionForward)
        factory.other_proto = self
        factory.coop = self.factory.coop
        factory.conn_id = self.conn_id

#emit was here

        d = ep.connect(factory)

        def bad(fail):
            message = fail.getErrorMessage()
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
        self.conn_id = allocate_connection_id()
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

    def __init__(self, reactor, wormhole, coop):
        self._reactor = reactor
        self._wormhole = wormhole
        self._done = When() # we have shut down completely
        self._connected = When()  # our Peer has connected
        self._got_welcome = When()  # we received the Welcome from the server

        self._we_sent_closing = False
        self._did_disconnect = False
        self._got_closing_from_peer_d = Deferred()
        self._peer_connected = False
        self._dilated = None  # DilatedWormhole instance from wh.dilate()
        self._coop = coop

    # XXX wants to be an IService?
    async def stop(self):
        await self._stop_listening()
        await self._close_active_connections()
        await self._wormhole.close()
        # XXX put "session ending" code here, if it's useful

    async def _stop_listening(self):
        self._coop._clean_roosts()

    async def _close_active_connections(self):
        pass

    # XXX maybe wants to be an IService?
    def start(self):
        # pick up code for the status
        ensureDeferred(self._wormhole.get_code()).addCallbacks(
            self._coop._status_tracker.code_allocated,
            self._handle_error,
        )

        # pass on the welcome message
        ensureDeferred(self._wormhole.get_welcome()).addCallbacks(
            self._coop._status_tracker.welcomed,
            self._handle_error,
        )

        # when we get the verifier and versions, we emit "peer
        # connected"
        # (note that wormhole will "error" these Deferreds when the
        # wormhole shuts down early, e.g. with LonelyError -- but we
        # handle that elsewhere, so ignore errors here)
        peer_connected_d = DeferredList(
            [
                self._wormhole.get_verifier(),
                self._wormhole.get_versions(),
            ],
            consumeErrors=True,
        )

        @peer_connected_d.addCallback
        def peer_is_verified(results):
            for ok, exc in results:
                if not ok:
                    self._handle_error(exc)
                    return
            verifier = results[0][1]
            versions = results[1][1]

            d = ensureDeferred(self._do_dilate())

            @d.addCallback
            def did_dilate(arg):
                hex_verifier = binascii.hexlify(verifier).decode("utf8")
                self._coop._status_tracker.peer_connected(hex_verifier, versions)
                self._peer_connected = True
                # could / is partially alreayd done by FowlCoop
                return arg

        # hook up "incoming message" to input; this is async
        # tail-recursion basically -- we keep asking for "the next
        # message" from the wormhole. These kinds of messages come via
        # the Mailbox!

        # (this is basically a prototype of what "could / should" be
        # in Wormhole itself for graceful shutdown)
        def got_message(plaintext):
            try:
                js = json.loads(plaintext)
                if "closing" in js:
                    self._got_closing_from_peer_d.callback(int(js["closing"]))
                    if not self._we_sent_closing:
                        d = ensureDeferred(self.disconnect_session())
                        d.addErrback(self._handle_error)
            except Exception as e:
                print("a bad thing?", e)
                pass
            ensureDeferred(self._wormhole.get_message()).addCallback(
                got_message,
            ).addErrback(self._handle_error)
        ensureDeferred(self._wormhole.get_message()).addCallback(
            got_message,
        ).addErrback(self._handle_error)

        # hook up wormhole closed to input -- this can be for a
        # variety of reasons (and note we're cheating a bit here and
        # hooking this as both the callback and errback)
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
            self._coop._status_tracker.wormhole_closed(reason)
        ensureDeferred(self._wormhole._closed_observer.when_fired()).addBoth(was_closed)

    # public API methods

    # XXX moved from elsewhere, unify with close_wormhole()
    async def disconnect_session(self):
        """
        Nicely disconnect the session, by communicating with our peer.

        This is a PoC / test of a more robust "Mailbox closing"
        mechanism. The main idea is that we have a "half-closed"
        state, such that we can be sure the other side has gotten all
        our messages (and vice versa).

        Two peer computers, "Laptop" and "Desktop", are connected.

        When Laptop's human is done their session, Laptop sends a
        {"closing": True} message to Desktop. This indicates that
        Laptop is "done" and will send no other RemoteListen etc
        requests. Laptop now waits for Desktop to finish.

        When Desktop receives the {"closing": True} message from
        Laptop, it knows that human is done. Regardless of what UX
        Desktop implements, at some point it too is "done". It then
        sends a {"closing": True} message as well.

        Once both sides have sent a {"closing": True} message, it is
        safe to close the wormhole. Thus, when a side has both
        "decided it is done" (and send its {"closing": True}) then it
        waits for the other side's {"closing": True} message -- once
        this is received, the wormhole may be closed and the program
        exits.
        """
        # FIXME: all these messages should probably be via 'status' or
        # similar, in case we're using all this as a library.

        if self._did_disconnect:
            return
        self._did_disconnect = True

        # before we emit "closing", we must ensure we won't start
        # any new channels.
        await self._stop_listening()
        # XXX probably do this via req/resp .. or at least don't
        # plumb it through FowlDaemon
        self._wormhole.send_message(json.dumps({
            "closing": self._wormhole._boss._next_tx_phase,
        }).encode("utf8"))
        self._we_sent_closing = True

        # this can take "forever" if the other side isn't
        # responding at all, so we want to just hit the "race"
        # codepath anyway
        _ = ensureDeferred(self._close_active_connections())

        async def wait_for_user():

            def user_got_bored_waiting(*args):
                """
                If the user presses ctrl-C again while we're waiting for the peer
                message, we shut down right away.
                """
                # add back original handler, probably Twisted's
                signal.signal(signal.SIGINT, old_handler)
                self._got_closing_from_peer_d.callback(-1)
            old_handler = signal.signal(signal.SIGINT, user_got_bored_waiting)

            start = self._reactor.seconds()
            delay = 0.5

            # we have sent our 'closing' message. two cases:
            #
            # 1: if we never connected to our peer, there's no
            # point waiting for them.
            #
            # 2: if we _did_ ever connect to our peer we wait for
            # a return closing message, printing messages (should
            # be via status?) so the user isn't bored.
            if self._peer_connected:
                while not self._got_closing_from_peer_d.called:
                    await deferLater(reactor, delay, lambda: None)
                    delay = delay * 2
                    if delay > 10.0:
                        delay = 10.0
                    delta = humanize.naturaldelta(reactor.seconds() - start)
                    print(f'Waited {delta} for "closing" message from peer')

        which, result = await race([
            self._got_closing_from_peer_d,
            ensureDeferred(wait_for_user()),
        ])
        if which == 0:
            # XXX result can be None here if we never hit 'ready'
            # notification, needs proper test ..
            if result is not None and result >= 0:
                print(f"Clean close; peer saw phase={result}")
            else:
                print("Never got closing message from peer")

        try:
            await self.close_wormhole()
        except wormhole_errors.LonelyError:
            # maybe just say nothing? why does the user care about
            # this? (they probably hit ctrl-c anyway, how else can you get here?)
            print("Wormhole closed without peer.")
        print("Done.")

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
            from .api import _LocalListeningEndpoint
            self._coop.roost(
                msg.name,
                _LocalListeningEndpoint(reactor, msg.local_listen_port, msg.bind_interface),
                msg.remote_connect_port,
            )
            await self._coop.when_roosted(msg.name)

        @cmd.register(RemoteListener)
        async def _(msg):
            # if remote_connect_port is specified .. what does that even mean?
            # (is this like "the only permission check we'll need?")
            await ensureDeferred(
                self._coop.fledge(
                    msg.name,
                    msg.local_connect_port,
                    msg.remote_listen_port,
                    msg.connect_address,
                )
            )

        @cmd.register(Ping)
        async def _(msg):
            if hasattr(self._wormhole, "_boss"):
                if hasattr(self._wormhole._boss, "_D"):
                    if self._wormhole._boss._D._manager is not None:
                        def got_pong(round_trip):
                            #XXX FIXME TODO
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

    async def _do_dilate(self):
        # XXX move FowlWormhole do its own module so imports aren't broken
        dilated = self._dilated = await self._coop.dilate(
            transit_relay_location=TRANSIT_RELAY,
        )
        # the "FowlCoop.dilate" method already listens for commands,
        # incoming connections

        await self._wormhole.get_unverified_key()
        verifier_bytes = await self._wormhole.get_verifier()  # might WrongPasswordError

        await self._dilated.when_dilated()
        self._connected.trigger(self._reactor, verifier_bytes)
        return None

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
        self._coop._status_tracker.error(str(e))


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

    @output_command.register(RemoteListener)
    def _(msg):
        js["kind"] = "remote"

    @output_command.register(AllocateCode)
    def _(msg):
        js["kind"] = "allocate-code"

    @output_command.register(SetCode)
    def _(msg):
        js["kind"] = "set-code"

    @output_command.register(Ping)
    def _(msg):
        js["kind"] = "ping"

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
        if port is None:
            return
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
        "local": parser(
            LocalListener,
            [("name", str)],
            [
                ("local_listen_port", is_valid_port),
                ("remote_connect_port", is_valid_port),
                ("bind_interface", None),  # XXX wants like is_valid_ip_address or so
            ],
        ),
        "remote": parser(
            RemoteListener,
            [("name", str)],
            [
                ("remote_listen_port", is_valid_port),
                ("local_connect_port", is_valid_port),
                ("connect_address", None),  # wants is_valid_address() or similar?
            ],
        ),
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
        ListeningFailed: "listening-failed",
        AwaitingConnect: "awaiting-connect",
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
    print("LOADING", repr(json_str))
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
        "listening": parser(Listening, [("name", None), ("listening_port", None)]),
        "listening-failed": parser(ListeningFailed, [("reason", None)]),
        "awaiting-connect": parser(AwaitingConnect, [("name", None), ("local_port", int)]),
        "remote-connect-failed": parser(RemoteConnectFailed, [("id", int), ("reason", None)]),
        "outgoing-connection": parser(OutgoingConnection, [("id", int), ("endpoint", None), ("name", None)]),
##        "outgoing-lost": parser(),
        "outgoing-done": parser(OutgoingDone, [("service_name", str)]),
        "incoming-connection": parser(IncomingConnection, [("id", int), ("endpoint", None), ("name", None)]),
        "incoming-lost": parser(IncomingLost, [("id", int), ("reason", None)]),
        "incoming-done": parser(IncomingDone, [("id", int)]),
        "bytes-in": parser(BytesIn, [("id", int), ("bytes", int)]),
        "bytes-out": parser(BytesOut, [("id", int), ("bytes", int)]),
        "closed": parser(WormholeClosed, [("result", str)]),
        "pong": parser(Pong, [("ping_id", bytes), ("time_of_flight", float)]),
        "error": parser(WormholeError, [("message", str)]),
    }
    return kind_to_message[kind](cmd), cmd.get("timestamp", None)


async def create_fowl(config, fowl_status_tracker):

    # can we make this "a status listener" instead?
    start_time = reactor.seconds()
    if config.output_debug_messages:
        def debug_message(msg):
            try:
                js = fowld_output_to_json(msg)
                # don't leak our absolute time, more convenient anyway
                js["timestamp"] = reactor.seconds() - start_time
                config.output_debug_messages.write(
                    json.dumps(js) + "\n"
                )
            except Exception as e:
                print(e)
        fowl_status_tracker.add_listener(debug_message)

    if config.output_status:
        def status(st):
            try:
                js = asdict(st)
                # don't leak our absolute time, more convenient anyway
                js["timestamp"] = reactor.seconds() - start_time
                # process the subchannel stuff so the visualizer works out
                for sc in js["subchannels"].values():
                    sc["i"] = [
                        [d, ts - start_time]
                        for d, ts in sc["i"]
                    ]
                    sc["o"] = [
                        [d, ts - start_time]
                        for d, ts in sc["o"]
                    ]
                config.output_status.write(
                    json.dumps(js) + "\n"
                )
            except Exception as e:
                print(e)
        fowl_status_tracker.add_status_listener(status)

    if config.debug_file:
        kind = "invite" if config.code is None else "accept"
        w.debug_set_trace(kind, which="B N M S O K SK R RC L C T", file=config.debug_file)

    def command_message(msg):
        # XXX so if we try to shut down due to incompatible versions,
        # we hit this .. but this is insufficient, since now both
        # sides will be "waiting for message from peer" since they DID
        # connect via wormhole ... although maybe in this case we want
        # to just unilaterally shut down? because who knows?
        from .messages import Ready
        if isinstance(msg, PleaseCloseWormhole):
            d = ensureDeferred(fowl.close_wormhole())
            d.addErrback(lambda f: print(f"Error closing: {f.value}"))
        elif isinstance(msg, Ready):
            fowl._coop._set_ready()
        else:
            print(msg)

    # XXX FIXME hook in "output_wrapper" as a listener on the status_tracker

    w = await wormhole_from_config(reactor, config, fowl_status_tracker.wormhole_status)

    from .api import create_coop
    coop = create_coop(reactor, w, fowl_status_tracker)

#    @sm.set_trace
#    def _(start, edge, end):
#        print(f"trace: {start} --[ {edge} ]--> {end}")
    fowl = FowlWormhole(reactor, w, coop)
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

    status_tracker = _StatusTracker()
    status_tracker.add_listener(output_fowl_message)

    fowl = await create_fowl(config, status_tracker)
    fowl.start()

    # arrange to read incoming commands from stdin
    create_stdio = config.create_stdio or StandardIO
    dispatch = LocalCommandDispatch(config, fowl)
    create_stdio(dispatch)

    try:
        await Deferred()
    except CancelledError:
        await fowl.stop()


# async def _local_to_remote_forward(reactor, config, connect_ep, on_listen, on_message, cmd, coop):
#     """
#     Listen locally, and for each local connection create an Outgoing
#     subchannel which will connect on the other end. So the daemon is
#     running on the other side.
#     """
#     #XXX okay so this is "LocalServer for a local listener" ....
#     factory = Factory.forProtocol(LocalServer)
#     factory.config = config
#     factory.unique_name = cmd.name
#     factory.connect_ep = connect_ep
#     from .api import _LocalListeningEndpoint
#     ep = _LocalListeningEndpoint(reactor, cmd.listening_port)
#     port = await ep.listen(factory)
#     print("PORT", port, dir(port))
#     on_listen(port)
#     coop._status_tracker.add_remote_service(
#         unique_name,
#         port._realPort,
#     )


_local_requests = dict()
_create_request_id = count(1)


class _SendFowlCommand(Protocol):
    """
    Protocol spoken when we are asking our peer to open a listener, a
    request-response style interaction.

    use `await p.send_command(...)` to make a request, which will
    yield once the response is received. Cannot do overlapping
    requests (make another subchannel for that).
    """
    # XXX could / should use a DeferredSemaphore to _enforce_ the "no
    # overlapping requests" part?

    def __init__(self):
        # can a "Protocol" be an attrs @define?
        self._when_connected = When()
        self._message = Next()

    async def send_command(self, unique_name, remote_listen_port=None):
        """
        Ask the peer to open a service called `unique_name`, possibly
        asking for an exact port to listen on (avoid doing this
        whenever possible, as it's easier to succeed on a random
        port).

        However, things like Web services often need identitcal ports
        on both peers. If `remote_listen_port` is specified, it is an
        error if the peer cannot use that port.

        Use `next_message()` to await the reply
        """
        await self.when_connected()
        self.transport.write(
            _pack_netstring(
                    msgpack.packb({
                        "kind": "request-listener",
                        "unique-name": unique_name,
                        "listen-port": remote_listen_port,
                    })
            )
        )
        msg = await self.next_message()
        return msg

    # users typically don't need to call any of these

    def when_connected(self):
        return self._when_connected.when_triggered()

    def next_message(self):
        return self._message.next_item()

    # IProtocol API methods / overrides

    def connectionMade(self):
        self._when_connected.trigger(self.factory._reactor, None)

    def dataReceived(self, data):
        self._message.trigger(self.factory._reactor, data)


# When() doesn't support this ...
#    def connectionLost(self, reason):
#        self._done.trigger(self.factory.reactor, None)


class FowlCommands(Protocol):
    """
    Listen for commands from the peer
    """

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self._ports = []
        # outstanding requests, awaiting replies
        self._remote_requests = dict()

    def dataReceived(self, data):
        # magic-wormhole abuses the API a little and always sends an
        # entire "message" per dataReceived() call
        bsize = len(data)
        assert bsize >= 2, "expected at least 2 bytes"
        expected_size, = struct.unpack("!H", data[:2])
        assert bsize == expected_size + 2, "data has more than the message: {} vs {}: {}".format(bsize, expected_size + 2, repr(data[:55]))
        msg = msgpack.unpackb(data[2:])
        if msg["kind"] == "request-listener":
            unique_name = msg["unique-name"]
            desired_port = msg.get("listen-port", None)

            # okay, so our peer is possibly requesting a port --
            # that's fine, but only if _we_ didn't already specify one
            try:
                listen_ep = self.factory.coop._endpoint_for_service(unique_name, desired_port=desired_port)
                # if _we_ cared about the other peer's port, it was via --local ...:remote-connect=...
                remote_connect_port = self.factory.coop._roosts[unique_name].remote_connect_port
            except RuntimeError as e:
                self._reply_negative(unique_name, str(e))
                self.factory.coop._status_tracker.error(
                    f'Failed to listen on "{unique_name}": {e}',
                )
                return

            factory = Factory.forProtocol(LocalServerFarSide)
            factory.coop = self.factory.coop
            factory.unique_name = unique_name
            # XXX this can fail (synchronously) if address in use, for example
            d = ensureDeferred(listen_ep.listen(factory))

            def got_port(port):
                self._reply_positive(unique_name, remote_connect_port)
                channel = self.factory.coop._did_listen_locally(unique_name, port)
                self.factory.coop._status_tracker.added_remote_service(
                    unique_name,
                    channel.connect_port,
                )
                self._ports.append(port)
                return port

            def error(f):
                self._reply_negative(unique_name, f.getErrorMessage())
                self.factory.coop._status_tracker.error(
                    f'Failed to listen on "{unique_name}": {f.value}',
                )
            d.addCallback(got_port)
            d.addErrback(error)
            # XXX should await port.stopListening() somewhere...at the appropriate time
        else:
            self.factory.coop._status_tracker.error(
                f"Unknown control command: {msg[kind]}",
            )

    def _reply_positive(self, unique_name, desired_port):
        """
        Send a positive reply to a remote request
        """
        return self._reply_generic(listening=True, unique_name=unique_name, desired_port=desired_port)

    def _reply_negative(self, unique_name, reason=None):
        """
        Send a negative reply to a remote request
        """
        return self._reply_generic(listening=False, unique_name=unique_name, reason=reason)

    def _reply_generic(self, listening, reason=None, unique_name=None, desired_port=None):
        """
        Send a positive or negative reply to a remote request
        """
        content = {
            "kind": "listener-response",
            "unique-name": unique_name,
            "listening": bool(listening),
        }
        if desired_port is not None:
            content["desired-port"] = desired_port
        if reason is not None and not listening:
            content["reason"] = str(reason)
        self.transport.write(
            _pack_netstring(
                msgpack.packb(content)
            )
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


class FowlCommandsListener(Factory):
    """
    The subprotocol registered under the name 'fowl-commands'.
    """
    protocol = FowlCommands

    def __init__(self, reactor, coop, status):
        self.reactor = reactor
        self.coop = coop
        self.status = status
        super(FowlCommandsListener, self).__init__()


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
