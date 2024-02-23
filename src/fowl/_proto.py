from __future__ import print_function

import sys
import json
import binascii
from typing import IO, Callable, Optional
from functools import partial

import struct
from functools import partial

from attrs import frozen, field, asdict

import msgpack
import automat
from twisted.internet import reactor
from twisted.internet.defer import returnValue, Deferred, succeed, ensureDeferred, maybeDeferred, CancelledError, DeferredList
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.error import ConnectionDone
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure
from zope.interface import directlyProvides
from wormhole.cli.public_relay import RENDEZVOUS_RELAY as PUBLIC_MAILBOX_URL

from .observer import When



APPID = u"meejah.ca/wormhole/forward"
WELL_KNOWN_MAILBOXES = {
    "default": PUBLIC_MAILBOX_URL,
    "local": "ws://localhost:4000/v1",
    "winden": "wss://mailbox.mw.leastauthority.com/v1",
    # Do YOU run a public mailbox service? Contact the project to
    # consider having it listed here
}


def _sequential_id():
    """
    Yield a stream of IDs, starting at 1
    """
    next_id = 0
    while True:
        next_id += 1
        yield next_id


allocate_connection_id = partial(next, _sequential_id())


class FowlOutputMessage:
    """
    An information message from fowld to the controller
    """


class FowlCommandMessage:
    """
    A command from the controller to fowld
    """


# if we had ADT / Union types, these would both be that -- is this as
# close as we can get in Python?


@frozen
class Welcome(FowlOutputMessage):
    """
    We have connected to the Mailbox Server and received the
    Welcome message.
    """
    # open-ended information from the server
    welcome: dict


@frozen
class WormholeClosed(FowlOutputMessage):
    """
    The wormhole has been terminated.
    """
    result: str


@frozen
class AllocateCode(FowlCommandMessage):
    """
    Create a fresh code on the server
    """
    length: Optional[int] = None


@frozen
class SetCode(FowlCommandMessage):
    """
    Give a code we know to the server
    """
    code: str


@frozen
class CodeAllocated(FowlOutputMessage):
    """
    The secret wormhole code has been determined
    """
    code: str


@frozen
class PeerConnected(FowlOutputMessage):
    """
    We have evidence that the peer has connected
    """
    # hex-encoded 32-byte hash output (should match other peer)
    verifier: str
    versions: dict


@frozen
class LocalListener(FowlCommandMessage):
    """
    We wish to open a local listener.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class RemoteListener(FowlCommandMessage):
    """
    We wish to open a listener on the peer.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class Listening(FowlOutputMessage):
    """
    We have opened a local listener.

    Any connections to this listener will result in a subchannel and a
    connect on the other side (to "connected_endpoint"). This message
    may result from a LocalListener or a RemoteListener command. This
    message will always appear on the side that's actually listening.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class LocalConnection(FowlOutputMessage):
    """
    Something has connected to one of our listeners
    """
    id: int


@frozen
class BytesIn(FowlOutputMessage):
    id: int
    bytes: int


@frozen
class BytesOut(FowlOutputMessage):
    id: int
    bytes: int


@frozen
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
    create_stdio: Callable = None  # returns a StandardIO work-alike, for testing
    debug_file: IO = None  # for state-machine transitions


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
    )
    if config.debug_state:
        w.debug_set_trace("forward", file=config.stdout)
    return w


async def frontend_invite(config, wormhole_coro):
    if config.debug_file:
        w.debug_set_trace("forward", which="B N M S O K SK R RC L C T", file=config.debug_file)
    w = await wormhole_coro
    print(w)
    js = await w.get_welcome()
    print(js)
    w.allocate_code()
    code = await w.get_code()
    print(code)



async def frontend_accept(config, wormhole_coro):
    w = await wormhole_coro
    print(w)
    w.set_code(config.code)
    v = await w.get_versions()
    w.dilate()
    print("versions", v)


async def forward(config, wormhole_coro, reactor=reactor):
    """
    Set up a wormhole and process commands relating to forwarding.
    """
    w = await wormhole_coro

    if config.debug_file:
        w.debug_set_trace("forward", which="B N M S O K SK R RC L C T", file=config.debug_file)

    try:
        # if we succeed, we are done and should close
        await _forward_loop(reactor, config, w)
        await w.close()  # waits for ack

    except Exception as e:
        print("hey it's an error: ", type(e), e)
        # if we catch an error, we should close and then return the original
        # error (the close might give us an error, but it isn't as important
        # as the original one)
        try:
            await w.close()  # might be an error too
        except Exception as e:
            print("moar error", e)
            pass
        raise


class ForwardConnecter(Protocol):
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
    def remote_not_connected(self):
        """
        The reply message was negative
        """

    @m.input()
    def too_much_data(self):
        """
        Too many bytes sent in the reply.
        """
        # XXX is this really an error in this direction? i think only
        # on the other side...

    @m.input()
    def subchannel_closed(self):
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
            self.remote_not_connected()

    @m.output()
    def send_queued_data(self):
        """
        Confirm to the other side that we've connected.
        """
        self.factory.other_proto.transport.resumeProducing()
        self.factory.other_proto._maybe_drain_queue()

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
            print(
                json.dumps({
                    "kind": "bytes-out",
                    "id": self.factory.conn_id,
                    "bytes": len(d),
                }),
                file=self.factory.config.stdout,
                flush=True,
            )
            self.factory.other_proto.transport.write(d)

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
    evaluating.upon(
        remote_connected,
        enter=forwarding_bytes,
        outputs=[send_queued_data]
    )
    evaluating.upon(
        remote_not_connected,
        enter=finished,
        outputs=[close_connection]
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
    # kind-of feel this one is truely extraneous, but maybe not? (does
    # happen in integration tests, but maybe points at different
    # problem?)
    finished.upon(
        subchannel_closed,
        enter=finished,
        outputs=[]
    )

    do_trace = m._setTrace

    def connectionMade(self):
        self._buffer = b""
        ##self.do_trace(lambda o, i, n: print("{} --[ {} ]--> {}".format(o, i, n)))

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        self.subchannel_closed()
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
    def stream_closed(self):
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
            print(
                json.dumps({
                    "kind": "bytes-out",
                    "id": self.factory.conn_id,
                    "bytes": len(d),
                }),
                file=self.factory.config.stdout,
                flush=True,
            )
            self.factory.other_proto.transport.write(d)

    @m.output()
    def close_other_side(self):
        try:
            if self.factory.other_proto:
                self.factory.other_proto.transport.loseConnection()
        except Exception:
            pass

    forwarding_bytes.upon(
        got_bytes,
        enter=forwarding_bytes,
        outputs=[forward_bytes]
    )
    forwarding_bytes.upon(
        stream_closed,
        enter=finished,
        outputs=[close_other_side]
    )

    def connectionMade(self):
        pass

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        self.stream_closed()


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

        def got_proto(proto):
            proto.local = self
            self.remote = proto
            msg = msgpack.packb({
                "local-destination": self.factory.endpoint_str,
            })
            prefix = struct.pack("!H", len(msg))
            proto.transport.write(prefix + msg)

            print(
                json.dumps({
                    "kind": "local-connection",
                    "id": self._conn_id,
                }),
                file=self.factory.config.stdout,
                flush=True,
            )

            # MUST wait for reply first -- queueing all data until
            # then
            self.transport.pauseProducing()
            return proto

        # XXX do we need registerProducer somewhere here?
        factory = Factory.forProtocol(ForwardConnecter)
        factory.other_proto = self
        factory.conn_id = self._conn_id
        factory.config = self.factory.config
        # Note: connect_ep here is the Wormhole provided
        # IClientEndpoint that lets us create new subchannels -- not
        # to be confused with the endpoint created from the "local
        # endpoint string"
        d = self.factory.connect_ep.connect(factory)
        d.addCallback(got_proto)

        def err(f):
            print(
                json.dumps({
                    "kind": "error",
                    "id": self._conn_id,
                    "message": str(f.value),
                }),
                file=self.factory.config.stdout,
                flush=True,
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
        # XXX FIXME if len(data) >= 65535 must split "because noise"
        # -- handle in Dilation code? (yes)

        print(
            json.dumps({
                "kind": "bytes-in",
                "id": self._conn_id,
                "bytes": len(data),
            })
        )
        if False:
            max_noise = 65000
            while len(data):
                d = data[:max_noise]
                data = data[max_noise:]

                if self.queue is not None:
                    self.queue.append(d)
                else:
                    self.remote.transport.write(d)
        else:
            ## if Dilation handling of "more than noise packet" works
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

    @m.state(initial=True)
    def await_message(self):
        """
        The other side must send us a message
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
    def got_bytes(self, data):
        """
        We received some bytes
        """

    @m.input()
    def too_much_data(self):
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
    def subchannel_closed(self):
        """
        This subchannel has been closed
        """

    @m.input()
    def connection_made(self):
        """
        We successfully made the local connection
        """

    @m.input()
    def connection_failed(self):
        """
        Making the local connection failed
        """

    @m.output()
    def close_connection(self):
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
        print(
            json.dumps({
                "kind": "bytes-out",
                "id": self._conn_id,
                "bytes": len(data),
            }),
            file=self.factory.config.stdout,
            flush=True,
        )

        # XXX handle in Dilation? or something?
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]
            self._local_connection.transport.write(d)

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
                    self.too_much_data()
                    return
                # warning: recursive state-machine message
                self.got_initial_message(first_msg)

    @m.output()
    def send_positive_reply(self):
        """
        Reply to the other side that we've connected properly
        """
        # XXX another section like this: pack_netstring() or something
        msg = msgpack.packb({
            "connected": True,
        })
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)

    @m.output()
    def establish_local_connection(self, msg):
        """
        FIXME
        """
        data = msgpack.unpackb(msg)
        ep = clientFromString(reactor, data["local-destination"])
        print(
            json.dumps({
                "kind": "connect-local",
                "id": self._conn_id,
                "endpoint": data["local-destination"],
            }),
            file=self.factory.config.stdout,
            flush=True,
        )
        factory = Factory.forProtocol(ConnectionForward)
        factory.other_proto = self
        factory.config = self.factory.config
        factory.conn_id = self._conn_id

        d = ep.connect(factory)

        def bad(fail):
            print(
                json.dumps({
                    "kind": "error",
                    "id": self._conn_id,
                    "message": fail.getErrorMessage(),
                }),
                file=self.factory.config.stdout,
                flush=True,
            )
            reactor.callLater(0, lambda: self.connection_failed())
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
        enter=local_connect,
        outputs=[establish_local_connection]
    )
    local_connect.upon(
        connection_made,
        enter=forwarding_bytes,
        outputs=[send_positive_reply]
    )
    local_connect.upon(
        connection_failed,
        enter=finished,
        outputs=[close_connection]  # send-negative-reply?
    )
#FIXME enable    local_connect.upon(
#        subchannel_closed,
#        enter=finished,
#        outputs=[cancel_connect]
#    )

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
        print(
            json.dumps({
                "kind": "incoming-connect",
                "id": self._conn_id,
            }),
            file=self.factory.config.stdout,
            flush=True,
        )
        # XXX first message should tell us where to connect, locally
        # (want some kind of opt-in on this side, probably)
        self._buffer = b""
        self._local_connection = None

    def connectionLost(self, reason):
        """
        Twisted API
        """
        print(
            json.dumps({
                "kind": "incoming-lost",
                "id": self._conn_id,
            }),
            file=self.factory.config.stdout,
            flush=True,
        )
        self.subchannel_closed()

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

    def __init__(self, reactor, wormhole, daemon):
        self._reactor = reactor
        self._listening_ports = []
        self._wormhole = wormhole
        self._daemon = daemon
        self._done = When() # we have shut down completely
        self._connected = When()  # our Peer has connected
        self._got_welcome = When()  # we received the Welcome from the server

        # XXX shouldn't need a queue here; rely on FowlDaemon / statemachine
        self._command_queue = []
        self._running_command = None  # Deferred if we're running a command now
        self.connect_ep = self.control_proto = None

    # XXX want to be an IService?
    def start(self):

        # tie "we got a code" into the state-machine
        ensureDeferred(self._wormhole.get_code()).addCallbacks(
            self._daemon.code_allocated,
            self._handle_error,
        )

        # pass on the welcome message (don't "go in" to the
        # state-machine here, maybe we could / should?)
        ensureDeferred(self._wormhole.get_welcome()).addCallbacks(
            #XXX private API, possibly bad?
            lambda hello: self._daemon._message_out(Welcome(hello)),
            self._handle_error,
        )

        # when we get the verifier and versions, we emit "peer connected"
        results_d = DeferredList([
            self._wormhole.get_verifier(),
            self._wormhole.get_versions(),
        ])

        @results_d.addCallback
        def got_results(results):
            for ok, exc in results:
                if not ok:
                    self._handle_error(exc)
                    raise RuntimeError("Error retrieving verifier or versions")
            verifier = results[0][1]
            versions = results[1][1]
            self._daemon.peer_connected(verifier, versions)



    # public API methods

    def command(self, command: FowlCommandMessage) -> None:
        """
        Process an incoming command
        """
        print("COMMAND")

    # called from FowlDaemon when it has interactions to do

    def fowl_output(self, msg: FowlOutputMessage) -> None:
        """
        Process messages coming out of FowlDaemon, handling both stdout
        interaction as well as wormhole interactions.
        """
        # are we "crossing the streams" here, by having output messages
        # trigger either "wormhole I/O" or "stdin/out I/O"?
        if isinstance(msg, AllocateCode):
            d = wormhole.allocate_code()
            #XXX error-handling
        elif isinstance(msg, SetCode):
            self._set_code(msg)
        elif isinstance(msg, Welcome):
            self._got_welcome.trigger(self._reactor, msg.welcome)
        else:
            print(
                json.dumps(fowld_output_to_json(msg)),
                file=config.stdout,
                flush=True,
            )

    def _set_code(self, msg: SetCode) -> None:
        self._wormhole.set_code(msg.code)
        d = self._wormhole.get_code()

        def got_code(code):
            self._code = code
            self.code_allocated()
            return code
        d.addCallbacks(got_code, self._handle_error)

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

    #XXX
    def do_dilate(self):
##XXX wait for do_dilate + _post_dilation_setup() to run before emitting the "code-allocated" message.....it's currently not working (the control connection)
        self.control_ep, self.connect_ep, self.listen_ep = self._wormhole.dilate(
            transit_relay_location="tcp:magic-wormhole-transit.debian.net:4001",
        )
        d = ensureDeferred(self._post_dilation_setup())
        d.addErrback(self._handle_error)

    def do_shutdown(self):
        """
        Perform any (possibly async) tasks related to shutting down:
        - remove listeners
        """
        print("do shutdown")
        d = ensureDeferred(self.control_proto.when_done())
        self.control_proto.transport.loseConnection()
        d.addBoth(lambda _: self.shutdown_finished())

    def _handle_error(self, f):
        print("HANDLE_ERROR", f)
        self._report_error(f.value)

    def _report_error(self, e):
        print(
            json.dumps({
                "kind": "error",
                "message": str(e),
            }),
            file=self._config.stdout,
            flush=True,
        )

    async def _post_dilation_setup(self):
        # listen for commands from the other side on the control channel
        assert self.control_ep is not None, "Need control connection"
        fac = Factory.forProtocol(Commands)
        fac.config = self._config
        fac.connect_ep = self.connect_ep  # so we can pass it command handlers
        self.control_proto = await self.control_ep.connect(fac)

        # listen for incoming subchannel OPENs
        in_factory = Factory.forProtocol(Incoming)
        in_factory.config = self._config
        in_factory.connect_ep = self.connect_ep
        listen_port = await self.listen_ep.listen(in_factory)
###        self._ports.append(listen_port)

        await self._wormhole.get_unverified_key()
        verifier_bytes = await self._wormhole.get_verifier()  # might WrongPasswordError

        self._connected.trigger(self._reactor, verifier_bytes)
        self.peer_connected(verifier_bytes)

        #XXX this isn't actually called -- we're cancelling some other
        #deferred in the end. move to "cleanup" states + handlers in
        #the state-machine
        def cancelled(x):
            print("hey hey cancelled", x)
            d = listen_port.stopListening()
            print("xx", d)
            for port in self._listening_ports:
                d = port.stopListening()
                print("DDD", d)
            print("close", self.control_proto)
            self.control_proto.transport.loseConnection()

        try:
            await Deferred(canceller=cancelled)
        except CancelledError:
            print("BADBADBAD")
            raise

    def handle_command(self, cmd):
        self._command_queue.append(cmd)
        self._maybe_run_command()

    def _maybe_run_command(self):
        if not self._command_queue:
            return
        if self._running_command is not None:
            self._running_command.addBoth(lambda _: self._maybe_run_command())
        if not self._command_queue:
            return
        cmd = self._command_queue.pop(0)
        self._running_command = ensureDeferred(self._run_command(cmd))
        self._running_command.addErrback(self._handle_error)

    # XXX _should_ be able to make this non-async function, because we
    # hide the "real" async work behind our other machinery
    async def _run_command(self, cmd):
        if isinstance(cmd, AllocateCode):
            self.allocate_code(self._config.code_length if cmd.length is None else cmd.length)

        elif isinstance(cmd, SetCode):
            self.set_code(cmd.code)

        elif isinstance(cmd, LocalListener):
            await self.when_connected()
            assert self.connect_ep is not None, "need connect ep"
            # XXX if we get this before we've dilated, just remember it?
            # listens locally, conencts to other side

            # XXX to get rid of the "await" part, we can just roll the
            # "message_out" call and the "listening_ports.append" into
            # one ...
            await _local_to_remote_forward(self._reactor, self._config, self.connect_ep, self._listening_ports.append, cmd)
            self._message_out(
                Listening(
                    cmd.listen,
                    cmd.connect,
                )
            )

        elif isinstance(cmd, RemoteListener):
            await self.when_connected()
            assert self.control_proto is not None, "Need a control proto"
            # asks the other side to listen, connecting back to us
            await _remote_to_local_forward(self.control_proto, self._listening_ports.append, cmd)

        else:
            raise KeyError(
                "Unknown command '{}'".format(cmd["kind"])
            )


##XXXX
# okay so if we really want "a sans-io core" then all
# the "messages" have to be processed synchronously (by the state-machine)
# so what _ARE_ the in / out messages?
# we have two categories:
# - "stuff for the wormhole" (async calls to / from .. _DelegatedWormhole instance)
# - "stuff for the controller" (stdin/stdout)
#
# I _think_ it's okay to literally "be" the "delegate" (since all sync.)
# so, brainstorming through this "in code":

### wormhole messages
# "to" the wormhole messages:

class ToWormhole:
    pass


# is this maybe just "outside" the whole thing?
# "somehow" we cause code_allocated() to be called (either "given to
# us" or "we asked workhole for it")

@frozen
class SetCode(ToWormhole):
    code: str


@frozen
class AllocateCode(ToWormhole):
    code_length: int = 2


@frozen
class SendMessage(ToWormhole):
    plaintext: str


@frozen
class CloseWormhole(ToWormhole):
    pass


# "from" the wormhole messages (eveything the "delegate" calls, wormhole_*)
# (do we "bother" with these, or just hook the "delegate" directly in..?)

# hrrrmmm .. from the 'state machine' perspective, we just use @m.input for all our input I guess?
# otherwise, we just have a "process_input_message" that will do dumb type introspection
# and call an actual @m.input method
# ...so it's only for "emit_*" things that we have "actual message classes"
# ..._OR_ we could I guess do a "delegate" sort of thing, like magic-wormhole


### sans-io story here is this:
### stuff "coming in" are @m.input() methods
###   - (things on standard-in start as FowlInputMessages via ".command()")
### stuff "going out" is a FowlOutputMessage subclass


class FowlOutputMessage:
    pass


@frozen
class GotMessageFromPeer(FowlOutputMessage):
    plaintext: str


@frozen
class SendMessageToPeer(FowlOutputMessage):
    plaintext: str


@frozen
class AllocateCode(FowlCommandMessage):
    """
    Create a fresh code on the server
    """
    length: Optional[int] = None


@frozen
class SetCode(FowlCommandMessage):
    """
    Give a code we know to the server
    """
    code: str


@frozen
class LocalListener(FowlCommandMessage):
    """
    We wish to open a local listener.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


@frozen
class RemoteListener(FowlCommandMessage):
    """
    We wish to open a listener on the peer.
    """
    listen: str  # Twisted server-type endpoint string
    connect: str  # Twisted client-type endpoint string


# -to outside (i.e. "emit on stdout")


# FowlDaemon is the state-machine
#  - ultimately, it goes some notifications from 'the wormhole' but only via the I/O thing
#  - no "async def" / Deferred-returning methods
#  - no I/O
#
# FowlWormhole is "the I/O thing"
#  - can do async
#  - can do I/O
#  - proxies I/O and async'ly things

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
    to an `@m.input()` decorated method.

    We are also the wormhole "delegate" so wormhole callbacks are
    implemented directly as @m.input() methods.
    """
    m = automat.MethodicalMachine()

    def __init__(self, reactor, config, message_handler):
        self._reactor = reactor
        self._config = config
        self._messages = []  # pending plaintext messages to peer
        self._verifier = None
        self._versions = None
        self._message_out = message_handler

    def _send_message(self, msg):
        """
        Internal helper to pass a message to our external message handler
        (and do something useful on error)
        """
        try:
            self._message_out(msg)
        except Exception as e:
            print(f"Error in user code sending a message: {e}")

    # _DelegatedWormhole callbacks; see also IWormholeDelegate

    # _DelegatedWormhole callback
    def wormhole_got_welcome(self, welcome: dict) -> None:
        self._message_out(Welcome(welcome))
        # what @input do we trigger?

    # _DelegatedWormhole callback
    def wormhole_got_code(self, code: str) -> None:
        self.code_allocated(code)

    # _DelegatedWormhole callback
    def wormhole_got_unverified_key(self, key: bytes) -> None:  # XXX definitely bytes?
        pass

    # _DelegatedWormhole callback
    def wormhole_got_verifier(self, verifier: bytes) -> None:  # XXX bytes, or str?
        self._verifier = verifier
        # we "should" get verifier, then versions .. but
        if self._versions is not None and self._verifier is not None:
            self.peer_connected(self._verifier, self._versions)

    # _DelegatedWormhole callback
    def wormhole_got_versions(self, versions: dict) -> None:
        self._versions = versions
        # we "should" get verifier, then versions .. but
        if self._versions is not None and self._verifier is not None:
            self.peer_connected(self._verifier, self._versions)

    # _DelegatedWormhole callback
    def wormhole_got_message(self, plaintext: bytes) -> None:  # XXX bytes, or str?
        self.got_message(plaintext)

    # _DelegatedWormhole callback
    def wormhole_closed(self, result: str) -> None:
        self.shutdown(result)

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
        self._message_out(CodeAllocated(code))

    @m.output()
    def emit_peer_connected(self, verifier, versions):
        """
        """
        self._message_out(
            PeerConnected(
                binascii.hexlify(verifier).decode("utf8"),
                versions,
            )
        )

    @m.output()
    def emit_send_message(self, plaintext):
        self._message_out(
            SendMessageToPeer(
                plaintext,
            )
        )

    @m.output()
    def emit_got_message(self, plaintext):
        self._message_out(
            GotMessageFromPeer(
                plaintext,
            )
        )

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
        self._message_out(
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
        peer_connected,
        enter=connected,
        outputs=[emit_peer_connected, send_queued_messages],
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
                    raise ValueError(f'"{k}" is missing')
            for k, process in optional_parsers:
                try:
                    args[k] = js[k] if process is None else process(js[k])
                except KeyError:
                    pass
            return cls(**args)
        return parse

    kind_to_message = {
        "allocate-code": parser(AllocateCode, [], [("length", int)]),
        "set-code": parser(SetCode, [("code", None)], []),
        "local": parser(LocalListener, [("listen", None), ("connect", None)], []),
        "remote": parser(RemoteListener, [("listen", None), ("connect", None)], []),
    }
    return kind_to_message[kind](cmd)


def fowld_output_to_json(msg: FowlOutputMessage) -> dict:
    """
    Turn the given `msg` into a corresponding JSON-friendly dict
    (suitable for json.dumps() for example)
    """
    js = asdict(msg)
    js["kind"] = {
        CodeAllocated: "code-allocated",
        PeerConnected: "peer-connected",
        Welcome: "welcome",
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
                    raise ValueError('"{k}" is missing')
            return cls(**args)
        return parse

    kind_to_message = {
        "welcome": parser(Welcome, [("welcome", None)]),
        "code-allocated": parser(CodeAllocated, [("code", None)]),
        "peer-connected": parser(PeerConnected, [("verifier", binascii.unhexlify)]),
        "listening": parser(Listening, [("endpoint", None), ("connect-endpoint", None)]),
        "local-connection": parser(LocalConnection, [("id", int)]),
        "bytes-in": parser(BytesIn, [("id", int), ("bytes", int)]),
        "bytes-out": parser(BytesOut, [("id", int), ("bytes", int)]),
    }
    return kind_to_message[kind](cmd)


async def _forward_loop(reactor, config, w):
    """
    Run the main loop of the forward:
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

    sm = FowlDaemon(reactor, config, w, output_fowl_message)

    # arrange to read incoming commands from stdin
    create_stdio = config.create_stdio or StandardIO
    dispatch = LocalCommandDispatch(config, sm)
    create_stdio(dispatch)

    # if config.code:
    #     sm.set_code(config.code)
    # else:
    #     sm.allocate_code(config.code_length)

    try:
        await sm.when_done()
    except Exception as e:
        print("ZINGA", sm._listening_ports)
        print("DING", type(e))
        # XXXX okay, this fixes it .. but how to hook in cleanup etc "properly"
        # (probably via state-machine etc)
        sm.shutdown()
        ###sm.control_proto.transport.loseConnection()
        raise


async def _local_to_remote_forward(reactor, config, connect_ep, on_listen, cmd):
    """
    Listen locally, and for each local connection create an Outgoing
    subchannel which will connect on the other end.
    """
    # XXX these lines are "uncovered" but we clearly run them ... so
    # something wrong with subprocess coverage?? again???
    ep = serverFromString(reactor, cmd.listen)
    factory = Factory.forProtocol(LocalServer)
    factory.config = config
    factory.endpoint_str = cmd.connect
    factory.connect_ep = connect_ep
    port = await ep.listen(factory)
    on_listen(port)


async def _remote_to_local_forward(control_proto, on_listen, cmd):
    """
    Ask the remote side to listen on a port, forwarding back here
    (where our Incoming subchannel will be told what to connect
    to).
    """
    msg = msgpack.packb({
        "kind": "remote-to-local",
        "listen-endpoint": cmd.listen,
        "connect-endpoint": cmd.connect,
    })
    prefix = struct.pack("!H", len(msg))
    control_proto.transport.write(prefix + msg)
    return None


class Commands(Protocol):
    """
    Listen for (and send) commands over the command subchannel
    """
    _ports = []
    _done = When()

    def when_done(self):
        return self._done.when_triggered()

    def dataReceived(self, data):
        # XXX can we depend on data being "one message"? or do we need length-prefixed?
        bsize = len(data)
        assert bsize >= 2, "expected at least 2 bytes"
        expected_size, = struct.unpack("!H", data[:2])
        assert bsize == expected_size + 2, "data has more than the message"
        msg = msgpack.unpackb(data[2:])
        if msg["kind"] == "remote-to-local":
            #XXX do this _after_ we're definitely listening
            print(
                json.dumps({
                    "kind": "listening",
                    "endpoint": msg["listen-endpoint"],
                }),
                file=self.factory.config.stdout,
                flush=True,
            )

            # XXX ask for permission
            listen_ep = serverFromString(reactor, msg["listen-endpoint"])
            factory = Factory.forProtocol(LocalServer)
            factory.config = self.factory.config
            factory.connect_ep = self.factory.connect_ep
            factory.endpoint_str = msg["connect-endpoint"]

            # XXX this can fail (synchronously) if address in use (e.g.)
            d = listen_ep.listen(factory)

            def got_port(port):
                print("XXX got port", port)
                self._ports.append(port)
                return port
            d.addCallback(got_port)
            # XXX should await proto.stopListening() somewhere...at the appropriate time
        else:
            print(
                json.dumps({
                    "kind": "error",
                    f"message": "Unknown control command: {msg[kind]}",
                    "endpoint": msg["listen-endpoint"],
                }),
                file=self.factory.config.stdout,
                flush=True,
            )

    def _unregister_ports(self):
        for port in self._ports:
            port.stopListening()

    def connectionLost(self, reason):
        self._unregister_ports()
        self._done.trigger(None)


class LocalCommandDispatch(LineReceiver):
    """
    Wait for incoming commands (as lines of JSON) and dispatch them.
    """
    delimiter = b"\n"

    def __init__(self, cfg, daemon):
        super(LocalCommandDispatch, self).__init__()
        self.config = cfg
        self.daemon = daemon

    def connectionMade(self):
        pass

    def lineReceived(self, line):
        # XXX FIXME since we don't have req/resp IDs etc we should
        # only allow ONE command to be run at a time, and then its
        # answer printed (so e.g. even if our controller gets
        # ahead and issues 3 commands without waiting for the
        # answer, we need to do them in order)
        try:
            cmd = parse_fowld_command(line)
            self.daemon.handle_command(cmd)
        except Exception as e:
            print("BAD", repr(e))
            print(f"{line.strip()}: failed: {e}")
            raise


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
            'Cannot find txtorcon library (try "pip istall txtorcon")'
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
