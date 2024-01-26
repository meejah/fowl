from __future__ import print_function

import sys
import json
import binascii
from typing import IO, Callable, Optional

import struct
from functools import partial

from attrs import frozen, field

import msgpack
import automat
from twisted.internet import reactor
from twisted.internet.defer import returnValue, Deferred, succeed, ensureDeferred, maybeDeferred, CancelledError
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.error import ConnectionDone
from twisted.internet.stdio import StandardIO
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure
from zope.interface import directlyProvides
from wormhole.cli.public_relay import RENDEZVOUS_RELAY as default_mailbox_url

from .observer import When



APPID = u"meejah.ca/wormhole/forward"


def _sequential_id():
    """
    Yield a stream of IDs, starting at 1
    """
    next_id = 0
    while True:
        next_id += 1
        yield next_id


allocate_connection_id = partial(next, _sequential_id())


@frozen
class _Config:
    """
    Represents a set of validated configuration
    """

    relay_url: str = default_mailbox_url
    code: str = None
    code_length: int = 2
    use_tor: bool = False
    appid: str = APPID
    debug_state: bool = False
    stdout: IO = sys.stdout
    create_stdio: Callable = None  # returns a StandardIO work-alike, for testing
    debug_file: IO = None  # for state-machine transitions


async def wormhole_from_config(config, wormhole_create=None):
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


async def frontend_accept(config, wormhole_coro):
    w = await wormhole_coro
    print(w)


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

    except Exception:
        # if we catch an error, we should close and then return the original
        # error (the close might give us an error, but it isn't as important
        # as the original one)
        try:
            await w.close()  # might be an error too
        except Exception:
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
        # -- handle in Dilation code?

        print(
            json.dumps({
                "kind": "bytes-in",
                "id": self._conn_id,
                "bytes": len(data),
            })
        )
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]

            if self.queue is not None:
                self.queue.append(d)
            else:
                self.remote.transport.write(d)


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


## refactoring _forward_loop etc
class FowlDaemon:
    m = automat.MethodicalMachine()

    def __init__(self, reactor, config, wormhole, message_out_handler=lambda _: None):
        self._reactor = reactor
        self._config = config
        self._wormhole = wormhole
        self._listening_ports = []
        self._code = None
        self._done = When()
        self._connected = When()
        self._command_queue = []
        self._running_command = None  # Deferred if we're running a command now
        self._message_out = message_out_handler
        self.connect_ep = self.control_proto = None

    def when_done(self):
        return self._done.when_triggered()

    def when_connected(self):
        return self._connected.when_triggered()

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
            await _local_to_remote_forward(self._reactor, self._config, self.connect_ep, self._listening_ports.append, cmd)
            print(
                json.dumps({
                    "kind": "listening",
                    "endpoint": cmd.listen_endpoint,
                    "connect-endpoint": cmd.local_endpoint,
                }),
                file=config.stdout,
                flush=True,
            )

        elif kind == "remote":
            print("remote commdn")
            await self.when_connected()
            assert self.control_proto is not None, "Need a control proto"
            # XXX if we get this before we've dilated, just remember it?
            # asks the other side to listen, connecting back to us
            try:
                await _remote_to_local_forward(self.control_proto, self._listening_ports.append, cmd)
            except Exception as e:
                self._report_error(e)

        else:
            raise KeyError(
                "Unknown command '{}'".format(cmd["kind"])
            )

    @m.state(initial=True)
    def no_code(self):
        """
        Connected, but haven't allocated code
        """

    @m.state()
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

    @m.input()
    def allocate_code(self, code_length):
        """
        """

    @m.input()
    def code_allocated(self):
        """
        """

    @m.input()
    def peer_connected(self, verifier):
        """
        """

    def _got_code(self, code):
        self._code = code
        self.code_allocated()

    def set_code(self, code):
        self._code = code
        self._wormhole.set_code(code)
        self.code_allocated()

    @m.output()
    def begin_allocate(self, code_length):
        self._wormhole.allocate_code(code_length)
        d = self._wormhole.get_code()
        d.addCallbacks(self._got_code, self._handle_error)

    @m.output()
    def emit_code_allocated(self):
        print(
            json.dumps({
                "kind": "code-allocated",
                "code": self._code
            }),
            file=self._config.stdout,
            flush=True,
        )

    @m.output()
    def emit_peer_connected(self, verifier):
        """
        """
        print(
            json.dumps({
                "kind": "peer-connected",
                "verifier": binascii.hexlify(verifier).decode("utf8"),
            }),
            file=self._config.stdout,
            flush=True,
        )

    @m.output()
    def do_dilate(self):
##XXX wait for do_dilate + _post_dilation_setup() to run before emitting the "code-allocated" message.....it's currently not working (the control connection)
        self.control_ep, self.connect_ep, self.listen_ep = self._wormhole.dilate(
            transit_relay_location="tcp:magic-wormhole-transit.debian.net:4001",
        )
        d = ensureDeferred(self._post_dilation_setup())
        d.addErrback(self._handle_error)
        d.addCallback(lambda _: self.emit_code_allocated())

    def _handle_error(self, f):
        self._report_error(f.error)

    def _report_Error(self, e):
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
        print("do dilate", self.control_proto)

        # listen for incoming subchannel OPENs
        in_factory = Factory.forProtocol(Incoming)
        in_factory.config = self._config
        in_factory.connect_ep = self.connect_ep
        listen_port = await self.listen_ep.listen(in_factory)

        await self._wormhole.get_unverified_key()
        verifier_bytes = await self._wormhole.get_verifier()  # might WrongPasswordError

        print("TRIGGER")
        try:
            self._connected.trigger(self._reactor, None)
        except Exception as e:
            print("ASDF",e)
        print("DONE")
        self.peer_connected(verifier_bytes)

        def cancelled(x):
            d = listen_port.stopListening()
            for port in self._listening_ports:
                d = port.stopListening()
            control_proto.transport.loseConnection()

        try:
            await Deferred(canceller=cancelled)
        except CancelledError:
            pass

    no_code.upon(
        allocate_code,
        enter=waiting_code,
        outputs=[begin_allocate],
    )
    no_code.upon(
        code_allocated,
        enter=waiting_peer,
        outputs=[do_dilate, emit_code_allocated],
    )

    waiting_code.upon(
        code_allocated,
        enter=waiting_peer,
        outputs=[do_dilate, emit_code_allocated],
    )

    waiting_peer.upon(
        peer_connected,
        enter=connected,
        outputs=[emit_peer_connected],
    )


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


class FowlOutputMessage:
    """
    An information message from fowld to the controller
    """


class FowlCommandMessage:
    """
    A command from the controller to fowld
    """


@frozen
class Welcome(FowlOutputMessage):
    """
    We have connected to the Mailbox Server and received the
    Welcome message.
    """
    # open-ended information from the server
    welcome: dict


@frozen
class AllocateCode(FowlCommandMessage):
    """
    Create a fresh code on the server
    """
    length: Optional[int] = None


@frozen
class SetCode(FowlCommandMessage):
    """
    Give a code we know to the servecr
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


@frozen
class LocalListener(FowlCommandMessage):
    """
    We wish to open a local listener.
    """
    listen_endpoint: str  # Twisted server-type endpoint string
    connect_endpoint: str  # Twisted client-type endpoint string


@frozen
class RemoteListener(FowlCommandMessage):
    """
    We wish to open a listener on the peer.
    """
    listen_endpoint: str  # Twisted server-type endpoint string
    connect_endpoint: str  # Twisted client-type endpoint string


@frozen
class Listening(FowlOutputMessage):
    """
    We have opened a local listener.

    Any connections to this litsener will result in a subchannel and a
    connect on the other side (to "connected_endpoint"). This message
    may result from a LocalListener or a RemoteListener command. This
    message will always appear on the side that's actually listening.
    """
    listen_endpoint: str  # Twisted server-type endpoint string
    connect_endpoint:str  # Twisted client-type endpoint string


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
                    raise ValueError('"{k}" is missing')
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
        "local": parser(LocalListener, [("listen-endpoint", None), ("connect-endpoint", None)], []),
        "remote": parser(RemoteListener, [("remote-endpoint", None), ("local-endpoint", None)], []),
    }
    return kind_to_message[kind](cmd)


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
        "code-allocatd": parser(CodeAllocated, [("code", None)]),
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

    welcome = await w.get_welcome()
    print(
        json.dumps({
            "kind": "welcome",
            "welcome": welcome,
        }),
        file=config.stdout,
        flush=True,
    )

    sm = FowlDaemon(reactor, config, w)
    # arrange to read incoming commands from stdin
    create_stdio = config.create_stdio or StandardIO
    dispatch = LocalCommandDispatch(config, sm)
    create_stdio(dispatch)

    # if config.code:
    #     sm.set_code(config.code)
    # else:
    #     sm.allocate_code(config.code_length)

    await sm.when_done()


async def _local_to_remote_forward(reactor, config, connect_ep, on_listen, cmd):
    """
    Listen locally, and for each local connection create an Outgoing
    subchannel which will connect on the other end.
    """
    # XXX these lines are "uncovered" but we clearly run them ... so
    # something wrong with subprocess coverage?? again???
    ep = serverFromString(reactor, cmd.listen_endpoint)
    factory = Factory.forProtocol(LocalServer)
    factory.config = config
    factory.endpoint_str = cmd.local_endpoint
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
        "listen-endpoint": cmd.remote_endpoint,
        "connect-endpoint": cmd.local_endpoint,
    })
    prefix = struct.pack("!H", len(msg))
    control_proto.transport.write(prefix + msg)
    return None


class Commands(Protocol):
    """
    Listen for (and send) commands over the command subchannel
    """
    _local_port = None

    # XXX make these msgpack too, for consistency!

    def dataReceived(self, data):
        # XXX can we depend on data being "one message"? or do we need length-prefixed?
        bsize = len(data)
        assert bsize >= 2, "expected at least 2 bytes"
        expected_size, = struct.unpack("!H", data[:2])
        assert bsize == expected_size + 2, "data has more than the message"
        msg = msgpack.unpackb(data[2:])
        if msg["kind"] == "remote-to-local":
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
                self._local_port = port
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

    def connectionLost(self, reason):
        if self._local_port is not None:
            return self._local_port.stopListening()


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
            print("doing command: ", cmd)
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
