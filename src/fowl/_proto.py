from __future__ import print_function

import sys
import json
from typing import IO, Callable

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


async def forward(config, wormhole_coro, reactor=reactor):
    """
    Set up a wormhole and process commands relating to forwarding.
    """
    w = await wormhole_coro

    try:
        # if we succeed, we are done and should close
        await _forward_loop(config, w)
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
                from twisted.internet import reactor
                reactor.callLater(0, lambda: self.got_reply(msg))
        return

    @m.output()
    def check_message(self, msg):
        """
        Initiate the local connection
        """
        print("MSG", msg)
        if msg.get("connected", False):
            self.remote_connected()
        else:
            self.remote_not_connected()

    @m.output()
    def send_queued_data(self):
        """
        Confirm to the other side that we've connected.
        """
        print("send queued")
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
        print("CONNECTOR forward_bytes", len(data))
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]
            print(
                json.dumps({
                    "kind": "forward-bytes",
                    "id": self.factory.conn_id,
                    "bytes": len(d),
                }),
                file=self.factory.config.stdout,
            )
            print("XXX", self.factory.other_proto.transport)
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
        self.do_trace(lambda o, i, n: print("{} --[ {} ]--> {}".format(o, i, n)))

    def dataReceived(self, data):
        self.got_bytes(data)

    def connectionLost(self, reason):
        print("CCCCCCC", reason)
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
                    "kind": "forward-bytes",
                    "id": self.factory.conn_id,
                    "bytes": len(d),
                    "hello": "foo",
                }),
                file=self.factory.config.stdout,
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
        print("ZZZZZ", reason)
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
            )
        d.addErrback(err)
        return d

    def _maybe_drain_queue(self):
        while self.queue:
            msg = self.queue.pop(0)
            self.remote.transport.write(msg)
        self.queue = None

    def connectionLost(self, reason):
        print("CCCCCASDFASDFASDFASDF", reason)
        # XXX causes duplice local_close 'errors' in magic-wormhole ... do we not want to do this?)
        if self.remote is not None and self.remote.transport:
            self.remote.transport.loseConnection()

    def dataReceived(self, data):
        # XXX FIXME if len(data) >= 65535 must split "because noise"
        # -- handle in Dilation code?
        print("DINGDING", data)

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
                "kind": "forward-bytes",
                "id": self._conn_id,
                "bytes": len(data),
                "zinga": "foo",
            }),
            file=self.factory.config.stdout,
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

        print("DINGDING", len(data))

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
        )
        # XXX first message should tell us where to connect, locally
        # (want some kind of opt-in on this side, probably)
        self._buffer = b""
        self._local_connection = None

    def connectionLost(self, reason):
        """
        Twisted API
        """
        print("LOST")
        print(
            json.dumps({
                "kind": "incoming-lost",
                "id": self._conn_id,
            }),
            file=self.factory.config.stdout,
        )
        self.subchannel_closed()

    def dataReceived(self, data):
        """
        Twisted API
        """
        print("RECV", len(data) )
        self.got_bytes(data)


async def _forward_loop(config, w):
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
    )

    if config.code:
        w.set_code(config.code)
    else:
        w.allocate_code(config.code_length)

    code = await w.get_code()
    # it's kind of weird to see this on "fow accept" so only show it
    # if we actually allocated a code
    if not config.code:
        print(
            json.dumps({
                "kind": "wormhole-code",
                "code": code,
            }),
            file=config.stdout,
        )

    control_ep, connect_ep, listen_ep = w.dilate(
        transit_relay_location="tcp:magic-wormhole-transit.debian.net:4001",
    )

    # listen for commands from the other side on the control channel
    fac = Factory.forProtocol(Commands)
    fac.config = config
    fac.connect_ep = connect_ep  # so we can pass it command handlers
    control_proto = await control_ep.connect(fac)

    # listen for incoming subchannel OPENs
    print("DING")
    in_factory = Factory.forProtocol(Incoming)
    in_factory.config = config
    in_factory.connect_ep = connect_ep
    x = await listen_ep.listen(in_factory)
    print("XX", x)

    await w.get_unverified_key()
    verifier_bytes = await w.get_verifier()  # might WrongPasswordError

    # arrange to read incoming commands from stdin
    create_stdio = config.create_stdio or StandardIO
    x = create_stdio(LocalCommandDispatch(reactor, config, control_proto, connect_ep))
    try:
        await Deferred(canceller=lambda _: None)
    except CancelledError:
        pass


async def _local_to_remote_forward(reactor, config, connect_ep, cmd):
    """
    Listen locally, and for each local connection create an Outgoing
    subchannel which will connect on the other end.
    """
    # XXX these lines are "uncovered" but we clearly run them ... so
    # something wrong with subprocess coverage?? again???
    ep = serverFromString(reactor, cmd["listen-endpoint"])
    factory = Factory.forProtocol(LocalServer)
    factory.config = config
    factory.endpoint_str = cmd["local-endpoint"]
    factory.connect_ep = connect_ep
    proto = await ep.listen(factory)
    print(
        json.dumps({
            "kind": "listening",
            "endpoint": cmd["listen-endpoint"],
            "connect-endpoint": cmd["local-endpoint"],
        }),
        file=config.stdout,
    )


async def _remote_to_local_forward(control_proto, cmd):
    """
    Ask the remote side to listen on a port, forwarding back here
    (where our Incoming subchannel will be told what to connect
    to).
    """
    msg = msgpack.packb({
        "kind": "remote-to-local",
        "listen-endpoint": cmd["remote-endpoint"],
        "connect-endpoint": cmd["local-endpoint"],
    })
    prefix = struct.pack("!H", len(msg))
    control_proto.transport.write(prefix + msg)
    return None


async def _process_command(reactor, config, control_proto, connect_ep, cmd):
    print("COMMAND", cmd)
    if "kind" not in cmd:
        raise ValueError("no 'kind' in command")

    if cmd["kind"] == "local":
        # listens locally, conencts to other side
        print("LLLLLLLLLLLLLLLLLL")
        return await _local_to_remote_forward(reactor, config, connect_ep, cmd)
    elif cmd["kind"] == "remote":
        print("RRRRRRRRRRRRRRRRRRRRR")
        # asks the other side to listen, connecting back to us
        return await _remote_to_local_forward(control_proto, cmd)

    raise KeyError(
        "Unknown command '{}'".format(cmd["kind"])
    )


class Commands(Protocol):
    """
    Listen for (and send) commands over the command subchannel
    """

    def connectionMade(self):
        pass

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
            )

            # XXX ask for permission
            listen_ep = serverFromString(reactor, msg["listen-endpoint"])
            factory = Factory.forProtocol(LocalServer)
            factory.config = self.factory.config
            factory.connect_ep = self.factory.connect_ep
            factory.endpoint_str = msg["connect-endpoint"]
            proto = listen_ep.listen(factory)
        else:
            print(
                json.dumps({
                    "kind": "error",
                    f"message": "Unknown control command: {msg[kind]}",
                    "endpoint": msg["listen-endpoint"],
                }),
                file=self.factory.config.stdout,
            )

    def connectionLost(self, reason):
        print("BYBY", reason)
        pass  # print("command connectionLost", reason)


class LocalCommandDispatch(LineReceiver):
    """
    Wait for incoming commands (as lines of JSON) and dispatch them.
    """
    delimiter = b"\n"

    def __init__(self, reactor, cfg, control_proto, connect_ep):
        super(LocalCommandDispatch, self).__init__()
        self.config = cfg
        self._reactor = reactor
        self._control_proto = control_proto
        self._connect_ep = connect_ep

    def connectionMade(self):
        print(
            json.dumps({
                "kind": "connected",
            }),
            file=self.config.stdout,
        )

    def lineReceived(self, line):
        # XXX FIXME since we don't have req/resp IDs etc we should
        # only allow ONE command to be run at a time, and then its
        # answer printed (so e.g. even if our controller gets
        # ahead and issues 3 commands without waiting for the
        # answer, we need to do them in order)
        print("LINE", line)
        try:
            cmd = json.loads(line)
            d = ensureDeferred(
                _process_command(self._reactor, self.config, self._control_proto, self._connect_ep, cmd)
            )
            def err(f):
                print("ERR: {}".format(f))
            d.addErrback(err)
            return d
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
