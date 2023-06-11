from __future__ import print_function

import sys
import json
from typing import IO

import struct
from functools import partial

from attrs import frozen

import msgpack
from twisted.internet import reactor
from twisted.internet.defer import returnValue, Deferred, succeed, ensureDeferred, maybeDeferred, CancelledError
from twisted.internet.endpoints import serverFromString, clientFromString
from twisted.internet.protocol import Factory, Protocol
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
    stdin: IO = sys.stdin


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
    Incoming connections from the other side produce this protocol.

    Forwards data to the `.other_protocol` in the Factory only after
    awaiting a single incoming length-prefixed msgpack message.

    This message tells us when the other side has successfully
    connected (or not).
    """

    def connectionMade(self):
        self._buffer = b""

    def dataReceived(self, data):
        if self._buffer is not None:
            self._buffer += data
            bsize = len(self._buffer)
            if bsize >= 2:
                msgsize, = struct.unpack("!H", self._buffer[:2])
                if bsize > msgsize + 2:
                    raise RuntimeError("leftover data in first message")
                elif bsize == msgsize + 2:
                    msg = msgpack.unpackb(self._buffer[2:2 + msgsize])
                    if not msg.get("connected", False):
                        self.transport.loseConnection()
                        raise RuntimeError("Other side failed to connect")
                    self.factory.other_proto.transport.resumeProducing()
                    self.factory.other_proto._maybe_drain_queue()
                    self._buffer = None
            return
        else:
            self.factory.other_proto.transport.write(data)

    def connectionLost(self, reason):
        if self.factory.other_proto:
            self.factory.other_proto.transport.loseConnection()


class Forwarder(Protocol):
    """
    Forwards data to the `.other_protocol` in the Factory.
    """

    def connectionMade(self):
        self._buffer = b""

    def dataReceived(self, data):
        if self._buffer is not None:
            self._buffer += data
            bsize = len(self._buffer)

            if bsize >= 2:
                msgsize, = struct.unpack("!H", self._buffer[:2])
                if bsize > msgsize + 2:
                    raise RuntimeError("leftover")
                elif bsize == msgsize + 2:
                    msg = msgpack.unpackb(self._buffer[2:2 + msgsize])
                    if not msg.get("connected", False):
                        self.transport.loseConnection()
                        raise RuntimeError("no connection")
                    self.factory.other_proto._maybe_drain_queue()
                    self._buffer = None
            return
        else:
            max_noise = 65000
            while len(data):
                d = data[:max_noise]
                data = data[max_noise:]
                self.factory.other_proto.transport.write(d)

    def connectionLost(self, reason):
        if self.factory.other_proto:
            self.factory.other_proto.transport.loseConnection()

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
        pass # print("local connection lost")

    def dataReceived(self, data):
        # XXX FIXME if len(data) >= 65535 must split "because noise"
        # -- handle in Dilation code?

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

    def connectionMade(self):
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
        print("GGGG connectionLost", reason)
        print(
            json.dumps({
                "kind": "incoming-lost",
                "id": self._conn_id,
            }),
            file=self.factory.config.stdout,
        )
        if self._local_connection and self._local_connection.transport:
            self._local_connection.transport.loseConnection()

    def forward(self, data):
        print(
            json.dumps({
                "kind": "forward-bytes",
                "id": self._conn_id,
                "bytes": len(data),
            }),
            file=self.factory.config.stdout,
        )

        # XXX handle in Dilation? or something?
        max_noise = 65000
        while len(data):
            d = data[:max_noise]
            data = data[max_noise:]
            self._local_connection.transport.write(d)

    async def _establish_local_connection(self, first_msg):
        data = msgpack.unpackb(first_msg)
        ep = clientFromString(reactor, data["local-destination"])
        print(
            json.dumps({
                "kind": "connect-local",
                "id": self._conn_id,
                "endpoint": data["local-destination"],
            }),
            file=self.factory.config.stdout,
        )
        factory = Factory.forProtocol(Forwarder)
        factory.other_proto = self
        try:
            self._local_connection = await ep.connect(factory)
        except Exception as e:
            print(
                json.dumps({
                    "kind": "error",
                    "id": self._conn_id,
                    "message": str(e),
                }),
                file=self.factory.config.stdout,
            )
            self.transport.loseConnection()
            return
        # this one doesn't have to wait for an incoming message
        self._local_connection._buffer = None
        # sending-reply maybe should move somewhere else?
        # XXX another section like this: pack_netstring() or something
        msg = msgpack.packb({
            "connected": True,
        })
        prefix = struct.pack("!H", len(msg))
        self.transport.write(prefix + msg)

    def dataReceived(self, data):
        # we _should_ get only enough data to comprise the first
        # message, then we send a reply, and only then should the
        # other side send us more data ... XXX so we need to produce
        # an error if we get any data between "we got the message" and
        # our reply is sent.

        if self._buffer is None:
            assert self._local_connection is not None, "expected local connection by now"
            self.forward(data)

        else:
            self._buffer += data
            bsize = len(self._buffer)
            if bsize >= 2:
                expected_size, = struct.unpack("!H", self._buffer[:2])
                if bsize >= expected_size + 2:
                    first_msg = self._buffer[2:2 + expected_size]
                    # there should be no "leftover" data
                    if bsize > 2 + expected_size:
                        raise RuntimeError("protocol error: more than opening message sent")

                    d = ensureDeferred(
                        self._establish_local_connection(
                            first_msg,
                        )
                    )
                    # XXX this "d" getting dropped
                    d.addErrback(print)
                    self._buffer = None


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
    control_proto = await control_ep.connect(fac)

    # listen for incoming subchannel OPENs
    in_factory = Factory.forProtocol(Incoming)
    in_factory.config = config
    in_factory.connect_ep = connect_ep
    listen_ep.listen(in_factory)

    await w.get_unverified_key()
    verifier_bytes = await w.get_verifier()  # might WrongPasswordError

    # arrange to read incoming commands from stdin
    x = StandardIO(LocalCommandDispatch(reactor, config, control_proto, connect_ep))
    try:
        await Deferred(canceller=lambda _: None)
    except CancelledError:
        pass


async def _local_to_remote_forward(reactor, config, connect_ep, cmd):
    """
    Listen locally, and for each local connection create an Outgoing
    subchannel which will connect on the other end.
    """
    ep = serverFromString(reactor, cmd["listen-endpoint"])
    factory = Factory.forProtocol(LocalServer)
    factory.config = config
    factory.endpoint_str = cmd["local-endpoint"]
    factory.connect_ep = connect_ep
    proto = await ep.listen(factory)
    print(
        json.dumps({
            "kind": "listening",
            "endpoint": cmd["local-endpoint"],
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
    if "kind" not in cmd:
        raise ValueError("no 'kind' in command")

    if cmd["kind"] == "local":
        # listens locally, conencts to other side
        return await _local_to_remote_forward(reactor, config, connect_ep, cmd)
    elif cmd["kind"] == "remote":
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
            factory.endpoint_str = msg["connect-endpoint"]
            proto = listen_ep.listen(factory)

    def connectionLost(self, reason):
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
        try:
            cmd = json.loads(line)
            d = ensureDeferred(
                _process_command(self._reactor, self.config, self._control_proto, self._connect_ep, cmd)
            )
            d.addErrback(print)
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
