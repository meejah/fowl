import os
import random
import string
import json
from io import StringIO

from click.testing import CliRunner
from attr import define

import pytest
import pytest_twisted

from twisted.internet.task import deferLater
from twisted.internet.defer import ensureDeferred, Deferred, CancelledError
from twisted.internet.protocol import ProcessProtocol, Protocol, Factory
from twisted.internet.endpoints import serverFromString, clientFromString


from fowl.cli import fowl
#from fow.cli import accept
from fowl.cli import invite
from fowl._proto import (
    _Config,
    wormhole_from_config,
    forward,
)
from fowl.observer import (
    When,
    Next,
    Accumulate,
)


# XXX ultimately we might want a "TestingWormhole" object or something
# to put into wormhole proper.
# It would be in-memory and hook up all protocols to .. itself?


def create_wormhole_factory():

    def stream_of_valid_codes():
        for number in range(1, 1000):
            code = "{}-{}-{}".format(
                number,
                random.choice(string.ascii_letters),
                random.choice(string.ascii_letters),
            )
            yield code

    wormholes = []
    codes = stream_of_valid_codes()

    async def memory_wormhole(cfg):
        print("memory wormhole", cfg)

        @define
        class Endpoint:
            connects: list = []
            listens: list = []

            async def connect(self, addr):
                print("connect", addr)
                return self.connects.pop(0)

            def listen(self, factory):
                print("listen", factory)
                ear = self.listens.pop(0)
                return ear(factory)

        @define
        class Wormhole:
            code: str = None
            control_ep: Endpoint = Endpoint()
            connect_ep: Endpoint = Endpoint()
            listen_ep: Endpoint = Endpoint()

            async def get_welcome(self):
                return {
                    "testing": "this is a testing wormhole",
                }

            def allocate_code(self, words):
                self.code = next(codes)
                return self.code

            async def get_code(self):
                return self.code

            async def get_unverified_key(self):
                return b"0" * 32

            async def get_verifier(self):
                return b"x" * 32

            def dilate(self):
                return (self.control_ep, self.connect_ep, self.listen_ep)

        w = Wormhole()
        wormholes.append(w)
        return w
    return memory_wormhole


async def sleep(reactor, t):
    await deferLater(reactor, t, lambda: None)


@pytest_twisted.ensureDeferred
async def find_message(reactor, config, kind=None, timeout=10):
    """
    Await a message of particular kind in the stdout of config
    """
    for _ in range(timeout):
        messages = [
            json.loads(line)
            for line in config.stdout.getvalue().split("\n")
            if line
        ]
        for msg in messages:
            if msg["kind"] == kind:
                return msg
        await sleep(reactor, 1)
        print("no '{}' yet: {}".format(kind, " ".join([m.get("kind", "<kind missing>") for m in messages])))
    raise RuntimeError(
        f"Waited {timeout}s for message of kind={kind}"
    )


class FakeStandardIO(object):
    def __init__(self, proto, reactor, messages):
        self.disconnecting = False  ## XXX why? this is in normal one?
        self.proto = proto
        self.reactor = reactor
        self.messages = messages
        self.proto.makeConnection(self)
        for msg in messages:
            assert isinstance(msg, bytes), "messages must be bytes"
            self.proto.dataReceived(msg)


def ignore_cancel(f):
    if f.trap(CancelledError):
        return None
    return f


# maybe Hypothesis better, via strategies.binary() ?
@pytest_twisted.ensureDeferred
@pytest.mark.parametrize("datasize", [2**6])#, 2**16, 2**14))
@pytest.mark.parametrize("who", [True])#, False])
async def test_forward(reactor, request, mailbox, datasize, who):

    stdios = [
        None,
        None,
    ]

    def create_stdin0(proto, reactor=None):
        stdios[0] = FakeStandardIO(proto, reactor, messages=[])
        return stdios[0]

    def create_stdin1(proto, reactor=None):
        stdios[1] = FakeStandardIO(proto, reactor, messages=[])
        return stdios[1]

    config0 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        create_stdio=create_stdin0,
        stdout=StringIO(),
    )
    # note: would like to get rid of this ensureDeferred, but it
    # doesn't start "running" the coro until we do this...
    d0 = ensureDeferred(forward(reactor, config0))
    d0.addErrback(ignore_cancel)
    msg = await find_message(reactor, config0, kind="welcome")
    stdios[0].proto.dataReceived(
        json.dumps({
            "kind": "allocate-code",
        }).encode("utf8") + b"\n"
    )

    msg = await find_message(reactor, config0, kind="code-allocated")
    assert 'code' in msg, "Missing code"

    config1 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        create_stdio=create_stdin1,
        stdout=StringIO(),
        code=msg["code"],
    )

    d1 = ensureDeferred(forward(reactor, config1))
    d1.addErrback(ignore_cancel)
    msg = await find_message(reactor, config1, kind="welcome")
    stdios[1].proto.dataReceived(
        json.dumps({
            "kind": "set-code",
            "code": config1.code,
        }).encode("utf8") + b"\n"
    )

    await find_message(reactor, config0, kind="peer-connected")
    await find_message(reactor, config1, kind="peer-connected")

    class Server(Protocol):
        _message = Accumulate(b"")

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        def send(self, data):
            self.transport.write(data)


    class Client(Protocol):
        _message = Accumulate(b"")

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        def send(self, data):
            self.transport.write(data)


    class ServerFactory(Factory):
        protocol = Server
        noisy = True
        _got_protocol = Next()

        async def next_client(self):
            return await self._got_protocol.next_item()

        def buildProtocol(self, *args):
            p = super().buildProtocol(*args)
            self._got_protocol.trigger(reactor, p)
            return p

    listener = ServerFactory()
    server_port = await serverFromString(reactor, "tcp:1111").listen(listener)

    # both sides are connected -- now we can issue a "remote listen"
    # request
    stdios[0].proto.dataReceived(
        json.dumps({
            "kind": "local",
            "listen": "tcp:7777",
            "connect": "tcp:localhost:1111",
        }).encode("utf8") + b"\n"
    )
    msg = await find_message(reactor, config0, kind="listening")

    # if we do 'too many' test-cases debian complains about
    # "twisted.internet.error.ConnectBindError: Couldn't bind: 24: Too
    # many open files."
    # gc.collect() doesn't fix it.
    client = clientFromString(reactor, "tcp:localhost:7777") # NB: same port as in "kind=local" message!
    client_proto = await client.connect(Factory.forProtocol(Client))
    server = await listener.next_client()

    def cleanup():
        d0.cancel()
        d1.cancel()
        client_proto.transport.loseConnection()
        server.transport.loseConnection()
        server_port.stopListening()
    request.addfinalizer(cleanup)

    data = os.urandom(datasize)
    if who:
        client_proto.send(data)
        msg = await server.next_message(len(data))
    else:
        server.send(data)
        msg = await client_proto.next_message(len(data))
    who = not who
    assert msg == data, "Incorrect data transfer"


@pytest_twisted.ensureDeferred
@pytest.mark.parametrize("datasize", range(2**6, 2**16, 2**14))
@pytest.mark.parametrize("who", [True, False])
@pytest.mark.parametrize("wait_peer", [True, False])
async def test_drawrof(reactor, request, mailbox, datasize, who, wait_peer):

    stdios = [
        None,
        None,
    ]

    def create_stdin0(proto, reactor=None):
        stdios[0] = FakeStandardIO(proto, reactor, messages=[])
        return stdios[0]

    def create_stdin1(proto, reactor=None):
        stdios[1] = FakeStandardIO(proto, reactor, messages=[])
        return stdios[1]

    config0 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        create_stdio=create_stdin0,
        stdout=StringIO(),
    )
    # note: would like to get rid of this ensureDeferred, but it
    # doesn't start "running" the coro until we do this...
    d0 = ensureDeferred(forward(reactor, config0))
    d0.addErrback(ignore_cancel)
    msg = await find_message(reactor, config0, kind="welcome")

    # when connected, issue a "open listener" to one side
    stdios[0].proto.dataReceived(
        json.dumps({
            "kind": "allocate-code",
        }).encode("utf8") + b"\n"
    )

    msg = await find_message(reactor, config0, kind="code-allocated")
    assert 'code' in msg, "Missing code"

    config1 = _Config(
        relay_url=mailbox.url,
        use_tor=False,
        create_stdio=create_stdin1,
        stdout=StringIO(),
        code=msg["code"],
    )
    d1 = ensureDeferred(forward(reactor, config1))
    d1.addErrback(ignore_cancel)
    msg = await find_message(reactor, config1, kind="welcome")

    # now we can set the code on this side
    stdios[1].proto.dataReceived(
        json.dumps({
            "kind": "set-code",
            "code": config1.code,
        }).encode("utf8") + b"\n"
    )

    class Server(Protocol):
        _message = Accumulate(b"")
        _done = When()

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        async def when_closed(self):
            return await self._done.when_triggered()

        def send(self, data):
            self.transport.write(data)

        def connectionLost(self, reason):
            print("lost", self, reason)
            self._done.trigger(reactor, None)


    class Client(Protocol):
        _message = Accumulate(b"")

        def dataReceived(self, data):
            self._message.some_results(reactor, data)

        async def next_message(self, expected_size):
            return await self._message.next_item(reactor, expected_size)

        def send(self, data):
            self.transport.write(data)

    class ServerFactory(Factory):
        protocol = Server
        noisy = True
        _got_protocol = Next()

        async def next_client(self):
            return await self._got_protocol.next_item()

        def buildProtocol(self, *args):
            p = super().buildProtocol(*args)
            self._got_protocol.trigger(reactor, p)
            return p

    listener = ServerFactory()
    server_port = await serverFromString(reactor, "tcp:3333").listen(listener)

    # whether we explicitly wait for our peer, the underlying fowl
    # code should "do the right thing" if we just start issuing
    # listen/etc commands
    if wait_peer:
        print("Explicitly awaiting peers")
        msg = await find_message(reactor, config0, kind="peer-connected")
        msg = await find_message(reactor, config1, kind="peer-connected")
        print("Both sides have a peer")

    # both sides are connected -- now we can issue a "remote listen"
    # request
    stdios[0].proto.dataReceived(
        json.dumps({
            "kind": "remote",
            "listen": "tcp:8888",
            "connect": "tcp:localhost:3333",
        }).encode("utf8") + b"\n"
    )

    msg = await find_message(reactor, config1, kind="listening")
    print("listening", msg)

    # if we do 'too many' test-cases debian complains about
    # "twisted.internet.error.ConnectBindError: Couldn't bind: 24: Too
    # many open files."
    # gc.collect() doesn't fix it.
    client = clientFromString(reactor, "tcp:localhost:8888")  # NB: same as remote-endpoint
    client_proto = await client.connect(Factory.forProtocol(Client))
    print("waiting next client")
    server = await listener.next_client()
    print("got", server)

    def cleanup():
        print("cleanup")
        print("cancel d0", d0)
        d0.cancel()
        print("cancel d1", d1)
        d1.cancel()
        print("cancelled")
        server.transport.loseConnection()
        server_port.stopListening()
        d = ensureDeferred(server.when_closed())
        print("DDD", d)
        pytest_twisted.blockon(d)
        print("done listening")
    request.addfinalizer(cleanup)

    data = os.urandom(datasize)
    if who:
        client_proto.send(data)
        msg = await server.next_message(len(data))
    else:
        server.send(data)
        msg = await client_proto.next_message(len(data))
    assert msg == data, "Incorrect data transfer"
