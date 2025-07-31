
import pytest_twisted
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import serverFromString, clientFromString

from util import fowld

from fowl.messages import *

# since the src/fowl/test/test_forward tests exercise the underlying
# "fowld" functionality (minus the entry-point), this tests the
# "user-friendly" frontend.


class HappyListener(Protocol):
    def __init__(self):
        self._waiting = []

    def when_made(self):
        d = Deferred()
        self._waiting.append(d)
        return d

    def dataReceived(self, data):
        print(f"unexpected client data: {data}")

    def connectionMade(self):
        self.transport.write(b"some test data" * 1000)
        self._waiting, waiting = [], self._waiting
        for d in waiting:
            d.callback(None)
        self.transport.loseConnection()


class HappyConnector(Protocol):
    """
    A client-type protocol for testing. Collects all data.
    """

    def connectionMade(self):
        self._data = b""
        self._waiting_exit = []

    def dataReceived(self, data):
        self._data += data

    def connectionLost(self, reason):
        self._waiting_exit, waiting = [], self._waiting_exit
        for d in waiting:
            d.callback(self._data)

    def when_done(self):
        """
        :returns Deferred: fires when the connection closes and delivers
            all data so far
        """
        d = Deferred()
        self._waiting_exit.append(d)
        return d


# could use hypothesis to try 'a bunch of ports' but fixed ports seem
# easier to reason about to me
@pytest_twisted.ensureDeferred
async def test_happy_remote(reactor, request, wormhole):
    """
    A session forwarding a single connection using the
    ``kind="remote"`` command.
    """
    f0 = await fowld(reactor, request, mailbox=wormhole.url)
    msg = await f0.protocol.next_message(Welcome)
    f0.protocol.send_message({"kind": "allocate-code"})
    code_msg = await f0.protocol.next_message(CodeAllocated)

    # normally the "code" is shared via human interaction

    f1 = await fowld(
        reactor, request,
        mailbox=wormhole.url
    )
    await f1.protocol.next_message(Welcome)
    f1.protocol.send_message({"kind": "set-code", "code": code_msg.code})
    await f1.protocol.next_message(CodeAllocated)

    await f0.protocol.next_message(PeerConnected)
    await f1.protocol.next_message(PeerConnected)

    # open a listener of some sort
    f0.protocol.send_message({
        "kind": "local",
        "name": "a unique service name",
    })
    f1.protocol.send_message({
        "kind": "remote",
        "name": "a unique service name",
        "remote_listen_port": 1111,
        "local_connect_port": 8888,
    })

    # f1 sent a remote-listen request, so f0 should receive it
    msg = await f0.protocol.next_message(Listening)
    assert isinstance(msg, Listening)
    assert msg.name == "a unique service name"
    assert msg.listening_port == 1111

    ep0 = serverFromString(reactor, "tcp:8888:interface=localhost")
    ep1 = clientFromString(reactor, "tcp:localhost:1111")

    # we listen on the "real" server interface
    port = await ep0.listen(Factory.forProtocol(HappyListener))
    request.addfinalizer(port.stopListening)
    # ...and connect via the "local" proxy/listener (so this
    # connection goes over the wormhole)
    client = await ep1.connect(Factory.forProtocol(HappyConnector))

    # extract the data
    data0 = await client.when_done()
    assert data0 == b"some test data" * 1000

    forwarded = await f1.protocol.next_message(BytesIn)
    assert forwarded.bytes == len(b"some test data" * 1000)


@pytest_twisted.ensureDeferred
async def test_happy_local(reactor, request, wormhole):
    """
    A session forwarding a single connection using the
    ``kind="local"`` command.
    """
    f0 = await fowld(reactor, request, mailbox=wormhole.url)
    f0.protocol.send_message({"kind": "danger-disable-permission-check"})
    f0.protocol.send_message({"kind": "allocate-code"})
    code_msg = await f0.protocol.next_message(CodeAllocated)

    # normally the "code" is shared via human interaction

    f1 = await fowld(reactor, request, mailbox=wormhole.url)
    f1.protocol.send_message({"kind": "danger-disable-permission-check"})
    f1.protocol.send_message({"kind": "set-code", "code": code_msg.code})
    # open a listener of some sort
    f1.protocol.send_message({
        "kind": "local",
        "name": "service0",
        "remote_connect_port": 1111,
        "local_listen_port": 8888,
    })
    f0.protocol.send_message({
        "kind": "remote",
        "name": "service0",
    })

    await f0.protocol.next_message(PeerConnected)
    await f1.protocol.next_message(PeerConnected)

    # f1 send a remote-listen request, so f0 should receive it
    msg = await f1.protocol.next_message(Listening)
    assert isinstance(msg, Listening)
    assert msg.name == "service0"
    assert msg.listening_port == 8888

    ep0 = serverFromString(reactor, "tcp:1111:interface=localhost")
    ep1 = clientFromString(reactor, "tcp:localhost:8888")

    # listen on the "real" server address
    port = await ep0.listen(Factory.forProtocol(HappyListener))
    request.addfinalizer(port.stopListening)
    # ...and connect via the configured "local listener" (so this goes
    # via the wormhole)
    client = await ep1.connect(Factory.forProtocol(HappyConnector))

    data0 = await client.when_done()
    assert data0 == b"some test data" * 1000

    b = await f0.protocol.next_message(BytesIn)
    assert b.bytes == len(b"some test data" * 1000)
