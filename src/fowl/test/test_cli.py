import click.testing

import pytest_twisted


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


#from twisted.internet.protocol import ProtocolBase
from zope.interface import implementer
from twisted.internet.interfaces import IProcessProtocol
from twisted.internet.protocol import ProcessProtocol, Protocol, Factory
from twisted.internet.task import deferLater
from twisted.internet.defer import ensureDeferred, Deferred, CancelledError, DeferredList
from twisted.internet.error import ProcessTerminated
from twisted.internet.endpoints import serverFromString, clientFromString
from fowl._proto import _Config
from io import StringIO
import sys
import os
import signal
from fowl.observer import When, Framer, Accumulate, Next


@implementer(IProcessProtocol)
class CollectStreams(ProcessProtocol):

    def __init__(self, reactor):
        self._reactor = reactor
        self._streams = {
            1: b"",
            2: b"",
        }
        self._done = When()
        self._lines = Framer(reactor)

    def when_done(self):
        return self._done.when_triggered()

    def next_line(self):
        return self._lines.next_message()

    def childDataReceived(self, fd, data):
        self._streams[fd] += data
        if fd == 1:
            self._lines.data_received(data)

    def processExited(self, reason):
        pass  #reason == Failure

    def processEnded(self, reason):
        self._done.trigger(self._reactor, reason)



class Server(Protocol):
    _message = Accumulate(b"")

    def dataReceived(self, data):
        self._message.some_results(self.factory.reactor, data)

    async def next_message(self, expected_size):
        return await self._message.next_item(self.factory.reactor, expected_size)

    def send(self, data):
        self.transport.write(data)


class Client(Protocol):
    _message = Accumulate(b"")

    def dataReceived(self, data):
        self._message.some_results(reactor, data)

    async def next_message(self, expected_size):
        return await self._message.next_item(self.factory.reactor, expected_size)

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
        self._got_protocol.trigger(self.reactor, p)
        return p


# maybe Hypothesis better, via strategies.binary() ?
@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, mailbox):
    """
    One side invites, other accepts.

    Some commands are executed.
    Improvement: let Hypothesis make up commands, order, etc (how to assert?)
    """

    print("Starting invite side", os.environ.get("COVERAGE_PROCESS_STARTUP", "no startup"))

    invite_proto = CollectStreams(reactor)
    invite = reactor.spawnProcess(
        invite_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", mailbox.url,
            # redundant "--allow-connect", "2121",
            "--remote", "2222:2121",
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:invite.signalProcess(signal.SIGTERM))

    line = await invite_proto.next_line()
    assert line == "Connected."

    line = await invite_proto.next_line()
    assert line.startswith("Secret code: "), "Expected secret code"
    code = line.split(":")[1].strip()

    print(f"Detected code: {code}")

    accept_proto = CollectStreams(reactor)
    accept = reactor.spawnProcess(
        accept_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", mailbox.url,
            "--allow-listen", "2222",
            code,
        ],
        env=os.environ,
    )
    request.addfinalizer(lambda:accept.signalProcess(signal.SIGTERM))

    print("Starting accept side")

    while True:
        result, who = await DeferredList(
            [invite_proto.next_line(), accept_proto.next_line()],
            fireOnOneCallback=True,
        )
        who = "ACC" if who == 1 else "INV"
        print(f"   {who}: {result.strip()}")
        if "Listening:" in result:
            print("  one side is listening")
            break

    # now that they are connected, and one side is listening -- we can
    # ourselves listen on the "connect" port and connect on the
    # "listen" port -- that is, listen on 2121 (where there is no
    # listener) and connect on 2222 (where this test is listening)

    listener = ServerFactory()
    listener.reactor = reactor
    server_port = await serverFromString(reactor, "tcp:2121").listen(listener)
    client = clientFromString(reactor, "tcp:localhost:2222")
    client_factory = Factory.forProtocol(Client)
    client_factory.reactor = reactor
    client_proto = await client.connect(client_factory)
    server = await listener.next_client()

    datasize = 1234
    data = os.urandom(datasize)

    client_proto.send(data)
    msg = await server.next_message(len(data))
    assert msg == data, "Incorrect data transfer"

    print("done")
