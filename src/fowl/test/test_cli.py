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
from twisted.internet.defer import ensureDeferred, Deferred, CancelledError
from twisted.internet.error import ProcessTerminated
from fowl._proto import _Config
from io import StringIO
import sys
from fowl.observer import When


@implementer(IProcessProtocol)
class CollectStreams(ProcessProtocol):

    def __init__(self, reactor):
        self._reactor = reactor
        self._streams = {
            1: b"",
            2: b"",
        }
        self._done = When()

    def when_done(self):
        return self._done.when_triggered()

#    def makeConnection(self, process):
#        pass

    def childDataReceived(self, fd, data):
        self._streams[fd] += data

    def childConnectionLost(self, fd):
        pass

    def processExited(self, reason):
        self._done.trigger(self._reactor, reason)

    def processEnded(self, reason):
        pass  #reason == Failure


# maybe Hypothesis better, via strategies.binary() ?
@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, mailbox):
    """
    One side invites, other accepts.

    Some commands are executed.
    Improvement: let Hypothesis make up commands, order, etc (how to assert?)
    """

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

    invite_proto = CollectStreams(reactor)
    invite = reactor.spawnProcess(
        invite_proto,
        sys.executable,
        [
            "python", "-m", "fowl.cli",
            "invite",
            "--mailbox", mailbox.url,
            "--allow-connect", "4321",
            "--remote", "4444:4321",
        ]
    )


    try:
        await invite_proto.when_done()
    except ProcessTerminated as e:
        print("failed", invite_proto._streams[2].decode("utf8"))
