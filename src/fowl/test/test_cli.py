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
from fowl._proto import _Config
from io import StringIO
import sys
import os
import signal
from fowl.observer import When, Framer


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


# maybe Hypothesis better, via strategies.binary() ?
@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, mailbox):
    """
    One side invites, other accepts.

    Some commands are executed.
    Improvement: let Hypothesis make up commands, order, etc (how to assert?)
    """

    print("Starting invite side")

    invite_proto = CollectStreams(reactor)
    invite = reactor.spawnProcess(
        invite_proto,
        sys.executable,
        [
            "python", "-u", "-m", "fowl.cli",
            "--mailbox", mailbox.url,
            "--allow-connect", "1111",
            "--remote", "2222:1111",
        ],
        env=os.environ,
    )

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

    invite.signalProcess(signal.SIGTERM)
    accept.signalProcess(signal.SIGTERM)
    print("done")
