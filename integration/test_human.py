import re
import sys
import json
from collections import defaultdict

import pytest_twisted
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import ProcessProtocol, Factory, Protocol
from twisted.internet.task import deferLater
from twisted.internet.error import ProcessExitedAlready, ProcessDone
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import serverFromString, clientFromString
from attrs import define

from util import run_service
from fowl.observer import Next

# since the src/fowl/test/test_forward tests exercise the underlying
# "fowld" functionality (minus the entry-point), this tests the
# "user-friendly" frontend.


@define
class _Fowl:
    transport: ITransport
    protocol: ProcessProtocol


class _FowlProtocol(ProcessProtocol):
    """
    This speaks to an underlying ``fowl`` sub-process.
    """

    def __init__(self, reactor):
        self._reactor = reactor
        self._messages = []
        self.exited = Deferred()
        self._next = Next()

    def processEnded(self, reason):
        self.exited.callback(None)

    async def next_line(self):
        msg = await self._next.next_item()
        return msg

    def childDataReceived(self, childFD, data):
        for line in data.decode("utf8").split("\n"):
            if line.strip():
                self._next.trigger(self._reactor, line)
                self._messages.append(line)


async def fowl(reactor, request, subcommand, *extra_args, mailbox=None):
    """
    Run `fowl` with a given subcommand
    """

    args = [
        "fowl.cli",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])

    args.append(subcommand)
    args.extend(extra_args)
    proto = _FowlProtocol(reactor)
    transport = await run_service(
        reactor,
        request,
        args=args,
        protocol=proto,
    )
    return _Fowl(transport, proto)


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
async def test_human(reactor, request, wormhole):
    """
    """
    f0 = await fowl(reactor, request, "invite", mailbox=wormhole.url)
    msg = await f0.protocol.next_line()
    assert "connect" in msg.lower()
    msg = await f0.protocol.next_line()
    m = re.match(".* code: (.*).*", msg)
    assert m is not None, "Can't find secret code"
    code = m.group(1)
    print("code", code)

    f1 = await fowl(reactor, request, "accept", code, mailbox=wormhole.url)
    msg = await f1.protocol.next_line()
    print("f1", msg)
    msg = await f1.protocol.next_line()
    print("f1", msg)

    # both should say they're connected
    msg = await f0.protocol.next_line()
    assert "peer" in msg.lower() and "connected" in msg.lower()

    msg = await f1.protocol.next_line()
    assert "peer" in msg.lower() and "connected" in msg.lower()

