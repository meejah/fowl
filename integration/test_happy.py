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

from fowl.messages import *
from fowl._proto import parse_fowld_output

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

    def __init__(self):
        # all messages we've received that _haven't_ yet been asked
        # for via next_message()
        self._messages = []
        # maps str -> list[Deferred]: kind-string to awaiters
        self._message_awaits = defaultdict(list)
        self.exited = Deferred()

    def processEnded(self, reason):
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        if childFD != 1:
            print(data.decode("utf8"), end="")
            return
        try:
            msg = parse_fowld_output(data)
        except Exception as e:
            print(f"Not JSON: {data}: {e}")
        else:
            self._maybe_notify(msg)

    def _maybe_notify(self, msg):
        type_ = type(msg)
        if type_ in self._message_awaits:
            notify, self._message_awaits[type_] = self._message_awaits[type_], list()
            for d in notify:
                d.callback(msg)
        else:
            self._messages.append(msg)

    def send_message(self, js):
        data = json.dumps(js).encode("utf8") + b"\n"
        self.transport.write(data)

    def next_message(self, klass):
        d = Deferred()
        for idx, msg in enumerate(self._messages):
            if isinstance(msg, klass):
                del self._messages[idx]
                d.callback(msg)
                return d
        self._message_awaits[klass].append(d)
        return d

    def all_messages(self, klass=None):
        # we _do_ want to make a copy of the list every time
        # (so the caller can't "accidentally" mess with our state)
        return [
            msg
            for msg in self._messages
            if klass is None or isinstance(msg, klass)
        ]


async def fowld(reactor, request, *extra_args, mailbox=None):
    """
    Run `fowl` with a given subcommand
    """

    args = [
        "fowl",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])
    args.extend(extra_args)
    proto = _FowlProtocol()
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

    # remote side will fail to listen if we don't authorize permissions
    f0.protocol.send_message({
        "kind": "grant-permission",
        "listen": [1111],
        "connect": [],
    })
    f1.protocol.send_message({
        "kind": "grant-permission",
        "listen": [],
        "connect": [8888],
    })

    # open a listener of some sort
    f1.protocol.send_message({
        "kind": "remote",
        "listen": "tcp:1111:interface=localhost",
        "connect": "tcp:localhost:8888",
    })

    # f1 sent a remote-listen request, so f0 should receive it
    msg = await f0.protocol.next_message(Listening)
    assert msg == Listening(
        listen="tcp:1111:interface=localhost",
        connect="tcp:localhost:8888",
    )

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
        "listen": "tcp:8888:interface=localhost",
        "connect": "tcp:localhost:1111",
    })

    await f0.protocol.next_message(PeerConnected)
    await f1.protocol.next_message(PeerConnected)

    # f1 send a remote-listen request, so f0 should receive it
    msg = await f1.protocol.next_message(Listening)
    assert msg == Listening(
        listen="tcp:8888:interface=localhost",
        connect="tcp:localhost:1111",
    )

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
