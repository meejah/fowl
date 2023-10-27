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


@define
class _Fowl:
    transport: ITransport
    protocol: ProcessProtocol


class _FowlProtocol(ProcessProtocol):
    """
    This speaks to an underlying ``fow`` sub-process.
    ``fow`` consumes and emits a line-oriented JSON protocol.
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
        try:
            js = json.loads(data)
        except Exception as e:
            print(f"Not JSON: {data}")
        else:
            self._maybe_notify(js)

    def _maybe_notify(self, js):
        kind = js["kind"]
        if kind in self._message_awaits:
            notify, self._message_awaits[kind] = self._message_awaits[kind], list()
            for d in notify:
                d.callback(js)
        else:
            self._messages.append(js)

    def next_message(self, kind):
        d = Deferred()
        for idx, msg in enumerate(self._messages):
            if kind == msg["kind"]:
                del self._messages[idx]
                d.callback(msg)
                return d
        self._message_awaits[kind].append(d)
        return d

    def all_messages(self, kind=None):
        # we _do_ want to make a copy of the list every time
        # (so the caller can't "accidentally" mess with our state)
        return [
            msg
            for msg in self._messages
            if kind is None or msg["kind"] == kind
        ]


async def fowl(reactor, request, *extra_args, mailbox=None, startup=True):
    """
    Run `fowl`
    """

    args = [
        sys.executable,
        "-m",
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
        executable=sys.executable,
        args=args,
        protocol=proto,
    )
    if startup:
        await proto.next_message(kind="welcome")
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
    f0 = await fowl(reactor, request, mailbox=wormhole.url, startup=False)
    code_msg = await f0.protocol.next_message(kind="wormhole-code")

    # normally the "code" is shared via human interaction

    f1 = await fowl(
        reactor, request, code_msg["code"],
        mailbox=wormhole.url, startup=False,
    )
    # open a listener of some sort
    f1.transport.write(
        json.dumps({
            "kind": "remote",
            "remote-endpoint": "tcp:1111:interface=localhost",
            "local-endpoint": "tcp:localhost:8888",
        }).encode("utf8") + b"\n"
    )

    await f0.protocol.next_message("connected")
    await f1.protocol.next_message("connected")

    # f1 send a remote-listen request, so f0 should receive it
    msg = await f0.protocol.next_message("listening")
    assert msg == {'kind': 'listening', 'endpoint': 'tcp:1111:interface=localhost'}

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

    forwarded = await f1.protocol.next_message("forward-bytes")
    assert forwarded["bytes"] == len(b"some test data" * 1000)


@pytest_twisted.ensureDeferred
async def test_happy_local(reactor, request, wormhole):
    """
    A session forwarding a single connection using the
    ``kind="local"`` command.
    """
    f0 = await fowl(reactor, request, mailbox=wormhole.url, startup=False)
    code_msg = await f0.protocol.next_message(kind="wormhole-code")

    # normally the "code" is shared via human interaction

    f1 = await fowl(
        reactor, request, code_msg["code"],
        mailbox=wormhole.url, startup=False,
    )
    # open a listener of some sort
    f1.transport.write(
        json.dumps({
            "kind": "local",
            "listen-endpoint": "tcp:8888:interface=localhost",
            "local-endpoint": "tcp:localhost:1111",
        }).encode("utf8") + b"\n"
    )

    await f0.protocol.next_message("connected")
    await f1.protocol.next_message("connected")

    # f1 send a remote-listen request, so f0 should receive it
    msg = await f1.protocol.next_message("listening")
    assert msg == {'kind': 'listening', 'endpoint': 'tcp:8888:interface=localhost', 'connect-endpoint': 'tcp:localhost:1111'}

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

    forwarded = await f0.protocol.next_message("forward-bytes")
    assert forwarded["bytes"] == len(b"some test data" * 1000)
