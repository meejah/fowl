import sys
import json
from collections import defaultdict

import pytest_twisted
from twisted.internet.interfaces import ITransport
from twisted.internet.protocol import ProcessProtocol
from twisted.internet.error import ProcessExitedAlready, ProcessDone
from twisted.internet.defer import Deferred
from attrs import define

from util import run_service


@define
class _Fow:
    transport: ITransport
    protocol: ProcessProtocol


class _FowProtocol(ProcessProtocol):

    def __init__(self):
        # maps str -> list[Deferred]: kind-string to awaiters
        self._messages = []
        self._message_awaits = defaultdict(list)
        self.exited = Deferred()

    def processEnded(self, reason):
        self.exited.callback(None)

    def childDataReceived(self, childFD, data):
        print("DING", data)
        js = json.loads(data)
        print("MSG", js)
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


async def fow(reactor, request, subcommand, *extra_args, mailbox=None, startup=True):
    """
    Run `fow` with a given subcommand
    """

    args = [
        sys.executable,
        "-m",
        "fow",
    ]
    if mailbox is not None:
        args.extend([
            "--mailbox", mailbox,
        ])
    args.append(subcommand)
    args.extend(extra_args)
    print(args)
    proto = _FowProtocol()
    transport = await run_service(
        reactor,
        request,
        executable=sys.executable,
        args=args,
        protocol=proto,
    )
    if startup:
        await proto.next_message(kind="welcome")
    return _Fow(transport, proto)


@pytest_twisted.ensureDeferred
async def test_happy_path(reactor, request, wormhole):
    """
    start a session and end it immediately

    (if this fails, nothing else will succeed)
    """
    print(wormhole)
    f0 = await fow(reactor, request, "invite", mailbox=wormhole.url, startup=False)
    print(f0)
    code_msg = await f0.protocol.next_message(kind="wormhole-code")
    f1 = await fow(
        reactor, request, "accept", code_msg["code"],
        mailbox=wormhole.url, startup=False,
    )
    print(f1)
    f1.transport.write(
        json.dumps({
            "kind": "remote",
            "remote-endpoint": "tcp:8889",
            "local-endpoint": "tcp:localhost:8888",
        }).encode("utf8") + b"\n"
    )

    await f0.protocol.next_message("connected")
    await f1.protocol.next_message("connected")
